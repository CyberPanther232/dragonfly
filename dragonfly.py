from threading import Thread, Lock
import socket
import requests
import time
from flask import Flask, request, jsonify, render_template, url_for
import logging
from datetime import datetime

# --- Configuration ---
DRAGONFLY_IP = "10.23.24.7"
DRAGONFLY_PORT = 8080
HEARTBEAT_PORT = 9999
SSH_PORT = 4663
HTTP_PORT = 8006

# --- Global State ---
nymph_agents = {}  # Key: (ip, device_name), Value: NymphAgent instance
nymph_agents_lock = Lock()
logger = logging.getLogger('dragonfly')

# --- Agent Class ---
class NymphAgent:
    def __init__(self, ip, device_name="nymph-1", os_name=None):
        self.ip = ip
        self.device_name = device_name
        self.last_heartbeat = None
        self.status = {
            "os": f"{os_name or 'unknown'}",
            "http": "unknown",
            "ssh": "unknown",
            "heartbeat": "unknown"
        }
        self.status_lock = Lock()
        self.threads_started = False

    def get_status(self):
        with self.status_lock:
            # Check if heartbeat has timed out
            if self.last_heartbeat and (datetime.now() - self.last_heartbeat).total_seconds() > 30:
                self.status["heartbeat"] = "offline"
            return dict(self.status)

    def update_heartbeat(self):
        with self.status_lock:
            self.status["heartbeat"] = "online"
            self.last_heartbeat = datetime.now()

    def start_detection_threads(self):
        if self.threads_started:
            return
        self.threads_started = True

        # --- Service Check Threads ---
        def httpecho():
            while True:
                try:
                    echo = requests.get(f"http://{self.ip}:{HTTP_PORT}/", timeout=5)
                    with self.status_lock:
                        if echo.status_code == 200:
                            self.status["http"] = "online"
                        else:
                            self.status["http"] = "offline"
                except requests.RequestException:
                    with self.status_lock:
                        self.status["http"] = "offline"
                finally:
                    # Log status regardless of outcome
                    with self.status_lock:
                        status_val = self.status["http"].upper()
                        log_msg = f"HTTP:{status_val}:{self.ip}:{HTTP_PORT}:{datetime.now()}"
                        if status_val == "ONLINE":
                            logger.info(log_msg)
                        else:
                            logger.error(log_msg)
                    time.sleep(10)

        def sshdetect():
            while True:
                try:
                    with socket.create_connection((self.ip, SSH_PORT), timeout=5):
                        with self.status_lock:
                            self.status["ssh"] = "online"
                except (socket.timeout, ConnectionRefusedError, OSError):
                    with self.status_lock:
                        self.status["ssh"] = "offline"
                finally:
                    with self.status_lock:
                        status_val = self.status["ssh"].upper()
                        log_msg = f"SSH:{status_val}:{self.ip}:{SSH_PORT}:{datetime.now()}"
                        if status_val == "ONLINE":
                            logger.info(log_msg)
                        else:
                            logger.error(log_msg)
                    time.sleep(10)

        Thread(target=httpecho, daemon=True).start()
        Thread(target=sshdetect, daemon=True).start()

# --- Centralized Heartbeat Listener ---
def global_heartbeat_listener():
    """A single listener to handle heartbeats from all agents."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((DRAGONFLY_IP, HEARTBEAT_PORT))
        logger.info(f"Heartbeat listener started on {DRAGONFLY_IP}:{HEARTBEAT_PORT}")
    except socket.error as e:
        logger.error(f"FATAL: Could not bind heartbeat listener socket: {e}")
        return

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            ip_from, _ = addr
            
            if data == b'heartbeat':
                with nymph_agents_lock:
                    # Find which agent this heartbeat belongs to
                    for agent in nymph_agents.values():
                        if agent.ip == ip_from:
                            agent.update_heartbeat()
                            logger.info(f"Heartbeat received from {agent.device_name} at {ip_from}")
                            sock.sendto(b'ack', addr)
                            break
        except socket.error as e:
            logger.error(f"Heartbeat listener socket error: {e}")
            time.sleep(5)


# --- Main Application ---
def main():
    logging.basicConfig(filename='dragonfly.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Start the single, global heartbeat listener
    Thread(target=global_heartbeat_listener, daemon=True).start()

    app = Flask(__name__)

    @app.route('/')
    def index():
        """Serves the main dashboard page."""
        return render_template('index.html')

    @app.route('/status')
    def get_status():
        """Provides the status of all agents as JSON."""
        with nymph_agents_lock:
            all_status = {f"{agent.device_name}-{agent.ip}": agent.get_status() for agent in nymph_agents.values()}
        return jsonify(all_status)

    @app.route('/nymph', methods=['POST'])
    def nymph_handler():
        """Registers a new Nymph agent."""
        data = request.json
        if not data or 'ip' not in data or 'device_name' not in data:
            return jsonify({"error": "Invalid request, 'ip' and 'device_name' are required"}), 400

        os_name = data.get('os') # Use .get for optional fields
        key = (data['ip'], data['device_name'])

        with nymph_agents_lock:
            if key not in nymph_agents:
                logger.info(f"Registering new agent: {data['device_name']} at {data['ip']}")
                nymph_agent = NymphAgent(data['ip'], data['device_name'], os_name=os_name)
                nymph_agents[key] = nymph_agent
                nymph_agent.start_detection_threads()
            else:
                logger.info(f"Agent already registered: {data['device_name']} at {data['ip']}")
                nymph_agent = nymph_agents[key]

        return jsonify({"message": "Nymph agent processed", "status": nymph_agent.get_status()}), 200

    app.run(host=DRAGONFLY_IP, port=DRAGONFLY_PORT, debug=False)

if __name__ == "__main__":
    main()