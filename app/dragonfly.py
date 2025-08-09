from threading import Thread, Lock
import socket
import requests
import time
from flask import Flask, request, jsonify, render_template, url_for
import logging
from datetime import datetime

# --- Configuration ---
DRAGONFLY_IP = "0.0.0.0"  # Bind to all interfaces to be accessible
DRAGONFLY_PORT = 8080
HEARTBEAT_PORT = 9999

# --- Global State ---
nymph_agents = {}  # Key: (ip, device_name), Value: NymphAgent instance
nymph_agents_lock = Lock()
alerts_list = [] # To store incoming alerts
alerts_lock = Lock()
logger = logging.getLogger('dragonfly')

# --- Agent Class ---
class NymphAgent:
    def __init__(self, ip, device_name="nymph-1", os_name=None, http=True, ssh=True, ssh_port=22, http_port=80):
        self.ip = ip
        self.device_name = device_name
        self.os_name = os_name or 'unknown'
        self.last_heartbeat = None
        self.status = {
            "os": self.os_name,
            "http": "unknown",
            "ssh": "unknown",
            "heartbeat": "unknown"
        }
        self.http = http
        self.ssh = ssh
        self.http_port = http_port
        self.ssh_port = ssh_port
        self.status_lock = Lock()
        self.threads_started = False

    def get_status(self):
        with self.status_lock:
            # Check if heartbeat has timed out (e.g., 35 seconds)
            if self.last_heartbeat and (datetime.now() - self.last_heartbeat).total_seconds() > 35:
                self.status["heartbeat"] = "offline"
            
            # Create a full dictionary to return, including non-status info
            full_info = {
                "ip": self.ip,
                "device_name": self.device_name,
                **self.status
            }
            return full_info
        
    def check_log(self):
        """Placeholder for log checking logic."""
        try:
            with open(f'{self.device_name}.log', 'r') as log_file:
                logs = log_file.readlines()
        except FileNotFoundError:
            logger.error(f"Log file for {self.device_name} not found.")
            open(f'{self.device_name}.log', 'w').close()  # Create an empty log file if it doesn't exist


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
                    requests.get(f"http://{self.ip}:{self.http_port}/", timeout=5)
                    with self.status_lock:
                        self.status["http"] = "online"
                except requests.RequestException:
                    with self.status_lock:
                        self.status["http"] = "offline"
                time.sleep(30) # Check every 30 seconds

        def sshdetect():
            while True:
                try:
                    with socket.create_connection((self.ip, self.ssh_port), timeout=5):
                        with self.status_lock:
                            self.status["ssh"] = "online"
                except (socket.timeout, ConnectionRefusedError, OSError):
                    with self.status_lock:
                        self.status["ssh"] = "offline"
                time.sleep(30) # Check every 30 seconds
        
        if self.http:
            Thread(target=httpecho, daemon=True).start()
        if self.ssh:
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
                            # logger.info(f"Heartbeat received from {agent.device_name} at {ip_from}")
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
        return render_template('dashboard.html')
    
    @app.route("/logout")
    def logout():
        """Handles user logout."""
        return jsonify({"message": "Logged out successfully"}), 200
    
    @app.route("/agent-profile/<device_name>")
    def agent_profile(device_name):
        """Serves the agent profile page for a specific device."""
        with nymph_agents_lock:
            agent = next((agent for agent in nymph_agents.values() if agent.device_name == device_name), None)
            if not agent:
                return jsonify({"error": "Agent not found"}), 404
            return render_template('agent_profile.html', agent=agent)
    
    @app.route('/dashboard')
    def dashboard():
        """Serves the dashboard page with agent status."""
        return render_template('dashboard.html')

    @app.route('/nymph_agents')
    def nymph_agents_view():
        """Displays the list of registered Nymph agents."""
        return render_template('nymph_agents.html')

    # --- API Routes ---
    @app.route('/api/agents')
    def get_agents_api():
        """Provides the status of all agents as JSON."""
        with nymph_agents_lock:
            agents_list = [agent.get_status() for agent in nymph_agents.values()]
        return jsonify(agents_list)

    @app.route('/api/alerts')
    def get_alerts_api():
        """Provides the list of alerts as JSON for the frontend."""
        with alerts_lock:
            # The JS expects 'active', for now, we send all alerts
            return jsonify({"active": alerts_list, "history": []})

    @app.route('/alert', methods=['POST'])
    def alert_handler():
        """Receives security alerts from Nymph agents."""
        data = request.json
        if not data or 'alert' not in data or 'agent_info' not in data:
            return jsonify({"error": "Invalid alert format"}), 400

        with alerts_lock:
            # Add a server-side timestamp and store the alert
            data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            alerts_list.insert(0, data) # Insert at the beginning to show newest first
            # Keep the list from growing indefinitely
            if len(alerts_list) > 500:
                alerts_list.pop()
        
        logger.warning(f"ALERT RECEIVED from {data['agent_info'].get('device_name')}: {data['alert'].get('type')}")
        return jsonify({"message": "Alert received"}), 200

    @app.route('/nymph', methods=['GET', 'POST'])
    def nymph_handler():
        if request.method == 'POST':
            data = request.json
            if not data or 'ip' not in data or 'device_name' not in data:
                return jsonify({"error": "Invalid request, 'ip' and 'device_name' are required"}), 400

            key = (data['ip'], data['device_name'])
            with nymph_agents_lock:
                if key not in nymph_agents:
                    logger.info(f"Registering new agent: {data['device_name']} at {data['ip']}")
                    nymph_agent = NymphAgent(
                        ip=data['ip'], 
                        device_name=data['device_name'],
                        os_name=data.get('os'),
                        ssh=data.get('ssh_service', True),
                        ssh_port=data.get('ssh_port', 22),
                        http=data.get('http_service', True),
                        http_port=data.get('http_port', 80)
                    )
                    nymph_agents[key] = nymph_agent
                    nymph_agent.start_detection_threads()
                else:
                    nymph_agent = nymph_agents[key]

            return jsonify({"message": "Nymph agent processed", "status": nymph_agent.get_status()}), 200

        # --- GET logic for sync check ---
        elif request.method == 'GET':
            ip = request.args.get('ip')
            device_name = request.args.get('device_name')
            if not ip or not device_name:
                return jsonify({"error": "Missing 'ip' or 'device_name' in query parameters"}), 400
            key = (ip, device_name)
            with nymph_agents_lock:
                if key in nymph_agents:
                    return jsonify({"message": "Agent is registered", "status": nymph_agents[key].get_status()}), 200
                else:
                    return jsonify({"error": "Agent not registered"}), 404

    app.run(host=DRAGONFLY_IP, port=DRAGONFLY_PORT, debug=False)

if __name__ == "__main__":
    main()
