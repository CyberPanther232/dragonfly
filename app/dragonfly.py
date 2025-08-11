import os
import time
import socket
import logging
import ast
import base64
from threading import Thread, Lock
from datetime import datetime
from urllib.parse import unquote

import requests
import nacl.secret
import nacl.utils
from flask import Flask, request, jsonify, render_template, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuration ---
DRAGONFLY_IP = "0.0.0.0"
DRAGONFLY_PORT = 8080
HEARTBEAT_PORT = 9999

# --- Global State ---
nymph_agents = {}
nymph_agents_lock = Lock()
alerts_list = []
alerts_lock = Lock()
logger = logging.getLogger('dragonfly')

# --- Flask App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24) # Use a random key for security

# --- Database Configuration ---
db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'users.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Flask-Login Configuration ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "You must be logged in to access this page."
login_manager.login_message_category = "info"


# --- Database Model (Moved here from login.py) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # You might want to add an email field back here if needed for registration
    # email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# --- User Loader for Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    """Load a user by their ID."""
    return User.query.get(int(user_id))


# --- Agent Class (No changes needed here) ---
class NymphAgent:
    def __init__(self, ip, nacl_key, device_name="nymph-1", os_name=None, http=True, ssh=True, ssh_port=22, http_port=80):
        self.ip = ip
        self.nacl_key = nacl_key
        self.device_name = device_name
        self.os_name = os_name or 'unknown'
        self.last_heartbeat = None
        self.status = {
            "os": self.os_name, "http": "unknown", "ssh": "unknown", "heartbeat": "unknown"
        }
        self.http = http
        self.ssh = ssh
        self.http_port = http_port
        self.ssh_port = ssh_port
        self.status_lock = Lock()
        self.threads_started = False

    def get_status(self):
        with self.status_lock:
            if self.last_heartbeat and (datetime.now() - self.last_heartbeat).total_seconds() > 35:
                self.status["heartbeat"] = "offline"
            return {"ip": self.ip, "device_name": self.device_name, **self.status}
        
    def check_log(self):
        log_path = os.path.join('.', 'logs', f'{self.device_name}.log')
        if not os.path.exists(log_path):
            open(log_path, 'w').close()
    
    def write_key(self):
        key_path = os.path.join('.', 'pond', f'{self.device_name}.key')
        try:
            with open(key_path, "wb") as key_file:
                key_file.write(self.nacl_key)
            return True
        except Exception as e:
            logger.error(f"Failed to write key for {self.device_name}: {e}")
            return False
            
    def update_heartbeat(self):
        with self.status_lock:
            self.status["heartbeat"] = "online"
            self.last_heartbeat = datetime.now()

    def start_detection_threads(self):
        if self.threads_started: return
        self.threads_started = True
        if self.http: Thread(target=self._httpecho, daemon=True).start()
        if self.ssh: Thread(target=self._sshdetect, daemon=True).start()

    def _httpecho(self):
        while True:
            try:
                requests.get(f"http://{self.ip}:{self.http_port}/", timeout=5)
                with self.status_lock: self.status["http"] = "online"
            except requests.RequestException:
                with self.status_lock: self.status["http"] = "offline"
            time.sleep(30)

    def _sshdetect(self):
        while True:
            try:
                with socket.create_connection((self.ip, self.ssh_port), timeout=5):
                    with self.status_lock: self.status["ssh"] = "online"
            except (socket.timeout, ConnectionRefusedError, OSError):
                with self.status_lock: self.status["ssh"] = "offline"
            time.sleep(30)


# --- Background Threads (No changes needed) ---
def global_heartbeat_listener():
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
            if data == b'heartbeat':
                with nymph_agents_lock:
                    for agent in nymph_agents.values():
                        if agent.ip == addr[0]:
                            agent.update_heartbeat()
                            sock.sendto(b'ack', addr)
                            break
        except socket.error as e:
            logger.error(f"Heartbeat listener socket error: {e}")
            time.sleep(5)

def update_nymph_log(device_name, message):
    log_path = os.path.join('.', 'logs', f'{device_name}.log')
    try:
        with open(log_path, 'a') as log_file:
            log_file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
    except Exception as e:
        logger.error(f"Failed to update log for {device_name}: {e}")


# --- Authentication Routes (Corrected Logic) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=True)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/settings")
@login_required
def settings():
    # This route now correctly renders the settings page.
    # Add POST logic here if you want to handle form submissions (e.g., password change).
    return render_template('settings.html')


# --- Core Application Routes (Protected) ---
@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))

@app.route("/agent-profile/<device_name>")
@login_required
def agent_profile(device_name):
    safe_device_name = unquote(device_name)
    with nymph_agents_lock:
        agent = next((a for a in nymph_agents.values() if a.device_name.lower() == safe_device_name.lower()), None)
    if not agent:
        return jsonify({"error": "Agent not found"}), 404
    with alerts_lock:
        agent_alerts = [a for a in alerts_list if a.get('agent_info', {}).get('device_name', '').lower() == safe_device_name.lower()]
    return render_template('agent_profile.html', agent=agent.get_status(), alerts=agent_alerts)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/nymph_agents')
@login_required
def nymph_agents_view():
    return render_template('nymph_agents.html')


# --- API Routes (Unprotected, as they are for agents) ---
@app.route('/api/agents')
def get_agents_api():
    with nymph_agents_lock:
        return jsonify([agent.get_status() for agent in nymph_agents.values()])

@app.route('/api/alerts')
def get_alerts_api():
    with alerts_lock:
        return jsonify({"active": alerts_list, "history": []})

@app.route('/alert', methods=['POST'])
def alert_handler():
    raw_data = request.json
    if not raw_data or 'device_id' not in raw_data:
        return jsonify({"error": "Invalid alert format"}), 400
    device_id = raw_data['device_id']
    key_path = os.path.join('.', 'pond', f'{device_id}.key')
    try:
        with open(key_path, "rb") as key_file: key = key_file.read()
        nacl_box = nacl.secret.SecretBox(key)
        decrypted_data = {
            "device_id": device_id,
            "category": nacl_box.decrypt(base64.b64decode(raw_data['category'])).decode('utf-8'),
            "severity": nacl_box.decrypt(base64.b64decode(raw_data['severity'])).decode('utf-8'),
            "agent_info": ast.literal_eval(nacl_box.decrypt(base64.b64decode(raw_data['agent_info'])).decode('utf-8')),
            "alert": ast.literal_eval(nacl_box.decrypt(base64.b64decode(raw_data['alert'])).decode('utf-8'))
        }
    except Exception as e:
        logger.error(f"Decryption error for device {device_id}: {e}")
        return jsonify({"error": "Decryption failed or key not found"}), 400
    
    with alerts_lock:
        decrypted_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        alerts_list.insert(0, decrypted_data)
        if len(alerts_list) > 500: alerts_list.pop()
    
    agent_name = decrypted_data['agent_info'].get('device_name', 'Unknown')
    alert_type = decrypted_data['alert'].get('type', 'Unknown')
    logger.warning(f"ALERT RECEIVED from {agent_name}: {alert_type}")
    update_nymph_log(agent_name, f"Alert received: {alert_type}")
    return jsonify({"message": "Alert received"}), 200

@app.route('/nymph', methods=['GET', 'POST'])
def nymph_handler():
    if request.method == 'POST':
        data = request.json
        if not data or 'ip' not in data or 'device_name' not in data:
            return jsonify({"error": "Invalid request"}), 400
        key = (data['ip'], data['device_name'])
        with nymph_agents_lock:
            if key not in nymph_agents:
                logger.info(f"Registering new agent: {data['device_name']} at {data['ip']}")
                nymph_agent = NymphAgent(ip=data['ip'], nacl_key=nacl.encoding.HexEncoder.decode(data['nacl_key'].encode()), **data)
                nymph_agents[key] = nymph_agent
                nymph_agent.check_log()
                if not nymph_agent.write_key(): return jsonify({"error": "Failed to write key"}), 500
                nymph_agent.start_detection_threads()
            return jsonify({"message": "Nymph agent processed", "status": nymph_agents[key].get_status()}), 200
    elif request.method == 'GET':
        ip, device_name = request.args.get('ip'), request.args.get('device_name')
        if not ip or not device_name: return jsonify({"error": "Missing params"}), 400
        key = (ip, device_name)
        with nymph_agents_lock:
            return jsonify({"status": nymph_agents[key].get_status()}) if key in nymph_agents else ({"error": "Agent not registered"}, 404)

# --- Database Initialization Command ---
@app.cli.command("init-db")
def init_db_command():
    """Clears existing data and creates new tables."""
    db.create_all()
    print("Initialized the database.")

# --- Main Execution ---
def main():
    log_dir = os.path.join('.', 'logs')
    pond_dir = os.path.join('.', 'pond')
    if not os.path.exists(log_dir): os.makedirs(log_dir)
    if not os.path.exists(pond_dir): os.makedirs(pond_dir)
    
    logging.basicConfig(filename=os.path.join(log_dir, 'dragonfly.log'), level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    Thread(target=global_heartbeat_listener, daemon=True).start()
    
    print(f"Dragonfly server starting on http://{DRAGONFLY_IP}:{DRAGONFLY_PORT}")
    app.run(host=DRAGONFLY_IP, port=DRAGONFLY_PORT, debug=False)

if __name__ == "__main__":
    main()
