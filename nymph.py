import os
import sys
import time
import socket
import platform
import requests
import threading
from collections import defaultdict, deque

# --- Nymph Agent Configuration ---
# Match this with your Dragonfly server configuration
SERVER_IP = "10.23.24.7"  # Change to your server's IP if needed
SERVER_PORT = 8080
HEARTBEAT_PORT = 9999
HTTP = True
SSH = True
SSH_PORT = 22
HTTP_PORT = 8080 # Note: This seems to be the same as SERVER_PORT

# --- Security Monitor Configuration ---
POLL_INTERVAL_SECONDS = 5
BRUTE_FORCE_THRESHOLD = 5  # Number of failed attempts to trigger an alert
BRUTE_FORCE_TIMEFRAME_SECONDS = 60  # Time window to detect brute force

# --- Platform Specific Configuration ---
# This block sets up the correct monitoring parameters based on the OS.
if sys.platform == "win32":
    try:
        import win32evtlog
    except ImportError:
        print("[!] The 'pywin32' library is required on Windows. Please run: pip install pywin32")
        sys.exit(1)
        
    LOG_TYPE = "Security"
    # Event IDs for Windows
    # 4624: Successful logon
    # 4625: Failed logon
    # 4740: Account lockout
    WINDOWS_EVENT_IDS = {
        4624: "SUCCESSFUL_LOGON",
        4625: "FAILED_LOGON",
        4740: "ACCOUNT_LOCKOUT"
    }
else:
    # Log files for Linux
    LINUX_LOG_FILES = [
        '/var/log/auth.log',    # For Debian/Ubuntu
        '/var/log/secure',       # For RHEL/CentOS/Fedora
        '/var/log/audit/audit.log'  # For systems using auditd
    ]
    # Keywords to find in Linux logs
    LINUX_KEYWORDS = {
        'Accepted password': 'SUCCESSFUL_LOGIN',
        'Accepted publickey': 'SUCCESSFUL_LOGIN_KEY',
        'Failed password': 'FAILED_LOGIN',
        'authentication failure': 'AUTH_FAILURE',
        'session opened for user': 'SESSION_OPENED',
        'invalid user': 'INVALID_USER',
        'sshd login success secure': 'SSH_LOGIN_SUCCESS',
        'sshd login failure secure': 'Failed password',
        'sshd brute force secure' : 'PAM 5 more authentication failures',
        'unix password check failed secure' : 'password check failed',
        'auditd user login' : 'USER_LOGIN',
        'auditd user logout' : 'USER_LOGOUT',
        'auditd user authentication' : 'USER_AUTH'
    }

# --- Brute-Force Detection Global Variable ---
# Stores recent failed login attempts: {source_ip: [timestamp1, timestamp2, ...]}
failed_attempts = defaultdict(lambda: deque())

# --- Core Agent Functions ---

def get_device_info():
    """Gathers and returns information about the client device."""
    try:
        os_name = platform.system()
        device_name = socket.gethostname().split('.')[0]
        # Discover the primary IP address by connecting to the server
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.connect((SERVER_IP, SERVER_PORT))
            client_ip = s.getsockname()[0]
    except Exception as e:
        print(f"[!] Error getting device info: {e}")
        # Fallback for offline or unusual network configs
        client_ip = "127.0.0.1"
        device_name = "unknown-host"
        os_name = platform.system()

    return {
        "ip": client_ip,
        "device_name": device_name,
        "os": os_name,
        "ssh_service": SSH,
        "ssh_port": SSH_PORT,
        "http_service": HTTP,
        "http_port": HTTP_PORT
    }

def run_heartbeat(server_ip, heartbeat_port):
    """Sends a UDP heartbeat to the server every 15 seconds."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(10.0)
        while True:
            try:
                sock.sendto(b'heartbeat', (server_ip, heartbeat_port))
                # print(f"[+] Heartbeat sent to {server_ip}:{heartbeat_port}") # Uncomment for verbose logging
                data, addr = sock.recvfrom(1024)
                # if data == b'ack':
                #     print(f"[+] Acknowledgement received from {addr}") # Uncomment for verbose logging
            except socket.timeout:
                print(f"[!] Warning: No heartbeat acknowledgement received from the server.")
            except socket.error as e:
                print(f"[!] Socket error during heartbeat: {e}. Retrying...")
            time.sleep(15)

# --- Security Monitoring Functions ---

def send_alert_to_server(alert_data, device_info):
    """Sends a security alert to the Dragonfly server."""
    api_url = f"http://{SERVER_IP}:{SERVER_PORT}/alert"
    payload = {
        "agent_info": device_info,
        "alert": alert_data
    }
    try:
        print(f"[*] Sending alert to server: {alert_data['type']}")
        requests.post(api_url, json=payload, timeout=5)
    except requests.RequestException as e:
        print(f"[!] Failed to send alert to server: {e}")

def check_brute_force(source_identifier, device_info):
    """Checks for and reports brute-force attempts."""
    current_time = time.time()
    failed_attempts[source_identifier].append(current_time)

    while failed_attempts[source_identifier] and \
          current_time - failed_attempts[source_identifier][0] > BRUTE_FORCE_TIMEFRAME_SECONDS:
        failed_attempts[source_identifier].popleft()

    if len(failed_attempts[source_identifier]) >= BRUTE_FORCE_THRESHOLD:
        alert = {
            "type": "BRUTE_FORCE_ALERT",
            "source": source_identifier,
            "count": len(failed_attempts[source_identifier]),
            "timeframe_seconds": BRUTE_FORCE_TIMEFRAME_SECONDS
        }
        send_alert_to_server(alert, device_info)
        failed_attempts[source_identifier].clear()

def monitor_windows_logs(device_info):
    """Monitors the Windows Security Event Log."""
    print("[*] Starting Windows security log monitor...")
    hand = win32evtlog.OpenEventLog(None, LOG_TYPE)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if events:
            for event in events:
                if event.EventID in WINDOWS_EVENT_IDS:
                    event_type = WINDOWS_EVENT_IDS[event.EventID]
                    alert_details = {
                        "type": event_type,
                        "source_name": event.SourceName,
                        "event_id": event.EventID,
                        "details": list(event.StringInserts)
                    }
                    send_alert_to_server(alert_details, device_info)

                    if event_type == "FAILED_LOGON":
                        user = event.StringInserts[5] if len(event.StringInserts) > 5 else 'N/A'
                        ip_address = event.StringInserts[19] if len(event.StringInserts) > 19 else 'N/A'
                        check_brute_force(f"{user}@{ip_address}", device_info)
        time.sleep(POLL_INTERVAL_SECONDS)

def tail_f(filename):
    """Generator that yields new lines from a file, like 'tail -f'."""
    with open(filename, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

def monitor_linux_logs(device_info):
    """Monitors Linux auth/secure log files."""
    print("[*] Starting Linux security log monitor...")
    log_file_to_watch = next((f for f in LINUX_LOG_FILES if os.path.exists(f)), None)

    if not log_file_to_watch:
        print("[!] Could not find a suitable log file to monitor on this system.")
        return

    print(f"[*] Watching log file: {log_file_to_watch}")
    try:
        for line in tail_f(log_file_to_watch):
            for keyword, event_type in LINUX_KEYWORDS.items():
                if keyword in line:
                    alert_details = {"type": event_type, "log_entry": line.strip()}
                    send_alert_to_server(alert_details, device_info)

                    if "FAILED_LOGIN" in event_type or "INVALID_USER" in event_type or "failed authentication" in event_type or "maximum authentication attempts exceeded" in event_type:
                        parts = line.split()
                        ip_address = 'N/A'
                        if 'from' in parts:
                            try:
                                ip_address = parts[parts.index('from') + 1]
                            except IndexError:
                                pass
                        check_brute_force(ip_address, device_info)
    except PermissionError:
        print("[!] Permission denied. Please run this agent with 'sudo' on Linux.")
    except Exception as e:
        print(f"[!] An error occurred in the Linux log monitor: {e}")

def start_security_monitor(device_info):
    """Starts the appropriate OS-specific log monitoring function."""
    if sys.platform == "win32":
        monitor_windows_logs(device_info)
    else:
        monitor_linux_logs(device_info)

# --- Main Execution ---

def main():
    """Main function to register with the server and start services."""
    print("--- Nymph Agent Initializing ---")
    device_info = get_device_info()
    api_url = f"http://{SERVER_IP}:{SERVER_PORT}/nymph"

    synced = False
    while not synced:
        try:
            print(f"[*] Attempting to register with server at {api_url}...")
            response = requests.post(api_url, timeout=10, json=device_info)
            if response.status_code == 200:
                print("✅ Successfully registered with Dragonfly server.")
                synced = True
            else:
                print(f"[-] Registration failed. Server responded with status {response.status_code}: {response.text}")
        except requests.RequestException as e:
            print(f"[-] Network error during registration: {e}")
        
        if not synced:
            print("[*] Retrying in 15 seconds...")
            time.sleep(15)

    print("[*] Starting background services...")
    # Start the heartbeat thread
    heartbeat_thread = threading.Thread(target=run_heartbeat, args=(SERVER_IP, HEARTBEAT_PORT), daemon=True)
    heartbeat_thread.start()

    # Start the security monitor thread
    security_thread = threading.Thread(target=start_security_monitor, args=(device_info,), daemon=True)
    security_thread.start()

    print("✅ Agent is now running. Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down agent.")

if __name__ == "__main__":
    main()
