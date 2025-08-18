import os
import sys
import time
import socket
import platform
import requests
import threading
import nacl.secret
import nacl.utils
import nacl.encoding
from collections import defaultdict, deque, OrderedDict
import base64

# --- Nymph Agent Configuration ---
# Match this with your Dragonfly server configuration
SERVER_IP = "localhost"  # Change to your server's IP if needed
SERVER_PORT = 8080
HEARTBEAT_PORT = 9999
HTTP = True
SSH = True
SSH_PORT = 22
HTTP_PORT = 8080 # Note: This seems to be the same as SERVER_PORT

# --- Agent Encryption ---
# Generate a random key for the SecretBox every time the agent starts
KEY = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
BOX = nacl.secret.SecretBox(KEY)

# --- Security Monitor Configuration ---
POLL_INTERVAL_SECONDS = 5
BRUTE_FORCE_THRESHOLD = 5  # Number of failed attempts to trigger an alert
BRUTE_FORCE_TIMEFRAME_SECONDS = 60  # Time window to detect brute force

# --- Platform Specific Configuration ---
if sys.platform == "win32":
    try:
        import win32evtlog
        import win32evtlogutil
        import win32com.client
        
    except ImportError:
        print("[!] The 'pywin32' library is required on Windows. Please run: pip install pywin32")
        sys.exit(1)
        
    # Windows Security Event Log Configuration
    LOG_TYPE = "Security"
    WINDOWS_EVENT_IDS = {
        4624: "SUCCESSFUL_LOGON",
        4625: "FAILED_LOGON",
        4740: "ACCOUNT_LOCKOUT"
    }
    
    # Scheduled Tasks Configuration
    TASK_STATE = {
        0 : 'Unknown',
        1 : 'Disabled',
        2 : 'Queued',
        3 : 'Ready',
        4 : 'Running'
    }
    
    TASK_ENUM_HIDDEN = 1 # 1 = Search for Hidden Scheduled Tasks
    TASK_ACTION_EXEC = 0 # Type code for an execution action (runs a program/script)
    TASK_RUNLEVEL = {
        0: 'Limited (LUA)', 
        1: 'Highest (Administrator)'
    }
    
    SCHEDULED_TASKS_REFRESH = 15 # Refresh Scheduled Tasks Lookup in Seconds
    
else:
    LINUX_LOG_FILES = [
        '/var/log/auth.log',    # For Debian/Ubuntu
        '/var/log/secure',       # For RHEL/CentOS/Fedora
        '/var/log/audit/audit.log'  # For systems using auditd
    ]
    # Use an OrderedDict to prioritize more specific keywords first.
    LINUX_KEYWORDS = OrderedDict([
        ('Too many authentication failures', 'BRUTE_FORCE_SUSPECTED'),
        ('Failed password', 'FAILED_LOGIN'),
        ('authentication failure', 'AUTH_FAILURE'),
        ('invalid user', 'INVALID_USER'),
        ('Accepted password', 'SUCCESSFUL_LOGIN'),
        ('Accepted publickey', 'SUCCESSFUL_LOGIN_KEY'),
        ('session opened for user', 'SESSION_OPENED'),
        # Keywords for auditd logs
        ('type=USER_LOGIN', 'AUDIT_USER_LOGIN'),
        ('type=USER_AUTH', 'AUDIT_USER_AUTH'),
        ('type=USER_LOGOUT', 'AUDIT_USER_LOGOUT')
    ])

# --- Brute-Force Detection Global Variable ---
failed_attempts = defaultdict(lambda: deque())

# --- Core Agent Functions ---

def get_device_info():
    """Gathers and returns information about the client device."""
    try:
        os_name = platform.system()
        device_name = socket.gethostname().split('.')[0]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.connect((SERVER_IP, SERVER_PORT))
            client_ip = s.getsockname()[0]
    except Exception as e:
        print(f"[!] Error getting device info: {e}")
        client_ip = "127.0.0.1"
        device_name = "unknown-host"
        os_name = platform.system()

    return {
        "ip": client_ip,
        "nacl_key": nacl.encoding.HexEncoder.encode(KEY).decode('utf-8'),
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
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                print(f"[!] Warning: No heartbeat acknowledgement received from the server.")
            except socket.error as e:
                print(f"[!] Socket error during heartbeat: {e}. Retrying...")
            time.sleep(15)

# --- Security Monitoring Functions ---

def send_alert_to_server(alert_data, device_info, nacl_box=BOX):
    
    def encrypt_and_encode(data_bytes):
        encrypted_data = nacl_box.encrypt(data_bytes)
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    """Sends a security alert to the Dragonfly server."""
    api_url = f"http://{SERVER_IP}:{SERVER_PORT}/alert"
    payload = {
        "device_id": device_info["device_name"],
        "category": encrypt_and_encode(alert_data["category"].encode('utf-8')),
        "severity": encrypt_and_encode(alert_data.get("severity", "Low").encode('utf-8')),
        "agent_info": encrypt_and_encode(str(device_info).encode('utf-8')),
        "alert": encrypt_and_encode(str(alert_data).encode('utf-8'))
    }
    
    try:
        # print(f"[*] Sending alert to server: {alert_data['type']}") # Uncomment for verbose logging
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
            "details": f"Login attempts: {len(failed_attempts[source_identifier])}",
            "timeframe_seconds": BRUTE_FORCE_TIMEFRAME_SECONDS,
            "category": "security",
            "severity": "High"
        }
        send_alert_to_server(alert, device_info)
        failed_attempts[source_identifier].clear()

def process_failed_ssh_login(event, device_info):
    """
    Tracks frequency of failed SSH login attempts for brute-force detection.
    """
    # Try to extract username and/or IP from event.StringInserts
    user = event.StringInserts[5] if len(event.StringInserts) > 5 else 'N/A'
    ip_address = event.StringInserts[18] if len(event.StringInserts) > 18 else 'N/A'
    identifier = f"{user}@{ip_address}"
    check_brute_force(identifier, device_info)

def monitor_windows_ssh(device_info):
    """Monitors the Windows Application Event Log."""
    print("[*] Starting Windows Application log monitor...")
    hand = win32evtlog.OpenEventLog(None, "OpenSSH/Operational")
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if events:
            for event in events:
                if event.EventID in WINDOWS_EVENT_IDS:
                    event_type = WINDOWS_EVENT_IDS[4]
                    
                    message = win32evtlogutil.SafeFormatMessage(event, "OpenSSH/Operational")
                    print(f"[*] Processing event: {message}")
                    timestamp = event.TimeGenerated.Format()
                    category = "informational"
                    severity = "Low"
            
                    if "Too many authentication failures" in message:
                        category = "security"
                        severity = "High"
                        
                    elif "Failed password" in message or "Invalid user" in message:
                        category = "informational"
                        severity = "Low"
                        process_failed_ssh_login(event, device_info)
                    
                    alert_details = {
                        "type": event_type,
                        "source_name": event.SourceName,
                        "event_id": event.EventID,
                        "details": list(event.StringInserts),
                        "category": category,
                        "severity": severity
                    }
                    
                    send_alert_to_server(alert_details, device_info, BOX)

        time.sleep(POLL_INTERVAL_SECONDS)
        
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
                    
                    category = "security"
                    severity = "Medium" if event_type == "FAILED_LOGON" else "Low"
                    
                    alert_details = {
                        "type": event_type,
                        "source_name": event.SourceName,
                        "event_id": event.EventID,
                        "details": list(event.StringInserts),
                        "category": category,
                        "severity": severity
                    }
                    send_alert_to_server(alert_details, device_info)

                    if event_type == "FAILED_LOGON":
                        user = event.StringInserts[5] if len(event.StringInserts) > 5 else 'N/A'
                        ip_address = event.StringInserts[19] if len(event.StringInserts) > 19 else 'N/A'
                        check_brute_force(f"{user}@{ip_address}", device_info)
        time.sleep(POLL_INTERVAL_SECONDS)

def monitor_windows_scheduled_tasks(device_info):
    """
    Connects to the Windows Task Scheduler service and monitors for any
    changes to scheduled tasks, including their privileges.
    """
    scheduler = win32com.client.Dispatch('Schedule.Service')
    scheduler.Connect()
    
    print("--- Starting Scheduled Task Monitor ---")
    
    baseline_tasks = {}
    is_first_run = True
    
    while True:
        try:
            current_tasks = {}
            folders = [scheduler.GetFolder('\\')]
            alert = False
            
            while folders:
                folder = folders.pop(0)
                folders += list(folder.GetFolders(0))
                tasks = list(folder.GetTasks(TASK_ENUM_HIDDEN))
            
                for task in tasks:
                    action_list = []
                    for action in task.Definition.Actions:
                        if action.Type == TASK_ACTION_EXEC:
                            action_list.append({
                                'Command': action.Path,
                                'Arguments': action.Arguments,
                            })
                    
                    # --- Build a comprehensive dictionary for the task ---
                    task_data = {
                        'State': TASK_STATE.get(task.State, "Unknown State"),
                        'Actions': action_list,
                        'Description': task.Definition.RegistrationInfo.Description,
                        'UserId': task.Definition.Principal.UserId,
                        'RunLevel': TASK_RUNLEVEL.get(task.Definition.Principal.RunLevel, "Unknown Level")
                    }
                    current_tasks[task.Path] = task_data

            # --- Logic for baselining and comparing ---
            if is_first_run:
                baseline_tasks = current_tasks
                is_first_run = False
                print(f"--- Baseline established with {len(baseline_tasks)} tasks. Monitoring for changes... ---\n")
            else:
                # Use set operations on dictionary keys to find differences
                baseline_keys = set(baseline_tasks.keys())
                current_keys = set(current_tasks.keys())
                
                new_tasks = current_keys - baseline_keys
                deleted_tasks = baseline_keys - current_keys
                
                if new_tasks or deleted_tasks or baseline_tasks != current_tasks:
                    print("!!! CHANGE DETECTED IN SCHEDULED TASKS !!!")
                    severity = "Low"

                    # Report newly created tasks and their descriptions
                    for task_path in new_tasks:
                        task_info = current_tasks[task_path]
                        if current_tasks[task_path]['RunLevel'] == 'Highest (Administrator)':
                            severity = "High"
                        print(f"\n[+] New Task Added: {task_path}")
                        print(f"    Description: {task_info['Description']}")
                        print(f"    Runs As: {task_info['UserId']} ({task_info['RunLevel']})")
                        
                        alert = {
                            "type": "SCHEDULED_TASK_CREATED",
                            "source": "Scheduled_Task_Monitor",
                            "details": f"Scheduled Task Modified: {task_path}",
                            "category": "security",
                            "severity": severity
                            }

                    # Report deleted tasks
                    for task_path in deleted_tasks:
                        print(f"\n[-] Task Deleted: {task_path}")
                        
                        alert = {
                            "type": "SCHEDULED_TASK_DELETED",
                            "source": "Scheduled_Task_Monitor",
                            "details": f"Scheduled Task Deleted: {task_path}",
                            "category": "security",
                            "severity": severity
                            }
                    
                    # Find and report modified tasks
                    for task_path in baseline_keys.intersection(current_keys):
                        if baseline_tasks[task_path] != current_tasks[task_path]:
                            print(f"\n[*] Task Modified: {task_path}")
                            print(task_path)
                            # You could add logic here to show exactly what changed
                            if current_tasks[task_path]['RunLevel'] == 'Highest (Administrator)':
                                severity = "High"
                            alert = {
                            "type": "SCHEDULED_TASK_MODIFIED",
                            "source": "Scheduled_Task_Monitor",
                            "details": f"Scheduled Task Modified: {task_path}",
                            "category": "security",
                            "severity": severity
                            }
                            print(alert)
                    
                    # Update the baseline to the new state for the next check
                    baseline_tasks = current_tasks
                
                else:
                    print("--- No changes detected. ---")

            print(f'--- Waiting {SCHEDULED_TASKS_REFRESH} seconds before next refresh. ---\n')
            
            if alert:
                send_alert_to_server(alert, device_info)
            
        except Exception as e:
            print(f"An error occurred: {e}")

        time.sleep(SCHEDULED_TASKS_REFRESH)

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
    """Monitors Linux auth/secure log files with prioritized keywords."""
    print("[*] Starting Linux security log monitor...")
    
    # Start monitoring all available log files in separate threads
    log_files_to_watch = [f for f in LINUX_LOG_FILES if os.path.exists(f)]

    if not log_files_to_watch:
        print("[!] Could not find any suitable log files to monitor on this system.")
        return

    for log_file in log_files_to_watch:
        thread = threading.Thread(target=watch_single_log, args=(log_file, device_info), daemon=True)
        thread.start()
        print(f"[*] Started watching log file: {log_file}")

def watch_single_log(log_file, device_info):
    """Watches a single log file for keywords."""
    try:
        for line in tail_f(log_file):
            # Iterate through the ordered dictionary of keywords
            for keyword, event_type in LINUX_KEYWORDS.items():
                if keyword in line:
                    category = "informational"
                    severity = "Low"
                    # Trigger brute-force check on specific failure types
                    if event_type in ['FAILED_LOGIN', 'INVALID_USER', 'AUTH_FAILURE', 'BRUTE_FORCE_SUSPECTED']:
                        severity = "Medium" if event_type == 'FAILED_LOGIN' else "High" if event_type == 'BRUTE_FORCE_SUSPECTED' else "Low"
                        category = "security"
                        parts = line.split()
                        ip_address = 'N/A'
                        if 'from' in parts:
                            try:
                                ip_address = parts[parts.index('from') + 1]
                            except IndexError:
                                pass
                        check_brute_force(ip_address, device_info)
                    
                    alert_details = {"type": event_type, "log_entry": line.strip(), "category": category, "severity": severity}
                    send_alert_to_server(alert_details, device_info)
                    
                    # Break after the first (most specific) match is found
                    break 
    except PermissionError:
        print(f"[!] Permission denied for {log_file}. Please run this agent with 'sudo'.")
    except Exception as e:
        print(f"[!] An error occurred while watching {log_file}: {e}")

def start_security_monitor(device_info):
    """Starts the appropriate OS-specific log monitoring function."""
    if sys.platform == "win32":
        threading.Thread(target=monitor_windows_logs, args=(device_info,), daemon=True).start() # Windows Security Log Thread
        threading.Thread(target=monitor_windows_ssh, args=(device_info,), daemon=True).start() # Windows SSH Log Thread
        threading.Thread(target=monitor_windows_scheduled_tasks, args=(device_info,), daemon=True).start() # Windows Scheduled Tasks Log Thread

    else:
        monitor_linux_logs(device_info)

# --- Sync Monitoring ---

def sync_monitor(api_url, device_info, check_interval=30):
    """Continuously checks if the agent is still synced with the Dragonfly server."""
    params = {
        "ip": device_info["ip"],
        "device_name": device_info["device_name"]
    }
    
    synced = True
    
    while True:
        try:
            if synced:
                response = requests.get(api_url, params=params, timeout=5)
            else:
                response = requests.post(api_url, json=device_info, timeout=5)
                print(f"[SYNC] Attempting resync with Dragonfly server at {api_url}...")
            
            if response.status_code == 200:
                print("[SYNC] Synced with Dragonfly server.")
            else:
                synced = False
                print(f"[SYNC] Lost sync! Server responded with status {response.status_code}: {response.text}")
        except requests.RequestException as e:
            synced = False
            print(f"[SYNC] Lost sync! Network error: {e}")
        time.sleep(check_interval)

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

    # --- Start sync monitor thread here ---
    sync_thread = threading.Thread(
        target=sync_monitor,
        args=(api_url, device_info),
        daemon=True
    )
    sync_thread.start()

    print("[*] Starting background services...")
    heartbeat_thread = threading.Thread(target=run_heartbeat, args=(SERVER_IP, HEARTBEAT_PORT), daemon=True)
    heartbeat_thread.start()

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
