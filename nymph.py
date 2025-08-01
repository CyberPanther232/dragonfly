import os
import socket
import time
import platform
from threading import Thread
import requests

# --- Configuration ---
# Match this with your Dragonfly server configuration
SERVER_IP = "127.0.0.1"
SERVER_PORT = 8080
HEARTBEAT_PORT = 9999

def get_device_info():
    """Gathers and returns information about the client device."""
    try:
        # Use platform.system() for more descriptive OS names (e.g., 'Windows', 'Linux')
        os_name = platform.system()
        # Clean up the hostname
        device_name = socket.gethostname().split('.')[0]

        # Discover the primary IP address by connecting to the server
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.connect((SERVER_IP, SERVER_PORT))
            client_ip = s.getsockname()[0]

        return {
            "ip": client_ip,
            "device_name": device_name,
            "os": os_name,
        }
    except Exception as e:
        print(f"[!] Error getting device info: {e}")
        # Fallback for offline or unusual network configs
        return {
            "ip": "127.0.0.1",
            "device_name": "unknown-host",
            "os": platform.system(),
        }

def run_heartbeat(server_ip, heartbeat_port):
    """
    Sends a UDP heartbeat to the server every 15 seconds and waits for an 'ack'.
    """
    # A client socket doesn't need to be bound; the OS will handle it.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Set a timeout for receiving the acknowledgement
        sock.settimeout(10.0)
        
        while True:
            try:
                # Send heartbeat message
                sock.sendto(b'heartbeat', (server_ip, heartbeat_port))
                print(f"[+] Heartbeat sent to {server_ip}:{heartbeat_port}")

                # Wait for the server's acknowledgement
                data, addr = sock.recvfrom(1024)
                if data == b'ack':
                    print(f"[+] Acknowledgement received from {addr}")

            except socket.timeout:
                print(f"[!] Warning: No heartbeat acknowledgement received from the server.")
            except socket.error as e:
                print(f"[!] Socket error during heartbeat: {e}. Retrying...")
            
            time.sleep(15)

def main():
    """Main function to register with the server and start services."""
    print("--- Nymph Agent Initializing ---")
    device_info = get_device_info()
    api_url = f"http://{SERVER_IP}:{SERVER_PORT}/nymph"
    
    # Loop until successfully registered with the server
    synced = False
    while not synced:
        try:
            print(f"[*] Attempting to register with server at {api_url}...")
            print(f"[*] Device Info: {device_info}")
            
            response = requests.post(api_url, timeout=10, json=device_info)
            
            if response.status_code == 200:
                print("✅ Successfully registered with Dragonfly server.")
                synced = True
            else:
                print(f"[-] Registration failed. Server responded with status {response.status_code}.")
                print(f"[-] Response: {response.text}")
        
        except requests.RequestException as e:
            print(f"[-] Network error during registration: {e}")
        
        if not synced:
            print("[*] Retrying in 10 seconds...")
            time.sleep(10)
            
    # Once registered, start the heartbeat thread
    print("[*] Starting heartbeat service...")
    heartbeat_thread = Thread(target=run_heartbeat, args=(SERVER_IP, HEARTBEAT_PORT), daemon=True)
    heartbeat_thread.start()
    
    # Keep the main thread alive to let the daemon thread run
    print("✅ Agent is now running. Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down agent.")

if __name__ == "__main__":
    main()