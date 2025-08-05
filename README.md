# Dragonfly SIEM

![Dragonfly Banner](https://github.com/CyberPanther232/dragonfly/blob/5012b75ed55a28d119a47b13452784cc64aa368f/Dragonfly_logo.png)

A lightweight, agent-based Security Information and Event Management (SIEM) system designed for real-time monitoring of security events across Windows and Linux endpoints.

---

## Table of Contents
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Dashboard Preview](#dashboard-preview)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Server Setup](#server-setup)
  - [Agent Setup](#agent-setup)
- [Usage](#usage)
- [Future Addons & Roadmap](#future-addons--roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Key Features

* **Cross-Platform Agents:** Lightweight "Nymph" agents for both **Windows** and **Linux** systems.
* **Real-Time Log Analysis:** Agents actively monitor critical security logs (`auth.log`, `secure`, Windows Event Log) for suspicious activity.
* **Event Classification:** Intelligent keyword matching to classify events such as successful/failed logins, authentication failures, and suspected brute-force activity.
* **Centralized Dashboard:** A Flask-based web interface (Dragonfly Server) that provides a single pane of glass for all incoming alerts.
* **Data Visualization:** Live charts displaying alert distributions by type and by agent for quick threat analysis.
* **Dynamic Filtering:** Easily search and filter the live alert feed to investigate specific events or hosts.
* **Service & Heartbeat Monitoring:** Keep track of agent online status and the availability of key services (SSH, HTTP).

---

## Architecture

Dragonfly operates on a classic client-server model:

* **Dragonfly Server:** This is the core of the system. It's a Python Flask application that serves the web dashboard, listens for agent registrations, receives heartbeats, and collects security alerts via a REST API.
* **Nymph Agent:** A Python script deployed on each endpoint you want to monitor. It gathers system information, tails security logs in a separate thread, and sends alerts back to the Dragonfly Server.

```
+------------------+      +------------------+
|  Linux Endpoint  |      | Windows Endpoint |
|  (Nymph Agent)   |      |  (Nymph Agent)   |
+--------+---------+      +--------+---------+
|                        |
| (Heartbeats, Alerts)   | (Heartbeats, Alerts)
|                        |
v                        v
+--------+------------------------+---------+
|                                          |
|           Dragonfly Server (Flask)       |
|                                          |
|  +----------+   +----------+   +-------+ |
|  | API      |   | Heartbeat|   | Web   | |
|  | (Alerts) |   | Listener |   | UI    | |
|  +----------+   +----------+   +-------+ |
|                                          |
+------------------------------------------+
^
|
| (HTTPS)
|
+---------+---------+
| Security Analyst  |
| (Web Browser)     |
+-------------------+

```
---

## Dashboard Preview

![Dashboard Screenshot](https://github.com/CyberPanther232/dragonfly/blob/8e3f9150a0f0a184ae477961eb65cab867ae5c44/dashboard_screenshot.png)

---

## Getting Started

### Prerequisites

* Python 3.7+
* `pip` for installing packages
* Git

### Server Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/CyberPanther232/dragonfly
    cd dragonfly/app
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Your `requirements.txt` should include `Flask`, `requests`, etc.)*

3.  **Configure the server:**
    Open the server script and ensure the `DRAGONFLY_IP` is set to the IP address of the machine it's running on (e.g., `0.0.0.0` to listen on all interfaces).

4.  **Run the server:**
    ```bash
    python dragonfly_server.py
    ```
    The server will now be running and accessible at `http://<your-server-ip>:8080`.

### Agent Setup

1.  **Copy the agent script** (`nymph_agent.py`) to the client machine (Windows or Linux).

2.  **Configure the agent:**
    Open `nymph_agent.py` and set the `SERVER_IP` variable to the IP address of your Dragonfly Server.

3.  **Install dependencies:**
    * **On all systems:**
        ```bash
        pip install requests
        ```
    * **On Windows only:**
        ```bash
        pip install pywin32
        ```

4.  **Run the agent:**
    * **On Linux:** It's recommended to run with `sudo` to ensure permissions to read log files.
        ```bash
        sudo python nymph_agent.py
        ```
    * **On Windows:** Run from a Command Prompt or PowerShell with administrator privileges.
        ```powershell
        python nymph_agent.py
        ```

---

## Usage

Once the server is running and agents are deployed, simply navigate to the Dragonfly dashboard in your web browser.

* **Alerts Dashboard:** View the main dashboard with charts and a real-time feed of security alerts from all registered agents. Use the filter controls to narrow down events.
* **Agents List:** See a list of all currently registered Nymph agents, their OS, IP address, and the status of their services.

---

## Future Addons & Roadmap

Dragonfly is an evolving project. Here are some of the features planned for future releases:

### 🔹 Enhanced Agent Capabilities
* **File Integrity Monitoring (FIM):** Watch critical system files and directories for unauthorized changes.
* **Process Monitoring:** Alert on suspicious processes being created or executed.
* **Network Connection Logging:** Track and alert on unusual outbound network connections from endpoints.
* **Configuration via Server:** Allow agents to pull their monitoring configurations (keywords, file paths) from the central server.

### 🔸 Improved Server & Dashboard
* **User Authentication:** Secure the dashboard with a proper login system.
* **Database Integration:** Store alerts in a database (like PostgreSQL or Elasticsearch) for long-term storage, historical analysis, and forensics.
* **Alert Correlation Engine:** Implement logic to link related but separate events into a single, higher-level incident (e.g., failed login -> successful login -> process creation).
* **Advanced Visualizations:** Create time-series graphs of alert volumes and geographical maps of attack sources.

### 🔺 Remote Actions & Response
* **Agent Tasking:** Give the server the ability to issue commands to agents.
* **Host Isolation:** A feature to automatically run a script on an agent to add firewall rules that isolate it from the network upon detection of a critical threat.
* **Process Termination:** Remotely kill a suspicious process identified by an agent.

### ▪️ Reporting & Scalability
* **Automated Reporting:** Generate and email daily or weekly PDF summaries of security events.
* **Containerization:** Provide Dockerfiles for both the server and agent for easy deployment and scaling.

---

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue to discuss proposed changes.

---

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.
