# Dragonfly SIEM

![Dragonfly Banner]()

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

