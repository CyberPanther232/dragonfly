document.addEventListener('DOMContentLoaded', () => {
    // Configuration
    const API_URL = 'http://10.23.25.2:8080/status';
    const REFRESH_INTERVAL = 5000; // in milliseconds

    // DOM Elements
    const agentContainer = document.getElementById('agent-container');
    const lastUpdatedSpan = document.getElementById('last-updated');

    /**
     * Fetches agent status from the Dragonfly API
     */
    async function fetchAgentStatus() {
        try {
            const response = await fetch(API_URL);
            if (!response.ok) {
                throw new Error(`Network response was not ok: ${response.statusText}`);
            }
            const data = await response.json();
            updateUI(data);
        } catch (error) {
            console.error('Failed to fetch agent status:', error);
            agentContainer.innerHTML = `<p style="color: var(--status-offline);">Error: Could not connect to Dragonfly server at ${API_URL}.</p>`;
        }
    }

    /**
     * Updates the UI with the fetched agent data
     * @param {object} agentsData - The JSON data from the /status endpoint
     */
    function updateUI(agentsData) {
        // Clear previous cards
        agentContainer.innerHTML = '';

        if (Object.keys(agentsData).length === 0) {
            agentContainer.innerHTML = '<p>No Nymph agents registered.</p>';
            return;
        }

        for (const agentId in agentsData) {
            const agent = agentsData[agentId];
            const card = createAgentCard(agentId, agent);
            agentContainer.appendChild(card);
        }
        
        // Update the timestamp
        lastUpdatedSpan.textContent = new Date().toLocaleTimeString();
    }

    /**
     * Creates an HTML element for a single agent card
     * @param {string} agentId - The unique ID of the agent (e.g., "nymph-1-10.23.25.2")
     * @param {object} agent - The status object for the agent
     * @returns {HTMLElement} The created card element
     */
    function createAgentCard(agentId, agent) {
        const card = document.createElement('div');
        card.className = 'agent-card';

        // Sanitize status values to be lowercase, as class names are case-sensitive
        const httpStatus = (agent.http || 'unknown').toLowerCase();
        const sshStatus = (agent.ssh || 'unknown').toLowerCase();
        const heartbeatStatus = (agent.heartbeat || 'unknown').toLowerCase();

        card.innerHTML = `
            <div class="card-header">
                <h2>${agentId}</h2>
                <p>OS: ${agent.os || 'Unknown'}</p>
            </div>
            <div class="status-grid">
                <div class="status-item">
                    <span>HTTP</span>
                    <span class="status-dot ${httpStatus}"></span>
                </div>
                <div class="status-item">
                    <span>SSH</span>
                    <span class="status-dot ${sshStatus}"></span>
                </div>
                <div class="status-item">
                    <span>Heartbeat</span>
                    <span class="status-dot ${heartbeatStatus}"></span>
                </div>
            </div>
        `;
        return card;
    }

    // Initial fetch and set interval for refreshing
    fetchAgentStatus();
    setInterval(fetchAgentStatus, REFRESH_INTERVAL);
});