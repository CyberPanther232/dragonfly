document.addEventListener('DOMContentLoaded', function () {
    const agentContainer = document.getElementById('agent-container');
    const lastUpdated = document.getElementById('last-updated');

    // --- SVG Icons for different Operating Systems (with updated Linux icon) ---
    const OS_ICONS = {
        'windows': `<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="currentColor"><path d="M3,12V3H12V12H3M3,21V13H12V21H3M13,21V13H21V21H13M13,12V3H21V12H13Z" /></svg>`,
        'linux': `<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="currentColor"><path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12C20,13.42 19.5,14.73 18.7,15.83L17.42,14.56C17.78,13.75 18,12.9 18,12A6,6 0 0,0 12,6A6,6 0 0,0 6,12C6,12.9 6.22,13.75 6.58,14.56L5.3,15.83C4.5,14.73 4,13.42 4,12A8,8 0 0,1 12,4M6.71,18.29C8.06,19.38 9.91,20 12,20C14.09,20 15.94,19.38 17.29,18.29L16.12,17.12C15.1,17.84 13.6,18.25 12,18.25C10.4,18.25 8.9,17.84 7.88,17.12L6.71,18.29Z" /></svg>`,
        'unknown': `<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="9" y1="3" x2="9" y2="21"></line><line x1="15" y1="3" x2="15" y2="21"></line><line x1="3" y1="9" x2="21" y2="9"></line><line x1="3" y1="15" x2="21" y2="15"></line></svg>`
    };

    /**
     * Fetches agent status from the Dragonfly API
     */
    async function fetchAgentStatus() {
        try {
            const response = await fetch('/api/agents'); // Correct API endpoint
            if (!response.ok) {
                throw new Error(`Network response was not ok: ${response.statusText}`);
            }
            const agents = await response.json();
            updateUI(agents);
        } catch (error) {
            console.error('Failed to fetch agent status:', error);
            if (agentContainer) {
                agentContainer.innerHTML = `<div class="alert alert-danger"><strong>Error: Could not connect to Dragonfly server.</strong></div>`;
            }
        }
    }

    /**
     * Updates the UI with the fetched agent data
     * @param {Array} agents - An array of agent objects from the API
     */
    function updateUI(agents) {
        if (!agentContainer) return;
        
        agentContainer.innerHTML = ''; // Clear previous cards

        if (!agents || agents.length === 0) {
            agentContainer.innerHTML = '<div class="alert alert-info">No Nymph agents are currently registered.</div>';
            return;
        }

        agents.forEach(agent => {
            const card = createAgentCard(agent);
            agentContainer.appendChild(card);
        });
        
        if(lastUpdated) {
            lastUpdated.textContent = new Date().toLocaleString();
        }
    }

    /**
     * Creates an HTML element for a single agent card
     * @param {object} agent - The status object for the agent
     * @returns {HTMLElement} The created card element
     */
    function createAgentCard(agent) {
        const card = document.createElement('div');
        card.className = 'agent-card';

        const osKey = (agent.os || 'unknown').toLowerCase();
        const osIcon = OS_ICONS[osKey] || OS_ICONS['unknown'];

        const createStatusItem = (label, status) => {
            const safeStatus = (status || 'unknown').toLowerCase();
            return `
                <div class="status-item">
                    <span>${escapeHtml(label)}</span>
                    <span class="status-dot ${escapeHtml(safeStatus)}"></span>
                </div>
            `;
        };

        card.innerHTML = `
            <div class="card-header">
                <div class="os-icon">${osIcon}</div>
                <div class="card-header-text">
                    <h2>${escapeHtml(agent.device_name)}</h2>
                    <p>${escapeHtml(agent.ip)}</p>
                </div>
            </div>
            <div class="status-grid">
                ${createStatusItem('Heartbeat', agent.heartbeat)}
                ${createStatusItem('SSH', agent.ssh)}
                ${createStatusItem('HTTP', agent.http)}
            </div>
        `;
        return card;
    }

    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str).replace(/[&<>"']/g, (m) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'})[m]);
    }

    // Initial fetch and set interval for refreshing
    fetchAgentStatus();
    setInterval(fetchAgentStatus, 5000); // Refresh every 5 seconds
});
