document.addEventListener('DOMContentLoaded', function () {
    const agentContainer = document.getElementById('agent-container');
    const lastUpdated = document.getElementById('last-updated');

    // --- SVG Icons for different Operating Systems (with corrected Linux icon) ---
    const OS_ICONS = {
        'windows': `<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="currentColor"><path d="M3,12V3H12V12H3M3,21V13H12V21H3M13,21V13H21V21H13M13,12V3H21V12H13Z" /></svg>`,
        'linux': `<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="currentColor"><path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M9,8C9.55,8 10,8.45 10,9C10,9.55 9.55,10 9,10C8.45,10 8,9.55 8,9C8,8.45 8.45,8 9,8M15,8C15.55,8 16,8.45 16,9C16,9.55 15.55,10 15,10C14.45,10 14,9.55 14,9C14,8.45 14.45,8 15,8M12,14C10.5,14 9.17,13.39 8.28,12.5C8.06,12.27 8.06,11.91 8.28,11.69C8.5,11.47 8.86,11.47 9.08,11.69C9.75,12.36 10.82,12.75 12,12.75C13.18,12.75 14.25,12.36 14.92,11.69C15.14,11.47 15.5,11.47 15.72,11.69C15.94,11.91 15.94,12.27 15.72,12.5C14.83,13.39 13.5,14 12,14Z" /></svg>`,
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
