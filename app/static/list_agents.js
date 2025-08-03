document.addEventListener('DOMContentLoaded', function () {
    const agentContainer = document.getElementById('agent-container');
    const lastUpdated = document.getElementById('last-updated');

    // --- SVG Icons for different Operating Systems (with updated Windows icon) ---
    const OS_ICONS = {
        'windows': `<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="currentColor"><path d="M3,12V3H12V12H3M3,21V13H12V21H3M13,21V13H21V21H13M13,12V3H21V12H13Z" /></svg>`,
        'linux': `<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="currentColor"><path d="M20.8,11.2c-0.3-0.2-0.7-0.1-1.1,0.2c-0.8,0.5-1.8,0.5-2.6-0.1c-0.4-0.3-0.9-0.2-1.2,0.1l-1.6,1.6c-0.2,0.2-0.5,0.3-0.8,0.3 c-0.3,0-0.6-0.1-0.8-0.3l-1.6-1.6C11,11.3,10.4,11.2,10,11.5c-0.8,0.5-1.8,0.5-2.6,0c-0.4-0.3-0.9-0.2-1.2,0.2L4.5,13.4 c-0.3,0.3-0.3,0.8,0,1.1C4.7,14.7,5,14.8,5.2,14.8s0.5-0.1,0.7-0.3l1.7-1.7c0.4-0.4,1-0.4,1.4,0c0.6,0.4,1.4,0.4,2,0 c0.4-0.4,1-0.4,1.4,0l1.6,1.6c0.4,0.4,1,0.4,1.4,0l1.6-1.6c0.4-0.4,1-0.4,1.4,0c0.6,0.4,1.4,0.4,2,0c0.4-0.4,1-0.4,1.4,0l1.7,1.7 c0.2,0.2,0.5,0.3,0.7,0.3s0.5-0.1,0.7-0.3c0.3-0.3,0.3-0.8,0-1.1L20.8,11.2z M12,2c-5.5,0-10,4.5-10,10s4.5,10,10,10s10-4.5,10-10 S17.5,2,12,2z M12,20c-4.4,0-8-3.6-8-8s3.6-8,8-8s8,3.6,8,8S16.4,20,12,20z"/></svg>`,
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
