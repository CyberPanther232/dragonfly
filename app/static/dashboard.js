document.addEventListener('DOMContentLoaded', function () {
    // --- DOM Elements ---
    const alertsList = document.getElementById('alerts-list');
    const lastUpdated = document.getElementById('last-updated');
    const filterText = document.getElementById('filter-text');
    const filterType = document.getElementById('filter-type');
    
    // --- Chart Contexts ---
    const alertsByTypeCtx = document.getElementById('alertsByTypeChart')?.getContext('2d');
    const alertsByAgentCtx = document.getElementById('alertsByAgentChart')?.getContext('2d');

    // --- State ---
    let allAlerts = [];
    let alertTypeChart, alertsByAgentChart;

    // --- SVG Icons ---
    const ICONS = {
        SUCCESS: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon-success"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="m9 12 2 2 4-4"></path></svg>`,
        WARNING: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon-warning"><path d="m21.73 18-8-14a2 2 0 0 0-3.46 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" x2="12" y1="9" y2="13"></line><line x1="12" x2="12.01" y1="17" y2="17"></line></svg>`,
        DANGER: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon-danger"><circle cx="12" cy="12" r="10"></circle><line x1="12" x2="12" y1="8" y2="12"></line><line x1="12" x2="12.01" y1="16" y2="16"></line></svg>`
    };

    /**
     * Main function to fetch data and update the entire dashboard
     */
    async function updateDashboard() {
        try {
            const response = await fetch('/api/alerts');
            if (!response.ok) throw new Error('Network response was not ok.');
            const data = await response.json();
            allAlerts = data.active || [];
            
            // Update all parts of the dashboard
            renderFilteredAlerts();
            updateCharts();
            populateFilterOptions();
            updateTimestamp();

        } catch (error) {
            console.error("Failed to fetch alerts:", error);
            if (alertsList) alertsList.innerHTML = '<div class="alert alert-danger"><strong>Error: Could not connect to the Dragonfly server.</strong></div>';
        }
    }

    /**
     * Renders the list of alerts based on current filter values
     */
    function renderFilteredAlerts() {
        if (!alertsList) return;

        const textValue = filterText.value.toLowerCase();
        const typeValue = filterType.value;

        const filteredAlerts = allAlerts.filter(fullAlert => {
            const alert = fullAlert.alert;
            const agent = fullAlert.agent_info;

            const matchesType = !typeValue || alert.type === typeValue;
            const matchesText = !textValue || 
                (alert.log_entry && alert.log_entry.toLowerCase().includes(textValue)) ||
                (alert.details && alert.details.join(',').toLowerCase().includes(textValue)) ||
                (agent.device_name && agent.device_name.toLowerCase().includes(textValue)) ||
                (agent.ip && agent.ip.toLowerCase().includes(textValue));

            return matchesType && matchesText;
        });

        if (filteredAlerts.length === 0) {
            alertsList.innerHTML = '<div class="alert alert-info"><strong>No alerts match the current filters.</strong></div>';
            return;
        }
        alertsList.innerHTML = filteredAlerts.map(formatAlertCard).join('');
    }

    /**
     * Updates the charts with the latest data
     */
    function updateCharts() {
        if (!alertsByTypeCtx || !alertsByAgentCtx) return;

        // --- Process data for charts ---
        const alertsByTypeData = allAlerts.reduce((acc, {alert}) => {
            acc[alert.type] = (acc[alert.type] || 0) + 1;
            return acc;
        }, {});

        const alertsByAgentData = allAlerts.reduce((acc, {agent_info}) => {
            acc[agent_info.device_name] = (acc[agent_info.device_name] || 0) + 1;
            return acc;
        }, {});

        // --- Chart Configurations ---
        const chartOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: '#E0E1DD' } } },
            scales: { 
                y: { ticks: { color: '#a8b2c5' }, grid: { color: 'rgba(168, 178, 197, 0.2)' } },
                x: { ticks: { color: '#a8b2c5' }, grid: { color: 'rgba(168, 178, 197, 0.2)' } }
            }
        };

        // --- Update or create "Alerts by Type" chart ---
        if (alertTypeChart) {
            alertTypeChart.data.labels = Object.keys(alertsByTypeData);
            alertTypeChart.data.datasets[0].data = Object.values(alertsByTypeData);
            alertTypeChart.update();
        } else {
            alertTypeChart = new Chart(alertsByTypeCtx, {
                type: 'bar',
                data: {
                    labels: Object.keys(alertsByTypeData),
                    datasets: [{
                        label: 'Alert Count',
                        data: Object.values(alertsByTypeData),
                        backgroundColor: 'rgba(88, 166, 255, 0.6)',
                        borderColor: 'rgba(88, 166, 255, 1)',
                        borderWidth: 1
                    }]
                },
                options: chartOptions
            });
        }

        // --- Update or create "Alerts by Agent" chart ---
        if (alertsByAgentChart) {
            alertsByAgentChart.data.labels = Object.keys(alertsByAgentData);
            alertsByAgentChart.data.datasets[0].data = Object.values(alertsByAgentData);
            alertsByAgentChart.update();
        } else {
            alertsByAgentChart = new Chart(alertsByAgentCtx, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(alertsByAgentData),
                    datasets: [{
                        data: Object.values(alertsByAgentData),
                        backgroundColor: ['#58A6FF', '#3FB950', '#F85149', '#ffc107', '#6f42c1', '#fd7e14'],
                    }]
                },
                options: { ...chartOptions, scales: {} }
            });
        }
    }

    /**
     * Populates the filter dropdown with unique alert types
     */
    function populateFilterOptions() {
        const existingOptions = new Set(Array.from(filterType.options).map(o => o.value));
        const alertTypes = new Set(allAlerts.map(a => a.alert.type));
        
        alertTypes.forEach(type => {
            if (!existingOptions.has(type)) {
                const option = document.createElement('option');
                option.value = type;
                option.textContent = type;
                filterType.appendChild(option);
            }
        });
    }

    /**
     * Creates the HTML for a single alert card
     */
    function formatAlertCard(fullAlert) {
        const { agent_info, alert, timestamp } = fullAlert;
        const escape = (str) => String(str).replace(/[&<>"']/g, (m) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'})[m]);
        let alertClass = 'alert-warning', icon = ICONS.WARNING, detailsHtml = '';

        if (alert.log_entry) detailsHtml = `<strong>Details:</strong> <code>${escape(alert.log_entry)}</code>`;
        else if (alert.details) detailsHtml = `<strong>Details:</strong> ${escape(alert.details.join(', '))}`;
        
        if (alert.type === 'BRUTE_FORCE_ALERT') {
            alertClass = 'alert-danger'; icon = ICONS.DANGER;
            detailsHtml = `<strong>Source:</strong> ${escape(alert.source)}<br><strong>Count:</strong> ${escape(alert.count)} attempts in ${escape(alert.timeframe_seconds)}s`;
        } else if (alert.type?.startsWith('SUCCESSFUL')) {
            alertClass = 'alert-success'; icon = ICONS.SUCCESS;
        } else if (alert.type?.startsWith('FAILED') || alert.type?.startsWith('INVALID')) {
            alertClass = 'alert-danger'; icon = ICONS.DANGER;
        }

        return `
            <div class="alert ${alertClass}">
                <div class="alert-icon">${icon}</div>
                <div class="alert-content">
                    <div class="alert-header">
                        <span class="alert-device">${escape(agent_info.device_name || 'Unknown')} (${escape(agent_info.ip || 'N/A')})</span>
                        <span class="alert-timestamp">${escape(timestamp)}</span>
                    </div>
                    <div class="alert-body">
                        <strong>Type:</strong> ${escape(alert.type || 'N/A')}<br>
                        ${detailsHtml}
                    </div>
                </div>
            </div>`;
    }

    function updateTimestamp() {
        if (lastUpdated) lastUpdated.textContent = new Date().toLocaleString();
    }

    // --- Event Listeners ---
    filterText.addEventListener('input', renderFilteredAlerts);
    filterType.addEventListener('change', renderFilteredAlerts);

    // --- Initial Load & Refresh Interval ---
    updateDashboard();
    setInterval(updateDashboard, 15000); // Refresh every 15 seconds
});
