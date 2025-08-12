// dashboard.js
document.addEventListener('DOMContentLoaded', function () {
    // --- DOM Elements ---
    const alertsList = document.getElementById('alerts-list');
    const lastUpdated = document.getElementById('last-updated');
    const filterText = document.getElementById('filter-text');
    const filterType = document.getElementById('filter-type');
    const countCriteriaSelector = document.getElementById('count-criteria-selector');
    const countBoxDisplay = document.getElementById('count-box-display');
    
    // --- Chart Contexts ---
    const alertsByTypeCtx = document.getElementById('alertsByTypeChart')?.getContext('2d');
    const alertsByAgentCtx = document.getElementById('alertsByAgentChart')?.getContext('2d');
    const alertsOverTimeCtx = document.getElementById('alertsOverTimeChart')?.getContext('2d');

    // --- State ---
    let allAlerts = [];
    let alertTypeChart, alertsByAgentChart, alertsOverTimeChart;

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
            
            renderFilteredAlerts();
            updateCharts();
            updateCountBox();
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
            const { alert, agent_info } = fullAlert;
            const matchesType = !typeValue || alert.type === typeValue;
            const matchesText = !textValue || 
                Object.values(alert).some(val => String(val).toLowerCase().includes(textValue)) ||
                Object.values(agent_info).some(val => String(val).toLowerCase().includes(textValue));
            return matchesType && matchesText;
        });

        if (filteredAlerts.length === 0) {
            alertsList.innerHTML = '<div class="alert alert-info"><strong>No alerts match the current filters.</strong></div>';
            return;
        }
        alertsList.innerHTML = filteredAlerts.map(formatAlertCard).join('');
    }

    /**
     * Updates all charts with the latest data
     */
    function updateCharts() {
        if (!alertsByTypeCtx || !alertsByAgentCtx || !alertsOverTimeCtx) return;

        const alertsByTypeData = allAlerts.reduce((acc, {alert}) => {
            acc[alert.type] = (acc[alert.type] || 0) + 1;
            return acc;
        }, {});

        const alertsByAgentData = allAlerts.reduce((acc, {agent_info}) => {
            acc[agent_info.device_name] = (acc[agent_info.device_name] || 0) + 1;
            return acc;
        }, {});

        // --- Data processing for Alerts Over Time ---
        const now = new Date();
        const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const hourlyAlerts = Array(24).fill(0);
        const labels = Array(24).fill().map((_, i) => {
            const date = new Date(now.getTime() - (23 - i) * 60 * 60 * 1000);
            return date;
        });

        allAlerts.forEach(({ timestamp }) => {
            const alertDate = new Date(timestamp.replace(' ', 'T') + 'Z'); // Make ISO compatible
            if (alertDate >= twentyFourHoursAgo) {
                const hourIndex = Math.floor((alertDate - twentyFourHoursAgo) / (1000 * 60 * 60));
                if(hourIndex >= 0 && hourIndex < 24) {
                    hourlyAlerts[hourIndex]++;
                }
            }
        });


        // --- Chart Configurations ---
        const barChartOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { 
                y: { ticks: { color: '#a8b2c5' }, grid: { color: 'rgba(168, 178, 197, 0.2)' } },
                x: { ticks: { color: '#a8b2c5' }, grid: { color: 'rgba(168, 178, 197, 0.2)' } }
            }
        };

        const doughnutChartOptions = {
            responsive: true,
            maintainAspectRatio: true,
            plugins: { legend: { position: 'top', labels: { color: '#E0E1DD' } } },
        };

        const lineChartOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { 
                    ticks: { color: '#a8b2c5', precision: 0 }, 
                    grid: { color: 'rgba(168, 178, 197, 0.2)' },
                    beginAtZero: true
                },
                x: { 
                    type: 'time',
                    time: { unit: 'hour', displayFormats: { hour: 'ha' } },
                    ticks: { color: '#a8b2c5' }, 
                    grid: { color: 'rgba(168, 178, 197, 0.2)' }
                }
            },
            elements: { line: { tension: 0.3 } }
        };

        // --- Update or create charts ---
        updateOrCreateChart(alertTypeChart, alertsByTypeCtx, 'bar', {
            labels: Object.keys(alertsByTypeData),
            datasets: [{ label: 'Alert Count', data: Object.values(alertsByTypeData), backgroundColor: 'rgba(88, 166, 255, 0.6)' }]
        }, barChartOptions, 'alertTypeChart');

        updateOrCreateChart(alertsByAgentChart, alertsByAgentCtx, 'doughnut', {
            labels: Object.keys(alertsByAgentData),
            datasets: [{ data: Object.values(alertsByAgentData), backgroundColor: ['#58A6FF', '#3FB950', '#F85149', '#ffc107', '#6f42c1'], borderWidth: 2, borderColor: '#1B263B' }]
        }, doughnutChartOptions, 'alertsByAgentChart');

        updateOrCreateChart(alertsOverTimeChart, alertsOverTimeCtx, 'line', {
            labels: labels,
            datasets: [{ label: 'Alerts', data: hourlyAlerts, backgroundColor: 'rgba(88, 166, 255, 0.2)', borderColor: 'rgba(88, 166, 255, 1)', fill: true }]
        }, lineChartOptions, 'alertsOverTimeChart');
    }

    function updateOrCreateChart(chartInstance, context, type, data, options, chartName) {
        if (chartInstance) {
            chartInstance.data = data;
            chartInstance.options = options;
            chartInstance.update();
        } else {
            window[chartName] = new Chart(context, { type, data, options });
        }
    }


    /**
     * Updates the count box based on the selected criteria
     */
    function updateCountBox() {
        if (!countBoxDisplay || !countCriteriaSelector) return;
        const criteria = countCriteriaSelector.value;
        let counts = {};

        if (criteria === 'severity') {
            counts = allAlerts.reduce((acc, { severity }) => {
                acc[severity || 'unknown'] = (acc[severity || 'unknown'] || 0) + 1;
                return acc;
            }, {});
        } else if (criteria === 'category') {
            counts = allAlerts.reduce((acc, { category }) => {
                acc[category || 'unknown'] = (acc[category || 'unknown'] || 0) + 1;
                return acc;
            }, {});
        } else if (criteria === 'agent') {
            counts = allAlerts.reduce((acc, { agent_info }) => {
                acc[agent_info.device_name || 'unknown'] = (acc[agent_info.device_name || 'unknown'] || 0) + 1;
                return acc;
            }, {});
        }

        countBoxDisplay.innerHTML = Object.entries(counts).map(([label, value]) => `
            <div class="count-item">
                <span class="count-value">${value}</span>
                <span class="count-label">${label}</span>
            </div>
        `).join('') || '<div class="alert alert-info" style="width: 100%;"><strong>No data for this criteria.</strong></div>';
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
        const { agent_info, alert, severity, category, timestamp } = fullAlert;
        const escape = (str) => String(str).replace(/[&<>"']/g, (m) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'})[m]);
        let alertClass = 'alert-info', icon = ICONS.WARNING;

        switch (severity?.toLowerCase()) {
            case 'high':
            case 'critical':
                alertClass = 'alert-danger'; icon = ICONS.DANGER; break;
            case 'medium':
                alertClass = 'alert-warning'; icon = ICONS.WARNING; break;
            case 'low':
                alertClass = 'alert-success'; icon = ICONS.SUCCESS; break;
        }

        const detailsHtml = alert.log_entry ? `<strong>Details:</strong> <code>${escape(alert.log_entry)}</code>` : '';

        return `
            <div class="alert ${alertClass}">
                <div class="alert-icon">${icon}</div>
                <div class="alert-content">
                    <div class="alert-header">
                        <span class="alert-device">${escape(agent_info.device_name || 'Unknown')} (${escape(agent_info.ip || 'N/A')})</span>
                        <span class="alert-timestamp">${escape(timestamp)}</span>
                    </div>
                    <div class="alert-body">
                        <strong>Type:</strong> ${escape(alert.type || 'N/A')} | 
                        <strong>Category:</strong> ${escape(category || 'N/A')} | 
                        <strong>Severity:</strong> ${escape(severity || 'N/A')}<br>
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
    countCriteriaSelector.addEventListener('change', updateCountBox);

    // --- Initial Load & Refresh Interval ---
    updateDashboard();
    setInterval(updateDashboard, 15000);
});
