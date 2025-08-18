// dashboard.js
document.addEventListener('DOMContentLoaded', function () {
    // --- DOM Elements ---
    const alertsList = document.getElementById('alerts-list');
    const lastUpdated = document.getElementById('last-updated');
    const filterText = document.getElementById('filter-text');
    const filterType = document.getElementById('filter-type');
    const countCriteriaSelector = document.getElementById('count-criteria-selector');
    const countBoxDisplay = document.getElementById('count-box-display');
    // NEW: Added for visual feedback on connection status.
    // Add <div id="status-indicator"></div> to your HTML to use this.
    const statusIndicator = document.getElementById('status-indicator');

    // --- Chart Contexts ---
    const alertsByTypeCtx = document.getElementById('alertsByTypeChart')?.getContext('2d');
    const alertsByAgentCtx = document.getElementById('alertsByAgentChart')?.getContext('2d');
    const alertsOverTimeCtx = document.getElementById('alertsOverTimeChart')?.getContext('2d');

    // --- State ---
    let allAlerts = [];
    let alertTypeChart, alertsByAgentChart, alertsOverTimeChart;
    // NEW: Prevents multiple update requests from running at the same time.
    let isUpdating = false;

    // --- SVG Icons ---
    // NOTE: Fill these with your actual SVG code.
    const ICONS = {
        SUCCESS: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-green-500"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`,
        WARNING: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-yellow-500"><path d="m21.73 18-8-14a2 2 0 0 0-3.46 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" x2="12" y1="9" y2="13"></line><line x1="12" x2="12.01" y1="17" y2="17"></line></svg>`,
        DANGER: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-red-500"><circle cx="12" cy="12" r="10"></circle><line x1="12" x2="12" y1="8" y2="12"></line><line x1="12" x2="12.01" y1="16" y2="16"></line></svg>`
    };

    /**
     * IMPROVED: Retry wrapper for fetch with exponential backoff and a timeout.
     * This is more resilient to slow or temporarily unavailable servers.
     */
    async function fetchWithRetry(url, retries = 3, initialDelay = 1000, timeout = 8000) {
        for (let i = 0; i < retries; i++) {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeout);

            try {
                const response = await fetch(url, { signal: controller.signal });
                clearTimeout(timeoutId); // Clear the timeout if the fetch completes
                if (!response.ok) throw new Error(`HTTP error ${response.status}`);
                return await response.json();
            } catch (err) {
                clearTimeout(timeoutId);
                const errorMessage = err.name === 'AbortError' ? 'Timeout' : err.message;
                console.warn(`Fetch attempt ${i + 1} failed: ${errorMessage}`);
                if (i < retries - 1) {
                    // Exponential backoff: 1s, 2s, 4s...
                    const delay = initialDelay * Math.pow(2, i);
                    await new Promise(r => setTimeout(r, delay));
                } else {
                    throw err; // Rethrow the error after the final attempt
                }
            }
        }
    }

    /**
     * IMPROVED: Main function to fetch data and update the dashboard.
     * Now includes error handling and prevents overlapping updates.
     */
    async function updateDashboard() {
        if (isUpdating) {
            console.log("Update already in progress. Skipping.");
            return;
        }
        isUpdating = true;
        if (statusIndicator) statusIndicator.className = 'status-indicator loading';
        if (alertsList && !allAlerts.length) {
            alertsList.innerHTML = `<div class="alert alert-info"><strong>Loading dashboard data...</strong></div>`;
        }


        try {
            const data = await fetchWithRetry('/api/alerts');
            allAlerts = data.active || [];

            // If successful, run all UI update functions
            renderFilteredAlerts();
            updateCharts();
            updateCountBox();
            populateFilterOptions();
            updateTimestamp();

            if (statusIndicator) statusIndicator.className = 'status-indicator success';
            console.log("Dashboard updated successfully at " + new Date().toLocaleTimeString());

        } catch (error) {
            console.error("Failed to update dashboard after multiple retries:", error);
            if (statusIndicator) statusIndicator.className = 'status-indicator error';
            // Optionally, show an error message on the dashboard itself
            if (alertsList && !allAlerts.length) { // Only show if there's no data at all
                 alertsList.innerHTML = `
                    <div class="alert alert-danger">
                        <strong>Connection Failed.</strong> Could not load data from the server. Will keep trying in the background.
                    </div>`;
            }
        } finally {
            isUpdating = false;
        }
    }

    /**
     * NEW: Self-correcting timer loop.
     * Replaces setInterval with a more robust recursive setTimeout pattern.
     * It waits for the update to finish before scheduling the next one.
     */
    function scheduleNextUpdate(delay) {
        setTimeout(async () => {
            await updateDashboard();
            scheduleNextUpdate(delay); // Schedule the *next* update
        }, delay);
    }

    /**
     * NEW: Initial load function to start the process.
     */
    async function initialLoad() {
        await updateDashboard(); // Perform the first update immediately
        scheduleNextUpdate(15000); // Start the recurring update loop
    }

    /**
     * Renders the list of alerts based on current filter values.
     * (Original function, no changes needed)
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

        if (filteredAlerts.length === 0 && allAlerts.length > 0) {
            alertsList.innerHTML = '<div class="alert alert-info"><strong>No alerts match the current filters.</strong></div>';
            return;
        }
        // If there are no alerts at all, the updateDashboard function will handle the message.
        if (allAlerts.length > 0) {
           alertsList.innerHTML = filteredAlerts.map(formatAlertCard).join('');
        }
    }

    /**
     * Updates all charts with the latest data.
     * (Original function, no changes needed)
     */
    function updateCharts() {
        if (!alertsByTypeCtx || !alertsByAgentCtx || !alertsOverTimeCtx) return;

        const alertsByTypeData = allAlerts.reduce((acc, { alert }) => {
            acc[alert.type] = (acc[alert.type] || 0) + 1;
            return acc;
        }, {});

        const alertsByAgentData = allAlerts.reduce((acc, { agent_info }) => {
            acc[agent_info.device_name] = (acc[agent_info.device_name] || 0) + 1;
            return acc;
        }, {});

        const now = new Date();
        const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const hourlyAlerts = Array(24).fill(0);
        const labels = Array(24).fill().map((_, i) => {
            const date = new Date(now.getTime() - (23 - i) * 60 * 60 * 1000);
            return date.toLocaleTimeString('en-US', { hour: 'numeric', hour12: true });
        });

        allAlerts.forEach(({ timestamp }) => {
            const alertDate = new Date(timestamp.replace(' ', 'T') + 'Z');
            if (alertDate >= twentyFourHoursAgo) {
                const hourIndex = Math.floor((alertDate - twentyFourHoursAgo) / (1000 * 60 * 60));
                if (hourIndex >= 0 && hourIndex < 24) {
                    hourlyAlerts[hourIndex]++;
                }
            }
        });

        const barChartOptions = { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } };
        const doughnutChartOptions = { responsive: true, maintainAspectRatio: true, plugins: { legend: { position: 'top' } } };
        const lineChartOptions = { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } };

        updateOrCreateChart(alertTypeChart, alertsByTypeCtx, 'bar', {
            labels: Object.keys(alertsByTypeData),
            datasets: [{ label: 'Alert Count', data: Object.values(alertsByTypeData), backgroundColor: '#3b82f6' }]
        }, barChartOptions, 'alertTypeChart');

        updateOrCreateChart(alertsByAgentChart, alertsByAgentCtx, 'doughnut', {
            labels: Object.keys(alertsByAgentData),
            datasets: [{ data: Object.values(alertsByAgentData), backgroundColor: ['#ef4444', '#f97316', '#eab308', '#84cc16', '#22c55e', '#14b8a6'] }]
        }, doughnutChartOptions, 'alertsByAgentChart');

        updateOrCreateChart(alertsOverTimeChart, alertsOverTimeCtx, 'line', {
            labels: labels,
            datasets: [{ label: 'Alerts', data: hourlyAlerts, borderColor: '#8b5cf6', tension: 0.1 }]
        }, lineChartOptions, 'alertsOverTimeChart');
    }

    function updateOrCreateChart(chartInstance, context, type, data, options, chartName) {
        if (chartInstance) {
            chartInstance.data = data;
            chartInstance.options = options;
            chartInstance.update();
        } else {
            // Use a dynamic variable assignment to handle the initial creation
            if (chartName === 'alertTypeChart') {
                alertTypeChart = new Chart(context, { type, data, options });
            } else if (chartName === 'alertsByAgentChart') {
                alertsByAgentChart = new Chart(context, { type, data, options });
            } else if (chartName === 'alertsOverTimeChart') {
                alertsOverTimeChart = new Chart(context, { type, data, options });
            }
        }
    }


    /**
     * Updates the count box.
     * (Original function, no changes needed)
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
     * Populate filter dropdown.
     * (Original function, no changes needed)
     */
    function populateFilterOptions() {
        if (!filterType) return;
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
     * Format a single alert card.
     * (Original function, no changes needed)
     */
    function formatAlertCard(fullAlert) {
        const { agent_info, alert, severity, category, timestamp } = fullAlert;
        const escape = (str) => String(str).replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[m]);
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
    if (filterText) filterText.addEventListener('input', renderFilteredAlerts);
    if (filterType) filterType.addEventListener('change', renderFilteredAlerts);
    if (countCriteriaSelector) countCriteriaSelector.addEventListener('change', updateCountBox);

    // --- Initial Load ---
    initialLoad();
});
