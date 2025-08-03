document.addEventListener('DOMContentLoaded', function () {
    const alertsList = document.getElementById('alerts-list');
    const alertsHistory = document.getElementById('alerts-history'); // Kept for future use
    const lastUpdated = document.getElementById('alerts-last-updated');

    function fetchAlerts() {
        fetch('/api/alerts')
            .then(response => response.json())
            .then(data => {
                renderAlerts(data.active || []);
                // renderHistory(data.history || []); // For future use
                updateTimestamp();
            })
            .catch(() => {
                alertsList.innerHTML = '<div class="alert alert-danger"><strong>Error: Could not connect to the Dragonfly server to load alerts.</strong></div>';
            });
    }

    function renderAlerts(alerts) {
        if (!alertsList) return; // Exit if the element doesn't exist

        if (alerts.length === 0) {
            alertsList.innerHTML = '<div class="alert alert-info"><strong>No new alerts. System is quiet.</strong></div>';
            return;
        }

        // Use a helper function to format each alert
        alertsList.innerHTML = alerts.map(formatAlert).join('');
    }

    function formatAlert(fullAlert) {
        const { agent_info, alert, timestamp } = fullAlert;

        // Sanitize function to prevent HTML injection
        const escape = (str) => str.replace(/[&<>"']/g, (m) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'})[m]);

        let title = `Alert from ${escape(agent_info.device_name || 'Unknown')} (${escape(agent_info.ip || 'N/A')})`;
        let message = `<strong>Type:</strong> ${escape(alert.type || 'N/A')}<br>`;
        let alertClass = 'alert-warning'; // Default class

        // Customize message and class based on alert type
        if (alert.log_entry) {
            message += `<strong>Details:</strong> <code>${escape(alert.log_entry)}</code>`;
        } else if (alert.details) {
            message += `<strong>Details:</strong> ${escape(alert.details.join(', '))}`;
        } else if (alert.type === 'BRUTE_FORCE_ALERT') {
            message += `<strong>Source:</strong> ${escape(alert.source)}<br>`;
            message += `<strong>Count:</strong> ${escape(alert.count.toString())} attempts in ${escape(alert.timeframe_seconds.toString())}s`;
            alertClass = 'alert-danger'; // Make brute-force alerts more prominent
        } else if (alert.type === 'SUCCESSFUL_LOGON' || alert.type === 'SUCCESSFUL_LOGIN') {
            alertClass = 'alert-success'; // Make successful logins green
        }

        return `
            <div class="alert ${alertClass}">
                <strong>${title}</strong><br>
                ${message}
                <div class="alert-meta">
                    <small>Received at: ${escape(timestamp)}</small>
                </div>
            </div>
        `;
    }

    function updateTimestamp() {
        if (!lastUpdated) return;
        const now = new Date();
        lastUpdated.textContent = now.toLocaleString();
    }

    // Initial fetch and periodic refresh every 10 seconds
    fetchAlerts();
    setInterval(fetchAlerts, 10000);
});
