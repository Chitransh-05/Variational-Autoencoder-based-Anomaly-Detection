// NIDS Dashboard JavaScript

let decisionChart, alertChart, protocolChart;

window.addEventListener('load', function () {
    initializeDashboard();
});

function initializeDashboard() {
    initializeCharts();
    loadDashboardData();
    setInterval(function () {
        loadDashboardData();
    }, 5000);
}

function initializeCharts() {
    const decisionCtx = document.getElementById('decisionChart');
    const alertCtx = document.getElementById('alertChart');
    const protocolCtx = document.getElementById('protocolChart');

    decisionChart = new Chart(decisionCtx.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['Normal', 'Suspicious', 'Attack'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });

    alertChart = new Chart(alertCtx.getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['Info', 'Warning', 'Critical'],
            datasets: [{
                label: 'Count',
                data: [0, 0, 0],
                backgroundColor: ['#10b981', '#f59e0b', '#ef4444']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });

    protocolChart = new Chart(protocolCtx.getContext('2d'), {
        type: 'pie',
        data: {
            labels: ['TCP', 'UDP', 'ICMP'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#0f766e', '#f59e0b', '#2563eb']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

function loadDashboardData() {
    fetch('/api/stats')
        .then(response => {
            if (!response.ok) {
                throw new Error('HTTP error ' + response.status);
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                updateStatus('Error', false);
                return;
            }

            updateStatistics(data);
            updateCharts(data);
            updateAlertsTable();
            updateStatus('Active', true);
        })
        .catch(() => {
            updateStatus('Error', false);
        });
}

function updateStatistics(data) {
    const summary = data.summary || {};
    const sessionInfo = summary.session_info || {};
    const statistics = summary.statistics || {};
    const decisions = statistics.decisions || {};

    document.getElementById('totalFlows').textContent = Number(sessionInfo.total_flows || 0).toLocaleString();
    document.getElementById('totalPackets').textContent = Number(sessionInfo.total_packets || 0).toLocaleString();
    document.getElementById('totalAlerts').textContent = Number(sessionInfo.total_alerts || 0).toLocaleString();
    document.getElementById('normalFlows').textContent = Number(decisions.NORMAL || 0).toLocaleString();
    document.getElementById('lastUpdate').textContent = data.last_updated || new Date().toLocaleTimeString();
}

function updateCharts(data) {
    const statistics = data.summary?.statistics || {};
    const decisions = statistics.decisions || {};
    const alertLevels = statistics.alert_levels || {};
    const protocols = statistics.protocols || {};

    decisionChart.data.datasets[0].data = [
        decisions.NORMAL || 0,
        decisions.SUSPICIOUS || 0,
        decisions.ATTACK || 0
    ];
    decisionChart.update();

    alertChart.data.datasets[0].data = [
        alertLevels.INFO || 0,
        alertLevels.WARNING || 0,
        alertLevels.CRITICAL || 0
    ];
    alertChart.update();

    protocolChart.data.datasets[0].data = [
        protocols.TCP || 0,
        protocols.UDP || 0,
        protocols.ICMP || 0
    ];
    protocolChart.update();
}

function updateAlertsTable() {
    fetch('/api/alerts')
        .then(response => response.json())
        .then(alerts => {
            const tbody = document.getElementById('alertsTableBody');

            if (!alerts || alerts.length === 0) {
                tbody.innerHTML = '<tr><td colspan="11" class="loading">No alerts yet</td></tr>';
                return;
            }

            const recentAlerts = alerts.slice(-20).reverse();
            tbody.innerHTML = recentAlerts.map(alert => {
                const topAlternatives = formatTopAlternatives(alert.top_3_attack_types || []);
                const packets = alert.total_packets ?? alert.packets ?? 0;
                const decision = alert.final_decision ?? alert.decision ?? 'N/A';
                const vaeError = Number(alert.vae_error ?? 0).toFixed(4);
                const attackType = alert.predicted_attack_type || 'Not classified';
                const confidence = formatConfidence(alert.attack_confidence);

                return `
                    <tr>
                        <td>${formatTime(alert.timestamp)}</td>
                        <td><code>${truncateIP(alert.src_ip)}</code></td>
                        <td>${alert.dst_port ?? 'N/A'}</td>
                        <td>${alert.protocol ?? 'N/A'}</td>
                        <td>${packets}</td>
                        <td>${vaeError}</td>
                        <td>${decision}</td>
                        <td><span class="badge badge-${String(alert.alert_level || 'info').toLowerCase()}">${alert.alert_level || 'INFO'}</span></td>
                        <td>${attackType}</td>
                        <td>${confidence}</td>
                        <td>${topAlternatives}</td>
                    </tr>
                `;
            }).join('');
        })
        .catch(() => {
            const tbody = document.getElementById('alertsTableBody');
            tbody.innerHTML = '<tr><td colspan="11" class="loading">Failed to load alerts</td></tr>';
        });
}

function updateStatus(text, isActive) {
    document.getElementById('statusText').textContent = text;
    document.getElementById('statusDot').style.background = isActive ? '#4ade80' : '#ef4444';
}

function formatTime(timestamp) {
    if (!timestamp) {
        return 'N/A';
    }
    const parts = String(timestamp).split(' ');
    return parts.length > 1 ? parts[1] : String(timestamp);
}

function truncateIP(ip) {
    if (!ip) {
        return 'N/A';
    }
    return ip.length > 30 ? ip.substring(0, 27) + '...' : ip;
}

function formatConfidence(value) {
    if (value === undefined || value === null || Number.isNaN(Number(value))) {
        return 'N/A';
    }
    return `${(Number(value) * 100).toFixed(1)}%`;
}

function formatTopAlternatives(items) {
    if (!items || items.length === 0) {
        return 'N/A';
    }

    return items
        .slice(1)
        .map(item => `${item.attack_type} (${(Number(item.probability) * 100).toFixed(1)}%)`)
        .join(', ') || 'N/A';
}
