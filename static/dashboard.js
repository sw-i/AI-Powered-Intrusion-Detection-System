// Dashboard functionality
document.addEventListener('DOMContentLoaded', function() {
    // State
    let monitoringActive = false;
    let refreshInterval;
    const refreshRate = 2000; // 2 seconds default
    let trafficChart, attackTypesChart, sourcesChart, attackTimelineChart;
    let chartsInitialized = {
        dashboard: false,
        analytics: false
    };

    // DOM elements
    const statusIndicator = document.getElementById('statusIndicator');
    const statusText = document.getElementById('statusText');
    const startMonitoringBtn = document.getElementById('startMonitoringBtn');
    const stopMonitoringBtn = document.getElementById('stopMonitoringBtn');
    const clearDataBtn = document.getElementById('clearDataBtn');
    const resetSystemBtn = document.getElementById('resetSystemBtn');
    const sidebarLinks = document.querySelectorAll('.sidebar-menu a');
    const pageContainers = document.querySelectorAll('.page-container');
    const sidebar = document.getElementById('sidebar');
    const sidebarToggle = document.getElementById('sidebarToggle');

    // Initialize charts for the active page on load
    initCharts();
    
    // Handle window resize to resize charts correctly
    let resizeTimeout;
    window.addEventListener('resize', function() {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(function() {
            resizeCharts();
        }, 250);
    });

    // Check initial monitoring status
    fetch('/api/stats')
    .then(response => response.json())
    .then(data => {
        monitoringActive = data.monitoring_active || false;
        updateStatus(monitoringActive);
        
        // Update button states based on monitoring status
        startMonitoringBtn.disabled = monitoringActive;
        stopMonitoringBtn.disabled = !monitoringActive;
        
        // Start refresh if monitoring is active
        if (monitoringActive) {
            startRefresh();
        }
    })
    .catch(error => console.error('Error checking monitoring status:', error));
    
    // Navigation with active page tracking
    sidebarLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Update active link
            sidebarLinks.forEach(l => l.classList.remove('active'));
            this.classList.add('active');
            
            // Get the target page
            const targetPage = this.getAttribute('data-page');
            
            // Handle page transition
            handlePageTransition(targetPage);
            
            // On mobile, hide sidebar after clicking
            if (window.innerWidth < 992) {
                sidebar.classList.remove('show');
            }
        });
    });

    // Mobile sidebar toggle
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', function() {
            sidebar.classList.toggle('show');
            
            // Force a resize event to adjust content margins
            setTimeout(() => {
                window.dispatchEvent(new Event('resize'));
            }, 300);
        });
    }
    
    // Button event listeners
    startMonitoringBtn.addEventListener('click', startMonitoring);
    stopMonitoringBtn.addEventListener('click', stopMonitoring);
    clearDataBtn.addEventListener('click', clearData);
    resetSystemBtn.addEventListener('click', resetSystem);
    
    // Setup dark mode toggle
    const darkModeToggle = document.getElementById('darkModeToggle');
    if (darkModeToggle) {
        darkModeToggle.addEventListener('click', function() {
            document.body.classList.toggle('dark-mode');
            
            // Save preference to localStorage
            const isDarkMode = document.body.classList.contains('dark-mode');
            localStorage.setItem('dark-mode', isDarkMode);
            
            // Update icon
            const icon = this.querySelector('i');
            if (isDarkMode) {
                icon.classList.remove('bi-moon-stars');
                icon.classList.add('bi-brightness-high');
            } else {
                icon.classList.remove('bi-brightness-high');
                icon.classList.add('bi-moon-stars');
            }
            
            // Update charts for dark mode
            cleanupCharts();
            
            // Re-init charts with dark theme
            if (document.querySelector('.active-page').id === 'dashboard-page') {
                initCharts();
                updateDashboard();
            } else if (document.querySelector('.active-page').id === 'analytics-page') {
                initAnalyticsCharts();
                updateAnalyticsCharts();
            }
        });
        
        // Check for saved preference on load
        if (localStorage.getItem('dark-mode') === 'true') {
            document.body.classList.add('dark-mode');
            const icon = darkModeToggle.querySelector('i');
            icon.classList.remove('bi-moon-stars');
            icon.classList.add('bi-brightness-high');
        }
    }

    // Functions
    function startMonitoring() {
        fetch('/api/start_monitoring', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                monitoringActive = true;
                updateStatus(true);
                startMonitoringBtn.disabled = true;
                stopMonitoringBtn.disabled = false;
                startRefresh();
            }
        })
        .catch(error => console.error('Error starting monitoring:', error));
    }

    function stopMonitoring() {
        fetch('/api/stop_monitoring', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                monitoringActive = false;
                updateStatus(false);
                startMonitoringBtn.disabled = false;
                stopMonitoringBtn.disabled = true;
                stopRefresh();
            }
        })
        .catch(error => console.error('Error stopping monitoring:', error));
    }

    function clearData() {
        if (confirm('Are you sure you want to clear all data?')) {
            fetch('/api/clear_data', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateDashboard();
                }
            })
            .catch(error => console.error('Error clearing data:', error));
        }
    }

    function resetSystem() {
        if (confirm('Are you sure you want to reset the system? This will stop monitoring and clear all data.')) {
            fetch('/api/reset_system', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    monitoringActive = false;
                    updateStatus(false);
                    startMonitoringBtn.disabled = false;
                    stopMonitoringBtn.disabled = true;
                    stopRefresh();
                    updateDashboard();
                }
            })
            .catch(error => console.error('Error resetting system:', error));
        }
    }

    function updateStatus(active) {
        const statusIndicator = document.querySelector('.status-indicator');
        const statusText = document.getElementById('statusText');
        const pulse = document.querySelector('.pulse');
        
        if (active) {
            statusIndicator.classList.add('active');
            statusText.textContent = 'Monitoring Active';
            pulse.style.backgroundColor = '#3ac47d';
        } else {
            statusIndicator.classList.remove('active');
            statusText.textContent = 'Monitoring Inactive';
            pulse.style.backgroundColor = '#f64e60';
        }
    }

    function startRefresh() {
        if (!refreshInterval) {
            refreshInterval = setInterval(updateDashboard, refreshRate);
        }
    }

    function stopRefresh() {
        if (refreshInterval) {
            clearInterval(refreshInterval);
            refreshInterval = null;
        }
    }

    function updateDashboard() {
        fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            updateUI(data);
            updateCharts(data);
            updateAlerts(data.alerts || []);
        })
        .catch(error => console.error('Error updating dashboard:', error));
    }

    function updateUI(data) {
        document.getElementById('totalPackets').textContent = data.total_packets || 0;
        document.getElementById('safePackets').textContent = data.safe_packets || 0;
        document.getElementById('threatPackets').textContent = data.threat_packets || 0;
        document.getElementById('suspiciousPackets').textContent = data.suspicious_packets || 0;
    }

    function updateAlerts(alerts) {
        const alertsTable = document.getElementById('alertsTable');
        alertsTable.innerHTML = '';
        
        alerts.slice(0, 5).forEach(alert => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${alert.timestamp}</td>
                <td>${alert.type}</td>
                <td>${alert.source_ip}</td>
                <td>${alert.destination_ip}</td>
                <td>${alert.protocol}</td>
                <td><span class="badge ${getAlertClass(alert.type)}">${alert.status}</span></td>
            `;
            alertsTable.appendChild(row);
        });
    }

    function getAlertClass(attackType) {
        switch(attackType.toLowerCase()) {
            case 'dos':
            case 'ddos':
                return 'bg-danger';
            case 'port_scan':
            case 'brute_force':
                return 'bg-warning';
            default:
                return 'bg-secondary';
        }
    }

    function initCharts() {
        if (chartsInitialized.dashboard) return;
        
        // Traffic Chart
        const trafficCtx = document.getElementById('trafficChart').getContext('2d');
        trafficChart = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Traffic',
                    data: [],
                    borderColor: '#4361ee',
                    tension: 0.4,
                    fill: true,
                    backgroundColor: 'rgba(67, 97, 238, 0.1)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            display: true,
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                }
            }
        });

        // Attack Types Chart
        const attackTypesCtx = document.getElementById('attackTypesChart').getContext('2d');
        attackTypesChart = new Chart(attackTypesCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#f64e60',
                        '#ff9800',
                        '#3ac47d',
                        '#4361ee'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            boxWidth: 12,
                            padding: 10
                        }
                    }
                }
            }
        });

        // Sources Chart
        const sourcesCtx = document.getElementById('sourcesChart').getContext('2d');
        sourcesChart = new Chart(sourcesCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Attack Sources',
                    data: [],
                    backgroundColor: '#4361ee'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            display: true,
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                }
            }
        });

        // Attack Timeline Chart
        const timelineCtx = document.getElementById('attackTimelineChart').getContext('2d');
        attackTimelineChart = new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Attacks',
                    data: [],
                    borderColor: '#f64e60',
                    tension: 0.4,
                    fill: true,
                    backgroundColor: 'rgba(246, 78, 96, 0.1)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            display: true,
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                }
            }
        });

        chartsInitialized.dashboard = true;
    }

    function updateCharts(data) {
        // Update Traffic Chart
        const trafficLabels = data.traffic_labels || [];
        const trafficData = data.traffic_data || [];
        
        trafficChart.data.labels = trafficLabels;
        trafficChart.data.datasets[0].data = trafficData;
        trafficChart.update();

        // Update Attack Types Chart
        const attackTypes = data.attack_types || {};
        attackTypesChart.data.labels = Object.keys(attackTypes);
        attackTypesChart.data.datasets[0].data = Object.values(attackTypes);
        attackTypesChart.update();

        // Update Sources Chart
        const sources = data.sources || {};
        sourcesChart.data.labels = Object.keys(sources);
        sourcesChart.data.datasets[0].data = Object.values(sources);
        sourcesChart.update();

        // Update Attack Timeline Chart
        const timelineLabels = data.timeline_labels || [];
        const timelineData = data.timeline_data || [];
        
        attackTimelineChart.data.labels = timelineLabels;
        attackTimelineChart.data.datasets[0].data = timelineData;
        attackTimelineChart.update();
    }

    function cleanupCharts() {
        if (trafficChart) trafficChart.destroy();
        if (attackTypesChart) attackTypesChart.destroy();
        if (sourcesChart) sourcesChart.destroy();
        if (attackTimelineChart) attackTimelineChart.update();
        
        chartsInitialized.dashboard = false;
    }

    function resizeCharts() {
        if (trafficChart) trafficChart.resize();
        if (attackTypesChart) attackTypesChart.resize();
        if (sourcesChart) sourcesChart.resize();
        if (attackTimelineChart) attackTimelineChart.resize();
    }

    function handlePageTransition(targetPage) {
        pageContainers.forEach(container => {
            container.style.visibility = 'hidden';
            container.style.position = 'absolute';
        });
        const targetContainer = document.getElementById(targetPage);
        if (targetContainer) {
            targetContainer.style.visibility = 'visible';
            targetContainer.style.position = 'relative';
            if (targetPage === 'dashboard-page' && !chartsInitialized.dashboard) {
                initCharts();
                updateDashboard();
            } else if (targetPage === 'analytics-page') {
                initAnalyticsCharts();
                updateAnalyticsCharts();
            } else if (targetPage === 'threats-page') {
                initThreatsPage();
            } else if (targetPage === 'settings-page') {
                initSettingsPage();
            }
        }
    }

    // --- Analytics Page Logic ---
    function initAnalyticsCharts() {
        if (chartsInitialized.analytics) return;
        // Example: Hourly Traffic Line Chart
        const analyticsChartEl = document.getElementById('analyticsChart');
        if (analyticsChartEl) {
            window.analyticsChart = new Chart(analyticsChartEl.getContext('2d'), {
                type: 'line',
                data: { labels: [], datasets: [{ label: 'Hourly Traffic', data: [], borderColor: '#4361ee', fill: true, backgroundColor: 'rgba(67,97,238,0.08)' }] },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
            });
        }
        chartsInitialized.analytics = true;
    }
    function updateAnalyticsCharts() {
        fetch('/api/analytics/data').then(r=>r.json()).then(data=>{
            if (window.analyticsChart && data.hourly_traffic) {
                window.analyticsChart.data.labels = data.hourly_traffic.labels;
                window.analyticsChart.data.datasets[0].data = data.hourly_traffic.values;
                window.analyticsChart.update();
            }
            // Add more analytics charts as needed
        });
    }
    // --- Threats Page Logic ---
    function initThreatsPage() {
        updateThreatsPage();
    }
    function updateThreatsPage() {
        fetch('/api/threats').then(r=>r.json()).then(data=>{
            const table = document.getElementById('threatsTable');
            if (table) {
                table.innerHTML = '';
                (data.threats||[]).forEach(threat=>{
                    const row = document.createElement('tr');
                    row.innerHTML = `<td>${threat.time||''}</td><td>${threat.type||''}</td><td>${threat.source||''}</td><td>${threat.severity||''}</td><td>${threat.status||''}</td><td><button class='btn btn-sm btn-danger' onclick='blockThreat("${threat.source}")'>Block</button></td>`;
                    table.appendChild(row);
                });
            }
        });
    }
    window.blockThreat = function(ip) {
        fetch('/api/threats/block', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})})
        .then(r=>r.json()).then(()=>updateThreatsPage());
    }
    // --- Settings Page Logic ---
    function initSettingsPage() {
        fetch('/api/system/settings').then(r=>r.json()).then(data=>{
            const form = document.getElementById('settingsForm');
            if (form && data.settings) {
                form.auto_reset.checked = data.settings.auto_reset;
                form.detection_sensitivity.value = data.settings.detection_sensitivity;
                form.log_level.value = data.settings.log_level;
                form.refresh_rate.value = data.settings.refresh_rate;
            }
        });
    }
    document.addEventListener('submit', function(e) {
        if (e.target && e.target.id === 'settingsForm') {
            e.preventDefault();
            const form = e.target;
            const settings = {
                auto_reset: form.auto_reset.checked,
                detection_sensitivity: form.detection_sensitivity.value,
                log_level: form.log_level.value,
                refresh_rate: form.refresh_rate.value
            };
            fetch('/api/system/settings', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(settings)})
            .then(r=>r.json()).then(()=>initSettingsPage());
        }
    });
}); 