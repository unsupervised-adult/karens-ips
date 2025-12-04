// SPDX-FileCopyrightText: 2025 Karen's IPS ML Ad Detector
// SPDX-License-Identifier: GPL-2.0-only


// Import Chart.js if not already loaded
let timelineChart = null;
let featureChart = null;

// Refresh interval (5 seconds)
const REFRESH_INTERVAL = 5000;
let refreshInterval = null;
let isInitialized = false;

// ----------------------------------------
// Initialize function
// ----------------------------------------
function initializeMLDetector() {
    if (isInitialized) {
        console.log("ML Detector: Already initialized");
        return;
    }
    
    console.log("ML Detector: Initializing...");

    // Initialize charts
    initializeCharts();

    // Initialize tables
    initializeTables();

    // Load initial data
    loadAllData();

    // Set up auto-refresh
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
    refreshInterval = setInterval(loadAllData, REFRESH_INTERVAL);

    isInitialized = true;
    console.log("ML Detector: Initialized successfully");
}

// ----------------------------------------
// Initialize on page load and tab show
// ----------------------------------------
console.log("ML Detector JS: Script loaded");

(function checkJQuery() {
    console.log("ML Detector JS: Checking for jQuery...", typeof jQuery);
    
    if (typeof jQuery === 'undefined') {
        console.log("ML Detector JS: jQuery not found, retrying...");
        setTimeout(checkJQuery, 50);
        return;
    }
    
    console.log("ML Detector JS: jQuery found, setting up...");
    
    jQuery(document).ready(function() {
        var $ = jQuery;
        
        console.log("ML Detector JS: DOM ready");
        console.log("ML Detector JS: Tab element exists:", $('#nav-ml-detector-tab').length > 0);
        
        // Initialize when ML Detector tab is shown
        $('#nav-ml-detector-tab').on('shown.bs.tab', function (e) {
            console.log("ML Detector: Tab shown, initializing...");
            initializeMLDetector();
        });
        
        // Also try click event as backup
        $('#nav-ml-detector-tab').on('click', function (e) {
            console.log("ML Detector: Tab clicked");
            setTimeout(function() {
                if ($('#nav-ml-detector').hasClass('show') || $('#nav-ml-detector').hasClass('active')) {
                    console.log("ML Detector: Tab is now visible, initializing...");
                    initializeMLDetector();
                }
            }, 100);
        });
        
        // If ML Detector tab is active on page load, initialize immediately
        if ($('#nav-ml-detector').hasClass('active')) {
            console.log("ML Detector: Tab active on load, initializing...");
            initializeMLDetector();
        }
        
        // Cleanup on page unload
        $(window).on('beforeunload', function() {
            if (refreshInterval) {
                clearInterval(refreshInterval);
            }
        });
        
        console.log("ML Detector JS: Setup complete");
    });
})();

// ----------------------------------------
// Chart Initialization
// ----------------------------------------
function initializeCharts() {
    // Check if Chart.js is loaded
    if (typeof Chart === 'undefined') {
        console.error('Chart.js is not loaded. Charts will not be available.');
        return;
    }

    // Timeline Chart
    const timelineCtx = document.getElementById('timeline_chart');
    if (timelineCtx) {
        timelineChart = new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Ads Detected',
                        data: [],
                        borderColor: 'rgb(220, 53, 69)',
                        backgroundColor: 'rgba(220, 53, 69, 0.1)',
                        tension: 0.4
                    },
                    {
                        label: 'Legitimate Traffic',
                        data: [],
                        borderColor: 'rgb(25, 135, 84)',
                        backgroundColor: 'rgba(25, 135, 84, 0.1)',
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    }
                }
            }
        });
    }

    // Feature Importance Chart
    const featureCtx = document.getElementById('feature_importance_chart');
    if (featureCtx) {
        featureChart = new Chart(featureCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Importance Score',
                    data: [],
                    backgroundColor: 'rgba(13, 110, 253, 0.7)',
                    borderColor: 'rgb(13, 110, 253)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                scales: {
                    x: {
                        beginAtZero: true,
                        max: 1.0
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }
}

// ----------------------------------------
// Table Initialization
// ----------------------------------------
function initializeTables() {
    // Check if tables already exist
    if (window.detectionsTable) {
        console.log("ML Detector: Tables already initialized");
        return;
    }
    
    // Check if DataTables is available
    if (!$.fn.DataTable) {
        console.error("DataTables is not loaded");
        return;
    }
    
    // Check if table elements are visible (important for DataTables)
    if (!$('#table_detections').is(':visible')) {
        console.log("ML Detector: Tables not visible yet, deferring initialization");
        return;
    }
    
    console.log("ML Detector: Initializing DataTables...");
    
    try {
        // Destroy existing DataTables if they exist
        if ($.fn.DataTable.isDataTable('#table_detections')) {
            $('#table_detections').DataTable().destroy();
        }
        if ($.fn.DataTable.isDataTable('#table_alerts')) {
            $('#table_alerts').DataTable().destroy();
        }
        
        // Detections Table
        window.detectionsTable = $('#table_detections').DataTable({
            columns: [
                { data: 'timestamp_formatted', defaultContent: 'N/A' },
                { data: 'src_ip', defaultContent: 'N/A' },
                { data: 'dst_ip', defaultContent: 'N/A' },
                { data: 'dst_port', defaultContent: 'N/A' },
                { data: 'protocol', defaultContent: 'N/A' },
                {
                    data: 'classification',
                    defaultContent: 'Unknown',
                    render: function(data) {
                        const isAd = data && (data.toLowerCase().includes('ad') || data === 'ad');
                        const badge = isAd ? 'danger' : 'success';
                        return `<span class="badge bg-${badge}">${data || 'Unknown'}</span>`;
                    }
                },
                {
                    data: 'confidence',
                    defaultContent: '0',
                    render: function(data) {
                        const value = parseFloat(data);
                        return (isNaN(value) ? 0 : value * 100).toFixed(2) + '%';
                    }
                },
                { data: 'bytes', defaultContent: '0' },
                { data: 'packets', defaultContent: '0' }
            ],
            order: [[0, 'desc']],
            pageLength: 25,
            searching: true,
            lengthChange: true,
            deferRender: true
        });
        console.log("ML Detector: Detections table initialized");

        // Initialize alerts table when its tab is shown
        $('#alerts-tab').one('shown.bs.tab', function() {
            if (!window.alertsTable && $('#table_alerts').is(':visible')) {
                console.log("ML Detector: Initializing alerts table...");
                try {
                    window.alertsTable = $('#table_alerts').DataTable({
                        columns: [
                            { data: 'timestamp_formatted', defaultContent: 'N/A' },
                            { data: 'alert_type', defaultContent: 'Unknown' },
                            {
                                data: 'severity',
                                defaultContent: 'low',
                                render: function(data) {
                                    let badge = 'info';
                                    if (data === 'high') badge = 'danger';
                                    else if (data === 'medium') badge = 'warning';
                                    return `<span class="badge bg-${badge}">${data}</span>`;
                                }
                            },
                            { data: 'src_ip', defaultContent: 'N/A' },
                            { data: 'description', defaultContent: 'No description' },
                            {
                                data: 'confidence',
                                defaultContent: '0',
                                render: function(data) {
                                    const value = parseFloat(data);
                                    return (isNaN(value) ? 0 : value * 100).toFixed(2) + '%';
                                }
                            }
                        ],
                        order: [[0, 'desc']],
                        pageLength: 25,
                        searching: true,
                        lengthChange: true,
                        deferRender: true
                    });
                    console.log("ML Detector: Alerts table initialized");
                    loadAlerts();
                } catch (error) {
                    console.error("ML Detector: Error initializing alerts table:", error);
                }
            }
        });
    } catch (error) {
        console.error("ML Detector: Error initializing tables:", error);
    }
}

// ----------------------------------------
// Data Loading Functions
// ----------------------------------------
function loadAllData() {
    loadStats();
    loadModelInfo();
    loadDetections();
    loadAlerts();
    loadTimeline();
    loadFeatureImportance();
}

function loadStats() {
    $.ajax({
        url: '/ml_detector/stats',
        method: 'GET',
        success: function(response) {
            if (response.data) {
                $('#stat_total_analyzed').text(response.data.total_analyzed || 0);
                $('#stat_ads_detected').text(response.data.detections_found || response.data.ads_detected || 0);
                $('#stat_legitimate').text(response.data.legitimate_traffic || 0);
                $('#stat_accuracy').text(response.data.accuracy || '0%');
            }
        },
        error: function(xhr, status, error) {
            console.error('Error loading stats:', error);
        }
    });
}

function loadModelInfo() {
    $.ajax({
        url: '/ml_detector/model/info',
        method: 'GET',
        success: function(response) {
            console.log("ML Detector: Model info received:", response);
            if (response.data) {
                const d = response.data;
                
                $('#model_type').text(d.model_type || '-');
                $('#model_version').text(d.version || '-');
                $('#model_algorithm').text(d.algorithm || '-');
                $('#model_architecture').text(d.model_architecture || '-');
                $('#model_threshold').text(d.confidence_threshold || '-');
                $('#model_training_accuracy').text(d.training_accuracy || '-');
                $('#model_validation_accuracy').text(d.validation_accuracy || '-');
                $('#model_fpr').text(d.false_positive_rate || '-');
                $('#model_last_trained').text(d.last_trained || '-');
                $('#model_training_dataset').text(d.training_dataset || '-');
                $('#model_feature_extraction').text(d.feature_extraction || '-');
                $('#model_detection_window').text(d.detection_window || '-');
                $('#model_update_frequency').text(d.update_frequency || '-');
                
                // Parse detection_methods if it's a JSON string
                let methods = d.detection_methods;
                if (typeof methods === 'string') {
                    try {
                        methods = JSON.parse(methods);
                    } catch (e) {
                        console.warn("Failed to parse detection_methods:", e);
                        methods = [];
                    }
                }
                
                if (methods && Array.isArray(methods)) {
                    const methodsHtml = methods.map(m => 
                        `<li><i class="fa fa-check-circle text-success"></i> ${m}</li>`
                    ).join('');
                    $('#model_detection_methods').html(methodsHtml);
                }
                
                // Parse features_used if it's a JSON string
                let features = d.features_used;
                if (typeof features === 'string') {
                    try {
                        features = JSON.parse(features);
                    } catch (e) {
                        console.warn("Failed to parse features_used:", e);
                        features = [];
                    }
                }
                
                if (features && Array.isArray(features)) {
                    const featuresHtml = features.map(f => 
                        `<li class="list-group-item py-1 small"><i class="fa fa-cog text-primary"></i> ${f}</li>`
                    ).join('');
                    $('#model_features_list').html(featuresHtml);
                }
                
                console.log("ML Detector: Model info populated successfully");
            }
        },
        error: function(xhr, status, error) {
            console.error('Error loading model info:', error);
        }
    });
}

function loadDetections() {
    $.ajax({
        url: '/ml_detector/detections/recent',
        method: 'GET',
        success: function(response) {
            if (response.data && window.detectionsTable) {
                window.detectionsTable.clear();
                window.detectionsTable.rows.add(response.data);
                window.detectionsTable.draw();
            }
        },
        error: function(xhr, status, error) {
            console.error('Error loading detections:', error);
        }
    });
}

function loadAlerts() {
    // Only load if alerts table is initialized
    if (!window.alertsTable) {
        return;
    }
    
    $.ajax({
        url: '/ml_detector/alerts',
        method: 'GET',
        success: function(response) {
            if (response.data && window.alertsTable) {
                window.alertsTable.clear();
                window.alertsTable.rows.add(response.data);
                window.alertsTable.draw();
            }
        },
        error: function(xhr, status, error) {
            console.error('Error loading alerts:', error);
        }
    });
}

function loadTimeline() {
    $.ajax({
        url: '/ml_detector/detections/timeline',
        method: 'GET',
        success: function(response) {
            if (response.data && timelineChart) {
                const labels = response.data.map(d => d.time);
                const adsData = response.data.map(d => d.ads || 0);
                const legitData = response.data.map(d => d.legitimate || 0);

                timelineChart.data.labels = labels;
                timelineChart.data.datasets[0].data = adsData;
                timelineChart.data.datasets[1].data = legitData;
                timelineChart.update();
            }
        },
        error: function(xhr, status, error) {
            console.error('Error loading timeline:', error);
        }
    });
}

function loadFeatureImportance() {
    $.ajax({
        url: '/ml_detector/features/importance',
        method: 'GET',
        success: function(response) {
            if (response.data && featureChart) {
                const labels = response.data.map(d => d.feature);
                const values = response.data.map(d => d.importance);

                featureChart.data.labels = labels;
                featureChart.data.datasets[0].data = values;
                featureChart.update();
            }
        },
        error: function(xhr, status, error) {
            console.error('Error loading feature importance:', error);
        }
    });
}

