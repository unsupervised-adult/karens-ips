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

                // Core Configuration
                $('#model_type').text(d.model_type || '-');
                $('#model_version').text(d.version || '-');
                $('#model_algorithm').text('SLIPS Behavioral Analysis');
                $('#model_architecture').text('Real-time Stream Processing');
                $('#model_threshold').text('Dynamic (Evidence-based)');

                // Performance Metrics
                $('#model_training_accuracy').text(d.training_accuracy || d.accuracy || '-');
                $('#model_validation_accuracy').text('-');
                $('#model_fpr').text('-');
                $('#model_last_trained').text(d.last_trained || '-');
                $('#model_training_dataset').text('-');

                // Feature Extraction Details
                $('#model_feature_extraction').text('Zeek Network Flows');
                $('#model_detection_window').text('Real-time (continuous)');
                $('#model_update_frequency').text('Live streaming analysis');

                // Detection Methods - parse from 'features' field
                const features = d.features || 'Real-time behavioral analysis, Flow monitoring, Evidence correlation';
                if (typeof features === 'string') {
                    const featuresList = features.split(',').map(f =>
                        `<li><i class="fa fa-check-circle text-success"></i> ${f.trim()}</li>`
                    ).join('');
                    $('#model_detection_methods').html(featuresList);
                } else if (Array.isArray(features)) {
                    const methodsHtml = features.map(m =>
                        `<li><i class="fa fa-check-circle text-success"></i> ${m}</li>`
                    ).join('');
                    $('#model_detection_methods').html(methodsHtml);
                }

                // Features Used - from 'features_used' field
                const featuresUsed = d.features_used || 'Flow patterns, connection duration, data transfer, domain analysis';
                if (typeof featuresUsed === 'string') {
                    // Split comma-separated string into list items
                    const featureItems = featuresUsed.split(',').map(f =>
                        `<li class="list-group-item py-1 small"><i class="fa fa-cog text-primary"></i> ${f.trim()}</li>`
                    ).join('');
                    $('#model_features_list').html(featureItems);
                } else if (Array.isArray(featuresUsed)) {
                    const featuresHtml = featuresUsed.map(f =>
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

let currentConfig = {};

function loadSettings() {
    $.ajax({
        url: '/ml_detector/settings',
        method: 'GET',
        success: function(config) {
            currentConfig = config;
            populateForm(config);
        },
        error: function(xhr, status, error) {
            console.error('Error loading settings:', error);
            showStatus('Failed to load settings', 'danger');
        }
    });
}

function populateForm(config) {
    const dt = config.detection_thresholds || {};
    const pd = config.protocol_detection || {};
    const ml = config.ml_parameters || {};
    
    $('#streaming_min_duration').val(dt.streaming_min_duration || 120);
    $('#ad_duration_min').val(dt.ad_duration_min || 5);
    $('#ad_duration_max').val(dt.ad_duration_max || 120);
    
    $('#streaming_min_bytes').val(dt.streaming_min_bytes || 15000);
    $('#streaming_min_packets').val(dt.streaming_min_packets || 20);
    $('#ad_min_bytes').val(dt.ad_min_bytes || 5000);
    
    const durationRatio = dt.duration_ratio_threshold || 0.3;
    $('#duration_ratio_threshold').val(durationRatio);
    $('#duration_ratio_value').text(Math.round(durationRatio * 100) + '%');
    
    const confidence = dt.confidence_threshold || 0.75;
    $('#confidence_threshold').val(confidence);
    $('#confidence_value').text(Math.round(confidence * 100) + '%');
    
    $('#enable_quic_detection').prop('checked', pd.enable_quic_detection !== false);
    $('#enable_encrypted_analysis').prop('checked', pd.enable_encrypted_analysis !== false);
    $('#analyze_timing_patterns').prop('checked', pd.analyze_timing_patterns !== false);
    $('#analyze_packet_sizes').prop('checked', pd.analyze_packet_sizes !== false);
    
    $('#n_estimators').val(ml.n_estimators || 100);
    $('#max_depth').val(ml.max_depth || 15);
    $('#model_type_select').val(ml.model_type || 'random_forest');
    $('#cpu_cores').val(ml.n_jobs || -1);
    $('#auto_retrain').prop('checked', ml.auto_retrain || false);
    $('#retrain_interval').val(ml.retrain_interval_hours || 24);
    $('#min_training_samples').val(ml.min_samples_for_training || 100);
    
    const perf = config.performance || {};
    $('#cache_predictions').prop('checked', perf.cache_predictions !== false);
}

$('#duration_ratio_threshold').on('input', function() {
    $('#duration_ratio_value').text(Math.round($(this).val() * 100) + '%');
});

$('#confidence_threshold').on('input', function() {
    $('#confidence_value').text(Math.round($(this).val() * 100) + '%');
});

function saveSettings() {
    const config = {
        detection_thresholds: {
            streaming_min_duration: parseFloat($('#streaming_min_duration').val()),
            ad_duration_min: parseFloat($('#ad_duration_min').val()),
            ad_duration_max: parseFloat($('#ad_duration_max').val()),
            streaming_min_bytes: parseInt($('#streaming_min_bytes').val()),
            streaming_min_packets: parseInt($('#streaming_min_packets').val()),
            ad_min_bytes: parseInt($('#ad_min_bytes').val()),
            duration_ratio_threshold: parseFloat($('#duration_ratio_threshold').val()),
            confidence_threshold: parseFloat($('#confidence_threshold').val())
        },
        protocol_detection: {
            enable_quic_detection: $('#enable_quic_detection').is(':checked'),
            enable_encrypted_analysis: $('#enable_encrypted_analysis').is(':checked'),
            analyze_timing_patterns: $('#analyze_timing_patterns').is(':checked'),
            analyze_packet_sizes: $('#analyze_packet_sizes').is(':checked')
        },
        ml_parameters: {
            n_estimators: parseInt($('#n_estimators').val()),
            max_depth: parseInt($('#max_depth').val()),
            model_type: $('#model_type_select').val(),
            n_jobs: parseInt($('#cpu_cores').val()),
            auto_retrain: $('#auto_retrain').is(':checked'),
            retrain_interval_hours: parseInt($('#retrain_interval').val()),
            min_samples_for_training: parseInt($('#min_training_samples').val())
        },
        feature_weights: currentConfig.feature_weights || {},
        performance: {
            cpu_cores: parseInt($('#cpu_cores').val()),
            cache_predictions: $('#cache_predictions').is(':checked')
        }
    };

    showStatus('Saving configuration...', 'info');
    
    $.ajax({
        url: '/ml_detector/settings',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(config),
        success: function(data) {
            if (data.success) {
                showStatus('Configuration saved and monitor restarted', 'success');
                currentConfig = config;
            } else {
                showStatus('Failed to save: ' + data.error, 'danger');
            }
        },
        error: function(xhr, status, error) {
            console.error('Error saving settings:', error);
            showStatus('Failed to save configuration', 'danger');
        }
    });
}

function applyPreset(presetName) {
    showStatus(`Applying ${presetName} preset...`, 'info');
    
    $.ajax({
        url: `/ml_detector/settings/preset/${presetName}`,
        method: 'POST',
        success: function(data) {
            if (data.success) {
                showStatus(`${presetName} preset applied`, 'success');
                loadSettings();
            } else {
                showStatus('Failed to apply preset: ' + data.error, 'danger');
            }
        },
        error: function(xhr, status, error) {
            console.error('Error applying preset:', error);
            showStatus('Failed to apply preset', 'danger');
        }
    });
}

function restartMonitor() {
    showStatus('Restarting monitor service...', 'info');
    
    $.ajax({
        url: '/ml_detector/settings',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(currentConfig),
        success: function(data) {
            if (data.success) {
                showStatus('Monitor service restarted', 'success');
            } else {
                showStatus('Failed to restart: ' + data.error, 'danger');
            }
        },
        error: function(xhr, status, error) {
            console.error('Error restarting monitor:', error);
            showStatus('Failed to restart monitor', 'danger');
        }
    });
}

function showStatus(message, type) {
    const statusDiv = $('#config_status');
    statusDiv.html(`<div class="alert alert-${type} alert-dismissible fade show" role="alert">
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>`);

    if (type === 'success') {
        setTimeout(() => {
            statusDiv.html('');
        }, 5000);
    }
}

// ========== Alerts & Actions Tab Functions ==========

function loadBlockingStatus() {
    $.getJSON('/ml_detector/blocking/status', function(response) {
        if (response.data) {
            const enabled = response.data.enabled;
            $('#live_blocking_toggle').prop('checked', enabled);

            if (enabled) {
                $('#blocking_status').html('<span class="badge bg-success">Active</span>');
                $('#blocking_status_message').html(
                    '<div class="alert alert-success">' +
                    '<i class="fa fa-shield"></i> Live blocking is ENABLED. Detected threats will be automatically blocked.' +
                    '</div>'
                );
            } else {
                $('#blocking_status').html('<span class="badge bg-danger">Disabled</span>');
                $('#blocking_status_message').html(
                    '<div class="alert alert-warning">' +
                    '<i class="fa fa-exclamation-triangle"></i> Live blocking is DISABLED. Threats will only be logged, not blocked.' +
                    '</div>'
                );
            }
        }
    }).fail(function() {
        $('#blocking_status').html('<span class="badge bg-secondary">Unknown</span>');
        $('#blocking_status_message').html(
            '<div class="alert alert-danger">Failed to check blocking status</div>'
        );
    });
}

function toggleBlocking() {
    const enabled = $('#live_blocking_toggle').is(':checked');

    $.ajax({
        url: '/ml_detector/blocking/status',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ enabled: enabled }),
        success: function(response) {
            loadBlockingStatus();
            const message = enabled ?
                '<div class="alert alert-success">Live blocking ENABLED</div>' :
                '<div class="alert alert-warning">Live blocking DISABLED</div>';
            $('#blocking_status_message').html(message);
        },
        error: function(xhr, status, error) {
            // Revert toggle on error
            $('#live_blocking_toggle').prop('checked', !enabled);
            $('#blocking_status_message').html(
                '<div class="alert alert-danger">Failed to update blocking status: ' + error + '</div>'
            );
        }
    });
}

function loadWhitelist() {
    $.getJSON('/ml_detector/whitelist', function(response) {
        if (response.data) {
            const ips = response.data.ips || [];
            const urls = response.data.urls || [];

            if (ips.length === 0 && urls.length === 0) {
                $('#whitelist_items').html('<div class="text-muted small">No whitelisted IPs or URLs</div>');
                return;
            }

            let html = '';

            // Display IPs
            ips.forEach(ip => {
                html += '<div class="list-group-item d-flex justify-content-between align-items-center">' +
                    '<span><i class="fa fa-shield text-success"></i> <strong>IP:</strong> ' + ip + '</span>' +
                    '<button class="btn btn-sm btn-outline-danger remove-whitelist" data-value="' + ip + '" data-type="ip">' +
                    '<i class="fa fa-times"></i> Remove</button>' +
                    '</div>';
            });

            // Display URLs
            urls.forEach(url => {
                html += '<div class="list-group-item d-flex justify-content-between align-items-center">' +
                    '<span><i class="fa fa-shield text-success"></i> <strong>URL:</strong> ' + url + '</span>' +
                    '<button class="btn btn-sm btn-outline-danger remove-whitelist" data-value="' + url + '" data-type="url">' +
                    '<i class="fa fa-times"></i> Remove</button>' +
                    '</div>';
            });

            $('#whitelist_items').html(html);
        } else {
            $('#whitelist_items').html('<div class="text-muted small">No whitelisted IPs or URLs</div>');
        }
    });
}

function addWhitelist() {
    const ip = $('#whitelist_ip').val().trim();
    const url = $('#whitelist_url').val().trim();

    if (!ip && !url) {
        alert('Please enter an IP address or URL');
        return;
    }

    let data = {};
    let entryLabel = '';
    let entryType = '';

    if (ip) {
        // Basic IP validation
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
        if (!ipPattern.test(ip)) {
            alert('Invalid IP address format');
            return;
        }
        data = { ip: ip, type: 'ip' };
        entryLabel = 'IP ' + ip;
        entryType = 'ip';
    } else if (url) {
        // Basic URL validation
        if (url.length < 3 || url.includes(' ')) {
            alert('Invalid URL format');
            return;
        }
        data = { url: url, type: 'url' };
        entryLabel = 'URL ' + url;
        entryType = 'url';
    }

    $.ajax({
        url: '/ml_detector/whitelist',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(data),
        success: function(response) {
            $('#whitelist_ip').val('');
            $('#whitelist_url').val('');
            loadWhitelist();
            $('#action_status').html('<div class="alert alert-success">Added ' + entryLabel + ' to whitelist</div>');
            setTimeout(() => $('#action_status').html(''), 3000);
        },
        error: function(xhr, status, error) {
            alert('Failed to add to whitelist: ' + error);
        }
    });
}

function removeWhitelist(value, type) {
    const entryLabel = type === 'url' ? 'URL ' + value : 'IP ' + value;
    if (confirm('Remove ' + entryLabel + ' from whitelist?')) {
        const data = type === 'url' ? { url: value, type: 'url' } : { ip: value, type: 'ip' };
        $.ajax({
            url: '/ml_detector/whitelist',
            method: 'DELETE',
            contentType: 'application/json',
            data: JSON.stringify(data),
            success: function(response) {
                loadWhitelist();
                $('#action_status').html('<div class="alert alert-info">Removed ' + entryLabel + ' from whitelist</div>');
                setTimeout(() => $('#action_status').html(''), 3000);
            },
            error: function(xhr, status, error) {
                alert('Failed to remove from whitelist: ' + error);
            }
        });
    }
}

function loadBlacklist() {
    $.getJSON('/ml_detector/blacklist', function(response) {
        if (response.data) {
            const ips = response.data.ips || [];
            const urls = response.data.urls || [];

            if (ips.length === 0 && urls.length === 0) {
                $('#blacklist_items').html('<div class="text-muted small">No blocked IPs or URLs</div>');
                return;
            }

            let html = '';

            // Display IPs
            ips.forEach(ip => {
                html += '<div class="list-group-item d-flex justify-content-between align-items-center">' +
                    '<span><i class="fa fa-ban text-danger"></i> <strong>IP:</strong> ' + ip + '</span>' +
                    '<button class="btn btn-sm btn-outline-success remove-blacklist" data-value="' + ip + '" data-type="ip">' +
                    '<i class="fa fa-times"></i> Unblock</button>' +
                    '</div>';
            });

            // Display URLs
            urls.forEach(url => {
                html += '<div class="list-group-item d-flex justify-content-between align-items-center">' +
                    '<span><i class="fa fa-ban text-danger"></i> <strong>URL:</strong> ' + url + '</span>' +
                    '<button class="btn btn-sm btn-outline-success remove-blacklist" data-value="' + url + '" data-type="url">' +
                    '<i class="fa fa-times"></i> Unblock</button>' +
                    '</div>';
            });

            $('#blacklist_items').html(html);
        } else {
            $('#blacklist_items').html('<div class="text-muted small">No blocked IPs or URLs</div>');
        }
    });
}

function addBlacklist() {
    const ip = $('#blacklist_ip').val().trim();
    const url = $('#blacklist_url').val().trim();

    if (!ip && !url) {
        alert('Please enter an IP address or URL');
        return;
    }

    let data = {};
    let entryLabel = '';
    let entryType = '';

    if (ip) {
        // Basic IP validation
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
        if (!ipPattern.test(ip)) {
            alert('Invalid IP address format');
            return;
        }
        data = { ip: ip, type: 'ip' };
        entryLabel = 'IP ' + ip;
        entryType = 'ip';
    } else if (url) {
        // Basic URL validation
        if (url.length < 3 || url.includes(' ')) {
            alert('Invalid URL format');
            return;
        }
        data = { url: url, type: 'url' };
        entryLabel = 'URL ' + url;
        entryType = 'url';
    }

    if (confirm('Block all traffic from ' + entryLabel + '?')) {
        $.ajax({
            url: '/ml_detector/blacklist',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(data),
            success: function(response) {
                $('#blacklist_ip').val('');
                $('#blacklist_url').val('');
                loadBlacklist();
                $('#action_status').html('<div class="alert alert-success">Blocked ' + entryLabel + '</div>');
                setTimeout(() => $('#action_status').html(''), 3000);
            },
            error: function(xhr, status, error) {
                alert('Failed to block: ' + error);
            }
        });
    }
}

function removeBlacklist(value, type) {
    const entryLabel = type === 'url' ? 'URL ' + value : 'IP ' + value;
    if (confirm('Unblock ' + entryLabel + '?')) {
        const data = type === 'url' ? { url: value, type: 'url' } : { ip: value, type: 'ip' };
        $.ajax({
            url: '/ml_detector/blacklist',
            method: 'DELETE',
            contentType: 'application/json',
            data: JSON.stringify(data),
            success: function(response) {
                loadBlacklist();
                $('#action_status').html('<div class="alert alert-info">Unblocked ' + entryLabel + '</div>');
                setTimeout(() => $('#action_status').html(''), 3000);
            },
            error: function(xhr, status, error) {
                alert('Failed to unblock: ' + error);
            }
        });
    }
}

function loadFeedbackTable() {
    if ($.fn.DataTable.isDataTable('#feedback_table')) {
        $('#feedback_table').DataTable().destroy();
    }

    $('#feedback_table').DataTable({
        ajax: {
            url: '/ml_detector/detections/recent',
            dataSrc: 'data'
        },
        columns: [
            {
                data: 'timestamp',
                render: function(data) {
                    return new Date(data).toLocaleString();
                }
            },
            { data: 'source_ip' },
            {
                data: 'classification',
                render: function(data) {
                    return '<span class="badge bg-danger">' + data + '</span>';
                }
            },
            {
                data: 'confidence',
                render: function(data) {
                    const percent = (data * 100).toFixed(1);
                    return percent + '%';
                }
            },
            {
                data: null,
                render: function(data, type, row) {
                    return '<div class="btn-group btn-group-sm" role="group">' +
                        '<button class="btn btn-outline-success feedback-correct" data-detection=\'' +
                        JSON.stringify(row) + '\'>' +
                        '<i class="fa fa-check"></i> Correct</button>' +
                        '<button class="btn btn-outline-danger feedback-false" data-detection=\'' +
                        JSON.stringify(row) + '\'>' +
                        '<i class="fa fa-times"></i> False Positive</button>' +
                        '</div>';
                }
            }
        ],
        order: [[0, 'desc']],
        pageLength: 10,
        language: {
            emptyTable: 'No recent detections available for feedback'
        }
    });
}

function submitFeedback(detection, feedback) {
    $.ajax({
        url: '/ml_detector/feedback',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            detection: detection,
            feedback: feedback,
            source_ip: detection.source_ip,
            classification: detection.classification
        }),
        success: function(response) {
            const message = feedback === 'correct' ?
                '<div class="alert alert-success">Feedback recorded: True positive confirmed</div>' :
                '<div class="alert alert-warning">Feedback recorded: False positive marked. Model will be retrained.</div>';
            $('#action_status').html(message);
            setTimeout(() => $('#action_status').html(''), 3000);
        },
        error: function(xhr, status, error) {
            alert('Failed to submit feedback: ' + error);
        }
    });
}

function clearAllBlocks() {
    if (confirm('Clear ALL firewall blocks? This will remove all blocked IPs.')) {
        $.ajax({
            url: '/ml_detector/actions/clear_blocks',
            method: 'POST',
            success: function(response) {
                loadBlacklist();
                $('#action_status').html(
                    '<div class="alert alert-success">All blocks cleared successfully</div>'
                );
                setTimeout(() => $('#action_status').html(''), 3000);
            },
            error: function(xhr, status, error) {
                $('#action_status').html(
                    '<div class="alert alert-danger">Failed to clear blocks: ' + error + '</div>'
                );
            }
        });
    }
}

function retrainModel() {
    if (confirm('Force immediate model retraining? This may take several minutes.')) {
        const btn = $('#btn_retrain_model');
        btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Retraining...');

        $.ajax({
            url: '/ml_detector/actions/retrain',
            method: 'POST',
            success: function(response) {
                btn.prop('disabled', false).html('Retrain Model Now');
                $('#action_status').html(
                    '<div class="alert alert-success">Model retrained successfully</div>'
                );
                setTimeout(() => $('#action_status').html(''), 3000);
                loadModelInfo();
            },
            error: function(xhr, status, error) {
                btn.prop('disabled', false).html('Retrain Model Now');
                $('#action_status').html(
                    '<div class="alert alert-danger">Failed to retrain model: ' + error + '</div>'
                );
            }
        });
    }
}

function exportDetections() {
    window.location.href = '/ml_detector/actions/export';
}

function viewLogs() {
    $.ajax({
        url: '/ml_detector/actions/logs',
        method: 'GET',
        success: function(response) {
            if (response.data) {
                const logs = response.data.logs || [];
                const logsHtml = logs.map(log =>
                    '<div class="mb-2 p-2 border-bottom">' +
                    '<small class="text-muted">' + log.timestamp + '</small><br>' +
                    '<code>' + log.message + '</code>' +
                    '</div>'
                ).join('');

                $('#action_status').html(
                    '<div class="card mt-3">' +
                    '<div class="card-header">Recent System Logs</div>' +
                    '<div class="card-body" style="max-height: 400px; overflow-y: auto;">' +
                    (logs.length > 0 ? logsHtml : '<p class="text-muted">No recent logs</p>') +
                    '</div>' +
                    '</div>'
                );
            }
        },
        error: function(xhr, status, error) {
            $('#action_status').html(
                '<div class="alert alert-danger">Failed to load logs: ' + error + '</div>'
            );
        }
    });
}

$(document).ready(function() {
    loadSettings();

    $('#btn_save_config').on('click', saveSettings);
    $('#btn_reset_config').on('click', loadSettings);
    $('#btn_restart_service').on('click', restartMonitor);

    $('#preset_aggressive').on('click', () => applyPreset('aggressive'));
    $('#preset_conservative').on('click', () => applyPreset('conservative'));
    $('#preset_short_videos').on('click', () => applyPreset('short_videos'));
    $('#preset_quic').on('click', () => applyPreset('quic_optimized'));

    // Alerts & Actions event handlers
    $('#live_blocking_toggle').on('change', toggleBlocking);
    $('#btn_add_whitelist').on('click', addWhitelist);
    $('#btn_add_blacklist').on('click', addBlacklist);
    $(document).on('click', '.remove-whitelist', function() {
        removeWhitelist($(this).data('value'), $(this).data('type'));
    });
    $(document).on('click', '.remove-blacklist', function() {
        removeBlacklist($(this).data('value'), $(this).data('type'));
    });
    $(document).on('click', '.feedback-correct', function() {
        const detection = JSON.parse($(this).attr('data-detection'));
        submitFeedback(detection, 'correct');
    });
    $(document).on('click', '.feedback-false', function() {
        const detection = JSON.parse($(this).attr('data-detection'));
        submitFeedback(detection, 'false_positive');
    });
    $('#btn_clear_blocks').on('click', clearAllBlocks);
    $('#btn_retrain_model').on('click', retrainModel);
    $('#btn_export_detections').on('click', exportDetections);
    $('#btn_view_logs').on('click', viewLogs);

    // Load Alerts & Actions data when tab is shown
    $('#alerts-tab').on('shown.bs.tab', function() {
        loadBlockingStatus();
        loadWhitelist();
        loadBlacklist();
        loadFeedbackTable();
    });
});

