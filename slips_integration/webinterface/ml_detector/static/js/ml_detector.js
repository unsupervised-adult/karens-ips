// SPDX-FileCopyrightText: 2025 Karen's IPS ML Ad Detector
// SPDX-License-Identifier: GPL-2.0-only

(function($) {
    'use strict';

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
$(document).ready(function() {
    // Initialize when ML Detector tab is shown
    $('#nav-ml-detector-tab').on('shown.bs.tab', function (e) {
        console.log("ML Detector: Tab shown, initializing...");
        initializeMLDetector();
    });
    
    // If ML Detector tab is active on page load, initialize immediately
    if ($('#nav-ml-detector').hasClass('active')) {
        initializeMLDetector();
    }
});

// Cleanup on page unload
$(window).on('beforeunload', function() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
});

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
                    const badge = data === 'ad' ? 'danger' : 'success';
                    const text = data === 'ad' ? 'Advertisement' : 'Legitimate';
                    return `<span class="badge bg-${badge}">${text}</span>`;
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
            { data: 'total_bytes', defaultContent: '0' },
            { data: 'total_packets', defaultContent: '0' }
        ],
        order: [[0, 'desc']],
        pageLength: 25,
        searching: true,
        lengthChange: true
    });

    // Alerts Table
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
        lengthChange: true
    });
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
            if (response.data) {
                $('#model_type').text(response.data.model_type || '-');
                $('#model_version').text(response.data.version || '-');
                $('#model_accuracy').text(response.data.training_accuracy || '-');
                $('#model_last_trained').text(response.data.last_trained || '-');
                $('#model_features').text(response.data.features_used || '-');
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

})(window.jQuery || window.$);
