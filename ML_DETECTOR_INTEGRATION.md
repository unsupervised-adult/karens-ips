# ML Detector Integration with SLIPS Web Interface

## Overview

This document describes the integration of Karen's IPS ML Ad Detector with the Stratosphere Linux IPS (SLIPS) web interface.

## Architecture

The ML Detector has been integrated as a new Flask Blueprint in the SLIPS web interface, providing a unified dashboard for monitoring machine learning-based ad detection in real-time.

## Components

### 1. Flask Blueprint (`/ml_detector`)

**Location:** `StratosphereLinuxIPS/webinterface/ml_detector/`

The ML Detector blueprint provides the following API endpoints:

- **`GET /ml_detector/`** - Main ML Detector dashboard page
- **`GET /ml_detector/stats`** - Overall statistics (total analyzed, ads detected, accuracy)
- **`GET /ml_detector/detections/recent`** - Recent ad detections (last 100)
- **`GET /ml_detector/detections/timeline`** - Time-series data for charts
- **`GET /ml_detector/model/info`** - ML model information (type, version, accuracy)
- **`GET /ml_detector/features/importance`** - Feature importance scores
- **`GET /ml_detector/alerts`** - ML detector alerts (last 50)

### 2. Frontend Components

#### HTML Template
**File:** `StratosphereLinuxIPS/webinterface/ml_detector/templates/ml_detector.html`

Features:
- Statistics cards (Total Analyzed, Ads Detected, Legitimate Traffic, Accuracy)
- Detection timeline chart (Line chart)
- Feature importance chart (Horizontal bar chart)
- Model information panel
- Data tables for recent detections and alerts

#### JavaScript
**File:** `StratosphereLinuxIPS/webinterface/ml_detector/static/js/ml_detector.js`

Features:
- Chart.js integration for visualizations
- DataTables for tabular data
- Auto-refresh every 5 seconds
- AJAX calls to backend API endpoints

#### CSS
**File:** `StratosphereLinuxIPS/webinterface/ml_detector/static/css/ml_detector.css`

Custom styling for the ML Detector dashboard.

### 3. Redis Data Structure

The ML Detector stores data in Redis with the following keys:

```
ml_detector:stats                   # Hash: Overall statistics
ml_detector:recent_detections       # List: Recent detections (FIFO, max 100)
ml_detector:timeline                # List: Timeline data for charts (max 1000)
ml_detector:model_info              # Hash: Model metadata
ml_detector:feature_importance      # Hash: Feature importance scores
ml_detector:alerts                  # List: Alerts (FIFO, max 50)
```

#### Data Formats

**Stats:**
```json
{
  "total_analyzed": "1234",
  "ads_detected": "456",
  "legitimate_traffic": "778",
  "accuracy": "0.955",
  "last_update": "2025-11-22 10:30:45"
}
```

**Detection:**
```json
{
  "timestamp": "1700651445.123",
  "src_ip": "192.168.1.100",
  "dst_ip": "8.8.8.8",
  "dst_port": "443",
  "protocol": "TCP",
  "classification": "ad",
  "confidence": "0.95",
  "total_bytes": "1024",
  "total_packets": "10"
}
```

**Timeline Entry:**
```json
{
  "time": "10:30",
  "ads": 15,
  "legitimate": 85
}
```

**Alert:**
```json
{
  "timestamp": "1700651445.123",
  "alert_type": "High Volume Ad Traffic",
  "severity": "high",
  "src_ip": "192.168.1.100",
  "description": "Detected unusually high volume of ad requests",
  "confidence": "0.92"
}
```

## Integration Points

### 1. Main Application (`app.py`)

The ML Detector blueprint is registered in the main application:

```python
from .ml_detector.ml_detector import ml_detector

app.register_blueprint(ml_detector, url_prefix="/ml_detector")
```

### 2. Main Template (`app.html`)

The ML Detector tab is added to the navigation:

```html
<li class="nav-item">
  <a class="nav-link" type="button" id="nav-ml-detector-tab"
     data-bs-toggle="tab" data-bs-target="#nav-ml-detector" role="tab">
    ML Detector
  </a>
</li>
```

And the tab content:

```html
<div class="tab-pane fade" id="nav-ml-detector" role="tabpanel">
  {% include 'ml_detector.html' %}
</div>
```

### 3. Dependencies

- **Chart.js** (v4.4.0) - Added for chart visualizations
- **jQuery** - Already included in SLIPS
- **DataTables** - Already included in SLIPS
- **Bootstrap 5** - Already included in SLIPS

## Usage

### Starting the Web Interface

The ML Detector is automatically available when you start the SLIPS web interface:

```bash
cd StratosphereLinuxIPS
./webinterface.sh
```

Or directly:

```bash
python3 -m webinterface.app
```

### Accessing the Dashboard

1. Open your browser to the SLIPS web interface (default: `http://localhost:55000`)
2. Click on the "ML Detector" tab
3. The dashboard will load and auto-refresh every 5 seconds

## Data Flow

1. **Karen's IPS ML Detector** → Analyzes traffic and classifies ads
2. **ML Detector Module** → Writes results to Redis
3. **Flask Blueprint** → Reads from Redis and serves via API
4. **JavaScript Frontend** → Fetches data and updates visualizations

## Future Enhancements

- [ ] Real-time WebSocket updates instead of polling
- [ ] Advanced filtering and search capabilities
- [ ] Export data to CSV/JSON
- [ ] Configurable alert thresholds
- [ ] Historical data visualization (beyond current session)
- [ ] Integration with SLIPS alerting system
- [ ] Model retraining interface
- [ ] A/B testing for multiple models

## Troubleshooting

### Dashboard shows "0" for all stats

- Verify Redis is running and accessible
- Check that the ML Detector module is writing to Redis
- Verify Redis key structure matches expected format

### Charts not rendering

- Check browser console for JavaScript errors
- Verify Chart.js library is loaded
- Ensure data format from API matches expected structure

### Tables not updating

- Check network tab for failed API calls
- Verify Flask routes are properly registered
- Check Redis data is in correct JSON format

## License

SPDX-License-Identifier: GPL-2.0-only
