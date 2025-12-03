# SLIPS Web UI Integration

This directory contains the integration components for extending the Stratosphere Linux IPS (SLIPS) web interface with Karen's IPS ML Ad Detector.

## Overview

The integration adds a new "ML Detector" tab to the SLIPS web interface, providing real-time visualization of machine learning-based ad detection.

## Directory Structure

```
slips_integration/
├── README.md                      # This file
├── install.sh                     # Automated installation script

└── webinterface/
    └── ml_detector/               # ML Detector Flask Blueprint
        ├── __init__.py
        ├── ml_detector.py         # Backend routes and API endpoints
        ├── templates/
        │   └── ml_detector.html   # Frontend dashboard template
        └── static/
            ├── js/
            │   └── ml_detector.js # JavaScript for charts and tables
            └── css/
                └── ml_detector.css # Custom styling
```

## Installation

### Automated Installation

1. Clone or navigate to the StratosphereLinuxIPS repository:

   ```bash
   git clone https://github.com/stratosphereips/StratosphereLinuxIPS.git
   cd StratosphereLinuxIPS
   ```

2. Run the installation script from the Karen's IPS repository:

   ```bash
   /path/to/karens-ips/slips_integration/install.sh /path/to/StratosphereLinuxIPS
   ```

3. The script will:
   - Validate the SLIPS installation
   - Create a backup of the webinterface directory
   - Copy the ML Detector blueprint
   - Install pre-modified SLIPS core files with ML Detector integration

### Manual Installation

If you prefer to install manually:

1. **Copy the ML Detector blueprint:**

   ```bash
   cp -r slips_integration/webinterface/ml_detector /path/to/StratosphereLinuxIPS/webinterface/
   ```

2. **Modify `webinterface/app.py`:**

   Add the import:

   ```python
   from .ml_detector.ml_detector import ml_detector
   ```

   Register the blueprint:

   ```python
   app.register_blueprint(ml_detector, url_prefix="/ml_detector")
   ```

3. **Modify `webinterface/templates/app.html`:**

   - Add CSS link in the `<head>` section:

     ```html
     <link rel="stylesheet" type="text/css" href="{{url_for('ml_detector.static', filename='css/ml_detector.css')}}" />
     ```

   - Add navigation tab:

     ```html
     <li class="nav-item">
       <a class="nav-link" type="button" id="nav-ml-detector-tab" data-bs-toggle="tab"
          data-bs-target="#nav-ml-detector" role="tab">
         ML Detector
       </a>
     </li>
     ```

   - Add tab content:

     ```html
     <div class="tab-pane fade" id="nav-ml-detector" role="tabpanel">
       {% include 'ml_detector.html' %}
     </div>
     ```

   - Add Chart.js library before closing `</body>`:

     ```html
     <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
     ```

   - Add ML Detector JavaScript:

     ```html
     <script src="{{url_for('ml_detector.static', filename='js/ml_detector.js')}}"></script>
     ```

## Usage

1. **Start SLIPS with your traffic source:**

   ```bash
   ./slips.py -c config/slips.yaml -f /path/to/pcap
   ```

2. **Start the web interface:**

   ```bash
   ./webinterface.sh
   ```

   Or manually:

   ```bash
   python3 -m webinterface.app
   ```

3. **Access the dashboard:**
   - Open browser to `http://localhost:55000`
   - Click the "ML Detector" tab
   - Dashboard auto-refreshes every 5 seconds

## API Endpoints

The ML Detector blueprint provides the following REST API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ml_detector/` | GET | Main dashboard page |
| `/ml_detector/stats` | GET | Overall statistics |
| `/ml_detector/detections/recent` | GET | Recent detections (last 100) |
| `/ml_detector/detections/timeline` | GET | Time-series data for charts |
| `/ml_detector/model/info` | GET | ML model metadata |
| `/ml_detector/features/importance` | GET | Feature importance scores |
| `/ml_detector/alerts` | GET | Recent alerts (last 50) |

## Redis Data Structure

The ML Detector reads from the following Redis keys (populated by the Karen's IPS ML detector module):

```
ml_detector:stats                   # Hash: Overall statistics
ml_detector:recent_detections       # List: Recent detections
ml_detector:timeline                # List: Timeline data
ml_detector:model_info              # Hash: Model information
ml_detector:feature_importance      # Hash: Feature importance scores
ml_detector:alerts                  # List: Alerts
```

See [ML_DETECTOR_INTEGRATION.md](../ML_DETECTOR_INTEGRATION.md) for detailed data formats.

## Dashboard Features

### Statistics Cards

- Total traffic analyzed
- Advertisements detected
- Legitimate traffic
- Model accuracy

### Visualizations

- **Detection Timeline Chart**: Line chart showing ads vs legitimate traffic over time
- **Feature Importance Chart**: Horizontal bar chart of ML model features

### Data Tables

- **Recent Detections**: Searchable, sortable table of detected traffic
- **Alerts**: High-priority alerts from the ML detector

### Model Information

- Model type and version
- Training accuracy
- Features used
- Last training date

## Troubleshooting

### Dashboard shows no data

**Problem**: All statistics show 0, tables are empty

**Solutions**:

1. Verify Redis is running:

   ```bash
   redis-cli ping
   ```

2. Check that Karen's IPS ML detector is writing to Redis:

   ```bash
   redis-cli HGETALL ml_detector:stats
   ```

3. Verify the web interface is connecting to the correct Redis instance

### Charts not rendering

**Problem**: Charts are blank or showing errors

**Solutions**:

1. Check browser console for JavaScript errors (F12)
2. Verify Chart.js is loaded (check Network tab)
3. Ensure timeline data format is correct

### File installation failed

**Problem**: Installation script reports missing source files

**Solution**:

1. Ensure slips_integration/webinterface directory contains app.py and templates/app.html
2. Verify the repository clone is complete
3. Check SLIPS version compatibility

## Dependencies

- **SLIPS**: Stratosphere Linux IPS (tested with v1.1.15)
- **Python**: 3.8+
- **Flask**: Already included with SLIPS
- **Redis**: Already used by SLIPS
- **Chart.js**: v4.4.0 (loaded via CDN)
- **jQuery**: Already included with SLIPS
- **DataTables**: Already included with SLIPS
- **Bootstrap 5**: Already included with SLIPS

## Uninstallation

To remove the ML Detector integration:

1. Restore from backup:

   ```bash
   rm -rf /path/to/StratosphereLinuxIPS/webinterface
   cp -r /path/to/backup /path/to/StratosphereLinuxIPS/webinterface
   ```

2. Or manually:

   ```bash
   rm -rf /path/to/StratosphereLinuxIPS/webinterface/ml_detector
   ```

   Then revert changes to `app.py` and `app.html`

## License

SPDX-License-Identifier: GPL-2.0-only

## Support

For issues and questions:

- Create an issue in the Karen's IPS repository
- Refer to the main integration documentation: [ML_DETECTOR_INTEGRATION.md](../ML_DETECTOR_INTEGRATION.md)
