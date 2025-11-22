# Karen's IPS

An intelligent Intrusion Prevention System with ML-powered ad detection and family-friendly network security.

## Overview

Karen's IPS is a comprehensive network security solution that combines:
- **Stratosphere Linux IPS (SLIPS)** - ML-based behavioral analysis
- **Suricata** - High-performance IPS engine
- **Custom ML Ad Detector** - Machine learning-based advertisement detection
- **Real-time Dashboard** - Web-based monitoring and visualization

Built with Python and machine learning models, it offers real-time protection while maintaining ease of use for home and family networks.

## Key Features

### Core Security
- ✅ Real-time network monitoring via NFQUEUE bridge mode
- ✅ ML-based behavioral threat detection (SLIPS)
- ✅ High-performance IPS with Suricata
- ✅ Family-friendly content filtering
- ✅ Automated threat blocking via nftables

### ML Ad Detector Dashboard
- ✅ Real-time ad detection visualization
- ✅ Detection timeline charts (ads vs legitimate traffic)
- ✅ Feature importance analysis
- ✅ Model performance metrics
- ✅ Searchable/sortable detection tables
- ✅ Auto-refresh every 5 seconds
- ✅ Fully integrated with SLIPS Web UI

### Monitoring & Management
- ✅ SLIPS Web UI (browser-based dashboard)
- ✅ Kalipso CLI (terminal interface)
- ✅ SystemD service management
- ✅ Comprehensive logging
- ✅ Redis-based data backend

## Project Structure

- `src/` - Python modules and core functionality
- `slips_integration/` - ML Detector dashboard for SLIPS Web UI
  - `webinterface/ml_detector/` - Flask blueprint for ML detector
  - `patches/` - Integration patches for SLIPS
  - `install.sh` - Standalone dashboard installer
- `training/` - Data collection and model training scripts
- `deployment/` - Installation and deployment scripts
- `scripts/` - Utility scripts
- `tests/` - Unit tests
- `config/` - YAML configuration files
- `karens-ips-installer.sh` - **Complete integrated installer**

## Quick Start Installation

### Automated Installation (Recommended)

Run the complete installer that sets up everything:
```bash
sudo ./karens-ips-installer.sh
```

This installs:
1. Base system and dependencies
2. Suricata IPS (NFQUEUE bridge mode)
3. SLIPS (Stratosphere Linux IPS)
4. **ML Detector Dashboard** (automatically integrated)
5. Redis database
6. Kalipso CLI
7. SLIPS Web UI with ML Detector tab
8. SystemD services for all components

### Post-Installation

Access the dashboards:
- **SLIPS Web UI**: `http://[SERVER-IP]:55000`
- **ML Detector**: Click the "ML Detector" tab in SLIPS Web UI

Service management:
```bash
# Check all services
systemctl status redis-server suricata slips slips-webui

# Start/stop services
systemctl start slips slips-webui
systemctl stop slips slips-webui

# View logs
journalctl -fu slips
tail -f /var/log/suricata/fast.log
```

## ML Detector Dashboard

The ML Detector Dashboard is automatically integrated during installation and provides:

### Dashboard Features
- **Statistics Cards**: Total analyzed, ads detected, legitimate traffic, model accuracy
- **Detection Timeline Chart**: Real-time line chart showing ads vs legitimate traffic trends
- **Feature Importance Chart**: Horizontal bar chart of ML model feature weights
- **Model Information Panel**: Model type, version, training accuracy, features used
- **Recent Detections Table**: Searchable, sortable table of recent detections with confidence scores
- **Alerts Table**: High-priority alerts from the ML detector

### Technical Details
- **Backend**: Flask Blueprint integrated into SLIPS
- **Frontend**: Chart.js for visualizations, DataTables for data display
- **Data Storage**: Redis keys populated by ML detector module
- **Auto-refresh**: Dashboard updates every 5 seconds
- **Security**: Robust error handling, no information disclosure, input validation

### Redis Data Structure
The ML Detector uses these Redis keys:
- `ml_detector:stats` - Overall statistics (hash)
- `ml_detector:recent_detections` - Recent detections (list, max 100)
- `ml_detector:timeline` - Time-series data (list, max 1000)
- `ml_detector:model_info` - Model metadata (hash)
- `ml_detector:feature_importance` - Feature importance scores (hash)
- `ml_detector:alerts` - Alerts (list, max 50)

See [ML_DETECTOR_INTEGRATION.md](ML_DETECTOR_INTEGRATION.md) for complete integration documentation.

## Architecture

```
Internet
    ↓
[Bridge Interface: enp6s19 ↔ enp6s20]
    ↓
[NFQUEUE] → [Suricata IPS] → Block/Allow
    ↓
[Traffic Mirroring] → [SLIPS Behavioral Analysis]
    ↓
[ML Ad Detector] → [Redis] → [Web Dashboard]
```

## Configuration

Configuration files are stored in the `config/` directory as YAML files.

For SLIPS configuration, see `/opt/StratosphereLinuxIPS/config/slips.conf`.

## Testing

Run tests from the project root:
```bash
python -m pytest tests/
```

## Documentation

- [ML_DETECTOR_INTEGRATION.md](ML_DETECTOR_INTEGRATION.md) - Complete dashboard integration guide
- [slips_integration/README.md](slips_integration/README.md) - Standalone dashboard installation
- [CODE_REVIEW.md](CODE_REVIEW.md) - Security and code quality review
- [BUILD_GUIDE.md](BUILD_GUIDE.md) - Step-by-step build instructions
- [QUICK_START.md](QUICK_START.md) - Quick start guide

## License

GPL-2.0-only

## Contributors

This project integrates with [Stratosphere Linux IPS (SLIPS)](https://github.com/stratosphereips/StratosphereLinuxIPS) by Stratosphere Research Laboratory.