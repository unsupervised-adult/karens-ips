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

### Community Blocklists
- ✅ Integrated blocklist management with SQLite database
- ✅ **Perflyst/PiHoleBlocklist** - SmartTV, Android, FireTV tracking blocklists
- ✅ **hagezi/dns-blocklists** - Comprehensive ad/tracker blocking (Pro & Native lists)
- ✅ Automatic import during installation (300K+ domains)
- ✅ Suricata IPS-level blocking (fallback when DNS blocking fails)
- ✅ Real-time sync with Suricata datasets
- ✅ CLI management: `ips-filter import-list`, `ips-filter sync`
- ✅ Support for multiple formats (domain lists, hosts files, RPZ)

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
3. **Community Blocklists** (Perflyst + hagezi, 300K+ domains)
4. SLIPS (Stratosphere Linux IPS)
5. **ML Detector Dashboard** (automatically integrated)
6. Redis database
7. Kalipso CLI
8. SLIPS Web UI with ML Detector tab
9. SystemD services for all components

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

## Community Blocklist Integration

Karen's IPS integrates community-maintained blocklists for IPS-level ad and tracker blocking, providing a fallback when DNS-based blocking (like Pi-hole) fails or is bypassed.

### Integrated Blocklists

**Perflyst/PiHoleBlocklist**
- SmartTV blocklist - Smart TV telemetry and ads
- Android tracking - Mobile app tracking domains
- Amazon FireTV - FireTV tracking and ads
- SessionReplay - Session replay tracking scripts

**hagezi/dns-blocklists**
- Pro blocklist (recommended) - ~345K domains, balanced blocking
- Native Tracker - Native app tracking domains
- Multiple formats supported: domains, hosts, RPZ

### How It Works

1. **Installation**: Blocklists are automatically cloned and imported during installation
2. **SQLite Database**: All domains stored in `/var/lib/suricata/ips_filter.db`
3. **Suricata Integration**: Domains synced to Suricata datasets for IPS-level blocking
4. **Real-time Blocking**: Traffic to blocked domains is dropped by Suricata before reaching its destination

### Blocklist Management

```bash
# View statistics
ips-filter stats

# Import additional domain list
ips-filter import-list /path/to/domains.txt ads

# Import RPZ file
ips-filter import-rpz /path/to/blocklist.rpz malware

# Manually add domain
ips-filter add example-ad-domain.com advertising

# Sync all domains to Suricata
ips-filter sync

# Update blocklists
cd /opt/karens-ips-blocklists
cd PiHoleBlocklist && git pull && cd ..
cd dns-blocklists && git pull && cd ..
ips-filter import-list /opt/karens-ips-blocklists/PiHoleBlocklist/SmartTV.txt ads
ips-filter sync
```

### Database Schema

**blocked_domains table:**
- `domain` - Domain name (unique per source)
- `category` - ads, tracking, malware, social_media
- `source` - perflyst_smarttv, hagezi_pro, etc.
- `added_by` - Import source identifier
- `active` - Enable/disable without deletion

**Locations:**
- Database: `/var/lib/suricata/ips_filter.db`
- Blocklists: `/opt/karens-ips-blocklists/`
- Suricata datasets: `/etc/suricata/datasets/`

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