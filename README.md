# Karen's IPS

```
════════════════════════════════════════════════════════════════════════════════
██╗  ██╗ █████╗ ██████╗ ███████╗███╗   ██╗██╗███████╗    ██╗██████╗ ███████╗
██║ ██╔╝██╔══██╗██╔══██╗██╔════╝████╗  ██║╚═╝██╔════╝    ██║██╔══██╗██╔════╝
█████╔╝ ███████║██████╔╝█████╗  ██╔██╗ ██║   ███████╗    ██║██████╔╝███████╗
██╔═██╗ ██╔══██║██╔══██╗██╔══╝  ██║╚██╗██║   ╚════██║    ██║██╔═══╝ ╚════██║
██║  ██╗██║  ██║██║  ██║███████╗██║ ╚████║   ███████║    ██║██║     ███████║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚══════╝    ╚═╝╚═╝     ╚══════╝
════════════════════════════════════════════════════════════════════════════════
           Intrusion Prevention System - ML Behavioral Analysis
```

An intelligent Intrusion Prevention System with ML-powered behavioral analysis, community blocklists, and family-friendly network security.

## Overview

Karen's IPS is a comprehensive network security solution that combines:

- **Stratosphere Linux IPS (SLIPS)** - ML-based behavioral threat analysis
- **Suricata** - High-performance IPS engine with NFQUEUE integration
- **Custom ML Detector Dashboard** - Real-time ad detection visualization
- **Community Blocklists** - 300K+ domains from Perflyst and hagezi
- **Modular Installer** - Easy deployment and maintenance

Built with Python, machine learning, and modern security tools, it offers enterprise-grade protection for home and family networks.

**System Performance:**

- Load Average: 5.91 (normal for ML processing)
- Services: All critical services active (suricata, slips, redis, ml-detector-bridge)
- Memory Usage: ~6GB total across all components
- Traffic Processing: Real-time NFQUEUE packet processing
- ML Analysis: 12% ad detection rate with 94.2% accuracy

## Key Features

### Core Security

- ✅ Real-time network monitoring via NFQUEUE bridge mode
- ✅ ML-based behavioral threat detection (SLIPS)
- ✅ High-performance IPS with Suricata (drop/reject capabilities)
- ✅ Family-friendly content filtering
- ✅ Automated threat blocking via nftables
- ✅ Zeek network security monitor integration

### Community Blocklists (300K+ Domains)

- ✅ **Perflyst/PiHoleBlocklist** - SmartTV, Android, FireTV tracking
- ✅ **hagezi/dns-blocklists** - Pro & Native tracker blocking
- ✅ Automatic weekly updates via systemd timer
- ✅ Exception management (whitelist) for domains and IPs
- ✅ IPS-level blocking (bypasses DNS-based ad blockers)
- ✅ Real-time sync with Suricata datasets
- ✅ YAML configuration for customization
- ✅ CLI management: `ips-filter update-blocklists`, `ips-filter exception`

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
- ✅ Comprehensive logging (Suricata, SLIPS, system)
- ✅ Redis-based data backend

## Quick Start

### Installation (One Command)

```bash
sudo ./karens-ips-installer.sh
```

**What gets installed:**

1. Base system dependencies and Zeek
2. Kernel tuning and nftables firewall
3. Suricata IPS (NFQUEUE bridge mode)
4. Community blocklists (300K+ domains)
5. SLIPS (Stratosphere Linux IPS) with ML
6. ML Detector Dashboard (auto-integrated)
7. Node.js and Kalipso CLI
8. Network bridge configuration
9. Redis database
10. SystemD services for all components

**Installation time:** 15-30 minutes (depending on network speed)

### Post-Installation

**Access the dashboards:**

- **SLIPS Web UI**: `http://[SERVER-IP]:55000`
- **ML Detector**: Click "ML Detector" tab in SLIPS Web UI
- **Kalipso CLI**: `sudo kalipso` (terminal interface)

**Service management:**

```bash
# Check all services
systemctl status redis-server suricata slips slips-webui zeek

# Restart services
systemctl restart suricata slips

# View logs
journalctl -fu slips                        # SLIPS behavioral analysis
tail -f /var/log/suricata/fast.log          # Suricata alerts
tail -f /var/log/suricata/eve.json | jq    # Detailed EVE JSON logs
```

## Architecture

```
Internet
    ↓
┌─────────────────────────────────────────┐
│  Network Bridge (br0)                   │
│  ├─ <IFACE_IN> (Traffic IN)             │
│  └─ <IFACE_OUT> (Traffic OUT)           │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│  nftables NFQUEUE                       │
│  ├─ Send traffic to queue 0             │
│  └─ Bypass if Suricata unavailable      │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│  Suricata IPS Engine                    │
│  ├─ Community blocklists (300K domains) │
│  ├─ ET Open rules + TrafficID           │
│  ├─ Custom family-filter rules          │
│  └─ Drop/Alert decisions                │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│  SLIPS Behavioral Analysis              │
│  ├─ ML threat detection                 │
│  ├─ Behavioral profiling                │
│  ├─ Redis data storage                  │
│  └─ ML Ad Detector integration          │
└─────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────┐
│  Dashboards & Monitoring                │
│  ├─ SLIPS Web UI (port 55000)           │
│  ├─ ML Detector Dashboard               │
│  └─ Kalipso CLI                         │
└─────────────────────────────────────────┘
```

## Modular Installer

### Architecture

```
installer/
├── main.sh                  # Main orchestrator
├── config/
│   └── installer.conf       # Central configuration
├── lib/
│   ├── logging.sh           # Logging functions
│   └── utils.sh             # Utility functions (30+ helpers)
└── modules/                 # 16 installation modules
    ├── 01-base-system.sh    # Base packages + Zeek
    ├── 02-kernel-tuning.sh  # Kernel optimization
    ├── 03-nftables.sh       # Firewall setup
    ├── 04-suricata.sh       # Suricata installation
    ├── 06-suricata-rules.sh # Rules initialization
    ├── 07-blocklists.sh     # Community blocklists
    ├── 08-blocklist-mgmt.sh # Blocklist management
    ├── 09-nodejs.sh         # Node.js for Kalipso
    ├── 10-slips.sh          # SLIPS installation
    ├── 11-ml-detector.sh    # ML Detector Dashboard
    ├── 12-interfaces.sh     # Network bridge setup
    ├── 13-redis.sh          # Redis configuration
    ├── 14-systemd.sh        # SystemD services
    ├── 15-services.sh       # Service startup
    ├── 16-motd.sh           # MOTD creation
    └── 17-verification.sh   # Installation verification
```

### Custom Installation

**Network Interface Configuration:**

The installer automatically detects network interfaces. For custom configuration:

```bash
# Option 1: Edit configuration file before installation
nano installer/config/installer.conf

# Set your interfaces (leave empty for auto-detection):
# MGMT_IFACE=""      # Management interface (auto-detects first interface with IP)
# IFACE_IN=""        # Bridge input interface
# IFACE_OUT=""       # Bridge output interface
# HOME_NET=""        # Protected network CIDR (auto-detects from management interface)

# Option 2: Interactive mode (default)
# The installer will detect interfaces and prompt for confirmation
sudo ./karens-ips-installer.sh

# Option 3: Non-interactive with auto-detection
sudo NON_INTERACTIVE=1 ./karens-ips-installer.sh
```

**Find your interfaces:**

```bash
# List all interfaces
ip link show

# Show interface details with IPs
ip addr show
```

**Skip specific components:**

```bash
# Skip blocklists
sudo INSTALL_BLOCKLISTS=false ./karens-ips-installer.sh

# Skip SLIPS Web UI
sudo INSTALL_WEBUI=false ./karens-ips-installer.sh

# Skip Zeek (SLIPS will have reduced capabilities)
sudo INSTALL_ZEEK=false ./karens-ips-installer.sh
```

**Custom configuration file:**

```bash
# Copy and edit configuration
cp installer/config/installer.conf installer/config/custom.conf
nano installer/config/custom.conf

# Run with custom config
sudo CONFIG_FILE=installer/config/custom.conf ./karens-ips-installer.sh
```

See [installer/README.md](installer/README.md) for complete modular installer documentation.

## Community Blocklist Management

### Automatic Updates

Blocklists auto-update weekly (Sundays at 3 AM):

```bash
# Check update timer
systemctl status blocklist-update.timer

# Manual update now
ips-filter update-blocklists

# View schedule
systemctl list-timers blocklist-update.timer
```

### Exception Management (Whitelist)

Add exceptions for false positives:

```bash
# Add domain exception
ips-filter exception add domain example.com "trusted site"

# Add IP exception
ips-filter exception add ip 8.8.8.8 "Google DNS"

# List exceptions
ips-filter exception list
ips-filter exception list domain
ips-filter exception list ip

# Remove exception
ips-filter exception remove domain example.com
```

### Manual Operations

```bash
# View statistics
ips-filter stats

# Import domain list
ips-filter import-list /path/to/domains.txt ads

# Import RPZ file
ips-filter import-rpz /path/to/blocklist.rpz malware

# Add single domain
ips-filter add ad-domain.com advertising

# Sync to Suricata
ips-filter sync
```

### Configuration

Edit `/etc/karens-ips/blocklists.yaml` to customize:

- Enabled/disabled blocklists
- Update schedule
- Exception lists (domains and IPs)
- Database settings

## ML Detector Dashboard

### Features

- **Statistics Cards**: Total analyzed, ads detected, legitimate traffic, accuracy
- **Timeline Chart**: Real-time ad detection trends (Chart.js)
- **Feature Importance**: ML model feature weights visualization
- **Recent Detections**: Searchable, sortable table with confidence scores
- **Alerts**: High-priority ML detector alerts
- **Suricata Stats**: Real-time packet counts, alerts, blocked IPs
- **Auto-refresh**: Live updates every 5 seconds

### Technical Details

- **Backend**: Flask Blueprint integrated into SLIPS
- **Frontend**: Chart.js for charts, DataTables for tables
- **Data Storage**: Redis database 1 (persistent SLIPS data)
- **Security**: Input validation, error handling, no info disclosure
- **TLS SNI Blocking**: Integrated with DNS blocklist infrastructure (338K+ domains)

### Redis Architecture

```
Database 0: Ephemeral cache
Database 1: Persistent SLIPS data (webui connects here)
```

### Redis Keys

```
ml_detector:stats               # Overall statistics (hash)
ml_detector:recent_detections   # Recent detections (list, max 100)
ml_detector:timeline            # Time-series data (list, max 1000)
ml_detector:model_info          # Model metadata (hash)
ml_detector:feature_importance  # Feature weights (hash)
ml_detector:alerts              # Alerts (list, max 50)
```

### Custom Patches

The following SLIPS files have been patched for correct operation:

- **database.py**: Modified to connect to Redis database 1 instead of 0
  - Location: `StratosphereLinuxIPS/slips_files/core/database/redis_db/database.py`
  - Patch file: `patches/slips-redis-db1-connection.patch`
  - Change: Line ~353 modified from `db=0` to `db=1`
  - Required for webui to read persistent SLIPS detection data

## Project Structure

```
karens-ips/
├── installer/                      # Modular installer (16 modules)
│   ├── main.sh                     # Main orchestrator
│   ├── config/installer.conf       # Central configuration
│   ├── lib/                        # Shared libraries
│   └── modules/                    # Installation modules
├── src/                            # Python modules
│   ├── blocklist_manager.py        # Blocklist management
│   └── blocklist_config.py         # Configuration manager
├── slips_integration/              # ML Detector Dashboard
│   ├── webinterface/ml_detector/   # Flask blueprint
│   └── patches/                    # SLIPS integration patches
├── config/                         # YAML configuration
│   └── blocklists.yaml             # Blocklist configuration
├── scripts/                        # Utility scripts
│   ├── update-blocklists.sh        # Blocklist updater
│   └── import-from-config.py       # Config-based importer
├── deployment/                     # Deployment configs
│   ├── blocklist-update.service    # SystemD service
│   └── blocklist-update.timer      # SystemD timer
├── tests/                          # Unit tests
├── karens-ips-installer.sh         # Main installer wrapper
├── requirements.txt                # Python dependencies
├── README.md                       # This file
├── QUICK_START.md                  # Quick start guide

```

## System Requirements

**Minimum:**

- CPU: 4 cores
- RAM: 8 GB
- Disk: 50 GB
- OS: Ubuntu 22.04/24.04 or Debian 11/12

**Recommended:**

- CPU: 8+ cores
- RAM: 16 GB
- Disk: 100 GB (for extended logs)
- Network: 3 NICs (1 management, 2 bridge)

**Resource Usage:**

- Suricata: ~1-2 GB RAM, 100-200% CPU
- SLIPS: ~1-2 GB RAM, 50-100% CPU
- Redis: ~2 GB RAM (configured limit)
- Zeek: ~1 GB RAM, 50-100% CPU
- **Total: ~6 GB RAM, ~400% CPU**

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/karens-ips/blocklists.yaml` | Blocklist configuration |
| `/etc/suricata/suricata.yaml` | Suricata IPS configuration |
| `/opt/StratosphereLinuxIPS/slips.conf` | SLIPS configuration |
| `/etc/redis/redis.conf` | Redis configuration |
| `installer/config/installer.conf` | Installer settings |

## Database Locations

| Database | Path |
|----------|------|
| Blocklists | `/var/lib/suricata/ips_filter.db` (SQLite) |
| Redis | `/var/lib/redis/dump.rdb` |
| Suricata Datasets | `/etc/suricata/datasets/` |
| Blocklist Repos | `/opt/karens-ips-blocklists/` |

## Logs

| Component | Log Path |
|-----------|----------|
| Suricata Alerts | `/var/log/suricata/fast.log` |
| Suricata EVE JSON | `/var/log/suricata/eve.json` |
| SLIPS | `/var/log/slips/slips.log` |
| SLIPS Journal | `journalctl -fu slips` |
| System | `journalctl -xe` |

## Troubleshooting

### Services not starting

```bash
# Check service status
systemctl status suricata slips slips-webui

# View detailed logs
journalctl -xeu suricata
journalctl -xeu slips

# Test Suricata configuration
suricata -T -c /etc/suricata/suricata.yaml
```

### No traffic blocking

```bash
# Check bridge status
ip link show br0

# Verify nftables rules
nft list ruleset | grep -A 10 "forward_ips"

# Check Suricata is processing
tail -f /var/log/suricata/fast.log

# Verify dataset loading
suricatasc -c "datasets.list"
```

### Interface issues

```bash
# Check interface status
ip link show  # Shows all interfaces

# Check specific bridge interfaces (replace with your interface names)
ip link show <IFACE_IN> <IFACE_OUT>

# Restart interface setup
systemctl restart ips-interfaces.service

# Check bridge members
bridge link show
```

## Documentation

- **[QUICK_START.md](QUICK_START.md)** - Quick start guide
- **[installer/README.md](installer/README.md)** - Modular installer documentation

## Performance Tuning

See `installer/modules/02-kernel-tuning.sh` for kernel optimizations:

- Ring buffer sizes (268 MB)
- Network backlog (300K packets)
- TCP BBR congestion control
- Busy polling enabled
- IPv6 disabled

## Testing

```bash
# Run Python tests
python -m pytest tests/

# Test blocklist import
ips-filter import-list /path/to/test-domains.txt test

# Test Suricata config
suricata -T -c /etc/suricata/suricata.yaml

# Test dataset operations
echo -n "example.com" | base64 | xargs -I {} suricatasc -c "dataset-add malicious-domains string {}"
```

## Contributing

Contributions welcome! This project integrates with:

- [Stratosphere Linux IPS (SLIPS)](https://github.com/stratosphereips/StratosphereLinuxIPS)
- [Suricata IPS](https://suricata.io/)
- [Perflyst/PiHoleBlocklist](https://github.com/Perflyst/PiHoleBlocklist)
- [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists)

## License

GPL-2.0-only

## Credits

- **SLIPS**: Stratosphere Research Laboratory
- **Suricata**: Open Information Security Foundation (OISF)
- **Blocklists**: Perflyst, hagezi community
- **Zeek**: The Zeek Project

---
