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
- Services: All critical services active (suricata, slips, redis, ml-detector-bridge, nginx)
- Memory Usage: ~6GB total across all components
- Traffic Processing: Real-time NFQUEUE packet processing (2.4M+ packets)
- ML Analysis: 253 detections, 45.59% detection rate, 85% accuracy
- QUIC Detection: Active for YouTube/streaming video ads
- Log Storage: 40GB contained (20GB Suricata, 10GB SLIPS, 5GB Redis, 5GB output)

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
- ✅ QUIC/HTTP3 protocol detection (YouTube, streaming video ads)
- ✅ **Adaptive learning**: SLIPS ML engine learns ad patterns and unique signatures over time
- ✅ **Multi-source correlation**: Cross-references blocklist DB (338K+ domains), SLIPS behavioral analysis, and temporal patterns
- ✅ **Flow-level blocking**: Surgical drops via conntrack - blocks ad flow without affecting CDN IPs
- ✅ **Universal video ad signatures**: Recognizes 6s bumper, 15s/30s non-skippable, skip-after-5 patterns across all platforms
- ✅ Detection timeline charts (ads vs legitimate traffic)
- ✅ Feature importance analysis with timing/size patterns
- ✅ Model performance metrics (45.59% detection rate, 85% accuracy)
- ✅ Searchable/sortable detection tables with confidence scores
- ✅ Auto-refresh every 5 seconds
- ✅ Fully integrated with SLIPS Web UI

### Monitoring & Management

- ✅ SLIPS Web UI (browser-based dashboard)
- ✅ Nginx reverse proxy with TLS 1.2/1.3 + authentication
- ✅ Custom auth page with modern design
- ✅ Let's Encrypt support for production certificates
- ✅ Kalipso CLI (terminal interface)
- ✅ SystemD service management
- ✅ Comprehensive logging (Suricata, SLIPS, system)
- ✅ Redis-based data backend

### Log & Disk Protection

- ✅ 40GB contained loop-mounted images for logs
- ✅ Aggressive logrotate (hourly EVE JSON, daily logs)
- ✅ Protection against disk exhaustion
- ✅ Automatic compression and retention policies
- ✅ Logs isolated from system disk

## Quick Start

### Installation (One Command)

```bash
sudo ./karens-ips-installer.sh
```

**What gets installed:**

1. Base system dependencies and Zeek
2. Kernel tuning and nftables firewall
3. Suricata IPS (NFQUEUE bridge mode)
4. **Log disk protection** (40GB contained images)
5. Suricata rules and datasets
6. Community blocklists (338K+ domains)
7. SLIPS (Stratosphere Linux IPS) with ML
8. ML Detector Dashboard with QUIC detection
9. Node.js and Kalipso CLI
10. Network bridge configuration
11. Redis database (persistent DB 1)
12. SystemD services for all components
13. **Aggressive logrotate** (hourly monitoring)
14. **Nginx reverse proxy** (TLS + auth)
15. MOTD and verification

**Installation time:** 15-30 minutes (depending on network speed)

### Post-Installation

**Access the dashboards:**

- **SLIPS Web UI**: `https://[SERVER-IP]` (Nginx reverse proxy with TLS + auth)
  - Default credentials: `/root/.karens-ips-credentials`
  - Direct access (localhost only): `http://127.0.0.1:55000`
- **ML Detector**: Click "ML Detector" tab - QUIC detection, 253 detections visible
- **Suricata Config**: Click "Suricata Config" tab for rules, datasets, TLS SNI management
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

## Usage

### Daily Operations

**Check system health:**

```bash
# View all service status
systemctl status redis-server suricata slips slips-webui zeek

# Check detection stats (shows real-time counts)
redis-cli -n 1 hgetall ml_detector:stats

# View Suricata alerts
tail -f /var/log/suricata/fast.log

# Monitor SLIPS detections
journalctl -fu slips | grep -i "detected\|alert"
```

**Monitor traffic:**

```bash
# Real-time Suricata stats
suricatasc -c "dump-counters" | jq '.message.decoder.pkts'

# View blocked IPs
cat /var/log/suricata/fast.log | grep "DROP\|REJECT" | awk '{print $NF}' | sort -u

# Check dataset stats (DNS blocklist, TLS SNI)
suricatasc -c "dataset-list"
```

### Web Interface Usage

**SLIPS Web UI (http://[SERVER-IP]:55000):**

1. **Overview Tab**: System status, active flows, network statistics
2. **ML Detector Tab**:
   - View detection statistics (253 detections, 45.59% detection rate)
   - Monitor ad blocking effectiveness
   - Review confidence scores and feature importance
   - Browse recent detections with search/filter
3. **Suricata Config Tab**:
   - View/reload Suricata rules
   - Manage DNS blocklists (338K+ domains)
   - Configure TLS SNI blocking
   - Monitor dataset statistics
   - Real-time packet/alert counts

### Blocklist Management

**Add custom blocks:**

```bash
# Block specific domain
ips-filter add malicious-site.com malware

# Import domain list
ips-filter import-list /path/to/domains.txt ads

# Sync to Suricata (happens automatically)
ips-filter sync
```

**Whitelist false positives:**

```bash
# Whitelist domain
ips-filter exception add domain trusted-site.com "Business application"

# Whitelist IP
ips-filter exception add ip 192.168.1.100 "Internal server"

# List all exceptions
ips-filter exception list
```

**Update blocklists:**

```bash
# Manual update (normally runs weekly via systemd timer)
ips-filter update-blocklists

# View blocklist sources and counts
ips-filter stats

# Check update schedule
systemctl list-timers blocklist-update.timer
```

### TLS SNI Blocking

Block domains at TLS handshake level (bypasses DNS):

**Via Web UI:**

1. Navigate to "Suricata Config" tab
2. Click "TLS SNI Management" section
3. Add domains or import lists
4. Domains automatically added to unified DNS blocklist

**Via API:**

```bash
# Add domain via curl
curl -X POST http://[SERVER-IP]:55000/suricata_config/tls_sni/add \
  -H "Content-Type: application/json" \
  -d '{"domain": "tracker.example.com"}'

# View TLS dataset
curl http://[SERVER-IP]:55000/suricata_config/tls_sni/view
```

### Troubleshooting

**No detections showing:**

```bash
# Verify Redis has data
redis-cli -n 1 hgetall ml_detector:stats

# Check SLIPS is analyzing traffic
journalctl -fu slips

# Verify Suricata is processing
tail -f /var/log/suricata/fast.log
```

**Dashboard shows zeros:**

```bash
# Verify webui connects to Redis DB 1
grep "db=1" StratosphereLinuxIPS/slips_files/core/database/redis_db/database.py

# Restart services
systemctl restart slips slips-webui

# Check for errors
journalctl -xeu slips-webui
```

**Blocklists not working:**

```bash
# Verify dataset loaded
suricatasc -c "dataset-list"

# Check database
sqlite3 /var/lib/suricata/ips_filter.db "SELECT COUNT(*) FROM blocklist_entries;"

# Reload Suricata
systemctl reload suricata
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
- **Recent Detections**: Searchable, sortable table with confidence scores (shows detection source: Blocklist, ML, SLIPS, Flow pattern)
- **Alerts**: High-priority ML detector alerts
- **Suricata Stats**: Real-time packet counts, alerts, blocked IPs
- **Auto-refresh**: Live updates every 5 seconds

### Intelligent Ad Detection System

**Multi-Layer Detection Pipeline:**

1. **Blocklist Database** (338K+ domains from Perflyst, hagezi)
   - Instant lookup: `ade.googlesyndication.com` → 95% confidence
   - Covers known ad servers, tracking domains, telemetry endpoints

2. **Universal Video Ad Patterns** (Platform-agnostic temporal signatures)
   - 6-second bumper ads (non-skippable)
   - 15-20 second forced ads
   - 30-second+ ads with skip-after-5 behavior
   - Bitrate analysis: Ads use lower quality encoding (1100-1300 bytes/packet vs 1350-1500 for content)
   - Works across YouTube, Twitch, Hulu, streaming platforms

3. **SLIPS Behavioral Analysis Integration**
   - Correlates flow data with SLIPS threat intelligence
   - Checks for malicious IP alerts, suspicious activity timelines
   - Learns unique ad server behavior patterns over time
   - Improves detection accuracy through continuous behavioral profiling

4. **ML Flow Pattern Recognition**
   - Duration analysis (short flows = likely ads)
   - Packet rate vs byte rate correlation
   - QUIC protocol-specific signatures
   - YouTube connection caching and pattern learning

**Adaptive Learning:**

- SLIPS ML engine stores ad patterns in Redis (`ml_detector:youtube_quic_patterns`)
- Builds confidence profiles for IP addresses over time
- Learns advertiser-specific signatures (e.g., Google's ad CDN patterns)
- Continuously improves detection accuracy with each analyzed flow

**Three-Tier Blocking Architecture:**

The system uses three complementary blocking mechanisms based on detection confidence and network layer:

1. **Suricata Rule-Based Blocking** (Signature + Dataset matching)
   - Dataset lookup: 338K+ domains from blocklist DB
   - TLS SNI inspection: Blocks at handshake (bypasses DNS, works for HTTPS)
   - Protocol-aware rules: ET Open, TrafficID, custom family filters
   - Best for: Known malicious domains, protocol violations, immediate drops

2. **TLS SNI Inspection** (Middle-ground HTTPS blocking)
   - Intercepts TLS Client Hello SNI field
   - Matches against unified DNS blocklist dataset
   - Blocks connection before encryption completes
   - Best for: HTTPS ad servers, tracking domains, bypassing DNS-based blocking

3. **ML-Driven Flow Termination** (Behavioral + Pattern analysis)
   - Conntrack flow drops for CDN-served ads
   - Multi-source detection pipeline (Blocklist + Pattern + SLIPS + ML)
   - Surgical termination of specific connections
   - Best for: Dynamic content, CDN-hosted ads, QUIC/HTTP3 streams

**Smart Blocking Strategy:**

| Scenario | Domain Example | IP Type | Confidence | Primary Action | Fallback |
|----------|---------------|---------|------------|----------------|----------|
| Known ad domain | `ads.example.com` | Any IP | 95% (dataset) | **Suricata DROP** via rule match | N/A - Immediate |
| HTTPS ad server | `ade.googlesyndication.com` | Any IP | 95% (blocklist) | **TLS SNI block** at handshake | Flow drop if SNI missed |
| Ad on CDN (QUIC) | `r5---sn-*.googlevideo.com` | Google CDN | 85% (pattern) + 88% (flow) = 90% + 5% boost | **Flow drop** via conntrack | Monitor (CDN shared IP) |
| Dedicated ad server | `ad.doubleclick.net` | Dedicated IP | 90% (blocklist) + 75% (pattern) = 90% + 5% boost | **IP block** via nftables | Suricata rule |
| Unknown short video | `cdn.example.com` | CDN IP | 70% (pattern only) | **Monitor only** | Escalate on repeat |
| Multi-layer detection | `pagead2.googlesyndication.com` | Google CDN | 95% (blocklist) + 88% (flow) + 75% (SLIPS) = **96%** | **TLS SNI block** + Flow drop | IP block |

**Confidence Boosting:**

- Multiple detection sources increase confidence
- Each additional confirming source adds 5% (max 15% boost)
- Example: Blocklist hit + Flow pattern match + SLIPS correlation = 3 sources = +10% confidence
- Prevents false positives while maximizing ad blocking effectiveness

**Private Network Exemption & Directional Blocking:**

The system uses **destination-based blocking** - it blocks where traffic is going, never the source device:

- **RFC1918 source addresses never blocked**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- **Link-local exempt**: 169.254.0.0/16 (APIPA), fe80::/10 (IPv6 link-local)
- **Loopback exempt**: 127.0.0.0/8, ::1/128
- **IoT devices are never blocked** - only their outbound connections to malicious destinations

**How Directional Blocking Works:**

```
IoT Device (10.10.1.50) → ads.tracking.com (8.8.8.8)
   ↓
NFQUEUE forwards to Suricata
   ↓
Suricata matches "ads.tracking.com" in dataset
   ↓
DROP verdict blocks OUTBOUND connection to 8.8.8.8
   ↓
IoT device (10.10.1.50) remains fully functional for legitimate traffic
```

**Traffic Direction Logic:**

- **Outbound (LAN → Internet)**: Block destination IPs/domains from blocklists via NFQUEUE
  - Example: SmartTV (192.168.1.20) tries to reach telemetry.samsung.com → **BLOCKED**
  - SmartTV can still access Netflix, YouTube, legitimate services
  
- **Inbound (Internet → LAN)**: Block source IPs from threat feeds
  - Example: Botnet IP (1.2.3.4) tries to reach your server → **BLOCKED**
  - Your devices remain accessible from legitimate sources

- **Internal (LAN → LAN)**: Always permitted
  - Example: Phone (192.168.1.10) → NAS (192.168.1.100) → **ALLOWED**
  - All RFC1918-to-RFC1918 traffic passes through unchecked

This ensures your IoT devices, printers, NAS, and servers are never blocked - only their attempts to reach malicious/ad/tracking destinations on the public internet are stopped.

### Technical Details

- **Backend**: Flask Blueprint integrated into SLIPS
- **Frontend**: Chart.js for charts, DataTables for tables
- **Data Storage**: Redis database 1 (persistent SLIPS data)
- **Learning Storage**: Redis lists for YouTube QUIC patterns (10K pattern history)
- **Blocklist Integration**: SQLite database query for domain lookups
- **Flow Control**: Conntrack for surgical connection termination
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

### Log Disk Protection

Logs grow rapidly in high-traffic environments. To prevent disk exhaustion, use contained loop-mounted images:

**Setup protected log directories:**

```bash
# Run the log protection script (creates 40GB of contained log space)
sudo ./scripts/setup-log-images.sh
```

**What it does:**

- Creates loop-mounted images for high-growth directories:
  - `/var/log/suricata` - 20GB (EVE JSON, fast.log, stats.log)
  - `/var/log/slips` - 10GB (SLIPS analysis logs)
  - `/var/lib/redis` - 5GB (Redis persistence)
  - `/opt/StratosphereLinuxIPS/output` - 5GB (SLIPS output files)
- Images stored in `/srv/images/`
- Original data preserved in `*.old` directories
- Automatic mount on boot via `/etc/fstab`
- Logs can fill to capacity without affecting system

**Monitor image usage:**

```bash
# Check disk usage of contained logs
df -h /var/log/suricata /var/log/slips /var/lib/redis

# View all loop mounts
losetup -a

# Check fstab entries
grep "/srv/images" /etc/fstab
```

**Adjust sizes if needed:**

```bash
# Edit the script before running
nano scripts/setup-log-images.sh

# Modify DIR_SIZES array:
# ["/var/log/suricata"]="30G"  # Increase if needed
```

**Setup aggressive log rotation:**

```bash
# Install stringent logrotate policies
sudo ./scripts/setup-logrotate.sh
```

**Log rotation policies:**

- **Suricata logs**: Daily rotation, 7 days retention, 1GB max per file
- **EVE JSON**: Hourly rotation, 2 days retention, 2GB max (high volume)
- **SLIPS logs**: Daily rotation, 7 days retention, 500MB max
- **SLIPS output**: Daily rotation, 3 days retention, 200MB max
- **Compression**: Enabled with 1-day delay
- **Frequency**: Hourly cron job monitors all logs

**Manual rotation:**

```bash
# Force immediate rotation
logrotate -f /etc/logrotate.d/suricata
logrotate -f /etc/logrotate.d/slips

# Test configuration
logrotate -d /etc/logrotate.d/suricata
```

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
