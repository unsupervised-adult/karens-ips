# Karen's IPS

**SLIPS + Suricata IPS** extended for privacy, telemetry blocking, and streaming ad removal while maintaining full network security functionality.

## ⚠️ Project Status (December 2025)

**Production-Ready:**
- ✅ Core IPS stack (SLIPS + Suricata + Zeek) with inline nftables blocking
- ✅ Threat detection, behavioral analysis, C2 blocking
- ✅ 350K+ telemetry/tracking domain blocklists (hagezi/perflyst)
- ✅ NGINX HTTPS reverse proxy with authentication
- ✅ Modular installer with 19 automated phases

**Known Issues:**
- ⚠️ **SLIPS Web UI** - Currently has app.py syntax error preventing startup (fix in progress)
- ⚠️ **ML Detector Dashboard** - Inaccessible until Web UI fixed
- ⚠️ **stream_ad_blocker** - Service installed but requires testing and configuration
- ⚠️ **ad_flow_blocker** - SLIPS module code exists but not yet in installer

**Recommendation:** Core IPS functionality is stable and working. ML/ad-blocking features are experimental. Use for network security; privacy extensions need additional configuration.

## Overview

Built on Stratosphere SLIPS (behavioral IPS) and Suricata (signature-based IPS), this system adds privacy-focused extensions:
- **Telemetry filtering** with 350K+ tracking domain datasets ✅ **WORKING**
- **Privacy protection** through TLS SNI inspection and DNS blocking ✅ **WORKING**
- **Streaming ad blocking (EXPERIMENTAL)** via QUIC flow analysis - needs configuration
- **Custom SLIPS modules (IN DEVELOPMENT)** for flow-level ad removal
- **ML-powered detection (EXPERIMENTAL)** with automatic training data collection

Core security features remain intact: threat detection, C2 blocking, malware prevention, behavioral profiling.

## Features

### Core IPS (SLIPS + Suricata) ✅ PRODUCTION-READY
- **SLIPS Behavioral Analysis** - ML-powered threat detection, IP reputation, C2 detection
- **Suricata Signature IPS** - 12+ threat intelligence sources, NFQUEUE inline blocking
- **Zeek Protocol Analysis** - Flow extraction, protocol parsing, conn/dns/http logs
- **Real-Time Blocking** - nftables IP blacklisting, conntrack flow termination
- **Modular Architecture** - 19-phase installer, systemd service management
- **NGINX Reverse Proxy** - HTTPS access with basic authentication

### Privacy & Telemetry Blocking ✅ WORKING
- **Telemetry Filtering** - 350K+ tracking/analytics domains (hagezi, perflyst)
- **TLS SNI Inspection** - Blocks HTTPS trackers at handshake (bypasses encrypted DNS)
- **Dataset-Based Blocking** - O(1) hash lookup, Suricata dataset integration
- **DNS/HTTP/TLS Rules** - Unified blocklist across all protocol layers

### Experimental Features ⚠️ IN DEVELOPMENT
- **Streaming Ad Blocking (EXPERIMENTAL)** - QUIC behavioral fingerprinting (installed, needs testing)
- **Custom SLIPS Module (NOT YET INSTALLED)** - ad_flow_blocker code exists, installer update needed
- **ML Detector Dashboard (BROKEN)** - Web UI syntax error preventing startup
- **LLM Integration (NOT CONFIGURED)** - Infrastructure ready, requires API keys
- **Auto Training Data (UNTESTED)** - Code exists in stream_ad_blocker.py
- **Web Management (PARTIALLY WORKING)** - NGINX proxy works, Flask app has startup issue

## Installation

**Single command:**

```bash
sudo ./karens-ips-installer.sh
```

**Time:** 15-30 minutes

**What gets installed:**

- **SLIPS** - Stratosphere behavioral IPS with Zeek integration
- **Suricata 8.0** - Signature-based IPS in NFQUEUE inline mode
- **Zeek** - Protocol analysis engine for flow extraction
- **Redis** - Pub/sub for SLIPS modules and statistics
- **Ad Blocker Extensions** - stream_ad_blocker service + ad_flow_blocker SLIPS module
- **Privacy Datasets** - hagezi/perflyst tracking domain lists (350K+ domains)
- **Web UI** - Flask-based management interface with ML detector dashboard
- **LLM Support** - Optional OpenAI/Ollama integration

## Quick Start

**Access web interface:**

```bash
https://[SERVER-IP]
```

Default credentials: `/root/.karens-ips-credentials`

**Service management:**

```bash
# Core IPS services
systemctl status slips suricata redis-server

# Privacy/ad blocking extensions
systemctl status stream-ad-blocker

# SLIPS web interface
systemctl status slips-webui

# View logs
journalctl -fu slips
journalctl -fu suricata
journalctl -fu stream-ad-blocker
```

**Configure threat feeds:**

1. Web UI → Suricata tab → DNS Blocklists
2. Import hagezi (Pro/Normal) or perflyst (SmartTV/Android) lists
3. Click "Sync to Suricata" to update dataset
4. Configuration tab → "Generate Dataset" for TLS SNI rules

## Web UI

**Dashboard** - Real-time SLIPS/Suricata statistics, system health, threat overview

**ML Detector** - Streaming ad detection, flow analysis, training data management

**Network Analysis** - SLIPS behavioral profiling, flow visualization, evidence correlation

**Intelligence** - Telemetry analysis, pattern detection, LLM-powered threat/ad classification

**Suricata Config** - Rule management, privacy datasets (hagezi/perflyst), manual domain blocking

**Configuration** - Network topology, SLIPS settings, LLM integration (OpenAI/Ollama)

**Operations** - Threat intelligence updates, exception management

**User Management** - Authentication, password changes, session management

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Internet Traffic                            │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                   ┌───────────▼───────────┐
                   │ br0 (Bridge Interface)│
                   └───────────┬───────────┘
                               │
                   ┌───────────▼───────────────────────┐
                   │       NFQUEUE (inline)            │
                   └───────────┬───────────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
┌───────▼─────────┐  ┌─────────▼──────────┐  ┌───────▼─────────┐
│  Suricata 8.0   │  │  Zeek (Bro)        │  │  Packet Mirror  │
│  • Signatures   │  │  • Protocol parse  │  │  (for Zeek)     │
│  • 350K domains │  │  • Flow extraction │  └─────────────────┘
│  • TLS SNI      │  │  • conn/dns/http   │
│  • EVE JSON     │  │    log generation  │
└────────┬────────┘  └─────────┬──────────┘
         │                     │
         │          ┌──────────▼──────────┐
         │          │   Redis DB 0        │
         │          │   • new_flow        │
         │          │   • new_dns         │
         │          │   • tw_modified     │
         │          └──────────┬──────────┘
         │                     │
         │          ┌──────────▼──────────────────────────────────┐
         │          │      SLIPS (Behavioral IPS)                 │
         │          │  • ML threat detection (Zeek flows)         │
         │          │  • IP reputation & C2 detection             │
         │          │  • Behavioral profiling                     │
         │          │  • Module system (IModule)                  │
         │          └──────┬──────────────────┬───────────────────┘
         │                 │                  │
         │      ┌──────────▼──────────┐  ┌────▼─────────────────┐
         │      │  ad_flow_blocker    │  │  SLIPS Blocking      │
         │      │  (SLIPS Module)     │  │  Module              │
         │      │  • Zeek flow sub    │  │  • nftables sets     │
         │      │  • ML ad scoring    │  │  • IP blacklist      │
         │      │  • conntrack drops  │  │  • Malicious IPs     │
         │      │  • Skip RFC1918 dst │  └──────────────────────┘
         │      └─────────────────────┘
         │
         │      ┌──────────────────────────────────────────────────┐
         │      │    stream_ad_blocker (Privacy Extension)        │
         │      │  • Redis DB 1 (separate namespace)              │
         │      │  • QUIC flow fingerprinting                     │
         │      │  • ML ad classifier (Random Forest)             │
         │      │  • Auto training data collection                │
         │      │  • LLM queue (0.30-0.90 confidence)             │
         │      │  • Triple blocking: conntrack/dataset/nftables  │
         │      │  • Skip RFC1918 destinations (not sources)      │
         │      └────────────┬─────────────────────────────────────┘
         │                   │
         │                   │  ┌────────────────────────────────┐
         │                   └─→│  LLM Service (Optional)        │
         │                      │  • OpenAI API / Ollama         │
         │                      │  • Flow classification         │
         │                      │  • Training data labeling      │
         │                      │  • Threat analysis             │
         │                      └────────────────────────────────┘
         │
         └──────────────────────┐
                                │
                    ┌───────────▼──────────────────────────────────┐
                    │         Web Interface (Flask)                │
                    │  • Dashboard (SLIPS/Suricata stats)          │
                    │  • ML Detector (ad/privacy flow analysis)    │
                    │  • Network Analysis (behavioral profiling)   │
                    │  • Intelligence (LLM-powered analysis)       │
                    │  • Suricata Config (datasets, manual block)  │
                    │  • Configuration (LLM, SLIPS, thresholds)    │
                    └──────────────────────────────────────────────┘
```

**Data Flow:**

1. **Traffic Capture**: br0 bridge → NFQUEUE → Suricata + Zeek parallel processing
2. **Suricata Path**: Signature matching → Dataset lookup → TLS SNI → Block/Allow → EVE JSON logs
3. **Zeek Path**: Protocol parsing → conn/dns/http logs → Redis DB 0 pub/sub
4. **SLIPS Analysis**: Subscribes to Zeek flows → ML behavioral analysis → Threat detection → nftables blocking
5. **Ad Extensions**: 
   - `ad_flow_blocker`: SLIPS module, Zeek flows → ML scoring → conntrack flow drops
   - `stream_ad_blocker`: Standalone service, QUIC analysis → ML classifier → training data → LLM queue
6. **LLM Integration**: Medium-confidence flows (0.30-0.90) → LLM labeling → training dataset
7. **Web UI**: Real-time stats from Redis, Suricata EVE JSON, SLIPS evidence database
        └─────────────────────────────────────────────────────────────┘
```

**Multi-Layer Defense:**

1. **Suricata IPS** (Signature-Based Detection)
   - NFQUEUE inline blocking on bridge interface
   - 350K+ tracking/telemetry domain dataset (O(1) hash lookup)
   - TLS SNI inspection blocks HTTPS ads/trackers at handshake
   - DNS/HTTP/TLS rules reference unified privacy dataset
   - Manual domain blocking via SQLite backend + web UI
   - 12+ threat intelligence sources (Emerging Threats, abuse.ch, etc.)

2. **SLIPS Behavioral Analysis** (ML + Zeek)
   - Zeek (Bro) for protocol analysis and flow extraction
   - Redis DB 0 pub/sub channels (new_flow, new_dns, tw_modified)
   - Native module system (IModule inheritance)
   - IP reputation, behavioral profiling, C2 detection, botnet tracking
   - Processes Zeek conn.log, dns.log, http.log
   - **Extended:** ad_flow_blocker module for streaming ad removal

3. **ad_flow_blocker** (SLIPS Module Extension)
   - Native SLIPS module for privacy-focused flow blocking
   - Flow-level blocking via conntrack (surgical, not IP blacklisting)
   - ML-based ad confidence scoring (thresholds: YouTube=0.60, CDN=0.85)
   - Private IP filtering (RFC1918/loopback/link-local exemptions)
   - Subscribes to SLIPS new_flow and new_dns Redis channels
   - **Purpose:** Extends SLIPS for ad/telemetry blocking while preserving security

4. **stream_ad_blocker** (Standalone Privacy Service)
   - Redis DB 1 (separate namespace from SLIPS)
   - QUIC encrypted stream behavioral fingerprinting
   - Detects video ads without payload decryption (YouTube, Twitch, etc.)
   - ML flow classification with automatic training data collection
   - Triple blocking: conntrack flow drops, Suricata dataset injection, nftables
   - **Purpose:** Privacy-focused extension for streaming platform ad removal

## Rule Sources

**Free sources (enable via web UI or CLI):**

- et/open - Emerging Threats (default)
- oisf/trafficid - Traffic identification
- abuse.ch/sslbl-blacklist - SSL threats
- abuse.ch/sslbl-ja3 - JA3 fingerprints
- abuse.ch/feodotracker - Botnet C2
- abuse.ch/urlhaus - Malicious URLs
- tgreen/hunting - Threat hunting
- stamus/lateral - Lateral movement
- pawpatrules - Community rules
- aleksibovellan/nmap - NMAP detection

**CLI:**

```bash
sudo suricata-update list-sources
sudo suricata-update enable-source abuse.ch/urlhaus
sudo suricata-update
sudo systemctl reload suricata
```

## Monitoring

```bash
# Suricata stats
tail -f /var/log/suricata/fast.log
tail -f /var/log/suricata/eve.json | jq

# SLIPS detections
journalctl -fu slips | grep -i alert

# Stream Ad Blocker stats
redis-cli -n 1 HGETALL stream_ad_blocker:stats
redis-cli -n 1 LRANGE ml_detector:recent_detections 0 10
journalctl -fu stream-ad-blocker | grep -E "detected|blocked"

# Redis stats
redis-cli -n 1 hgetall ml_detector:stats

# Dataset info
suricatasc -c "dataset-list"
```

## Configuration

**HOME_NET:** Set in web UI → Configuration tab

**Stream Ad Blocker (QUIC Behavioral Fingerprinting):**

Detects and blocks encrypted video ads on YouTube, Twitch, and other platforms via flow pattern analysis without payload decryption.

**Ad Flow Blocker (Native Slips Module):**

Custom Slips module providing surgical flow-level ad removal using conntrack. Integrates with Slips behavioral analysis for intelligent ad detection.

**Features:**
- Native Slips module (IModule integration)
- Subscribes to new_flow and new_dns Redis channels
- Uses ML classifier for ad confidence scoring
- Performs flow-level drops via conntrack (not IP blacklisting)
- RFC1918/loopback/link-local filtering (prevents internal network false positives)
- Thresholds: YouTube=0.60, CDN=0.85, ControlPlane=0.70
- Auto-deployed via installer to /opt/StratosphereLinuxIPS/modules/ad_flow_blocker/

**Training Data Collection:**

Automatic dataset building without LLM requirement:
- High-confidence detections (>0.90) auto-saved as 'ad' samples
- Blocklist matches (1.0 confidence) auto-saved as 'ad' samples  
- Low-confidence flows (<0.30) auto-saved as 'legitimate' samples (10% sampling)
- Persists to training_data.json (max 10,000 samples, auto-trimmed)
- Enables model retraining without manual labeling

**Service Management:**
**Service Management:**

```bash
# Status check
sudo systemctl status stream-ad-blocker
journalctl -u stream-ad-blocker --since '10 minutes ago'

# View real-time detections
journalctl -fu stream-ad-blocker | grep -E "BLOCKED|detected|TRAIN"

# Check detection stats
redis-cli -n 1 HGETALL stream_ad_blocker:stats

# View training data count
redis-cli -n 1 GET ml_detector:training:count
ls -lh /opt/StratosphereLinuxIPS/webinterface/ml_detector/training_data.json

# View recent detections (JSON format)
redis-cli -n 1 LRANGE ml_detector:recent_detections 0 10

# Check ad_flow_blocker Slips module
ps aux | grep ad_flow_blocker
tail -f /opt/StratosphereLinuxIPS/output/br0_*/slips.log | grep 'FLOW BLOCKED'

# Restart services after config changes
sudo systemctl restart stream-ad-blocker
sudo systemctl restart slips
```

**Redis Configuration Keys (Database 1):**
```bash
# Detection thresholds (0.0 - 1.0)
redis-cli -n 1 SET stream_ad_blocker:youtube_threshold 0.35      # Video ad flows (35% confidence)
redis-cli -n 1 SET stream_ad_blocker:cdn_threshold 0.50          # Generic CDN ads (50%)
redis-cli -n 1 SET stream_ad_blocker:control_plane_threshold 0.45 # Ad auction endpoints (45%)

# LLM analysis zone (flows in this range get analyzed by LLM)
redis-cli -n 1 SET stream_ad_blocker:llm_min_threshold 0.25      # Lower bound (25%)
redis-cli -n 1 SET stream_ad_blocker:llm_max_threshold 0.75      # Upper bound (75%)

# Duration filters (seconds)
redis-cli -n 1 SET stream_ad_blocker:ad_duration_min 3           # Minimum ad duration
redis-cli -n 1 SET stream_ad_blocker:ad_duration_max 120         # Maximum ad duration

# Size filters (bytes)
redis-cli -n 1 SET stream_ad_blocker:min_bytes 5120              # Minimum flow size (5KB)

# Enable/disable blocking
redis-cli -n 1 SET ml_detector:blocking_enabled 1                # 1=active, 0=monitor only
```

**Detection Patterns:**
- **Bumper ads**: ≤6s duration, >50KB
- **Skippable ads**: 5-30s, >100KB/s byte rate
- **Non-skippable ads**: 15-30s, 1-15MB
- **Long ads**: 30-60s, <25MB
- **Pre-roll sequences**: <180s, >50pps packet rate
- **Ad beacons**: <50KB, <20 packets
- **Ad pods**: Multiple sequential ads detected via timing correlation

**How It Works:**
1. Subscribes to SLIPS `new_flow` channel (Redis DB 0)
2. Analyzes QUIC flows (UDP port 443) for behavioral fingerprints
3. Pattern matching on packet rates, byte sizes, duration, burst timing
4. ML model (ad_classifier_model.pkl) provides additional classification
5. **Triple blocking:** conntrack flow drops, Suricata dataset injection, nftables IP blacklist
6. No payload decryption - analyzes flow metadata only

**Troubleshooting:**
```bash
# Check if service is receiving flows
journalctl -u stream-ad-blocker --since '1 minute ago' | grep "Processing flow"

# Verify SLIPS is publishing flows (Zeek flows via Redis)
redis-cli -n 0 PUBSUB CHANNELS | grep new_flow

# Check for ad detections and blocks
journalctl -u stream-ad-blocker --since '5 minutes ago' | grep -E "BLOCKED|ad_pod|preroll"

# View conntrack flow drops (live connections terminated)
sudo conntrack -L | wc -l  # Total connections
redis-cli -n 1 GET stream_ad_blocker:stats  # Check flows_dropped counter

# View Suricata dataset blocks (flow tuples)
redis-cli -n 1 SMEMBERS stream_blocker:blocked_flows
sudo cat /var/lib/suricata/datasets/llm-blocked-flows.lst

# View nftables IP blacklist (persistent ad servers)
sudo nft list set inet home blocked4 | grep "elements"

# Clear all blocks
redis-cli -n 1 DEL stream_blocker:blocked_flows
sudo rm /var/lib/suricata/datasets/llm-blocked-flows.lst
# Note: conntrack blocks are temporary (flow-level), nftables requires manual cleanup
```

**Performance Tuning:**

- Lower thresholds = more detections, more false positives
- Higher thresholds = fewer false positives, may miss some ads
- LLM zone (25-75%) captures borderline cases for training data
- Ultra-sensitive mode: youtube_threshold=0.30, llm_min=0.20

**LLM integration:** Configuration tab → Intelligence Settings

- OpenAI API key for GPT-4 analysis
- Ollama local models (llama3.2, mistral, etc.)
- Automatic threat correlation and evidence analysis

**DNS blocklists:** Suricata Config tab → DNS Blocklists

- hagezi (Pro/Pro++/Ultimate) - 350K+ domains
- perflyst (SmartTV/Android/FireTV) - Tracking prevention
- Automatic sync to Suricata datasets

**Manual domain blocking:** Suricata Config tab → Add TLS SNI Domain

- Add individual domains to blocklist
- View manually added domains (reads SQLite directly)
- Instant dataset regeneration and Suricata reload

**TLS SNI blocking:** Configuration tab → Generate Dataset (creates DNS/HTTP/TLS rules from unified database)

**Exception management:** Operations → Manual Exception Entry

## Requirements

- Ubuntu 24.04 LTS
- 16GB+ RAM (32GB recommended)
- 8+ CPU cores (ML processing intensive)
- 3 network interfaces (management + bridge pair)

## License

GPL-2.0

## Credits

- SLIPS by Stratosphere Laboratory
- Suricata by OISF
- Threat intelligence by hagezi, perflyst

## Troubleshooting

### Known Issue: SLIPS Web UI Won't Start

**Symptom:**
```bash
$ sudo systemctl status slips-webui
● slips-webui.service - SLIPS Web Interface
     Active: activating (auto-restart) (Result: exit-code)
```

**Error in logs:**
```
IndentationError: unexpected indent
File "/opt/StratosphereLinuxIPS/webinterface/app.py", line 69
```

**Root Cause:**
The slips_integration installer uses a pre-modified `app.py` file that has incorrect indentation from multiple ml_detector blueprint registrations.

**Temporary Workaround:**
The core IPS functionality (SLIPS analysis, Suricata blocking, threat detection) works fine without the web UI. You can monitor via command line:
```bash
# View SLIPS detections
journalctl -fu slips | grep -i alert

# View Suricata blocks
tail -f /var/log/suricata/fast.log

# Check Redis stats
redis-cli -n 0 keys "*"
redis-cli -n 1 HGETALL ml_detector:stats
```

**Permanent Fix:**
A corrected installer is being prepared. For now, core IPS features work correctly even without the web interface.

---

### Services Not Starting

```bash
systemctl status suricata slips
journalctl -xeu suricata
suricata -T -c /etc/suricata/suricata.yaml
```

### No Blocking

```bash
tail -f /var/log/suricata/fast.log
nft list ruleset | grep forward
suricatasc -c "dataset-list"
```

### Interface Issues

```bash
ip link show br0
systemctl restart ips-interfaces.service
```

## System Requirements

- Ubuntu 24.04 LTS
- 8GB+ RAM recommended
- 2+ CPU cores
- Bridge-mode network interface

## Documentation

- [installer/README.md](installer/README.md) - Full installer documentation
