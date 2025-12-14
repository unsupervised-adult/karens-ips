# Karen's IPS

Enterprise-grade Intrusion Prevention System combining ML behavioral analysis with signature-based detection for network security and traffic intelligence.

## Features

- **Behavioral Analysis** - ML-powered threat detection with adaptive learning (SLIPS)
- **QUIC Ad Blocking** - Encrypted stream behavioral fingerprinting (YouTube, Twitch, etc.)
- **High-Performance IPS** - Suricata 8.0 in NFQUEUE bridge mode
- **Dataset Intelligence** - 350K+ domain patterns (hagezi/perflyst) with O(1) hash lookup
- **TLS SNI Inspection** - Deep packet inspection at TLS handshake (bypasses encrypted DNS)
- **DNS Dataset Integration** - Unified blocklist database synced to Suricata datasets
- **Manual Domain Blocking** - Add/view individual domains via web UI with SQLite backend
- **LLM Intelligence** - OpenAI/Ollama integration for threat analysis and evidence correlation
- **Bidirectional Correlation** - SLIPS ↔ Suricata threat intelligence sync
- **Real-Time Dashboard** - Live flow statistics, ML detector metrics, behavioral profiling
- **Unified Dashboard** - Network flows, telemetry analysis, configuration management
- **Extensible Rules** - 12+ free threat intelligence sources
- **Flow-Level Blocking** - Custom Slips module for surgical ad stream removal (conntrack)
- **Auto Training Data** - Automatic dataset building from high-confidence detections (no LLM required)
- **Private IP Filtering** - RFC1918/loopback exemption prevents false positives on internal networks

## Installation

**Single command:**

```bash
sudo ./karens-ips-installer.sh
```

**Time:** 15-30 minutes

**What gets installed:**

- Suricata 8.0 (NFQUEUE inline mode)
- SLIPS ML behavioral engine
- Stream Ad Blocker (QUIC behavioral fingerprinting)
- Dataset-based pattern matching
- Web management interface
- Threat intelligence feeds
- SystemD service integration

## Quick Start

**Access web interface:**

```bash
https://[SERVER-IP]
```

Default credentials: `/root/.karens-ips-credentials`

**Service management:**

```bash
systemctl status suricata slips slips-webui redis-server stream-ad-blocker
systemctl restart suricata
systemctl restart stream-ad-blocker
journalctl -fu slips
journalctl -fu stream-ad-blocker
```

**Configure threat feeds:**

1. Web UI → Suricata tab → DNS Blocklists
2. Import hagezi (Pro/Normal) or perflyst (SmartTV/Android) lists
3. Click "Sync to Suricata" to update dataset
4. Configuration tab → "Generate Dataset" for TLS SNI rules

## Web UI

**Dashboard** - Real-time network statistics, system health monitoring

**ML Detector** - Live flow analysis (29K+ flows), suspicious activity tracking, behavioral metrics

**Network Analysis** - Flow visualization, behavioral profiling, evidence correlation

**Intelligence** - Telemetry analysis, protocol inspection, pattern detection, LLM-powered threat analysis

**Suricata Config** - Rule management, dataset configuration, source feeds, manual domain blocking

**Configuration** - Network topology, dataset generation, LLM integration (OpenAI/Ollama)

**Operations** - Rule updates, source management, exception handling

**User Management** - Password changes, session management, authentication settings

## Architecture

```
                                    ┌─────────────────────────┐
                                    │   Internet Traffic      │
                                    └───────────┬─────────────┘
                                                │
                                    ┌───────────▼─────────────┐
                                    │  br0 (Bridge Interface) │
                                    └───────────┬─────────────┘
                                                │
                        ┌───────────────────────┼───────────────────────┐
                        │                  NFQUEUE                      │
                        │              (inline mode)                    │
                        └───────────────────────┬───────────────────────┘
                                                │
                        ┌───────────────────────▼───────────────────────┐
                        │           Suricata 8.0 IPS                    │
                        │  • Signature detection                        │
                        │  • Dataset blocking (350K+ domains)           │
                        │  • TLS SNI inspection                         │
                        │  • EVE JSON logging                           │
                        └───────┬───────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    │                       │
        ┌───────────▼──────────┐  ┌────────▼─────────────────┐
        │   EVE JSON Logs      │  │    Redis DB 0            │
        │   (eve.json)         │  │    (SLIPS channels)      │
        └───────────┬──────────┘  └────────┬─────────────────┘
                    │                       │
        ┌───────────▼─────────────────────┬─▼─────────────────────────┐
        │              SLIPS Behavioral Analysis                       │
        │  • Machine learning threat detection                         │
        │  • Behavioral profiling                                      │
        │  • IP reputation                                             │
        │  • Native modules (ad_flow_blocker)                          │
        └──────────┬────────────────────────────────────┬──────────────┘
                   │                                    │
        ┌──────────▼──────────┐              ┌─────────▼──────────────┐
        │  ad_flow_blocker    │              │  Blocking Module       │
        │  (Slips Module)     │              │  (nftables sets)       │
        │  • Flow-level drops │              │  • IP blacklisting     │
        │  • conntrack        │              │  • Malicious IPs       │
        │  • Ad stream blocks │              │  • C2 blocking         │
        │  • Private IP skip  │              └────────────────────────┘
        └─────────────────────┘
                   
        ┌───────────────────────────────────────────────────────────────┐
        │          stream_ad_blocker Service (Standalone)               │
        │  • Redis DB 1 (separate namespace)                            │
        │  • QUIC behavioral fingerprinting                             │
        │  • ML flow classification                                     │
        │  • Automatic training data collection                         │
        │  • Blocking methods: conntrack, Suricata dataset, nftables    │
        │  • Private IP filtering (RFC1918)                             │
        └──────────┬────────────────────────────────────────────────────┘
                   │
        ┌──────────▼──────────────────────────────────────────────────┐
        │                    Web Interface                            │
        │  • Dashboard (stats, health monitoring)                     │
        │  • ML Detector (flow analysis, detections)                  │
        │  • Suricata Config (datasets, rules, manual blocking)       │
        │  • Configuration (LLM, network topology)                    │
        │  • Bidirectional Suricata ↔ SLIPS sync                      │
        └─────────────────────────────────────────────────────────────┘
```

**Multi-Layer Defense:**

1. **Suricata IPS** (Signature + Dataset)
   - 350K+ domain hash table (O(1) lookup)
   - TLS SNI inspection blocks HTTPS at handshake
   - DNS/HTTP/TLS rules reference unified dataset
   - Manual domain blocking via SQLite backend
   - RFC1918 exemptions (won't block local DNS)

2. **SLIPS Behavioral Analysis** (ML + Modules)
   - Redis DB 0 for flow analysis
   - Native module system (IModule inheritance)
   - IP reputation and behavioral profiling
   - Integrates with Suricata via EVE JSON

3. **ad_flow_blocker** (Native Slips Module)
   - Flow-level blocking via conntrack
   - Surgical ad stream removal (not IP blacklisting)
   - Private IP filtering (RFC1918/loopback/link-local)
   - Subscribes to new_flow and new_dns Redis channels

4. **stream_ad_blocker** (Standalone Service)
   - Redis DB 1 (separate from SLIPS)
   - QUIC encrypted stream analysis
   - ML confidence-based classification
   - Auto training data (high/low confidence samples)
   - Triple blocking: conntrack, Suricata dataset, nftables

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
5. Blocks via URL/IP blocklist or Suricata NFQUEUE flow dropping
6. No payload decryption - analyzes flow metadata only

**Troubleshooting:**
```bash
# Check if service is receiving flows
journalctl -u stream-ad-blocker --since '1 minute ago' | grep "Processing flow"

# Verify SLIPS is publishing flows
redis-cli -n 0 PUBSUB CHANNELS | grep new_flow

# Check for detection patterns
journalctl -u stream-ad-blocker --since '5 minutes ago' | grep -E "quic_|preroll|ad_pod"

# View blocked IPs
redis-cli -n 1 SMEMBERS stream_ad_blocker:blocked_ips

# Clear all blocks
redis-cli -n 1 DEL stream_ad_blocker:blocked_ips
redis-cli -n 1 DEL stream_ad_blocker:blocked_urls
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

**Services not starting:**

```bash
systemctl status suricata slips
journalctl -xeu suricata
suricata -T -c /etc/suricata/suricata.yaml
```

**No blocking:**

```bash
tail -f /var/log/suricata/fast.log
nft list ruleset | grep forward
suricatasc -c "dataset-list"
```

**Interface issues:**

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
