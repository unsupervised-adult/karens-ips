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
Internet → br0 (bridge) → NFQUEUE → Suricata (datasets) → SLIPS (ML) → nftables
                                         ↓                      ↓
                                   EVE JSON              Redis DB
                                         ↓                      ↓
                                   Web UI ←→ SLIPS ↔ Suricata Sync
```

**Dataset approach:**

- 3 Suricata rules (DNS/HTTP/TLS) reference 1 hash table
- O(1) lookup for 350K+ domains (hagezi Pro, perflyst SmartTV/Android)
- TLS SNI inspection blocks HTTPS traffic at handshake
- DNS dataset integration with SQLite backend
- RFC1918 exemptions (won't block local DNS)

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

**Service Management:**
```bash
# Status check
sudo systemctl status stream-ad-blocker
journalctl -u stream-ad-blocker --since '10 minutes ago'

# View real-time detections
journalctl -fu stream-ad-blocker | grep -E "BLOCKED|detected"

# Check detection stats
redis-cli -n 1 HGETALL stream_ad_blocker:stats

# View recent detections (JSON format)
redis-cli -n 1 LRANGE ml_detector:recent_detections 0 10

# Restart service after config changes
sudo systemctl restart stream-ad-blocker
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
