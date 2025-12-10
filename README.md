# Karen's IPS

Enterprise-grade Intrusion Prevention System combining ML behavioral analysis with signature-based detection for network security and traffic intelligence.

## Features

- **Behavioral Analysis** - ML-powered threat detection with adaptive learning (SLIPS)
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
systemctl status suricata slips slips-webui redis-server
systemctl restart suricata
journalctl -fu slips
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

# Redis stats
redis-cli -n 1 hgetall ml_detector:stats

# Dataset info
suricatasc -c "dataset-list"
```

## Configuration

**HOME_NET:** Set in web UI → Configuration tab

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
