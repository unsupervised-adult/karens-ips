# Karen's IPS

Hybrid Intrusion Prevention System combining ML behavioral analysis (SLIPS) with signature-based detection (Suricata).

## Features

- **SLIPS** - ML behavioral threat detection with adaptive learning
- **Suricata 8.0** - High-performance IPS in NFQUEUE bridge mode
- **Dataset Blocking** - 350K+ domains with O(1) hash lookup (3 rules + hash table)
- **SLIPS ↔ Suricata Sync** - Bidirectional IP blocking correlation
- **Web UI** - SLIPS dashboard, ML detector, Suricata config, LLM integration
- **12 Free Rule Sources** - ET Open, abuse.ch, tgreen/hunting, stamus/lateral, etc.

## Installation

**Single command:**

```bash
sudo ./karens-ips-installer.sh
```

**Time:** 15-30 minutes

**What gets installed:**
- Suricata 8.0 (NFQUEUE bridge mode)
- SLIPS ML engine with Redis
- Dataset-based domain blocking
- Web UI with nginx reverse proxy
- Community blocklists (hagezi, perflyst)
- SystemD services

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

**Import blocklists:**

1. Open web UI → Suricata tab → DNS Blocklists
2. Click "Pro" or "Normal" to import hagezi lists
3. Click "Sync to Suricata" to apply
4. Generate dataset: Configuration tab → "Generate Dataset"

## Web UI Tabs

**SLIPS** - Network flows, behavioral analysis, evidence viewer

**ML Detector** - Ad detection stats, QUIC analysis, model performance

**Suricata** - Rules, datasets, blocklists, CLI commands

**Configuration** - HOME_NET, dataset generation, LLM settings

**Actions** - Reload rules, update sources, whitelist IPs

**Database** - Query blocked domains, manage sources, sync to Suricata

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
- O(1) lookup for 350K+ domains
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

**LLM integration:** Configuration tab → LLM Settings (OpenAI/Ollama)

**Blocklists:** Suricata tab → DNS Blocklists → Import → Sync

**Whitelist:** Actions tab → Manual Whitelist Entry

## Requirements

- Ubuntu 24.04 LTS
- 8GB+ RAM
- 2+ CPU cores
- Bridge interface (br0)

## License

GPL-2.0

## Credits

- SLIPS by Stratosphere Laboratory
- Suricata by OISF
- Blocklists by hagezi, perflyst

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

## License

GPL-2.0

## Credits

- SLIPS by Stratosphere Laboratory
- Suricata by OISF
- Blocklists by hagezi, perflyst
- **Feature Importance**: ML model feature weights visualization
