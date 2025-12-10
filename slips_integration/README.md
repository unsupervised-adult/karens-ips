# SLIPS Web UI Integration

This directory contains the integration components for extending the Stratosphere Linux IPS (SLIPS) web interface with Karen's IPS ML Ad Detector.

## Overview

The integration adds a new "ML Detector" tab to the SLIPS web interface, providing real-time visualization of machine learning-based ad detection.

## Directory Structure

```bash
slips_integration/
├── README.md                      # This file
├── install.sh                     # Automated installation script

└── webinterface/
    └── ml_detector/               # ML Detector Flask Blueprint
        ├── __init__.py
        ├── ml_detector.py         # Backend routes and API endpoints
        ├── stream_ad_blocker.py   # QUIC stream ad blocking service
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
   - Login with default credentials: `admin` / `admin`
   - **Change password immediately** via user menu (top right) → Change Password
   - Click the "ML Detector" tab
   - Dashboard auto-refreshes every 5 seconds

## API Endpoints

The ML Detector blueprint provides the following REST API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ml_detector/` | GET | Main dashboard page |
| `/ml_detector/stats` | GET | Overall SLIPS evidence-based statistics |
| `/ml_detector/stream_stats` | GET | QUIC stream blocking statistics |
| `/ml_detector/detections/recent` | GET | Recent detections (last 100) |
| `/ml_detector/detections/timeline` | GET | Time-series data for charts |
| `/ml_detector/model/info` | GET | ML model metadata |
| `/ml_detector/features/importance` | GET | Feature importance scores |
| `/ml_detector/alerts` | GET | Recent alerts (last 50) |

## Redis Data Structure

The ML Detector reads from the following Redis keys:

**Database 0 (SLIPS Core Data):**

```bash
ml_detector:stats                   # Hash: SLIPS evidence-based statistics
ml_detector:recent_detections       # List: Recent detections
ml_detector:timeline                # List: Timeline data
ml_detector:model_info              # Hash: Model information
ml_detector:feature_importance      # Hash: Feature importance scores
ml_detector:alerts                  # List: Alerts
```

**Database 1 (Stream Ad Blocker):**

```bash
stream_ad_blocker:stats             # Hash: QUIC stream blocking statistics
  - total_analyzed                  # Total QUIC streams analyzed
  - ads_detected                    # Advertisement streams detected
  - ips_blocked                     # Unique IPs blocked
  - urls_blocked                    # Unique URLs blocked
  - legitimate_traffic              # Legitimate streams allowed
  - blocking_status                 # Active/Monitoring Only/Not Running
  - last_update                     # Last stats update timestamp
```

See [ML_DETECTOR_INTEGRATION.md](../ML_DETECTOR_INTEGRATION.md) for detailed data formats.

## Dashboard Features

The ML Detector dashboard displays two independent monitoring systems side-by-side:

### SLIPS Evidence Detection (Blue Cards)

Behavioral analysis using SLIPS core detection engine:

- Total packets analyzed
- Advertisements detected via ML behavioral analysis
- Legitimate traffic
- Model accuracy

### QUIC/HTTP3 Stream Analysis (Yellow Cards)

Real-time protocol inspection for syndication networks and telemetry:

- Total streams analyzed
- Suspicious flows filtered
- Unique endpoints blocked
- Service status (Active/Monitoring/Not Running)

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

### SLIPS ↔ Suricata Dataset Synchronization

The `slips_suricata_dataset_sync.py` service provides bidirectional integration between SLIPS behavioral analysis and Suricata signature-based detection.

**How It Works:**

1. **SLIPS → Suricata**: When SLIPS detects malicious behavior (C&C, port scans, malware), blocked IPs are added to `/var/lib/suricata/datasets/slips-blocked-ips.lst`
2. **Suricata → SLIPS**: High-priority Suricata alerts (severity 1-2) are fed back to SLIPS for behavioral correlation
3. **Combined Detection**: Both systems share intelligence for higher confidence blocking decisions

**Dataset Files:**

- `slips-blocked-ips.lst` - IPs blocked by SLIPS behavioral analysis
- `suricata-detected-ips.lst` - IPs detected by Suricata signatures
- `blocked-domains.lst` - Domains from blocklist DB (existing)

**Suricata Integration Rules:**

```suricata
# Auto-generated in /var/lib/suricata/rules/slips-integration.rules
drop ip $EXTERNAL_NET any -> $HOME_NET any (msg:"SLIPS Blocked IP (Behavioral)"; ip.src; dataset:isset,slips-blocked-ips; sid:9000001;)
drop ip $HOME_NET any -> $EXTERNAL_NET any (msg:"SLIPS Blocked IP Destination"; ip.dst; dataset:isset,slips-blocked-ips; sid:9000002;)
alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"Suricata + SLIPS Correlated Threat"; ip.src; dataset:isset,suricata-detected-ips; sid:9000003;)
```

**Service Management:**

```bash
# Start service
sudo systemctl start slips-suricata-sync

# Enable on boot
sudo systemctl enable slips-suricata-sync

# Check status
sudo systemctl status slips-suricata-sync

# View logs
sudo journalctl -fu slips-suricata-sync
```

**Statistics:**

Check Redis for sync statistics:

```bash
redis-cli HGETALL slips_suricata_sync:stats
```

### QUIC/HTTP3 Stream Analysis Engine

The stream_ad_blocker.py service provides real-time QUIC stream analysis and filtering with **dual focus**:

1. **Video Stream Ad Filtering** - Detects and blocks video advertisements in YouTube, Twitch, and streaming platforms
2. **Syndication Network Blocking** - Filters advertising syndication networks and telemetry endpoints

### Features

- **Protocol**: QUIC (UDP port 443) and HTTP/3 stream inspection
- **Video Ad Detection**: Identifies video ads by temporal patterns (duration, bitrate, packet sequences)
- **Detection Methods**:
  - Pattern matching for universal ad signatures (bumper ads, skippable ads, ad pods)
  - ML classifier for flow-based behavioral analysis
  - LLM enhancement for intelligent reasoning on borderline cases
- **Action**: Automatic IP blocking via nftables or monitoring-only mode
- **Statistics**: Real-time stats to Redis DB 1 for dashboard display
- **Dual Database**: Reads SLIPS data from DB 0, writes stats to DB 1

### Video Ad Detection Capabilities

**Supported Platforms:**
- YouTube (QUIC-based video delivery)
- Twitch (live streaming ads)
- Embedded video players (advertising syndication)
- Any QUIC/HTTP3 video service

**Ad Pattern Recognition:**
- **Bumper Ads**: 6-second non-skippable pre-roll ads
- **Skippable Ads**: 15-90 second ads with skip button at 5s
- **Non-Skippable Ads**: 15-30 second forced viewing ads
- **Ad Pods**: Sequential ad blocks (2x30s, 3x30s, 4x30s patterns)
- **Mid-Roll Ads**: Ads appearing during video playback
- **Ad Telemetry**: Tracking beacons and analytics pings

**Detection Methodology:**
1. **Temporal Analysis**: Matches flow duration to known ad length standards
2. **Bitrate Profiling**: Distinguishes ad streams from content by bitrate patterns
3. **Sequence Detection**: Identifies consecutive ad deliveries (ad pod patterns)
4. **ML Classification**: 8-feature model for flow behavioral analysis
5. **LLM Reasoning**: Intelligent analysis for uncertain cases with explainable decisions

**Why QUIC Requires Special Handling:**
- Traditional DNS/SNI filtering doesn't work (SNI encrypted in QUIC)
- Must analyze flow characteristics: duration, bitrate, packet patterns, temporal sequences
- Requires behavioral analysis rather than domain-based blocking

### Service Management

```bash
# Start service
sudo systemctl start stream-ad-blocker

# Enable on boot
sudo systemctl enable stream-ad-blocker

# Check status
sudo systemctl status stream-ad-blocker

# View logs
sudo journalctl -fu stream-ad-blocker
```

### Configuration

Edit `/etc/systemd/system/stream-ad-blocker.service`:

```ini
[Service]
Environment="BLOCKING_MODE=active"     # active or monitoring
Environment="REDIS_HOST=localhost"
Environment="REDIS_PORT=6379"
```

### LLM Integration

The stream blocker integrates with LLM (Large Language Model) for intelligent flow analysis on borderline cases where ML confidence is uncertain (0.60-0.85).

**Supported Models:**

- **IBM Granite 4-h-tiny**: Fast, efficient, good for real-time analysis (recommended)
- **Qwen 3-4B**: More detailed reasoning but slower
- **Custom Ollama models**: Any model compatible with OpenAI API

**Configure LLM via Redis:**

```bash
# Enable LLM with IBM Granite model (recommended)
redis-cli HSET ml_detector:llm_settings \
  enabled '1' \
  endpoint 'http://your-ollama-server:1234/v1' \
  api_key '' \
  model 'ibm/granite-4-h-tiny'

# Verify configuration
redis-cli HGETALL ml_detector:llm_settings
```

**Or configure via Web UI:**

1. Navigate to ML Detector tab
2. Click "Settings" or "Configure LLM"
3. Enable LLM integration
4. Enter Ollama endpoint URL
5. Select model: `ibm/granite-4-h-tiny`
6. Save settings

**How LLM Enhancement Works:**

1. Stream blocker captures QUIC flow (video stream)
2. ML classifier analyzes flow patterns:
   - Flow duration (matches ad length standards: 6s, 15s, 30s?)
   - Bitrate (ad streams vs content streams have different profiles)
   - Packet count and timing patterns
   - ASN/IP reputation
3. If ML confidence is borderline (0.60-0.85):
   - Calls LLM endpoint with enriched flow details
   - LLM prompt includes:
     - Flow characteristics (duration, bitrate, packet size)
     - Known video ad patterns (bumper, skippable, ad pods)
     - DNS history and IP context
     - Temporal patterns (is this part of an ad sequence?)
   - LLM analyzes against video ad signatures
   - Returns classification with explainable reasoning
4. Combines ML + LLM confidence for final decision
5. Stores LLM reasoning in Redis for dashboard display

**Example Video Ad Detection:**
```
Flow: 142.250.71.72:443 (googlevideo.com)
Duration: 6.1 seconds
Bitrate: 12 Kbps
Packets: 35

ML Analysis: 0.75 confidence (borderline)
LLM Analysis: "Short duration (6s) and low bitrate suggest bumper ad 
              rather than video content. Matches YouTube's 6-second 
              non-skippable ad pattern."
LLM Confidence: 0.85
Combined: 0.80 → BLOCK

Result: Ad blocked, content continues uninterrupted
```

### Multi-Layer Blocking Architecture

Once the system identifies ad flows with high confidence, it implements **progressive inline blocking** across multiple layers:

#### Layer 1: nftables IP Blocking (Immediate)

When confidence > 0.85, the IP is added to nftables blocked set for instant packet dropping:

```bash
# Automatic blocking by stream-ad-blocker service
sudo nft add element inet home blocked4 { 142.250.71.72 }

# View currently blocked IPs
sudo nft list set inet home blocked4

# Remove IP if false positive
sudo nft delete element inet home blocked4 { 142.250.71.72 }
```

**Effect**: All future packets from/to this IP are dropped at kernel level (fastest blocking)

#### Layer 2: Suricata Dataset Integration

High-confidence IPs are added to Suricata's dataset for signature-based correlation:

```bash
# Added to dataset file
echo "142.250.71.72" >> /var/lib/suricata/datasets/llm-blocked-ips.lst

# Suricata rule automatically triggers
drop ip $EXTERNAL_NET any -> $HOME_NET any (msg:"LLM-Detected Video Ad IP"; ip.src; dataset:isset,llm-blocked-ips; sid:9100001;)
```

**Effect**: Suricata logs the block, feeds back to SLIPS for behavioral correlation

#### Layer 3: SLIPS Evidence Correlation

Blocked IPs are fed into SLIPS as evidence for behavioral analysis:

```bash
# SLIPS correlates with other behavioral indicators
# If IP shows multiple bad behaviors, confidence increases
redis-cli HSET slips:blocked_ips 142.250.71.72 "llm_video_ad:0.85:2025-12-10"
```

**Effect**: Future flows from this IP start with negative reputation, faster detection

#### Progressive Blocking Flow

```
1. Initial Detection (First Flow)
   ├─ Duration: 6.1s, Bitrate: 12 Kbps
   ├─ ML: 0.75 (borderline) → Triggers LLM
   ├─ LLM: "Bumper ad pattern" → 0.85 confidence
   └─ Combined: 0.80 → ALLOW (learning phase)

2. Second Occurrence (Same IP, Similar Pattern)
   ├─ Duration: 6.0s, Bitrate: 11 Kbps  
   ├─ ML: 0.78 (learned from feedback)
   ├─ LLM: 0.87 confidence
   ├─ Combined: 0.825
   └─ Action: ADD TO MONITORING LIST

3. Third Occurrence (Pattern Confirmed)
   ├─ Duration: 6.2s, Bitrate: 12 Kbps
   ├─ ML: 0.82 (pattern reinforced)
   ├─ LLM: 0.90 confidence  
   ├─ Combined: 0.86 → CONFIDENCE THRESHOLD EXCEEDED
   └─ Action: INLINE BLOCK
       ├─ nftables: Immediate kernel-level drop
       ├─ Suricata: Dataset blocking + logging
       └─ SLIPS: Evidence correlation

4. Future Flows (IP Blocked)
   ├─ All packets from 142.250.71.72 dropped instantly
   ├─ No LLM analysis needed (IP already in blocklist)
   └─ Periodic review (24h) for false positive check
```

#### Adaptive Learning

The system learns and adapts:

- **Week 1**: Analyzes every borderline flow with LLM, blocks cautiously
- **Week 2**: ML model improves from feedback, fewer LLM calls needed
- **Week 3**: Known ad IP patterns blocked immediately at nftables
- **Week 4**: Self-tuning confidence thresholds based on accuracy

#### Monitoring Blocking Layers

```bash
# Layer 1: nftables blocks
sudo nft list set inet home blocked4 | wc -l

# Layer 2: Suricata dataset blocks
wc -l /var/lib/suricata/datasets/llm-blocked-ips.lst

# Layer 3: SLIPS evidence
redis-cli HLEN slips:blocked_ips

# LLM-enhanced blocks specifically
redis-cli -n 1 HGET stream_ad_blocker:stats llm_enhanced_detections

# Total inline blocks across all layers
tail -100 /var/log/suricata/fast.log | grep -c "LLM-Detected"
```

#### Safety Mechanisms

**False Positive Protection:**
- First detection: Log only, no block (confidence < 0.85)
- Second detection: Monitor and track (confidence 0.80-0.85)
- Third detection: Block after pattern confirmation (confidence > 0.85)
- Auto-unblock after 24h if no further detections
- User feedback loop via dashboard (mark as incorrect)

**Content Protection:**
- Content streams have consistent high bitrate (> 1000 Kbps)
- Ad streams have variable/low bitrate (5-50 Kbps)
- Duration clustering distinguishes ads from short content
- IP reputation considers ASN (Google/CDN trusted higher)

### Verification

Check real-time statistics:

```bash
# View stream stats
redis-cli -n 1 HGETALL stream_ad_blocker:stats

# Expected output:
# total_analyzed: 67
# ads_detected: 5
# ips_blocked: 5
# blocking_status: Active
# last_update: 2025-12-08 06:08:18
# llm_enhanced_detections: 12
```

Check LLM analysis results:

```bash
# View recent LLM analyses with reasoning
redis-cli LRANGE stream_blocker:llm_reasoning 0 4

# View LLM statistics
redis-cli HGETALL ml_detector:llm_stats
```

View blocked IPs in nftables (inline blocking):

```bash
# View all blocked IPs across layers
sudo nft list set inet home blocked4

# Count total blocked IPs
sudo nft list set inet home blocked4 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l

# Check if specific IP is blocked
sudo nft list set inet home blocked4 | grep "142.250.71.72"

# Real-time blocking events
sudo nft monitor | grep blocked4
```

Verify inline blocking is working:

```bash
# Test if blocked IP is actually dropped
ping -c 3 142.250.71.72
# Should timeout if inline blocking active

# Watch packet drops in real-time
sudo tcpdump -i any -nn host 142.250.71.72
# Should show no packets after blocking

# Suricata inline blocking stats
tail -100 /var/log/suricata/stats.log | grep -E "ips\.(accepted|blocked|rejected)"
# Expected output:
# ips.accepted    | 45231
# ips.blocked     | 342  ← Inline blocks
# ips.rejected    | 0
```

Monitor live LLM analysis (real-time):

```bash
# Watch LLM-enhanced detections in real-time
watch -n 1 'redis-cli -n 1 HGET stream_ad_blocker:stats llm_enhanced_detections'

# View most recent LLM analysis with reasoning
redis-cli LINDEX stream_blocker:llm_reasoning 0 | jq

# Test LLM endpoint directly (debugging)
curl -X POST http://localhost:55000/ml_detector/analyze_flow_with_llm \
  -H 'Content-Type: application/json' \
  -d '{
    "daddr": "142.250.71.72",
    "dport": 443,
    "packets": 35,
    "bytes": 9500,
    "duration": 6.1,
    "dns_history": ["googlevideo.com"],
    "ml_confidence": 0.75
  }' | jq
```

**Example LLM Response:**

```json
{
  "success": true,
  "classification": "ad_telemetry",
  "confidence": 0.85,
  "ml_confidence": 0.75,
  "combined_confidence": 0.80,
  "reasoning": "The flow exhibits key indicators of ad tracking/analytics. The short duration (6 seconds) and low bitrate (12 Kbps) suggest ad telemetry rather than video content.",
  "recommended_action": "block"
}
```

### Video Stream Filtering Best Practices

**For YouTube Ad Blocking:**

1. **Enable LLM Enhancement**: Essential for accurate QUIC flow classification
   ```bash
   redis-cli HSET ml_detector:llm_settings enabled '1' \
     endpoint 'http://your-ollama:1234/v1' \
     model 'ibm/granite-4-h-tiny'
   ```

2. **Monitor Detection Patterns**:
   ```bash
   # Watch for ad pod sequences (multiple ads in a row)
   sudo journalctl -u stream-ad-blocker -f | grep "ad_pod"
   
   # Check if legitimate content is being blocked (false positives)
   redis-cli LRANGE stream_blocker:llm_reasoning 0 10 | jq '.reasoning'
   ```

3. **Tune Confidence Thresholds**: Edit `ml_ad_classifier.py`
   ```python
   # Lower threshold = more aggressive blocking (may have false positives)
   # Higher threshold = more conservative (may miss some ads)
   BLOCKING_THRESHOLD = 0.75  # Default: 0.75 (75% confidence)
   ```

**Classification Types:**

| Classification | Description | Action |
|----------------|-------------|--------|
| `video_ad` | Confirmed video advertisement | Block immediately |
| `ad_telemetry` | Ad tracking/analytics beacon | Block immediately |
| `ad_pod` | Sequential ad delivery pattern | Block all flows in sequence |
| `legitimate_video` | Actual content stream | Allow |
| `uncertain` | Cannot determine (low confidence) | Allow (fail-safe) |

**Avoiding False Positives:**

- **Short Content Videos**: 6-second TikToks, Instagram Reels might match bumper ad patterns
  - Solution: Whitelist trusted social media IPs or ASNs
  
- **Live Stream Segments**: Some live streams use 6-15s chunks
  - Solution: ML learns to distinguish by bitrate (content = higher bitrate)
  
- **Video Previews**: Trailer/preview clips can be 15-30s
  - Solution: LLM considers context (preview bitrate higher than ads)

**Performance Tuning:**

```bash
# For high-traffic environments (100+ Mbps video streams)
# Adjust analysis interval in stream_ad_blocker.py
Environment="ANALYSIS_INTERVAL=30"  # Check flows every 30s (default: 10s)

# For low-latency requirements (gaming streams, video calls)
Environment="BLOCKING_MODE=monitoring"  # Log only, don't block
```

**Monitoring Effectiveness:**

```bash
# Check blocking effectiveness
redis-cli -n 1 HGET stream_ad_blocker:stats ads_detected
redis-cli -n 1 HGET stream_ad_blocker:stats legitimate_traffic

# Calculate block rate
echo "scale=2; $(redis-cli -n 1 HGET stream_ad_blocker:stats ads_detected) / \
$(redis-cli -n 1 HGET stream_ad_blocker:stats total_analyzed) * 100" | bc
# Expected: 5-15% for typical YouTube viewing
```

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

3. Check stream ad blocker stats (DB 1):

   ```bash
   redis-cli -n 1 HGETALL stream_ad_blocker:stats
   ```

4. Verify the web interface is connecting to the correct Redis instance

### QUIC Stream Blocking shows "Not Running"

**Problem**: QUIC Stream Blocking section shows "Not Running" with zeros

**Solutions**:

1. Check stream-ad-blocker service status:

   ```bash
   sudo systemctl status stream-ad-blocker
   ```

2. Verify service is writing to Redis DB 1:

   ```bash
   redis-cli -n 1 HGETALL stream_ad_blocker:stats
   ```

3. Check web UI is reading from correct database (ml_detector.py should use redis_db1 connection)

4. Restart web UI after any changes:

   ```bash
   sudo systemctl restart slips-webui
   ```

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

## TLS SNI Blocking Rules Generation

Karen's IPS includes a powerful feature to generate Suricata drop rules from blocked domains database for true inline IPS blocking based on TLS Server Name Indication (SNI).

### Overview

The TLS SNI blocking system enables **true IPS mode** where Suricata directly drops packets inline when the TLS handshake contains a Server Name Indication matching domains in your blocklist database. This is more efficient than external scripts and provides real intrusion prevention.

### How It Works

1. **Blocklist Database**: 344,806+ blocked domains stored in `/var/lib/suricata/ips_filter.db`
2. **Rule Generation**: Python script reads domains and generates Suricata `drop` rules
3. **Inline Blocking**: Suricata inspects TLS handshakes and drops matching packets in real-time
4. **NFQueue Mode**: Traffic flows through NFQueue where Suricata performs inline inspection

### Components

- **Script**: `generate_suricata_rules.py` - Converts domains to Suricata drop rules
- **Rules File**: `/var/lib/suricata/rules/ml-detector-blocking.rules` - Generated drop rules (~58 MB)
- **Web UI**: Suricata Dashboard → Configuration tab → "TLS SNI Blocking Rules"
- **Backup**: Automatic backup of old rules to `/var/lib/suricata/rules/backups/`

### Usage

#### Via Web Interface

1. Navigate to `http://your-ip:55000/suricata/`
2. Click the **Configuration** tab
3. Scroll to **"TLS SNI Blocking Rules"** section
4. Click **"Check Status"** to view current state:
   - Domains in Database: 344,806
   - Rules Generated: 344,806
   - Last Updated: timestamp
   - Status: Up to Date / Needs Regeneration

5. Click **"Generate TLS SNI Rules"** to create/update rules:
   - Backs up existing rules automatically
   - Generates fresh rules from database (takes 2-3 minutes)
   - Reloads Suricata to activate new rules

#### Via Command Line

```bash
sudo python3 /opt/StratosphereLinuxIPS/generate_suricata_rules.py
```

### When to Regenerate Rules

Regenerate TLS SNI blocking rules after:

- Importing new blocklists (Hagezi, Perflyst, etc.)
- Manually adding domains to the database
- Blocklist repository updates
- Database shows more domains than generated rules

### Web UI Buttons Explained

| Button | Function | Safe? | What It Does |
|--------|----------|-------|--------------|
| **Check Status** | Read-only status check | ✅ Yes | Displays current stats without modifying anything |
| **Generate TLS SNI Rules** | Full rule regeneration | ⚠️ Takes 2-3 min | Replaces all rules with fresh ones from database |

**Check Status** - Safe to use anytime:

- Queries database for domain count
- Checks rules file existence and counts rules
- Shows last generation timestamp
- Displays sync status with color coding (green/yellow/red)

**Generate TLS SNI Rules** - Creates fresh rules:

1. Backs up old rules with timestamp
2. Reads all domains from database
3. Generates Suricata drop rules with TLS SNI matching
4. Writes 58 MB rules file (~344k rules)
5. Reloads Suricata to activate rules immediately

### Technical Details

**Rule Format:**

```
drop tls any any -> any any (msg:"Blocked ads domain: example.com"; tls.sni; content:"example.com"; nocase; classtype:policy-violation; sid:9000000; rev:1;)
```

**Database:**

- Path: `/var/lib/suricata/ips_filter.db`
- Tables: `blocked_domains`, `blocklist_sources`, `blocklist_metadata`
- Domains: 344,806+ ad/tracking/malware domains

**Generated Rules:**

- Output: `/var/lib/suricata/rules/ml-detector-blocking.rules`
- Size: ~58 MB (344,806 rules + header)
- SID Range: 9000000 - 9344806 (avoids conflicts)

**Suricata Configuration:**

- Mode: NFQueue (`suricata -q 0`)
- Rules loaded: Configured in `/etc/suricata/suricata.yaml`
- Reload: Graceful via `systemctl reload suricata`

### Verification

Check that rules are active and blocking:

```bash
# View Suricata stats
tail -100 /var/log/suricata/stats.log | grep ips.blocked

# Expected output:
# ips.blocked                    | Total                     | 146

# Check generated rules
wc -l /var/lib/suricata/rules/ml-detector-blocking.rules

# View recent blocks in logs
tail -f /var/log/suricata/fast.log | grep "Blocked ads domain"
```

### Backup & Recovery

**Automatic Backups:**

- Location: `/var/lib/suricata/rules/backups/`
- Format: `ml-detector-blocking.rules.YYYYMMDD_HHMMSS`
- Created before each regeneration

**Manual Restore:**

```bash
# List backups
ls -lh /var/lib/suricata/rules/backups/

# Restore from backup
sudo cp /var/lib/suricata/rules/backups/ml-detector-blocking.rules.20251207_235201 \
        /var/lib/suricata/rules/ml-detector-blocking.rules

# Reload Suricata
sudo systemctl reload suricata
```

### API Endpoints

The Suricata web interface provides REST API endpoints for rule management:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/suricata/api/tls-sni/generate-rules` | POST | Generate TLS SNI rules from database |
| `/suricata/api/tls-sni/rules-status` | GET | Get current rules status and counts |

**Example API Usage:**

```bash
# Check status
curl http://localhost:55000/suricata/api/tls-sni/rules-status

# Generate rules
curl -X POST http://localhost:55000/suricata/api/tls-sni/generate-rules
```

### Performance Considerations

**Rule Loading:**

- 344k rules load in ~10 seconds on modern hardware
- Memory usage: ~500 MB additional RAM for rule storage
- No noticeable performance impact on packet processing

**Generation Time:**

- Small database (<10k domains): ~5 seconds
- Medium database (100k domains): ~30 seconds
- Large database (344k domains): ~2-3 minutes

**Blocking Performance:**

- Inline inspection: < 1ms latency per packet
- TLS SNI lookup: Constant time O(1) via hash table
- No external script overhead

### Troubleshooting

**Rules not blocking traffic:**

1. Verify Suricata is in IPS mode:

   ```bash
   ps aux | grep suricata
   # Should show: suricata -q 0
   ```

2. Check rules are loaded:

   ```bash
   grep "ml-detector-blocking.rules" /etc/suricata/suricata.yaml
   ```

3. Verify nftables is sending traffic to queue:

   ```bash
   sudo nft list ruleset | grep queue
   ```

**Generation fails:**

1. Check database exists:

   ```bash
   ls -lh /var/lib/suricata/ips_filter.db
   ```

2. Verify permissions:

   ```bash
   sudo chown root:root /opt/StratosphereLinuxIPS/generate_suricata_rules.py
   sudo chmod +x /opt/StratosphereLinuxIPS/generate_suricata_rules.py
   ```

3. Check disk space:

   ```bash
   df -h /var/lib/suricata/
   # Need ~100 MB free
   ```

**Web UI button not showing:**

1. Clear browser cache (Ctrl+Shift+R)
2. Verify files deployed:

   ```bash
   ls -l /opt/StratosphereLinuxIPS/webinterface/suricata_config/
   ```

3. Restart web interface:

   ```bash
   sudo systemctl restart slips-webui
   ```

## License

SPDX-License-Identifier: GPL-2.0-only

## Support

For issues and questions:

- Create an issue in the Karen's IPS repository
- Refer to the main integration documentation: [ML_DETECTOR_INTEGRATION.md](../ML_DETECTOR_INTEGRATION.md)
