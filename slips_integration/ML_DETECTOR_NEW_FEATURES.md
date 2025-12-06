# ML Detector WebUI - New Features

## Overview

The ML Detector WebUI has been enhanced with three major feature sets to provide complete control over the IPS system through the web interface.

## 🔧 Features Added

### 1. Exception/Whitelist Management

Add domains, IPs, URLs, or CIDR ranges to whitelist via the WebUI.

**API Endpoints:**

- `GET /ml_detector/exceptions/list` - List all exceptions
- `POST /ml_detector/exceptions/add` - Add new exception
- `POST /ml_detector/exceptions/remove` - Remove exception
- `POST /ml_detector/exceptions/check` - Check if value is whitelisted
- `GET /ml_detector/exceptions/stats` - Get exception statistics

**Request Format (Add Exception):**
```json
{
  "type": "domain",           // Options: ip, domain, url, cidr
  "value": "example.com",
  "reason": "Trusted website",
  "permanent": true,           // Optional: false for temporary
  "expires_hours": 24          // Optional: hours until expiry
}
```

**Response Format:**
```json
{
  "success": true,
  "message": "Domain exception added successfully"
}
```

**Integration:**
- Uses existing `/home/ficus/Documents/Project-Code/IPS/karens-ips/src/exception_manager.py`
- Exceptions stored in database and synced with Suricata
- Supports temporary exceptions with auto-expiry
- Full CRUD operations via WebUI

### 2. URL Pattern Management

Add custom regex patterns for ad detection and content identification.

**API Endpoints:**

- `GET /ml_detector/patterns/list` - List custom patterns
- `POST /ml_detector/patterns/add` - Add new pattern
- `POST /ml_detector/patterns/remove` - Remove pattern
- `POST /ml_detector/patterns/test` - Test pattern against URLs

**Request Format (Add Pattern):**
```json
{
  "type": "ad",                                    // Options: ad, content
  "pattern": ".*doubleclick\\.net",               // Regex pattern
  "description": "DoubleClick ad server"
}
```

**Test Pattern:**
```json
{
  "pattern": ".*googlevideo\\.com/videoplayback.*&adsid=",
  "test_urls": [
    "https://googlevideo.com/videoplayback?id=123&adsid=yes",
    "https://googlevideo.com/videoplayback?id=456"
  ]
}
```

**Response (Test):**
```json
{
  "success": true,
  "results": [
    {"url": "https://googlevideo.com/videoplayback?id=123&adsid=yes", "matches": true},
    {"url": "https://googlevideo.com/videoplayback?id=456", "matches": false}
  ]
}
```

**Integration:**
- Patterns stored in Redis (`ml_detector:custom_patterns`)
- Real-time regex validation
- Test patterns before applying
- Import/export capability

### 3. ML Engine Configuration (Already Existing - Enhanced)

Adjust ML detection parameters and apply presets.

**Existing Endpoints:**

- `GET /ml_detector/config` - Get configuration
- `POST /ml_detector/config` - Update configuration
- `POST /ml_detector/settings/preset/<preset_name>` - Apply preset

**Available Presets:**

1. **Aggressive** - Lower thresholds, more detections
   - Min duration: 90s → 3s
   - Confidence: 75% → 60%

2. **Conservative** - Higher thresholds, fewer false positives
   - Min duration: 150s
   - Confidence: 85%

3. **Short Videos** - Optimized for TikTok/Shorts
   - Min duration: 60s
   - Ad duration: 3-30s

4. **QUIC Optimized** - Enhanced for encrypted traffic
   - Timing importance: 2.5x
   - Size importance: 1.5x

## 🎨 Workflow Examples

### Quick Whitelist from Detection

When you see a false positive in the detections table:

1. Click "Whitelist" button on the detection
2. Modal appears with domain pre-filled
3. Add reason: "Netflix streaming"
4. Click "Add Exception"
5. Detection stops immediately

### Add Custom Ad Pattern

For a new ad server you discovered:

1. Go to "Patterns" tab
2. Enter pattern: `.*newadserver\.com.*`
3. Click "Test Pattern"
4. Enter test URLs to validate
5. Click "Add Pattern"
6. Pattern active immediately

### Adjust Detection Sensitivity

For a noisy environment:

1. Go to "Settings" tab
2. Click "Conservative" preset
3. Or manually adjust:
   - Confidence threshold: 85%
   - Min duration: 150s
4. Click "Save & Restart"
5. ML engine restarts with new settings

## 📊 Dashboard Integration

All features integrate into the existing ML Detector dashboard tabs:

```
┌─────────────────────────────────────────────┐
│ ML Detector Dashboard                       │
├─────────────────────────────────────────────┤
│ [Overview] [Exceptions] [Patterns] [Settings] │
└─────────────────────────────────────────────┘

Overview:
  - Statistics cards
  - Detection timeline chart
  - Recent detections table
  - Alerts feed

Exceptions (NEW):
  - Exception type selector (IP/Domain/URL/CIDR)
  - Add exception form with reason
  - Exceptions table with remove buttons
  - Quick "whitelist this" on detections
  - Statistics: Total exceptions by type

Patterns (NEW):
  - Pattern type selector (Ad/Content)
  - Regex pattern input with validation
  - Pattern tester with sample URLs
  - Patterns table with edit/remove
  - Export/import pattern sets

Settings (Enhanced):
  - Preset buttons (Aggressive/Conservative/etc.)
  - Threshold sliders
  - Detection method toggles
  - Model info display
  - Restart service button
```

## 🔒 Security Considerations

- All endpoints validate input
- Regex patterns validated before storage
- SQL injection prevention via parameterized queries
- Exception manager uses existing secure database
- Service restarts require sudo (handled by systemd)

## 🚀 Deployment

### Installation Steps

1. Run the installer (includes ML detector integration):
```bash
cd karens-ips
sudo bash karens-ips-installer.sh
```

2. Access WebUI:
```
http://[SERVER-IP]:55000
```

3. Navigate to "ML Detector" tab

### API Testing

Test exception management:
```bash
# List exceptions
curl http://localhost:55000/ml_detector/exceptions/list

# Add domain exception
curl -X POST http://localhost:55000/ml_detector/exceptions/add \
  -H "Content-Type: application/json" \
  -d '{"type":"domain","value":"netflix.com","reason":"Streaming service"}'

# Remove exception
curl -X POST http://localhost:55000/ml_detector/exceptions/remove \
  -H "Content-Type: application/json" \
  -d '{"type":"domain","value":"netflix.com"}'
```

Test pattern management:
```bash
# List patterns
curl http://localhost:55000/ml_detector/patterns/list

# Add ad pattern
curl -X POST http://localhost:55000/ml_detector/patterns/add \
  -H "Content-Type: application/json" \
  -d '{"type":"ad","pattern":".*badads\\.com","description":"Bad ad server"}'

# Test pattern
curl -X POST http://localhost:55000/ml_detector/patterns/test \
  -H "Content-Type: application/json" \
  -d '{"pattern":".*google.*","test_urls":["https://google.com","https://facebook.com"]}'
```

## 📝 TODO: Frontend Implementation

The backend API endpoints are complete. Still needed:

1. **Exception Management Tab UI**
   - Form for adding exceptions
   - Table displaying current exceptions
   - Delete buttons
   - Filter by type (IP/Domain/URL/CIDR)

2. **Pattern Management Tab UI**
   - Pattern input form with type selector
   - Regex tester with live feedback
   - Pattern library table
   - Export/Import buttons

3. **Enhanced Settings Tab UI**
   - Preset quick-select buttons
   - Slider controls for thresholds
   - Toggle switches for detection methods
   - Visual feedback on save/restart

4. **Quick Actions on Detections Table**
   - "Whitelist" button on each detection row
   - Modal for adding exception with pre-filled domain
   - Success/error notifications

## 🔗 Integration Points

### With Exception Manager
```python
from src.exception_manager import ExceptionManager

manager = ExceptionManager()
manager.add_domain_exception("example.com", "Whitelisted via UI", "webui")
```

### With Redis
```python
# Pattern storage
db.rdb.r.hset("ml_detector:custom_patterns", "ad_patterns", json.dumps(patterns))

# Pattern retrieval
patterns = db.rdb.r.hgetall("ml_detector:custom_patterns")
```

### With Suricata
Exceptions automatically sync to:
- `/etc/suricata/rules/exceptions.rules`
- Suricata datasets
- nftables ipsets

## 📈 Future Enhancements

1. **Bulk Operations**
   - Import exception lists from CSV
   - Export patterns as JSON
   - Batch remove exceptions

2. **Advanced Pattern Management**
   - Pattern categories/tags
   - Pattern effectiveness metrics
   - Pattern sharing/community library

3. **Smart Whitelisting**
   - AI-suggested exceptions based on false positives
   - Automatic temporary whitelist for trusted users
   - Learning mode for new environments

4. **Enhanced Configuration**
   - Schedule-based settings (aggressive during day, conservative at night)
   - Per-network/VLAN settings
   - A/B testing for detection methods

## 🐛 Known Limitations

1. Service restart requires sudo privileges
   - Handled gracefully with warning message
   - Manual restart if automation fails

2. Pattern validation is basic
   - Only checks regex syntax
   - Doesn't validate effectiveness
   - No performance impact analysis

3. Exception manager path hardcoded
   - Assumes `/opt/StratosphereLinuxIPS` location
   - May need adjustment for custom installations

## ✅ Testing Checklist

After installation:

- [ ] Access http://[IP]:55000/ml_detector/
- [ ] Test /ml_detector/exceptions/list endpoint
- [ ] Add domain exception via API
- [ ] Verify exception in list
- [ ] Remove exception via API
- [ ] Test pattern validation with invalid regex
- [ ] Add valid ad pattern
- [ ] Test pattern against sample URLs
- [ ] Remove pattern
- [ ] Apply preset configuration
- [ ] Verify ML engine restart
- [ ] Check exception manager database directly

## 📚 Related Files

- `/home/ficus/Documents/Project-Code/IPS/karens-ips/slips_integration/webinterface/ml_detector/ml_detector.py` - Main blueprint with all endpoints
- `/home/ficus/Documents/Project-Code/IPS/karens-ips/src/exception_manager.py` - Exception management backend
- `/home/ficus/Documents/Project-Code/IPS/karens-ips/scripts/manage-exceptions.py` - CLI tool for exceptions
- `/home/ficus/Documents/Project-Code/IPS/karens-ips/slips_integration/webinterface/app.py` - Flask app (fixed blueprint registration)

## 🎓 Architecture Notes

The implementation follows Flask Blueprint best practices:
- RESTful API design
- JSON request/response format
- Proper error handling with HTTP status codes
- Logging for debugging
- Graceful degradation when services unavailable
- Integration with existing Karen's IPS components
