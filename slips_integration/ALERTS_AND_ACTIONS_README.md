# ML Detector Alerts & Actions Setup Guide

This guide explains how to set up and use the new **Alerts & Actions** functionality in the Karen's IPS ML Detector dashboard.

## Features

### 🛡️ Live Blocking Control

- Toggle automatic threat blocking on/off
- When enabled, detected threats are automatically blocked at the firewall level using **nftables**
- Visual status indicators showing current blocking state

### ✅ IP Whitelist

- Add trusted IP addresses that will NEVER be blocked
- Supports individual IPs and CIDR notation (e.g., `192.168.1.0/24`)
- Default whitelisted: `127.0.0.1`, `::1` (localhost)

### 🚫 IP Blacklist

- Manually block specific IP addresses
- Automatically adds firewall rules when blocking is enabled
- Easy unblock functionality

### 📊 Detection Feedback & Model Training

- Review recent detections in an interactive table
- Mark detections as "Correct" (true positive) or "False Positive"
- Feedback is stored for continuous model improvement
- Automatic suggestion to whitelist IPs with multiple false positives

### ⚡ Quick Actions

- **Clear All Blocks**: Remove all firewall rules and blacklisted IPs
- **Retrain Model Now**: Force immediate model retraining with feedback data
- **Export Detections**: Download all detections as CSV file
- **View System Logs**: Display recent system activity and actions

## Installation

### Prerequisites

- Karen's IPS with SLIPS integration installed
- Redis server running
- nftables installed (NOT iptables!)
- Root access for initial setup

### Setup Steps

1. **Run the setup script as root:**

   ```bash
   cd /path/to/karens-ips/slips_integration
   sudo ./setup_ml_detector_blocking.sh
   ```

   This script will:
   - Auto-detect your web server user (www-data, apache, nginx)
   - Configure sudoers to allow nftables commands
   - Create nftables table, set, and rules for IP blocking
   - Make nftables rules persistent across reboots
   - Initialize Redis data structures
   - Add default whitelist entries (localhost)
   - Test permissions

2. **Restart your web server:**

   ```bash
   # For Apache
   sudo systemctl restart apache2

   # For Nginx
   sudo systemctl restart nginx
   ```

3. **Start the ML data feeder (if not already running):**

   ```bash
   cd /path/to/karens-ips/slips_integration
   python3 simple_ml_feeder.py
   ```

## Usage

### Accessing the Dashboard

**Standalone Version:**

- Navigate to: `http://your-server/ml_detector/standalone`
- Click on the "Alerts & Actions" tab

**Integrated Version:**

- Navigate to: `http://your-server/ml_detector/`
- Click on the "Alerts & Actions" tab

### Enabling Live Blocking

⚠️ **IMPORTANT: Whitelist your own IP before enabling blocking!**

1. Go to the "Alerts & Actions" tab
2. In the **IP Whitelist** section, add your IP address
3. Click "Add"
4. Toggle the **Live Blocking Control** switch to ON
5. Confirm the status shows "Active" with a green badge

### Managing Whitelisted IPs

**To add an IP to whitelist:**

1. Enter IP address in the "IP Whitelist" input field
2. Supports:
   - Single IP: `192.168.1.100`
   - CIDR notation: `192.168.1.0/24`
3. Click "Add"

**To remove from whitelist:**

1. Find the IP in the whitelist
2. Click the "Remove" button next to it
3. Confirm the removal

### Managing Blacklisted IPs

**To manually block an IP:**

1. Enter IP address in the "IP Blacklist" input field
2. Click "Block"
3. Confirm the action
4. If live blocking is enabled, the IP is immediately blocked at the firewall

**To unblock an IP:**

1. Find the IP in the blacklist
2. Click the "Unblock" button
3. Confirm the action
4. The IP is removed from the blacklist and firewall

### Providing Detection Feedback

1. Go to the **Detection Feedback & Model Training** section
2. Review recent detections in the table
3. For each detection:
   - Click **"Correct"** if it's a true positive (legitimate threat)
   - Click **"False Positive"** if it was incorrectly flagged

4. Feedback is stored and used for model retraining
5. If an IP gets 3+ false positives within 24 hours, consider whitelisting it

### Using Quick Actions

**Clear All Blocks:**

- Removes ALL firewall rules and blacklisted IPs
- Use with caution!
- Whitelisted IPs are NOT affected

**Retrain Model Now:**

- Forces immediate model retraining
- Requires at least 10 feedback samples
- Updates the "Last Trained" timestamp
- May take several minutes

**Export Detections:**

- Downloads all detections as a CSV file
- Filename format: `ml_detections_YYYYMMDD_HHMMSS.csv`
- Includes: timestamp, IPs, protocol, port, classification, confidence, threat level, description

**View System Logs:**

- Displays the last 100 system actions
- Shows: blocking enabled/disabled, IPs added/removed, feedback submitted, etc.
- Useful for auditing and troubleshooting

## API Endpoints

All endpoints are prefixed with `/ml_detector/`

| Endpoint | Methods | Description |
|----------|---------|-------------|
| `/blocking/status` | GET, POST | Get or set live blocking status |
| `/whitelist` | GET, POST, DELETE | Manage IP whitelist |
| `/blacklist` | GET, POST, DELETE | Manage IP blacklist |
| `/feedback` | POST | Submit detection feedback |
| `/actions/clear_blocks` | POST | Clear all firewall blocks |
| `/actions/retrain` | POST | Force model retraining |
| `/actions/export` | GET | Export detections as CSV |
| `/actions/logs` | GET | Get recent system logs |

### Example API Calls

**Enable live blocking:**

```bash
curl -X POST http://localhost/ml_detector/blocking/status \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'
```

**Add IP to whitelist:**

```bash
curl -X POST http://localhost/ml_detector/whitelist \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100"}'
```

**Block an IP:**

```bash
curl -X POST http://localhost/ml_detector/blacklist \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.0.0.5"}'
```

**Submit feedback:**

```bash
curl -X POST http://localhost/ml_detector/feedback \
  -H "Content-Type: application/json" \
  -d '{
    "detection": {...},
    "feedback": "false_positive",
    "source_ip": "192.168.1.50",
    "classification": "Port Scan"
  }'
```

## nftables Configuration

### Table and Set Structure

The setup creates the following nftables configuration:

```nftables
table inet filter {
    set ml_detector_blacklist {
        type ipv4_addr
        flags interval
    }

    chain input {
        type filter hook input priority 0; policy accept;
        ip saddr @ml_detector_blacklist drop
    }
}
```

### Manual nftables Commands

**List blacklisted IPs:**

```bash
sudo nft list set inet filter ml_detector_blacklist
```

**Add IP manually:**

```bash
sudo nft add element inet filter ml_detector_blacklist "{ 192.168.1.100 }"
```

**Remove IP manually:**

```bash
sudo nft delete element inet filter ml_detector_blacklist "{ 192.168.1.100 }"
```

**Flush entire blacklist:**

```bash
sudo nft flush set inet filter ml_detector_blacklist
```

## Redis Data Structures

### Keys Used

- `ml_detector:blocking_enabled` - String: "0" or "1"
- `ml_detector:whitelist` - Set: Whitelisted IP addresses
- `ml_detector:blacklist` - Set: Blacklisted IP addresses
- `ml_detector:feedback` - List: Detection feedback entries (last 10,000)
- `ml_detector:action_logs` - List: System action logs (last 500)
- `ml_detector:fp_count:{ip}` - Counter: False positive count per IP (expires after 24h)
- `ml_detector:processed_evidence` - Set: Already processed evidence IDs

## Troubleshooting

### Live blocking toggle doesn't work

1. Check if nftables is running: `sudo systemctl status nftables`
2. Verify sudoers configuration: `sudo cat /etc/sudoers.d/ml_detector_iptables`
3. Test permissions: `sudo -u www-data sudo nft list set inet filter ml_detector_blacklist`

### IPs not being blocked

1. Confirm live blocking is **enabled** (toggle shows "Active")
2. Check nftables blacklist: `sudo nft list set inet filter ml_detector_blacklist`
3. Verify the IP is in Redis blacklist: `redis-cli SMEMBERS ml_detector:blacklist`
4. Check system logs in the dashboard

### Cannot add IP to whitelist/blacklist

1. Verify IP address format (must be valid IPv4 or CIDR)
2. Check Redis connection: `redis-cli PING`
3. Check browser console for JavaScript errors

### Model retraining fails

1. Ensure at least 10 feedback samples exist
2. Check Redis: `redis-cli LLEN ml_detector:feedback`
3. View error in system logs or web server logs

### nftables rules not persistent after reboot

1. Check if nftables service is enabled: `sudo systemctl is-enabled nftables`
2. Enable if needed: `sudo systemctl enable nftables`
3. Verify configuration file exists:
   - `/etc/nftables.d/ml_detector.nft` OR
   - Rules in `/etc/nftables.conf`

## Security Considerations

1. **Always whitelist your own IP before enabling live blocking**
2. **Test thoroughly before using in production**
3. **Monitor system logs regularly for false positives**
4. **Keep a backup method to access the system** (console, IPMI, etc.)
5. **Consider whitelisting management IPs and trusted networks**
6. **Review blacklist periodically** - some IPs may be temporarily malicious

## Files Modified/Created

**Backend:**

- `webinterface/ml_detector/ml_detector_live.py` - Added 8 new API endpoints (450+ lines)

**Frontend (Standalone):**

- `webinterface/ml_detector/templates/ml_detector_standalone.html` - Added Alerts & Actions tab HTML
- JavaScript handlers for all functionality (400+ lines)

**Frontend (Integrated):**

- `webinterface/ml_detector/templates/ml_detector.html` - Added Alerts & Actions tab HTML
- `webinterface/ml_detector/static/js/ml_detector.js` - Added JavaScript handlers (400+ lines)

**Setup:**

- `setup_ml_detector_blocking.sh` - Automated setup script
- `/etc/sudoers.d/ml_detector_iptables` - Sudoers configuration for nftables
- `/etc/nftables.d/ml_detector.nft` - Persistent nftables configuration

## Support

For issues or questions:

1. Check the troubleshooting section above
2. Review system logs: `sudo journalctl -u apache2 -f` (or nginx)
3. Check Redis logs if needed
4. Examine nftables rules: `sudo nft list ruleset`

## License

GPL-2.0-only (same as Karen's IPS)
