#!/bin/bash
# Deploy ML Dynamic IP Blocker (Dataset Mode - No Reloads!)

set -e

echo "Deploying ML Dynamic IP Blocker (Dataset Mode)..."

# Create required directories
echo "[*] Creating required directories..."
sudo mkdir -p /var/lib/suricata
sudo chmod 755 /var/lib/suricata
sudo mkdir -p /etc/suricata/rules

# Copy the Python script
echo "[*] Installing dynamic rule generator..."
sudo cp slips_integration/dynamic_rule_generator.py /opt/StratosphereLinuxIPS/
sudo chmod +x /opt/StratosphereLinuxIPS/dynamic_rule_generator.py

# Copy systemd service
echo "[*] Installing systemd service..."
sudo cp slips_integration/services/ml-dynamic-rules.service /etc/systemd/system/
sudo systemctl daemon-reload

# Check if dynamic rules file is in suricata.yaml
if ! sudo grep -q "ml-dynamic-blocks.rules" /etc/suricata/suricata.yaml; then
    echo "[*] Adding dynamic rules to suricata.yaml..."
    sudo sed -i '/rule-files:/a\  - ml-dynamic-blocks.rules' /etc/suricata/suricata.yaml
    echo "[✓] Added to suricata.yaml"
else
    echo "[✓] Dynamic rules already in suricata.yaml"
fi

# Enable and start service
echo "[*] Enabling and starting ml-dynamic-rules service..."
sudo systemctl enable ml-dynamic-rules
sudo systemctl start ml-dynamic-rules

# Check status
sleep 2
sudo systemctl status ml-dynamic-rules --no-pager -l || true

echo ""
echo "✓ ML Dynamic IP Blocker deployed successfully!"
echo ""
echo "Dataset Mode: IPs added/removed without Suricata reloads"
echo ""
echo "Commands:"
echo "  Status:       sudo systemctl status ml-dynamic-rules"
echo "  Logs:         sudo journalctl -fu ml-dynamic-rules"
echo "  Blocked IPs:  sudo cat /var/lib/suricata/ml-blocked-ips.txt"
echo "  Rule:         sudo cat /etc/suricata/rules/ml-dynamic-blocks.rules"
echo "  Stop:         sudo systemctl stop ml-dynamic-rules"
echo ""
