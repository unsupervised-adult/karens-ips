#!/bin/bash
set -e

echo "======================================"
echo "ML Detector Deployment Script"
echo "======================================"
echo ""

VM_IP="${1:-10.10.254.39}"
VM_USER="${2:-karen}"
SSH_CMD="ssh ${VM_USER}@${VM_IP}"

echo "Target: ${VM_USER}@${VM_IP}"
echo ""

echo "[1/6] Pulling latest code on VM..."
$SSH_CMD "cd /opt/StratosphereLinuxIPS && sudo git pull origin main"

echo ""
echo "[2/6] Installing DNS labeler service..."
$SSH_CMD "sudo cp /opt/StratosphereLinuxIPS/slips_integration/dns-labeler.service /etc/systemd/system/ && sudo systemctl daemon-reload"

echo ""
echo "[3/6] Installing stream monitor service..."
$SSH_CMD "sudo cp /opt/StratosphereLinuxIPS/slips_integration/webinterface/ml_detector/stream-monitor.service /etc/systemd/system/ && sudo systemctl daemon-reload"

echo ""
echo "[4/6] Checking blocklist database..."
$SSH_CMD "sudo ls -lh /var/lib/karens-ips/blocklists.db || echo 'Database not found - run installer blocklist phase'"

echo ""
echo "[5/6] Restarting web interface..."
$SSH_CMD "sudo systemctl restart slips-webinterface && sudo systemctl status slips-webinterface --no-pager"

echo ""
echo "[6/6] Starting DNS labeler..."
$SSH_CMD "sudo systemctl enable dns-labeler && sudo systemctl start dns-labeler && sudo systemctl status dns-labeler --no-pager"

echo ""
echo "======================================"
echo "Deployment Complete!"
echo "======================================"
echo ""
echo "Next steps:"
echo "1. Open browser: http://${VM_IP}:55000"
echo "2. Navigate to ML Detector → Settings tab"
echo "3. Verify Settings tab is visible"
echo ""
echo "Check DNS labeler logs:"
echo "  ssh ${VM_USER}@${VM_IP} 'journalctl -u dns-labeler -f'"
echo ""
echo "Check training data accumulation:"
echo "  ssh ${VM_USER}@${VM_IP} 'redis-cli -n 1 LLEN ml_detector:training_data'"
echo ""
echo "When training data >= 100:"
echo "  ssh ${VM_USER}@${VM_IP} 'cd /opt/StratosphereLinuxIPS/webinterface/ml_detector && python3 train_model.py'"
