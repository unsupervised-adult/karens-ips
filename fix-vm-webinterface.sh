#!/bin/bash
# Fix SLIPS webinterface on VM by restoring original and applying patches correctly

set -e

SLIPS_DIR="/opt/StratosphereLinuxIPS"
KARENS_IPS_REPO="/home/ficus/Documents/Project-Code/IPS/karens-ips"

echo "=================================="
echo "SLIPS Web Interface Fix"
echo "=================================="
echo ""

# Stop the web service
echo "Stopping SLIPS web service..."
sudo systemctl stop slips-webui || true

# Backup current broken state
echo "Backing up current broken state..."
sudo cp -r "$SLIPS_DIR/webinterface" "$SLIPS_DIR/webinterface.broken.$(date +%Y%m%d_%H%M%S)"

# Restore original SLIPS app.py from fresh clone
echo "Restoring original SLIPS app.py..."
TEMP_SLIPS="/tmp/slips-restore-$$"
git clone --depth 1 https://github.com/stratosphereips/StratosphereLinuxIPS.git "$TEMP_SLIPS"

sudo cp "$TEMP_SLIPS/webinterface/app.py" "$SLIPS_DIR/webinterface/app.py"
sudo chown -R slips:slips "$SLIPS_DIR/webinterface/app.py"

echo "Original app.py restored!"
echo ""

# Now apply the ML Detector patches correctly
echo "Applying ML Detector integration patches..."
cd "$SLIPS_DIR"

# Apply app.py patch
if ! grep -q "from .ml_detector.ml_detector import ml_detector" webinterface/app.py; then
    echo "  Patching app.py to add ml_detector import..."
    sudo sed -i '/from \.documentation\.documentation import documentation/a from .ml_detector.ml_detector import ml_detector' webinterface/app.py
    echo "  Patching app.py to register ml_detector blueprint..."
    sudo sed -i '/app\.register_blueprint(documentation, url_prefix="\/documentation")/a \    app.register_blueprint(ml_detector, url_prefix="/ml_detector")' webinterface/app.py
    echo "  ✓ app.py patched"
else
    echo "  ✓ app.py already has ml_detector"
fi

# Copy ml_detector blueprint if not present
if [ ! -d "$SLIPS_DIR/webinterface/ml_detector" ]; then
    echo "  Copying ml_detector blueprint..."
    sudo cp -r "$KARENS_IPS_REPO/slips_integration/webinterface/ml_detector" "$SLIPS_DIR/webinterface/"
    sudo chown -R slips:slips "$SLIPS_DIR/webinterface/ml_detector"
    echo "  ✓ ml_detector blueprint installed"
else
    echo "  ✓ ml_detector blueprint already exists"
fi

# Install ML Dashboard Feeder SLIPS module (THIS IS CRITICAL FOR LIVE DATA!)
if [ ! -d "$SLIPS_DIR/modules/ml_dashboard_feeder" ]; then
    echo "  Installing ML Dashboard Feeder SLIPS module..."
    sudo cp -r "$KARENS_IPS_REPO/slips_integration/modules/ml_dashboard_feeder" "$SLIPS_DIR/modules/"
    sudo chown -R slips:slips "$SLIPS_DIR/modules/ml_dashboard_feeder"
    echo "  ✓ ml_dashboard_feeder module installed"
else
    echo "  ✓ ml_dashboard_feeder module already exists"
fi

# Fix permissions
echo "Setting permissions..."
sudo chown -R slips:slips "$SLIPS_DIR/webinterface"
sudo chmod -R 755 "$SLIPS_DIR/webinterface"

# Clean up temp clone
rm -rf "$TEMP_SLIPS"

echo ""
echo "=================================="
echo "✓ Fix complete!"
echo "=================================="
echo ""
echo "Starting SLIPS web service..."
sudo systemctl start slips-webui

sleep 3
sudo systemctl status slips-webui --no-pager || true

echo ""
echo "The SLIPS web interface should now have:"
echo "  - Database tab (original SLIPS)"
echo "  - Analysis tab (original SLIPS)"
echo "  - General tab (original SLIPS)"
echo "  - Documentation tab (original SLIPS)"
echo "  - ML Detector tab (Karen's IPS addition)"
echo ""
echo "Access at: http://10.10.254.39:55000"
echo ""
echo "IMPORTANT: Restart SLIPS to load ML Dashboard Feeder module:"
echo "  sudo systemctl restart slips"
echo ""
echo "The ML Detector will show LIVE data once SLIPS processes traffic!"
