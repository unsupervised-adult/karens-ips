#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS ML Ad Detector
# SPDX-License-Identifier: GPL-2.0-only

# Installation script for Karen's IPS ML Detector integration with SLIPS

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Karen's IPS ML Detector - SLIPS Web UI Integration Installer${NC}"
echo "=============================================================="
echo ""

# Check if SLIPS path is provided
if [ -z "$1" ]; then
    echo -e "${RED}Error: Please provide the path to your StratosphereLinuxIPS installation${NC}"
    echo "Usage: $0 /path/to/StratosphereLinuxIPS"
    exit 1
fi

SLIPS_PATH="$(cd "$1" && pwd)"

# Validate SLIPS installation
if [ ! -d "$SLIPS_PATH" ]; then
    echo -e "${RED}Error: Directory $SLIPS_PATH does not exist${NC}"
    exit 1
fi

if [ ! -f "$SLIPS_PATH/slips.py" ]; then
    echo -e "${RED}Error: $SLIPS_PATH does not appear to be a valid SLIPS installation${NC}"
    echo "Could not find slips.py"
    exit 1
fi

if [ ! -d "$SLIPS_PATH/webinterface" ]; then
    echo -e "${RED}Error: $SLIPS_PATH does not have a webinterface directory${NC}"
    exit 1
fi

echo -e "${GREEN}[+]${NC} Found valid SLIPS installation at: $SLIPS_PATH"
echo ""

# Create backup
BACKUP_DIR="${SLIPS_PATH}_backup_$(date +%Y%m%d_%H%M%S)"
echo -e "${YELLOW}Creating backup at: $BACKUP_DIR${NC}"
cp -r "$SLIPS_PATH/webinterface" "$BACKUP_DIR"
echo -e "${GREEN}[+]${NC} Backup created"
echo ""

# Copy ML Detector blueprint
echo "Installing ML Detector blueprint..."
ML_DETECTOR_DEST="$SLIPS_PATH/webinterface/ml_detector"

if [ -d "$ML_DETECTOR_DEST" ]; then
    echo -e "${YELLOW}Warning: ML Detector already exists. Removing old version...${NC}"
    rm -rf "$ML_DETECTOR_DEST"
fi

cp -r "$SCRIPT_DIR/webinterface/ml_detector" "$ML_DETECTOR_DEST"
echo -e "${GREEN}[+]${NC} ML Detector blueprint installed"

# Copy Suricata Config blueprint
echo "Installing Suricata Config blueprint..."
SURICATA_CONFIG_DEST="$SLIPS_PATH/webinterface/suricata_config"

if [ -d "$SURICATA_CONFIG_DEST" ]; then
    echo -e "${YELLOW}Warning: Suricata Config already exists. Removing old version...${NC}"
    rm -rf "$SURICATA_CONFIG_DEST"
fi

cp -r "$SCRIPT_DIR/webinterface/suricata_config" "$SURICATA_CONFIG_DEST"
echo -e "${GREEN}[+]${NC} Suricata Config blueprint installed"

# Install stream_ad_blocker.py service
echo "Installing stream ad blocker service..."
if [ -f "$SCRIPT_DIR/webinterface/ml_detector/stream_ad_blocker.py" ]; then
    cp "$SCRIPT_DIR/webinterface/ml_detector/stream_ad_blocker.py" "$SLIPS_PATH/webinterface/ml_detector/stream_ad_blocker.py"
    echo -e "${GREEN}[+]${NC} Stream ad blocker service installed"
else
    echo -e "${YELLOW}[!]${NC} stream_ad_blocker.py not found"
fi
echo ""

# Install pre-modified SLIPS files
echo "Installing ML Detector integrated SLIPS files..."

# Install app.py
echo "  - Installing webinterface/app.py"
if [ -f "$SCRIPT_DIR/webinterface/app.py" ]; then
    cp "$SCRIPT_DIR/webinterface/app.py" "$SLIPS_PATH/webinterface/app.py"
    echo -e "    ${GREEN}[+]${NC} app.py installed successfully"
else
    echo -e "    ${RED}[!]${NC} app.py source file not found"
    exit 1
fi

# Install app.html
echo "  - Installing webinterface/templates/app.html"
if [ -f "$SCRIPT_DIR/webinterface/templates/app.html" ]; then
    cp "$SCRIPT_DIR/webinterface/templates/app.html" "$SLIPS_PATH/webinterface/templates/app.html"
    echo -e "    ${GREEN}[+]${NC} app.html installed successfully"
else
    echo -e "    ${RED}[!]${NC} app.html source file not found"
    exit 1
fi

# Install dashboard.html
echo "  - Installing webinterface/templates/dashboard.html"
if [ -f "$SCRIPT_DIR/webinterface/templates/dashboard.html" ]; then
    cp "$SCRIPT_DIR/webinterface/templates/dashboard.html" "$SLIPS_PATH/webinterface/templates/dashboard.html"
    echo -e "    ${GREEN}[+]${NC} dashboard.html installed successfully"
else
    echo -e "    ${RED}[!]${NC} dashboard.html source file not found"
    exit 1
fi

# Enable active blocking by default in Redis
echo "Configuring stream ad blocker..."
if command -v redis-cli &> /dev/null; then
    redis-cli -n 1 SET ml_detector:blocking_enabled 1 > /dev/null 2>&1 && \
        echo -e "${GREEN}[+]${NC} Active blocking enabled by default" || \
        echo -e "${YELLOW}[!]${NC} Could not enable blocking (Redis might not be running)"
else
    echo -e "${YELLOW}[!]${NC} redis-cli not found. You'll need to enable blocking manually:"
    echo "    redis-cli -n 1 SET ml_detector:blocking_enabled 1"
fi

echo ""
echo -e "${GREEN}[+] Installation complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Start your SLIPS instance with traffic analysis"
echo "2. Start the SLIPS web interface:"
echo "   cd $SLIPS_PATH && ./webinterface.sh"
echo "3. Start the stream ad blocker service:"
echo "   sudo systemctl enable --now stream-ad-blocker"
echo "4. Open your browser to http://localhost:55000"
echo "5. Click on the 'ML Detector' tab to view the dashboard"
echo ""
echo "The ML Detector will display data from Redis keys:"
echo "  - ml_detector:stats"
echo "  - ml_detector:recent_detections"
echo "  - ml_detector:timeline"
echo "  - ml_detector:model_info"
echo "  - ml_detector:feature_importance"
echo "  - ml_detector:alerts"
echo ""
echo "Stream Ad Blocker Status:"
echo "  - Blocking mode: ACTIVE (enabled by default)"
echo "  - Targets: QUIC streams (UDP 443) - YouTube ads, etc."
echo "  - Check status: redis-cli -n 1 HGETALL stream_ad_blocker:stats"
echo ""
echo -e "${YELLOW}Backup location: $BACKUP_DIR${NC}"
echo "If anything goes wrong, you can restore from the backup."
