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

# Show Git Information
echo "Pre-installation checks..."
if command -v git &> /dev/null && [ -d "$SCRIPT_DIR/../.git" ]; then
    CURRENT_BRANCH=$(cd "$SCRIPT_DIR/.." && git branch --show-current 2>/dev/null || echo "unknown")
    LATEST_COMMIT=$(cd "$SCRIPT_DIR/.." && git log -1 --oneline 2>/dev/null || echo "unknown")
    echo -e "${GREEN}[+]${NC} Git branch: ${YELLOW}$CURRENT_BRANCH${NC}"
    echo -e "${GREEN}[+]${NC} Latest commit: $LATEST_COMMIT"
else
    echo -e "${YELLOW}[!]${NC} Not a git repository or git not installed"
fi

# Verify critical source files exist
echo ""
echo "Checking source files..."
MISSING_FILES=0
declare -a SOURCE_FILES=(
    "$SCRIPT_DIR/webinterface/app.py"
    "$SCRIPT_DIR/webinterface/templates/app.html"
    "$SCRIPT_DIR/webinterface/templates/dashboard.html"
    "$SCRIPT_DIR/webinterface/ml_detector/ml_detector.py"
    "$SCRIPT_DIR/webinterface/suricata_config/suricata_config.py"
)

for file in "${SOURCE_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✓${NC} $(basename "$file") found in source"
    else
        echo -e "${RED}✗${NC} Missing source file: $file"
        MISSING_FILES=1
    fi
done

if [ $MISSING_FILES -eq 1 ]; then
    echo -e "${RED}[!] Critical source files are missing!${NC}"
    echo -e "${YELLOW}Make sure you're on the correct git branch with all fixes.${NC}"
    exit 1
fi
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

# Ensure templates directory exists
if [ ! -d "$SLIPS_PATH/webinterface/templates" ]; then
    echo -e "${YELLOW}Creating templates directory...${NC}"
    mkdir -p "$SLIPS_PATH/webinterface/templates"
    echo -e "${GREEN}[+]${NC} Templates directory created"
fi

# Install app.py
echo "  - Installing webinterface/app.py"
if [ -f "$SCRIPT_DIR/webinterface/app.py" ]; then
    cp -v "$SCRIPT_DIR/webinterface/app.py" "$SLIPS_PATH/webinterface/app.py"
    echo -e "    ${GREEN}[+]${NC} app.py installed successfully"
else
    echo -e "    ${RED}[!]${NC} app.py source file not found at: $SCRIPT_DIR/webinterface/app.py"
    exit 1
fi

# Install app.html
echo "  - Installing webinterface/templates/app.html"
if [ -f "$SCRIPT_DIR/webinterface/templates/app.html" ]; then
    cp -v "$SCRIPT_DIR/webinterface/templates/app.html" "$SLIPS_PATH/webinterface/templates/app.html"
    echo -e "    ${GREEN}[+]${NC} app.html installed successfully"
else
    echo -e "    ${RED}[!]${NC} app.html source file not found at: $SCRIPT_DIR/webinterface/templates/app.html"
    exit 1
fi

# Install dashboard.html
echo "  - Installing webinterface/templates/dashboard.html"
if [ -f "$SCRIPT_DIR/webinterface/templates/dashboard.html" ]; then
    cp -v "$SCRIPT_DIR/webinterface/templates/dashboard.html" "$SLIPS_PATH/webinterface/templates/dashboard.html"
    echo -e "    ${GREEN}[+]${NC} dashboard.html installed successfully"
else
    echo -e "    ${RED}[!]${NC} dashboard.html source file not found at: $SCRIPT_DIR/webinterface/templates/dashboard.html"
    echo -e "    ${RED}[!]${NC} Current directory: $(pwd)"
    echo -e "    ${RED}[!]${NC} Script directory: $SCRIPT_DIR"
    ls -la "$SCRIPT_DIR/webinterface/templates/" 2>&1 || echo "Templates directory doesn't exist"
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
echo "Verifying installation..."
VERIFICATION_FAILED=0

# Check critical files with detailed info
declare -a CRITICAL_FILES=(
    "$SLIPS_PATH/webinterface/app.py"
    "$SLIPS_PATH/webinterface/templates/app.html"
    "$SLIPS_PATH/webinterface/templates/dashboard.html"
    "$SLIPS_PATH/webinterface/ml_detector/ml_detector.py"
    "$SLIPS_PATH/webinterface/suricata_config/suricata_config.py"
)

for file in "${CRITICAL_FILES[@]}"; do
    if [ -f "$file" ]; then
        FILE_SIZE=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
        echo -e "${GREEN}✓${NC} $(basename "$file") deployed (${FILE_SIZE} bytes)"
    else
        echo -e "${RED}✗${NC} Missing: $file"
        VERIFICATION_FAILED=1
    fi
done

echo ""
echo "Deployed templates:"
ls -lh "$SLIPS_PATH/webinterface/templates/" 2>/dev/null | grep -E "\.html$" | awk '{print "  - " $9 " (" $5 ")"}'

if [ $VERIFICATION_FAILED -eq 1 ]; then
    echo ""
    echo -e "${RED}[!] Installation verification failed!${NC}"
    echo -e "${YELLOW}Some files are missing. Please check the errors above.${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}[+] Installation complete and verified!${NC}"
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
