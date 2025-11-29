#!/bin/bash
# Karen's IPS Easy Installer for Friends
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "=================================================================="
echo "          Karen's IPS - Easy Installer for Friends"
echo "=================================================================="
echo -e "${NC}"
echo ""
echo -e "${GREEN}✓ Automatic installation${NC}"
echo -e "${GREEN}✓ Blocks Samsung TV/fridge ads${NC}" 
echo -e "${GREEN}✓ Blocks Netflix ads${NC}"
echo -e "${GREEN}✓ ML-powered threat detection${NC}"
echo -e "${GREEN}✓ Zero configuration required${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}"
   echo "Please run: sudo $0"
   exit 1
fi

# Check system requirements
echo -e "${BLUE}Checking system requirements...${NC}"

# Check Ubuntu/Debian
if ! command -v apt-get >/dev/null 2>&1; then
    echo -e "${RED}Error: This installer requires Ubuntu or Debian${NC}"
    exit 1
fi

# Check memory (minimum 1GB)
MEMORY_MB=$(free -m | awk '/^Mem:/ {print $2}')
if [ "$MEMORY_MB" -lt 1024 ]; then
    echo -e "${YELLOW}Warning: Low memory detected (${MEMORY_MB}MB). Recommended: 2GB+${NC}"
    echo "Installation will continue with reduced performance settings."
    sleep 3
fi

# Check network interfaces
INTERFACE_COUNT=$(ip link show | grep -E '^[0-9]+:' | wc -l)
if [ "$INTERFACE_COUNT" -lt 2 ]; then
    echo -e "${RED}Error: At least 2 network interfaces required for IPS bridge mode${NC}"
    echo "Current interfaces:"
    ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | sed 's/^ //'
    exit 1
fi

echo -e "${GREEN}✓ System requirements met${NC}"
echo ""

# Ask for confirmation
echo -e "${YELLOW}Ready to install Karen's IPS with the following defaults:${NC}"
echo "• SmartTV/IoT ad blocking (Samsung, LG, etc)"
echo "• Netflix ad blocking"
echo "• hagezi Pro blocklist (balanced blocking)"
echo "• ML-based threat detection"
echo "• Automatic updates every Sunday at 3 AM"
echo "• Web interface on port 55000"
echo ""

read -p "Continue installation? [Y/n]: " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ ! -z $REPLY ]]; then
    echo "Installation cancelled."
    exit 0
fi

echo ""
echo -e "${BLUE}Starting automatic installation...${NC}"
echo "This will take 15-30 minutes depending on your internet speed."
echo ""

# Set auto-mode configuration
export KARENS_IPS_CONFIG="auto-mode"
export NON_INTERACTIVE=1

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if installer exists
if [[ ! -f "$SCRIPT_DIR/karens-ips-installer.sh" ]]; then
    echo -e "${RED}Error: Main installer not found${NC}"
    echo "Make sure you have the complete Karen's IPS package"
    exit 1
fi

# Run the main installer in auto mode
echo -e "${GREEN}Running automated installer...${NC}"
if bash "$SCRIPT_DIR/karens-ips-installer.sh" --config=auto-mode; then
    echo ""
    echo -e "${GREEN}=================================================================="
    echo "🎉 Karen's IPS Installation Complete!"
    echo "=================================================================="
    echo -e "${NC}"
    echo ""
    echo -e "${GREEN}✓ Your network is now protected against:${NC}"
    echo "  • Samsung TV/appliance ads"
    echo "  • Netflix advertising"
    echo "  • Tracking and malware"
    echo "  • IoT device telemetry"
    echo ""
    echo -e "${BLUE}📱 Web Interface:${NC} http://$(hostname -I | awk '{print $1}'):55000"
    echo -e "${BLUE}📊 Status Command:${NC} sudo karens-ips status"
    echo -e "${BLUE}🔄 Update Command:${NC} sudo karens-ips update"
    echo ""
    echo -e "${YELLOW}⚠️  Important Notes:${NC}"
    echo "• Configure your router to route traffic through this device"
    echo "• The system updates automatically every Sunday at 3 AM"
    echo "• Check the web interface for real-time protection status"
    echo ""
    echo -e "${GREEN}Enjoy your ad-free network! 🚫📺${NC}"
else
    echo ""
    echo -e "${RED}=================================================================="
    echo "❌ Installation failed"
    echo "=================================================================="
    echo -e "${NC}"
    echo "Check the log file: /var/log/ips-installer.log"
    echo "For support, visit: https://github.com/unsupervised-adult/suricata-ips"
    exit 1
fi