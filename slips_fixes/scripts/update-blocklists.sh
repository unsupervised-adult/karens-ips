#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Blocklist Update Script
# Updates blocklist repositories and re-imports domains

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

# Configuration
BLOCKLISTS_DIR="${BLOCKLISTS_DIR:-/opt/karens-ips-blocklists}"
CONFIG_FILE="${CONFIG_FILE:-/etc/karens-ips/blocklists.yaml}"
IPS_FILTER_DB="/opt/ips-filter-db.py"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root"
    exit 1
fi

log "========================================"
log "Karen's IPS Blocklist Update"
log "========================================"
log ""

# Check if blocklists directory exists
if [ ! -d "$BLOCKLISTS_DIR" ]; then
    error "Blocklists directory not found: $BLOCKLISTS_DIR"
    error "Run the installer first: sudo ./karens-ips-installer.sh"
    exit 1
fi

cd "$BLOCKLISTS_DIR"

# Update Perflyst/PiHoleBlocklist
if [ -d "PiHoleBlocklist" ]; then
    log "Updating Perflyst/PiHoleBlocklist..."
    cd PiHoleBlocklist

    if git pull --quiet 2>&1 | grep -q "Already up to date"; then
        log "  ✓ Already up to date"
    else
        log "  ✓ Updated successfully"
    fi
    cd ..
else
    warn "PiHoleBlocklist not found, cloning..."
    if git clone --depth 1 https://github.com/Perflyst/PiHoleBlocklist.git; then
        log "  ✓ Cloned successfully"
    else
        error "  ✗ Failed to clone"
    fi
fi

# Update hagezi/dns-blocklists
if [ -d "dns-blocklists" ]; then
    log "Updating hagezi/dns-blocklists..."
    cd dns-blocklists

    if git pull --quiet 2>&1 | grep -q "Already up to date"; then
        log "  ✓ Already up to date"
    else
        log "  ✓ Updated successfully"
    fi
    cd ..
else
    warn "dns-blocklists not found, cloning..."
    if git clone --depth 1 https://github.com/hagezi/dns-blocklists.git; then
        log "  ✓ Cloned successfully"
    else
        error "  ✗ Failed to clone"
    fi
fi

log ""
log "Repositories updated successfully"
log ""

# Re-import blocklists based on configuration
log "Re-importing blocklists (based on /etc/karens-ips/blocklists.yaml)..."
log "This may take several minutes..."
log ""

# Use configuration-based importer
if [ -f "/usr/local/bin/import-from-config" ]; then
    /usr/local/bin/import-from-config
else
    warn "Configuration-based importer not found, using fallback method..."

    # Fallback to importing only enabled defaults
    if [ -f "PiHoleBlocklist/SmartTV.txt" ]; then
        log "Importing Perflyst SmartTV..."
        $IPS_FILTER_DB import-list --list-file "$BLOCKLISTS_DIR/PiHoleBlocklist/SmartTV.txt" \
            --category ads --source-name perflyst_smarttv 2>&1 | grep -E "(Imported:|Skipped:)" || true
    fi

    if [ -f "dns-blocklists/domains/pro.txt" ]; then
        log "Importing hagezi Pro..."
        $IPS_FILTER_DB import-list --list-file "$BLOCKLISTS_DIR/dns-blocklists/domains/pro.txt" \
            --category ads --source-name hagezi_pro 2>&1 | grep -E "(Imported:|Skipped:|Processing line)" || true
    fi

    log ""
    log "Syncing to Suricata..."
    $IPS_FILTER_DB sync 2>&1 | grep -E "(Syncing|Successfully|Progress:|Warning:)" || true
fi

log ""
log "========================================"
log "Blocklist update complete!"
log "========================================"
log ""

# Show statistics
$IPS_FILTER_DB stats

# Generate active blocking rules if the module is available
if command -v karens-ips-active-blocking >/dev/null 2>&1; then
    log ""
    log "Updating active blocking rules..."
    karens-ips-active-blocking generate
fi


log ""
log "All blocking mechanisms updated!"
karens-ips-active-blocking status 2>/dev/null || true
