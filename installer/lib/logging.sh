#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Logging Functions Library
# Provides standardized logging for installer modules

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Log file
LOG_FILE="${LOG_FILE:-/var/log/ips-installer.log}"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Standard log message
log() {
    local msg="$(date +'%Y-%m-%d %H:%M:%S') - $1"
    echo -e "${GREEN}${msg}${NC}"
    echo "$msg" >> "$LOG_FILE"
}

# Warning message
warn() {
    local msg="$(date +'%Y-%m-%d %H:%M:%S') - WARNING: $1"
    echo -e "${YELLOW}${msg}${NC}"
    echo "$msg" >> "$LOG_FILE"
}

# Error message and exit
error_exit() {
    local msg="$(date +'%Y-%m-%d %H:%M:%S') - ERROR: $1"
    echo -e "${RED}${msg}${NC}" >&2
    echo "$msg" >> "$LOG_FILE"
    exit 1
}

# Info message (blue)
info() {
    echo -e "${BLUE}$1${NC}"
}

# Success message
success() {
    local msg="$(date +'%Y-%m-%d %H:%M:%S') - SUCCESS: $1"
    echo -e "${GREEN}✓ ${msg}${NC}"
    echo "$msg" >> "$LOG_FILE"
}

# Debug message (only if DEBUG=1)
debug() {
    if [[ "${DEBUG:-0}" == "1" ]]; then
        local msg="$(date +'%Y-%m-%d %H:%M:%S') - DEBUG: $1"
        echo -e "${BLUE}${msg}${NC}"
        echo "$msg" >> "$LOG_FILE"
    fi
}

# Log section header
log_section() {
    local msg="$1"
    log "=========================================="
    log "$msg"
    log "=========================================="
}

# Log subsection
log_subsection() {
    local msg="$1"
    log "------------------------------------------"
    log "$msg"
    log "------------------------------------------"
}
