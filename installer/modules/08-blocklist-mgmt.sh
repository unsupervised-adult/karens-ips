#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: Blocklist Management
# Phase: 8
# Description: Set up blocklist management scripts and automation

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    exit 1
fi

setup_blocklist_management() {
    log_subsection "Blocklist Management Setup"

    if [[ "${SETUP_BLOCKLIST_MGMT:-true}" != "true" ]]; then
        log "Blocklist management setup disabled, skipping"
        return 0
    fi

    log "Setting up blocklist management..."

    # Configuration already created by config module
    # Scripts already created by blocklists module
    # Just ensure directories exist

    mkdir -p /etc/karens-ips
    mkdir -p "$BLOCKLISTS_DIR"

    success "Blocklist management configured"
}

verify_blocklist_mgmt() {
    [[ -d /etc/karens-ips ]] && success "Blocklist management verified" && return 0 || { warn "Configuration directory not found"; return 1; }
}

export -f setup_blocklist_management verify_blocklist_mgmt
