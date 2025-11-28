#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: MOTD Creation
# Phase: 16
# Description: Create Message of the Day with IPS usage instructions

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ============================================================================
# MOTD CREATION
# ============================================================================

create_motd() {
    log_subsection "MOTD Creation"

    # Check if MOTD creation is enabled
    if [[ "${CREATE_MOTD:-true}" != "true" ]]; then
        log "MOTD creation disabled, skipping"
        return 0
    fi

    log "Creating MOTD with IPS access instructions..."

    # Detect management IP
    local mgmt_ip="127.0.0.1"
    if [[ -n "${MGMT_IFACE:-}" ]]; then
        mgmt_ip=$(ip addr show "$MGMT_IFACE" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || echo "127.0.0.1")
    fi

    # Create simplified MOTD
    cat > /etc/motd << 'MOTD_EOF'

════════════════════════════════════════════════════════════════════════════════
██╗  ██╗ █████╗ ██████╗ ███████╗███╗   ██╗██╗███████╗    ██╗██████╗ ███████╗
██║ ██╔╝██╔══██╗██╔══██╗██╔════╝████╗  ██║╚═╝██╔════╝    ██║██╔══██╗██╔════╝
█████╔╝ ███████║██████╔╝█████╗  ██╔██╗ ██║   ███████╗    ██║██████╔╝███████╗
██╔═██╗ ██╔══██║██╔══██╗██╔══╝  ██║╚██╗██║   ╚════██║    ██║██╔═══╝ ╚════██║
██║  ██╗██║  ██║██║  ██║███████╗██║ ╚████║   ███████║    ██║██║     ███████║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚══════╝    ╚═╝╚═╝     ╚══════╝
════════════════════════════════════════════════════════════════════════════════
           Intrusion Prevention System - ML Behavioral Analysis

 WEB INTERFACES
   SLIPS ML Analysis:    http://MGMT_IP:55000
   Kalipso Terminal:     sudo kalipso

 SERVICE MANAGEMENT
   Status:    systemctl status suricata slips slips-webui
   Restart:   systemctl restart suricata slips
   Logs:      journalctl -fu suricata

 MONITORING
   Live Blocking:  tail -f /var/log/suricata/fast.log
   SLIPS Alerts:   journalctl -fu slips

════════════════════════════════════════════════════════════════════════════════

MOTD_EOF

    # Replace placeholder
    sed -i "s/MGMT_IP/${mgmt_ip}/g" /etc/motd
    chmod 644 /etc/motd
    log "MOTD created at /etc/motd"

    # Copy MOTD to SSH banner
    cp /etc/motd /etc/ssh/banner
    chmod 644 /etc/ssh/banner
    log "SSH banner created at /etc/ssh/banner"

    # Configure SSH to use the banner
    if ! grep -q "^Banner /etc/ssh/banner" /etc/ssh/sshd_config; then
        # Backup sshd_config
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

        # Add Banner directive
        echo "" >> /etc/ssh/sshd_config
        echo "# Karen's IPS Banner" >> /etc/ssh/sshd_config
        echo "Banner /etc/ssh/banner" >> /etc/ssh/sshd_config

        log "SSH banner configured in sshd_config"

        # Restart SSH service to apply changes
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
        log "SSH service restarted"
    else
        log "SSH banner already configured"
    fi

    success "MOTD and SSH banner created"
}

verify_motd() {
    [[ -f /etc/motd ]] && success "MOTD verified" && return 0 || { warn "MOTD not found"; return 1; }
}

export -f create_motd verify_motd
