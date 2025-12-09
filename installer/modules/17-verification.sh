#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: Installation Verification
# Phase: 17
# Description: Verify complete IPS installation and functionality

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ============================================================================
# INSTALLATION VERIFICATION
# ============================================================================

verify_installation() {
    log_subsection "Installation Verification"

    log "Verifying complete IPS installation..."

    # Verify interfaces
    verify_interfaces_status

    # Verify services
    verify_services_status

    # Verify Suricata configuration
    verify_suricata_config

    # Display summary
    display_verification_summary

    success "Installation verification complete"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

verify_interfaces_status() {
    log "Interface status:"

    if [[ -n "${MGMT_IFACE:-}" ]]; then
        local mgmt_ip=$(ip addr show "$MGMT_IFACE" 2>/dev/null | grep 'inet ' | head -1 | awk '{print $2}' || echo 'No IP')
        log "  Management: $mgmt_ip"
    fi

    if [[ -n "${IFACE_IN:-}" ]]; then
        local in_status=$(ip link show "$IFACE_IN" 2>/dev/null | grep -q 'state UP' && echo 'UP' || echo 'DOWN')
        log "  Traffic IN:  $in_status"
    fi

    if [[ -n "${IFACE_OUT:-}" ]]; then
        local out_status=$(ip link show "$IFACE_OUT" 2>/dev/null | grep -q 'state UP' && echo 'UP' || echo 'DOWN')
        log "  Traffic OUT: $out_status"
    fi
}

verify_services_status() {
    log "Service status:"

    local services=("redis-server" "suricata" "slips" "slips-webui" "zeek")

    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log "  $service: Running"
        else
            log "  $service: Not running"
        fi
    done
}

verify_suricata_config() {
    log "Suricata configuration test:"

    local test_output
    test_output=$(suricata -T -c /etc/suricata/suricata.yaml 2>&1)
    
    if echo "$test_output" | grep -q "Configuration provided was successfully loaded"; then
        success "  Configuration test passed"
    else
        warn "  Configuration test failed"
        log "  Errors:"
        echo "$test_output" | grep -E "ERROR|Warning" | sed 's/^/    /'
    fi
}

display_verification_summary() {
    log ""
    log "════════════════════════════════════════════════════════════════"
    log "  Installation Summary"
    log "════════════════════════════════════════════════════════════════"
    log ""

    # Detect management IP
    local mgmt_ip="127.0.0.1"
    if [[ -n "${MGMT_IFACE:-}" ]]; then
        mgmt_ip=$(ip addr show "$MGMT_IFACE" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || echo "127.0.0.1")
    fi

    log "  Web Interfaces:"
    log "    SLIPS ML Analysis: http://${mgmt_ip}:55000"
    log "    Kalipso Terminal:  sudo kalipso"
    log ""
    log "  Key Commands:"
    log "    Service Status:  systemctl status suricata slips"
    log "    Live Monitoring: tail -f /var/log/suricata/fast.log"
    log "    SLIPS Logs:      journalctl -fu slips"
    log ""
    log "════════════════════════════════════════════════════════════════"
}

# Export functions
export -f verify_installation
export -f verify_interfaces_status
export -f verify_services_status
export -f verify_suricata_config
export -f display_verification_summary
