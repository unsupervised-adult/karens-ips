#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: nftables Configuration
# Phase: 3
# Description: Set up nftables for host protection and NFQUEUE integration

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ============================================================================
# NFTABLES SETUP
# ============================================================================

setup_nftables_blocking() {
    log_subsection "nftables Host Protection and NFQUEUE Integration"

    # Check if nftables setup is enabled
    if [[ "${SETUP_NFTABLES:-true}" != "true" ]]; then
        log "nftables setup disabled, skipping"
        return 0
    fi

    log "Setting up nftables for host protection and SLIPS integration..."

    # Install nftables
    install_nftables

    # Create nftables configuration
    create_nftables_config

    # Load configuration
    load_nftables_config

    # Enable nftables service
    enable_nftables_service

    success "nftables host protection configured"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

install_nftables() {
    log "Installing nftables..."

    if ! command -v nft >/dev/null 2>&1; then
        wait_for_apt_lock
        apt-get install -y nftables || error_exit "Failed to install nftables"
        success "nftables installed"
    else
        log "nftables already installed"
    fi
}

create_nftables_config() {
    log "Creating nftables configuration..."

    # Create configuration directory
    mkdir -p /etc/nftables.d

    # Create IPS blocking sets configuration
    cat > /etc/nftables.d/ips-blocksets.nft << 'NFT_CONFIG_EOF'
#!/usr/sbin/nft -f

# IPS Dynamic Blocking Sets
table inet home {
    # IPv4 blocking set with timeout support (IPv6 disabled)
    set blocked4 {
        type ipv4_addr;
        flags interval, timeout;
        timeout 1h;
        gc-interval 1h;
        comment "IPS blocked IPv4 addresses";
    }

    # Host protection chains (INPUT/OUTPUT for IPS sensor protection)
    chain input_filter {
        type filter hook input priority 0; policy accept;
        tcp dport 55000 accept comment "SLIPS Web UI";
    }

    chain output_filter {
        type filter hook output priority 0; policy accept;
    }

    # NFQUEUE chain for bridge traffic inspection (IPS mode)
    chain forward_ips {
        type filter hook forward priority 0; policy accept;

        # Block malicious IPs on bridge traffic only (not management)
        iifname "br0" ip saddr @blocked4 counter drop comment "Block malicious sources on bridge";
        oifname "br0" ip daddr @blocked4 counter drop comment "Block malicious destinations on bridge";

        # Send remaining bridge traffic to Suricata nfqueue
        iifname "br0" counter queue num 0 bypass comment "Send bridge traffic to Suricata IPS";
        oifname "br0" counter queue num 0 bypass comment "Send bridge traffic to Suricata IPS";
    }
}
NFT_CONFIG_EOF

    chmod +x /etc/nftables.d/ips-blocksets.nft
    success "nftables configuration created"
}

load_nftables_config() {
    log "Loading nftables configuration..."

    if nft -f /etc/nftables.d/ips-blocksets.nft; then
        success "nftables configuration loaded"
    else
        error_exit "Failed to load nftables configuration"
    fi

    # Save ruleset for persistence
    nft list ruleset > /etc/nftables.conf
}

enable_nftables_service() {
    log "Enabling nftables service..."

    if systemctl enable nftables; then
        success "nftables service enabled"
    else
        warn "Failed to enable nftables service"
    fi
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_nftables() {
    log "Verifying nftables configuration..."

    local errors=0

    # Check if nft command exists
    if ! command -v nft >/dev/null 2>&1; then
        warn "nft command not found"
        ((errors++))
    fi

    # Check if configuration file exists
    if [[ ! -f /etc/nftables.d/ips-blocksets.nft ]]; then
        warn "nftables configuration file not found"
        ((errors++))
    fi

    # Check if nftables service is enabled
    if ! systemctl is-enabled --quiet nftables 2>/dev/null; then
        warn "nftables service not enabled"
        ((errors++))
    fi

    # Check if blocked4 set exists
    if nft list set inet home blocked4 >/dev/null 2>&1; then
        log "blocked4 set exists"
    else
        warn "blocked4 set not found"
        ((errors++))
    fi

    if [[ $errors -eq 0 ]]; then
        success "nftables verification passed"
        return 0
    else
        warn "nftables verification found $errors issues"
        return 1
    fi
}

# Export functions
export -f setup_nftables_blocking
export -f install_nftables
export -f create_nftables_config
export -f load_nftables_config
export -f enable_nftables_service
export -f verify_nftables
