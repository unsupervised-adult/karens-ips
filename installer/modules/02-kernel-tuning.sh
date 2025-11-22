#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: Kernel Tuning
# Phase: 2
# Description: Load kernel modules and configure system tuning for high-performance IPS

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ============================================================================
# KERNEL TUNING
# ============================================================================

setup_kernel_and_tuning() {
    log_subsection "Kernel Modules and System Tuning"

    # Check if kernel tuning is enabled
    if [[ "${SETUP_KERNEL_TUNING:-true}" != "true" ]]; then
        log "Kernel tuning disabled, skipping"
        return 0
    fi

    log "Setting up kernel modules and system tuning..."

    # Load kernel modules
    load_kernel_modules

    # Configure sysctl for performance
    configure_sysctl

    # Apply sysctl changes
    apply_sysctl

    success "Kernel modules and tuning configured"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

load_kernel_modules() {
    log "Loading required kernel modules..."

    local modules=(
        "nfnetlink"
        "nf_conntrack"
        "nf_defrag_ipv4"
        "nf_tables"
        "nfnetlink_queue"
        "af_packet"
        "br_netfilter"
    )

    for module in "${modules[@]}"; do
        if modprobe "$module" 2>/dev/null; then
            log "Loaded: $module"
        else
            warn "Could not load module: $module"
        fi

        # Add to /etc/modules for persistence (avoid duplicates)
        if ! grep -q "^$module$" /etc/modules 2>/dev/null; then
            echo "$module" >> /etc/modules
        fi
    done

    success "Kernel modules loaded"
}

configure_sysctl() {
    log "Configuring sysctl for IPS performance..."

    # Check if already configured (avoid duplicates)
    if grep -q "# IPS Network Tuning" /etc/sysctl.conf; then
        log "Sysctl already configured, skipping"
        return 0
    fi

    # Append IPS tuning configuration
    cat >> /etc/sysctl.conf << 'EOF'

# IPS Network Tuning
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.core.rmem_default = 134217728
net.core.wmem_default = 134217728
net.core.netdev_max_backlog = 300000
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000
net.core.dev_weight = 64
vm.max_map_count = 262144

# Reduce context switching
net.core.busy_read = 50
net.core.busy_poll = 50

# Bridge netfilter (enabled for NFQUEUE)
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-arptables = 1

# IP forwarding not needed for L2 bridge
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable IPv6 completely (not used)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# TCP optimization for high throughput
net.ipv4.tcp_rmem = 4096 65536 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# Security
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
EOF

    success "Sysctl configuration added"
}

apply_sysctl() {
    log "Applying sysctl settings..."

    if sysctl -p; then
        success "Sysctl settings applied"
    else
        warn "Some sysctl settings failed to apply"
    fi
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_kernel_tuning() {
    log "Verifying kernel tuning..."

    local errors=0

    # Check if key modules are loaded
    local required_modules=("nfnetlink_queue" "br_netfilter" "nf_tables")

    for module in "${required_modules[@]}"; do
        if lsmod | grep -q "^$module"; then
            log "Module loaded: $module"
        else
            warn "Module not loaded: $module"
            ((errors++))
        fi
    done

    # Check sysctl configuration
    if grep -q "# IPS Network Tuning" /etc/sysctl.conf; then
        log "Sysctl configuration present"
    else
        warn "Sysctl configuration not found"
        ((errors++))
    fi

    if [[ $errors -eq 0 ]]; then
        success "Kernel tuning verification passed"
        return 0
    else
        warn "Kernel tuning verification found $errors issues"
        return 1
    fi
}

# Export functions
export -f setup_kernel_and_tuning
export -f load_kernel_modules
export -f configure_sysctl
export -f apply_sysctl
export -f verify_kernel_tuning
