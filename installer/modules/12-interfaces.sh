#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: Network Interfaces
# Phase: 12
# Description: Set up network bridge for NFQUEUE IPS mode

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ============================================================================
# NETWORK INTERFACE SETUP
# ============================================================================

setup_interfaces() {
    log_subsection "Network Bridge Setup for NFQUEUE IPS Mode"

    # Check if interface setup is enabled
    if [[ "${SETUP_INTERFACES:-true}" != "true" ]]; then
        log "Interface setup disabled, skipping"
        return 0
    fi

    log "Setting up network bridge for NFQUEUE IPS mode..."

    # Create interface setup script
    create_interface_setup_script

    # Run interface setup immediately
    run_interface_setup

    # Create SystemD service for interface setup
    create_interface_service

    # Create netplan configuration for persistence
    create_netplan_config

    success "Network interfaces configured for NFQUEUE IPS mode"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

create_interface_setup_script() {
    log "Creating interface setup script..."

    cat > /usr/local/bin/ips-interface-setup.sh << EOF
#!/bin/bash
# IPS Interface Setup Script for NFQUEUE Bridge Mode

# Management interface (keep existing configuration)
# ${MGMT_IFACE} - no changes needed

# Create bridge for IPS
ip link add name br0 type bridge
ip link set br0 up

# Add interfaces to bridge
ip link set ${IFACE_IN} master br0
ip link set ${IFACE_OUT} master br0

# Bring up bridge ports
ip link set ${IFACE_IN} up
ip link set ${IFACE_OUT} up

# Disable hardware offloading on bridge ports
ethtool -K ${IFACE_IN} gro off lro off tso off gso off rx off tx off 2>/dev/null || true
ethtool -K ${IFACE_OUT} gro off lro off tso off gso off rx off tx off 2>/dev/null || true

# Bridge settings for IPS mode
ip link set br0 type bridge stp_state 0  # Disable STP for performance
ip link set br0 type bridge ageing_time 30000  # Fast MAC aging

# Disable reverse path filtering
sysctl -w net.ipv4.conf.br0.rp_filter=0
sysctl -w net.ipv4.conf.${IFACE_IN}.rp_filter=0
sysctl -w net.ipv4.conf.${IFACE_OUT}.rp_filter=0

# Bridge netfilter for nfqueue
sysctl -w net.bridge.bridge-nf-call-iptables=1
sysctl -w net.bridge.bridge-nf-call-ip6tables=1

echo "IPS bridge configured for NFQUEUE mode"
echo "  Management: ${MGMT_IFACE} (unchanged)"
echo "  Bridge:     br0 (forwarding at kernel speed)"
echo "  Ports:      ${IFACE_IN} <-> ${IFACE_OUT}"
EOF

    chmod +x /usr/local/bin/ips-interface-setup.sh
    success "Interface setup script created"
}

run_interface_setup() {
    log "Running interface setup..."

    if /usr/local/bin/ips-interface-setup.sh; then
        success "Interface setup completed"
    else
        error_exit "Interface setup failed"
    fi
}

create_interface_service() {
    log "Creating SystemD service for interface setup..."

    cat > /etc/systemd/system/ips-interfaces.service << EOF
[Unit]
Description=IPS Bridge Setup for NFQUEUE Mode
After=network-online.target
Wants=network-online.target
Before=suricata.service nftables.service
DefaultDependencies=false

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/ips-interface-setup.sh
ExecStop=/bin/bash -c 'ip link set ${IFACE_IN} nomaster; ip link set ${IFACE_OUT} nomaster; ip link del br0'
TimeoutStartSec=30
# Health check for bridge
ExecStartPost=/bin/bash -c 'sleep 2; ip link show br0 up || exit 1'

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable ips-interfaces.service || warn "Failed to enable ips-interfaces.service"
    success "SystemD service created"
}

create_netplan_config() {
    log "Creating netplan configuration..."

    cat > /etc/netplan/99-ips-interfaces.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${IFACE_IN}:
      dhcp4: no
      dhcp6: no
      optional: true
    ${IFACE_OUT}:
      dhcp4: no
      dhcp6: no
      optional: true
EOF

    # Apply netplan configuration if available (Ubuntu-specific)
    if command -v netplan >/dev/null 2>&1; then
        log "Applying netplan configuration..."
        if netplan apply 2>/dev/null; then
            success "Netplan configuration applied"
        else
            warn "netplan apply failed, changes will take effect on reboot"
        fi
    else
        log "Netplan not available (non-Ubuntu system), network changes will take effect on reboot"
    fi
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_interfaces() {
    log "Verifying interface setup..."

    local errors=0

    # Check if setup script exists
    if [[ ! -f /usr/local/bin/ips-interface-setup.sh ]]; then
        warn "Interface setup script not found"
        ((errors++))
    fi

    # Check if service exists
    if [[ ! -f /etc/systemd/system/ips-interfaces.service ]]; then
        warn "Interface service not found"
        ((errors++))
    fi

    # Check if netplan config exists
    if [[ ! -f /etc/netplan/99-ips-interfaces.yaml ]]; then
        warn "Netplan configuration not found"
        ((errors++))
    fi

    # Check if bridge interface exists (if setup already ran)
    if ip link show br0 >/dev/null 2>&1; then
        log "Bridge interface br0 is up"
    else
        log "Bridge interface not yet created (will be created on service start)"
    fi

    if [[ $errors -eq 0 ]]; then
        success "Interface verification passed"
        return 0
    else
        warn "Interface verification found $errors issues"
        return 1
    fi
}

# Export functions
export -f setup_interfaces
export -f create_interface_setup_script
export -f run_interface_setup
export -f create_interface_service
export -f create_netplan_config
export -f verify_interfaces
