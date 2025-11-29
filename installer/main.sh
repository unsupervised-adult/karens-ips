#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Karen's IPS Main Installer
# Modular installation orchestrator

set -Eeuo pipefail
trap 'echo "[FATAL] Line $LINENO: $BASH_COMMAND" >&2; exit 1' ERR

# ============================================================================
# INITIALIZATION
# ============================================================================

# Get installer directory
INSTALLER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$INSTALLER_DIR")"

# Load libraries
source "$INSTALLER_DIR/lib/logging.sh"
source "$INSTALLER_DIR/lib/utils.sh"

# Load configuration
CONFIG_FILE="${CONFIG_FILE:-$INSTALLER_DIR/config/installer.conf}"
if [[ ! -f "$CONFIG_FILE" ]]; then
    error_exit "Configuration file not found: $CONFIG_FILE"
fi
source "$CONFIG_FILE"

# ============================================================================
# PRE-FLIGHT CHECKS
# ============================================================================

preflight_checks() {
    log_section "Pre-Flight Checks"

    # Check root
    check_root

    # Check OS
    check_os

    # Check internet
    check_internet

    # Check system requirements
    check_system_requirements "$MIN_MEMORY_MB" "$MIN_CPU_CORES"

    # Set timezone
    set_timezone "$TIMEZONE"

    success "All pre-flight checks passed"
}

# ============================================================================
# SHOW CONFIGURATION
# ============================================================================

show_configuration() {
    log_section "Installation Configuration"

    info "Network Configuration:"
    info "  Management Interface: $MGMT_IFACE"
    info "  Bridge Interfaces: $IFACE_IN <-> $IFACE_OUT"
    info "  Home Network: $HOME_NET"
    info ""

    info "Features:"
    info "  SLIPS: ${INSTALL_SLIPS}"
    info "  ML Detector: ${INSTALL_ML_DETECTOR}"
    info "  Blocklists: ${INSTALL_BLOCKLISTS}"
    info "  Web UI: ${INSTALL_WEBUI}"
    info ""

    info "Paths:"
    info "  SLIPS: $SLIPS_DIR"
    info "  Suricata Config: $SURICATA_CONFIG_DIR"
    info "  Blocklists: $BLOCKLISTS_DIR"
    info ""

    if [[ "${NON_INTERACTIVE:-0}" != "1" ]]; then
        ask_yes_no "Proceed with installation?" "y" || error_exit "Installation aborted by user"
    fi
}

# ============================================================================
# MODULE LOADING
# ============================================================================

# Load all installation modules
load_modules() {
    local module_dir="$INSTALLER_DIR/modules"

    # Check if modules directory exists
    if [[ ! -d "$module_dir" ]]; then
        error_exit "Modules directory not found: $module_dir - installation cannot proceed"
    fi

    # Source all module files in order
    for module in "$module_dir"/*.sh; do
        if [[ -f "$module" ]]; then
            debug "Loading module: $(basename "$module")"
            source "$module"
        fi
    done

    return 0
}

# ============================================================================
# MAIN INSTALLATION
# ============================================================================

main_install() {
    log_section "Starting Complete IPS Installation"
    log "Installation started at: $(date)"
    log "Configuration file: $CONFIG_FILE"
    log "Installer version: 4.0"
    log ""

    # Phase 1: Base System
    if command -v install_base_system &>/dev/null; then
        log "Phase 1: Installing base system..."
        install_base_system
    else
        warn "Module install_base_system not found, skipping..."
    fi

    # Phase 2: Kernel Tuning
    if [[ "${ENABLE_KERNEL_TUNING:-true}" == "true" ]]; then
        if command -v setup_kernel_and_tuning &>/dev/null; then
            log "Phase 2: Setting up kernel modules and tuning..."
            setup_kernel_and_tuning
        else
            warn "Module setup_kernel_and_tuning not found, skipping..."
        fi
    fi

    # Phase 3: nftables
    if command -v setup_nftables_blocking &>/dev/null; then
        log "Phase 3: Setting up nftables blocking infrastructure..."
        setup_nftables_blocking
    else
        warn "Module setup_nftables_blocking not found, skipping..."
    fi

    # Phase 4: Suricata Installation
    if command -v install_suricata &>/dev/null; then
        log "Phase 4: Installing Suricata..."
        install_suricata
    else
        warn "Module install_suricata not found, skipping..."
    fi

    # Phase 5: Suricata Rules
    if command -v update_suricata_rules &>/dev/null; then
        log "Phase 5: Updating Suricata rules..."
        update_suricata_rules
    else
        warn "Module update_suricata_rules not found, skipping..."
    fi

    # Phase 6: Community Blocklists
    if [[ "${INSTALL_BLOCKLISTS:-true}" == "true" ]]; then
        if command -v import_community_blocklists &>/dev/null; then
            log "Phase 6: Importing community blocklists..."
            import_community_blocklists
        else
            warn "Module import_community_blocklists not found, skipping..."
        fi
    fi

    # Phase 7: Blocklist Management
    if [[ "${INSTALL_BLOCKLISTS:-true}" == "true" ]]; then
        if command -v setup_blocklist_management &>/dev/null; then
            log "Phase 7: Setting up blocklist management..."
            setup_blocklist_management
        else
            warn "Module setup_blocklist_management not found, skipping..."
        fi
    fi


    # Phase 7.5: Extract threat IPs from SQLite to datasets (after blocklist import)
    if [[ "${INSTALL_BLOCKLISTS:-true}" == "true" ]]; then
        if command -v extract_initial_threat_ips &>/dev/null; then
            log "Phase 7.5: Extracting threat IPs from SQLite to Suricata datasets..."
            extract_initial_threat_ips
        else
            warn "Module extract_initial_threat_ips not found, skipping..."
        fi
    fi

    # Phase 8: Active Blocking
    if [[ "${INSTALL_BLOCKLISTS:-true}" == "true" ]]; then
        if command -v install_active_blocking &>/dev/null; then
            log "Phase 8: Setting up active packet blocking..."
            install_active_blocking
        else
            warn "Module install_active_blocking not found, skipping..."
        fi
    fi

    # Phase 10: Node.js
    if [[ "${INSTALL_NODEJS:-true}" == "true" ]]; then
        if command -v install_nodejs &>/dev/null; then
            log "Phase 10: Installing Node.js..."
            install_nodejs
        else
            warn "Module install_nodejs not found, skipping..."
        fi
    fi

    # Phase 11: SLIPS
    if [[ "${INSTALL_SLIPS:-true}" == "true" ]]; then
        if command -v install_slips &>/dev/null; then
            log "Phase 11: Installing SLIPS..."
            install_slips
        else
            warn "Module install_slips not found, skipping..."
        fi
    fi

    # Phase 12: ML Detector Dashboard
    if [[ "${INSTALL_ML_DETECTOR:-true}" == "true" ]]; then
        if command -v install_ml_detector_dashboard &>/dev/null; then
            log "Phase 12: Installing ML Detector Dashboard..."
            install_ml_detector_dashboard
        else
            warn "Module install_ml_detector_dashboard not found, skipping..."
        fi
    fi

    # Phase 13: Network Interfaces
    if command -v setup_interfaces &>/dev/null; then
        log "Phase 13: Setting up network interfaces..."
        setup_interfaces
    else
        warn "Module setup_interfaces not found, skipping..."
    fi

    # Phase 14: Redis
    if command -v configure_redis &>/dev/null; then
        log "Phase 14: Configuring Redis..."
        configure_redis
    else
        warn "Module configure_redis not found, skipping..."
    fi

    # Phase 15: SystemD Services
    if command -v create_systemd_services &>/dev/null; then
        log "Phase 15: Creating SystemD services..."
        create_systemd_services
    else
        warn "Module create_systemd_services not found, skipping..."
    fi

    # Phase 16: Start Services
    if command -v start_services &>/dev/null; then
        log "Phase 16: Starting services..."
        start_services
    else
        warn "Module start_services not found, skipping..."
    fi

    # Phase 17: MOTD
    if command -v create_motd &>/dev/null; then
        log "Phase 17: Creating MOTD..."
        create_motd
    else
        warn "Module create_motd not found, skipping..."
    fi

    # Phase 18: Verification
    if command -v verify_installation &>/dev/null; then
        log "Phase 18: Verifying installation..."
        verify_installation
    else
        warn "Module verify_installation not found, skipping..."
    fi

    log_section "COMPLETE IPS INSTALLATION FINISHED!"
    log "Installation completed at: $(date)"
    success "All installation phases completed successfully"
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

main() {
    # Show banner with ASCII art
    echo ""
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo "██╗  ██╗ █████╗ ██████╗ ███████╗███╗   ██╗██╗███████╗    ██╗██████╗ ███████╗"
    echo "██║ ██╔╝██╔══██╗██╔══██╗██╔════╝████╗  ██║╚═╝██╔════╝    ██║██╔══██╗██╔════╝"
    echo "█████╔╝ ███████║██████╔╝█████╗  ██╔██╗ ██║   ███████╗    ██║██████╔╝███████╗"
    echo "██╔═██╗ ██╔══██║██╔══██╗██╔══╝  ██║╚██╗██║   ╚════██║    ██║██╔═══╝ ╚════██║"
    echo "██║  ██╗██║  ██║██║  ██║███████╗██║ ╚████║   ███████║    ██║██║     ███████║"
    echo "╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚══════╝    ╚═╝╚═╝     ╚══════╝"
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo "           Intrusion Prevention System - ML Behavioral Analysis"
    echo ""
    log_section "Installation System"
    info "Version: 4.0 (Modular)"
    info "Date: $(date)"
    info ""

    # Pre-flight checks
    preflight_checks

    # Configure network interfaces (auto-detect or interactive)
    configure_network_interfaces

    # Show configuration
    show_configuration

    # Load modules
    if ! load_modules; then
        error_exit "Failed to load installer modules. Check installer/modules/ directory."
    fi

    log "Loaded modular installer - all modules ready"

    # Execute installation
    main_install
}

# Run main if executed (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
