#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: SLIPS Installation
# Phase: 10
# Description: Install Stratosphere Linux IPS (SLIPS) ML behavioral analysis engine

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ============================================================================
# SLIPS INSTALLATION
# ============================================================================

install_slips() {
    log_subsection "SLIPS (Stratosphere Linux IPS) Installation"

    # Check if SLIPS installation is enabled
    if [[ "${INSTALL_SLIPS:-true}" != "true" ]]; then
        log "SLIPS installation disabled, skipping"
        return 0
    fi

    log "Installing SLIPS (Stratosphere Linux IPS)..."

    # Check if Zeek is available
    check_zeek_availability

    # Clone SLIPS repository
    clone_slips_repository

    # Set up Python virtual environment
    setup_slips_venv

    # Configure SLIPS
    configure_slips

    # Install Kalipso dependencies (Web UI)
    install_kalipso

    # Configure Zeek integration
    configure_zeek_integration

    # Set up directories and permissions
    setup_slips_directories

    # Configure SLIPS web interface
    configure_slips_webui

    success "SLIPS installed successfully"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

check_zeek_availability() {
    local zeek_available=false

    if command -v zeek >/dev/null 2>&1; then
        zeek_available=true
        log "Zeek detected - SLIPS will have full functionality"
    else
        warn "Zeek not available - SLIPS will run with reduced capabilities"
    fi
}

clone_slips_repository() {
    log "Cloning SLIPS repository..."

    cd /opt || error_exit "Failed to change to /opt directory"

    if [ ! -d "$SLIPS_DIR" ]; then
        git clone --depth 1 https://github.com/stratosphereips/StratosphereLinuxIPS.git || error_exit "Failed to clone SLIPS repository"
        success "SLIPS repository cloned"
    else
        log "SLIPS repository already exists"
    fi

    cd "$SLIPS_DIR" || error_exit "Failed to change to SLIPS directory"
}

setup_slips_venv() {
    log "Creating Python virtual environment for SLIPS..."

    cd "$SLIPS_DIR" || error_exit "Failed to change to SLIPS directory"

    # Create Python virtual environment
    python3 -m venv venv || error_exit "Failed to create virtual environment"
    source venv/bin/activate

    # Upgrade pip
    pip install --upgrade pip setuptools wheel || warn "Failed to upgrade pip"

    # Install SLIPS requirements
    if [ -f install/requirements.txt ]; then
        log "Installing SLIPS dependencies..."
        pip install -r install/requirements.txt || warn "Some SLIPS dependencies failed to install"
        success "SLIPS dependencies installed"
    else
        warn "SLIPS requirements.txt not found"
    fi

    deactivate
}

configure_slips() {
    log "Configuring SLIPS..."

    cd "$SLIPS_DIR" || error_exit "Failed to change to SLIPS directory"

    # Create SLIPS configuration
    cat > slips.conf << 'SLIPS_CONFIG_EOF'
# SLIPS Configuration with Zeek Integration
[main]
output = /var/log/slips/
zeek_folder = /opt/zeek
zeek_logs = /var/log/zeek/
store_zeek_files = True
logfile = /var/log/slips/slips.log
verbose = 2

[input]
zeek_logs_input = /var/log/zeek/
process_zeek_logs = True

[redis]
redis_host = 127.0.0.1
redis_port = 6379
redis_db = 1

[ml]
use_ml = True
ml_models_folder = modules/ml/models/
SLIPS_CONFIG_EOF

    success "SLIPS configuration created"
}

install_kalipso() {
    log "Installing Kalipso dependencies (SLIPS Web UI)..."

    cd "$SLIPS_DIR" || error_exit "Failed to change to SLIPS directory"

    if [ -d modules/kalipso ]; then
        cd modules/kalipso
        npm install --production || warn "Failed to install Kalipso dependencies"
        cd ../..
        success "Kalipso dependencies installed"
    else
        warn "Kalipso directory not found, skipping"
    fi
}

configure_zeek_integration() {
    log "Configuring Zeek for SLIPS integration..."

    # Create directories with root ownership (Docker-proven approach)
    mkdir -p /var/log/zeek /var/spool/zeek
    chown -R root:root /var/log/zeek /var/spool/zeek
    chmod -R 755 /var/log/zeek /var/spool/zeek

    # Create Zeek node configuration
    if [[ -d /opt/zeek/etc ]]; then
        log "Creating Zeek node configuration..."

        # Validate IFACE_IN is set
        if [[ -z "${IFACE_IN}" ]]; then
            error_exit "IFACE_IN not set. Network interfaces must be configured before installing Zeek."
        fi

        cat > /opt/zeek/etc/node.cfg << ZEEK_NODE_EOF
# Zeek Node Configuration - Standalone Mode for SLIPS Integration
# Monitors primary copy interface for traffic analysis
[zeek]
type=standalone
host=localhost
interface=${IFACE_IN}
ZEEK_NODE_EOF

        # Create Zeek control configuration
        cat > /opt/zeek/etc/zeekctl.cfg << 'ZEEK_CFG_EOF'
# ZeekControl Configuration (Docker-proven settings)
LogDir = /var/log/zeek
SpoolDir = /var/spool/zeek
CfgDir = /opt/zeek/etc
ZEEK_CFG_EOF

        # Set permissions
        chown -R root:root /opt/zeek/etc
        chmod 755 /opt/zeek/etc
        chmod 644 /opt/zeek/etc/node.cfg /opt/zeek/etc/zeekctl.cfg

        success "Zeek integration configured"
    else
        warn "Zeek not installed, skipping Zeek configuration"
    fi
}

setup_slips_directories() {
    log "Setting up SLIPS directories..."

    cd "$SLIPS_DIR" || error_exit "Failed to change to SLIPS directory"

    # Make slips executable
    chmod +x slips.py

    # Create log directory
    mkdir -p /var/log/slips
    chown -R root:root /var/log/slips
    chmod 755 /var/log/slips

    success "SLIPS directories configured"
}

configure_slips_webui() {
    log "Configuring SLIPS web interface..."

    cd "$SLIPS_DIR" || error_exit "Failed to change to SLIPS directory"

    # Detect management IP
    local mgmt_ip="127.0.0.1"
    if [[ -n "${MGMT_IFACE:-}" ]]; then
        mgmt_ip=$(ip addr show "$MGMT_IFACE" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || echo "127.0.0.1")
    fi

    # Update SLIPS config for web interface
    if [ -f config/slips.conf ]; then
        sed -i "s/web_interface_ip = .*/web_interface_ip = $mgmt_ip/" config/slips.conf || true
        sed -i 's/web_interface_port = .*/web_interface_port = 55000/' config/slips.conf || true
        log "SLIPS web interface configured for $mgmt_ip:55000"
    fi

    success "SLIPS web UI configured"
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_slips() {
    log "Verifying SLIPS installation..."

    local errors=0

    # Check if SLIPS directory exists
    if [[ ! -d "$SLIPS_DIR" ]]; then
        warn "SLIPS directory not found at $SLIPS_DIR"
        ((errors++))
    fi

    # Check if slips.py exists
    if [[ ! -f "$SLIPS_DIR/slips.py" ]]; then
        warn "slips.py not found"
        ((errors++))
    fi

    # Check if virtual environment exists
    if [[ ! -d "$SLIPS_DIR/venv" ]]; then
        warn "SLIPS virtual environment not found"
        ((errors++))
    fi

    # Check log directory
    if [[ ! -d "/var/log/slips" ]]; then
        warn "SLIPS log directory not found"
        ((errors++))
    fi

    if [[ $errors -eq 0 ]]; then
        success "SLIPS verification passed"
        return 0
    else
        warn "SLIPS verification found $errors issues"
        return 1
    fi
}

# Export functions
export -f install_slips
export -f check_zeek_availability
export -f clone_slips_repository
export -f setup_slips_venv
export -f configure_slips
export -f install_kalipso
export -f configure_zeek_integration
export -f setup_slips_directories
export -f configure_slips_webui
export -f verify_slips
