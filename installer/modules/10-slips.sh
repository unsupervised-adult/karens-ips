#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: SLIPS Installation
# Phase: 10
# Description: Install Stratosphere Linux IPS (SLIPS) ML behavioral analysis engine

# Note: This module must be sourced by main.sh, not executed directly

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

    # Install Karen's IPS ML integration modules
    install_karens_ips_ml_modules

    # Patch SLIPS for bridge interface support
    patch_slips_bridge_support

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

    # Fix ownership and git permissions
    chown -R root:root "$SLIPS_DIR"
    git config --global --add safe.directory "$SLIPS_DIR"

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
    
    # Install core ML and Redis dependencies first
    pip install scikit-learn joblib numpy pandas redis || warn "Failed to install core ML dependencies"
    
    # Install additional dependencies for Karen's IPS integration
    pip install flask flask-socketio eventlet || warn "Failed to install web dependencies"

    # Install SLIPS requirements
    # Check if requirements.txt exists and show contents for debugging
    if [[ -f install/requirements.txt ]]; then
        log "Found SLIPS requirements.txt, contents:"
        cat install/requirements.txt | head -20  # Show first 20 lines for debugging
        
        log "Installing SLIPS dependencies (this may take several minutes)..."
        pip install -r install/requirements.txt || warn "Some SLIPS dependencies failed to install"
    else
        log "requirements.txt not found, checking alternate locations..."
        find . -name "requirements*.txt" -type f | head -5 | while read req_file; do
            log "Found: $req_file"
            cat "$req_file" | head -10
        done
        log "Installing SLIPS dependencies (this may take several minutes)..."
        pip install -r install/requirements.txt || warn "Some SLIPS dependencies failed to install"

        # Explicitly install idmefv2 from GitHub (critical dependency)
        log "Installing idmefv2 from GitHub..."
        if pip install git+https://github.com/SECEF/python-idmefv2.git; then
            success "idmefv2 installed successfully"
        else
            error_exit "Failed to install idmefv2 - SLIPS cannot function without this dependency"
        fi

        # Verify idmefv2 is installed
        if python -c "import idmefv2" 2>/dev/null; then
            success "SLIPS dependencies installed and verified"
        else
            error_exit "idmefv2 import failed - installation incomplete"
        fi
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

install_karens_ips_ml_modules() {
    log "Installing Karen's IPS ML integration modules..."

    local modules_dir="$SLIPS_DIR/modules"
    local source_modules_dir="$PROJECT_ROOT/slips_integration/modules"
    local source_scripts_dir="$PROJECT_ROOT/slips_integration"
    
    # Create modules directory if it doesn't exist
    mkdir -p "$modules_dir"
    
    # Copy ML dashboard feeder module
    if [[ -d "$source_modules_dir/ml_dashboard_feeder" ]]; then
        log "Installing ML Dashboard Feeder module..."
        cp -r "$source_modules_dir/ml_dashboard_feeder" "$modules_dir/"
        chown -R root:root "$modules_dir/ml_dashboard_feeder"
        chmod 755 "$modules_dir/ml_dashboard_feeder"
        chmod 644 "$modules_dir/ml_dashboard_feeder"/*.py
        success "ML Dashboard Feeder module installed"
    else
        warn "ML Dashboard Feeder module not found at $source_modules_dir/ml_dashboard_feeder"
    fi
    
    # Copy simple ML feeder script  
    if [[ -f "$source_scripts_dir/simple_ml_feeder.py" ]]; then
        log "Installing simple ML feeder script..."
        cp "$source_scripts_dir/simple_ml_feeder.py" "$SLIPS_DIR/"
        chown root:root "$SLIPS_DIR/simple_ml_feeder.py"
        chmod 755 "$SLIPS_DIR/simple_ml_feeder.py"
        success "Simple ML feeder script installed"
    else
        warn "Simple ML feeder script not found at $source_scripts_dir/simple_ml_feeder.py"
    fi
    
    # Copy ML detector webinterface integration
    local webinterface_dir="$SLIPS_DIR/webinterface"
    local source_webinterface_dir="$PROJECT_ROOT/slips_integration/webinterface"
    
    if [[ -d "$source_webinterface_dir/ml_detector" ]]; then
        log "Installing ML detector web interface..."
        cp -r "$source_webinterface_dir/ml_detector" "$webinterface_dir/"
        chown -R root:root "$webinterface_dir/ml_detector"
        chmod 755 "$webinterface_dir/ml_detector"
        chmod 644 "$webinterface_dir/ml_detector"/*.py
        
        # Update webinterface app.py to include ML detector blueprint
        if [[ -f "$webinterface_dir/app.py" ]] && ! grep -q "ml_detector" "$webinterface_dir/app.py"; then
            log "Integrating ML detector into SLIPS web interface..."
            
            # Backup original app.py
            cp "$webinterface_dir/app.py" "$webinterface_dir/app.py.backup"
            
            # Add ML detector import and blueprint registration
            sed -i '/^from .*database import db$/a from .ml_detector.ml_detector import ml_detector' "$webinterface_dir/app.py"
            sed -i '/app\.register_blueprint.*url_prefix/a app.register_blueprint(ml_detector, url_prefix="/ml_detector")' "$webinterface_dir/app.py"
            
            success "ML detector integrated into SLIPS web interface"
        fi
        
        success "ML detector web interface installed"
    else
        warn "ML detector web interface not found at $source_webinterface_dir/ml_detector"
    fi

    success "Karen's IPS ML integration modules installed"
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

patch_slips_bridge_support() {
    log "═══════════════════════════════════════════════"
    log "Installing SLIPS bridge interface support..."
    log "═══════════════════════════════════════════════"

    local karens_ips_dir
    karens_ips_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    
    local source_file="$karens_ips_dir/slips_integration/managers/host_ip_manager.py"
    local dest_file="$SLIPS_DIR/managers/host_ip_manager.py"

    log "Checking for source file: $source_file"

    if [[ ! -f "$source_file" ]]; then
        warn "host_ip_manager.py not found at: $source_file"
        return 1
    fi

    log "Checking destination: $dest_file"

    if [[ ! -f "$dest_file" ]]; then
        warn "Destination file not found at: $dest_file"
        return 1
    fi

    # Check if already installed
    if grep -q "Interface has no IP (e.g., bridge interface)" "$dest_file"; then
        success "SLIPS bridge support already installed"
        return 0
    fi

    log "Installing bridge-enabled host_ip_manager.py..."

    # Backup original file
    cp "$dest_file" "${dest_file}.backup"
    log "Backup created: ${dest_file}.backup"

    # Copy our modified version
    if cp "$source_file" "$dest_file"; then
        success "SLIPS bridge support installed successfully!"
        log "Verifying installation..."
        if grep -q "Interface has no IP" "$dest_file"; then
            success "✓ Bridge support verification successful"
        else
            warn "File copied but verification failed"
        fi
    else
        warn "Failed to copy host_ip_manager.py"
        log "═══════════════════════════════════════════════"
        return 1
    fi

    log "Installing Bootstrap 5 compatible app.js..."
    local app_js_source="$karens_ips_dir/slips_integration/webinterface/static/app.js"
    local app_js_dest="$SLIPS_DIR/webinterface/static/app.js"
    
    if [[ -f "$app_js_source" ]]; then
        cp "$app_js_dest" "${app_js_dest}.backup" 2>/dev/null || true
        if cp "$app_js_source" "$app_js_dest"; then
            success "✓ Bootstrap 5 app.js installed"
        else
            warn "Failed to copy app.js"
        fi
    fi

    log "Installing Bootstrap 5 compatible app.html..."
    local app_html_source="$karens_ips_dir/slips_integration/webinterface/templates/app.html"
    local app_html_dest="$SLIPS_DIR/webinterface/templates/app.html"
    
    if [[ -f "$app_html_source" ]]; then
        cp "$app_html_dest" "${app_html_dest}.backup" 2>/dev/null || true
        if cp "$app_html_source" "$app_html_dest"; then
            success "✓ Bootstrap 5 app.html installed"
        else
            warn "Failed to copy app.html"
        fi
    fi

    log "═══════════════════════════════════════════════"
    return 0
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
export -f patch_slips_bridge_support
export -f verify_slips
