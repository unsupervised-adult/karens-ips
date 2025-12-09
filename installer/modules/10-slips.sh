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

    # Download GeoIP databases for enrichment
    download_geoip_databases

    # Install Kalipso dependencies (Web UI)
    install_kalipso

    # Configure Zeek integration
    configure_zeek_integration

    # Set up directories and permissions
    setup_slips_directories

    # Configure SLIPS web interface
    configure_slips_webui
    
    # Configure Suricata web UI permissions
    configure_suricata_webui_permissions

    # Install Karen's IPS ML integration modules
    install_karens_ips_ml_modules

    # Patch SLIPS for Redis DB 1 connection
    patch_slips_redis_db

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

    # Check if valid SLIPS installation exists
    if [ -d "$SLIPS_DIR" ] && [ -f "$SLIPS_DIR/slips.py" ]; then
        log "SLIPS repository already exists and appears valid"
    else
        # Remove incomplete/invalid installation
        if [ -d "$SLIPS_DIR" ]; then
            # Check if only output directory exists (created by log protection module)
            local dir_count=$(find "$SLIPS_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)
            if [ "$dir_count" -eq 1 ] && [ -d "$SLIPS_DIR/output" ] && [ ! -f "$SLIPS_DIR/slips.py" ]; then
                log "Found only output directory (created by log protection), keeping structure"
            else
                warn "Found incomplete SLIPS installation (missing slips.py), removing..."
                
                # Unmount any loop devices first (safety check)
                local unmounted=0
                for mount_point in "$SLIPS_DIR/output" "$SLIPS_DIR"/*; do
                    if mountpoint -q "$mount_point" 2>/dev/null; then
                        log "Unmounting $mount_point..."
                        umount "$mount_point" 2>/dev/null || true
                        unmounted=1
                    fi
                done
                
                [[ $unmounted -eq 0 ]] && log "No mounted filesystems found, proceeding with removal"
                rm -rf "$SLIPS_DIR"
            fi
        fi
        
        # Clone SLIPS (latest version with new whitelist system)
        log "Cloning SLIPS (latest version)..."
        git clone https://github.com/stratosphereips/StratosphereLinuxIPS.git || error_exit "Failed to clone SLIPS repository"

        cd "$SLIPS_DIR" || error_exit "Failed to change to SLIPS directory"

        log "Using latest SLIPS with O(1) whitelist system"

        cd /opt || error_exit "Failed to return to /opt"

        success "SLIPS repository cloned (latest version)"

        # Verify slips.py exists (git clone succeeded)
        if [ ! -f "$SLIPS_DIR/slips.py" ]; then
            error_exit "SLIPS repository cloned but slips.py not found - clone may have failed"
        fi
    fi

    # Fix ownership and git permissions
    chown -R root:root "$SLIPS_DIR"
    git config --global --add safe.directory "$SLIPS_DIR"

    cd "$SLIPS_DIR" || error_exit "Failed to change to SLIPS directory"
}

setup_slips_venv() {
    log "Creating Python virtual environment for SLIPS..."

    cd "$SLIPS_DIR" || error_exit "Failed to change to SLIPS directory"

    # Verify Python3 venv module is available
    if ! python3 -m venv --help &>/dev/null; then
        error_exit "Python3 venv module not installed. Install with: apt install python3-venv"
    fi

    # Create Python virtual environment
    python3 -m venv venv || error_exit "Failed to create virtual environment"
    source venv/bin/activate

    # Upgrade pip
    pip install --upgrade pip setuptools wheel || error_exit "Failed to upgrade pip - check network connectivity"

    # Install core ML and Redis dependencies first
    pip install scikit-learn joblib numpy pandas redis || error_exit "Failed to install core ML dependencies - SLIPS cannot function without these"

    # Install additional dependencies for Karen's IPS integration and authentication
    pip install flask flask-socketio eventlet bcrypt || warn "Failed to install web dependencies"

    # Install SLIPS requirements
    if [[ -f install/requirements.txt ]]; then
        log "Found SLIPS requirements.txt"
        log "Installing SLIPS dependencies (this may take several minutes)..."
        pip install -r install/requirements.txt || warn "Some SLIPS dependencies failed to install"

        # Verify git is installed for idmefv2 installation
        if ! command -v git >/dev/null 2>&1; then
            error_exit "git not installed - required for idmefv2 dependency. Install with: apt install git"
        fi

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
        warn "SLIPS requirements.txt not found at install/requirements.txt"
    fi

    deactivate
}

configure_slips() {
    log "Configuring SLIPS..."

    cd "$SLIPS_DIR" || error_exit "Failed to change to SLIPS directory"

    # Create config directory if it doesn't exist
    mkdir -p config

    # Create SLIPS configuration in YAML format
    cat > config/slips.yaml << 'SLIPS_CONFIG_EOF'
# SLIPS Configuration with Zeek Integration
main:
  output: /var/log/slips/
  zeek_folder: /opt/zeek
  zeek_logs: /var/log/zeek/
  store_zeek_files: yes
  logfile: /var/log/slips/slips.log
  verbose: 2

input:
  zeek_logs_input: /var/log/zeek/
  process_zeek_logs: no

redis:
  redis_host: 127.0.0.1
  redis_port: 6379
  redis_db: 1

ml:
  use_ml: yes
  ml_models_folder: modules/ml/models/

threatintelligence:
  ti_files: config/TI_feeds.csv
  ja3_feeds: config/JA3_feeds.csv
  ssl_feeds: config/SSL_feeds.csv

modules:
  disable:
    - template
  enable:
    - flowmldetection
    - ml_dashboard_feeder
    - asn
    - blocking
    - flowalerts
    - http_analyzer
    - ip_info
    - leak_detector
    - riskiq
    - threat_intelligence
    - timeline
    - virustotal
    - update_manager

update_manager:
  update_period: 86400
SLIPS_CONFIG_EOF

    # Create empty feed files to prevent "Bad file descriptor" errors
    log "Creating feed configuration files..."
    
    # Create main TI feeds file (required by SLIPS)
    cat > config/TI_feeds.csv << 'TI_FEEDS_EOF'
# Main Threat Intelligence Feeds
# Format: URL,threat_level,tags
# threat_level: info, low, medium, high, critical
# tags: optional comma-separated tags
https://rules.emergingthreats.net/blockrules/compromised-ips.txt,high
https://cinsscore.com/list/ci-badguys.txt,medium
https://www.spamhaus.org/drop/drop.txt,high
TI_FEEDS_EOF

    # Create JA3 feeds file
    cat > config/JA3_feeds.csv << 'JA3_FEEDS_EOF'
# JA3 Threat Intelligence Feeds
# Format: URL,threat_level,tags
https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv,high
JA3_FEEDS_EOF

    # Create SSL feeds file
    cat > config/SSL_feeds.csv << 'SSL_FEEDS_EOF'
# SSL Certificate Threat Intelligence Feeds
# Format: URL,threat_level,tags
https://sslbl.abuse.ch/blacklist/sslblacklist.csv,high
SSL_FEEDS_EOF

    # Create JARM feeds file (empty but required)
    cat > config/JARM_feeds.csv << 'JARM_FEEDS_EOF'
# JARM Threat Intelligence Feeds
# Format: URL,threat_level,tags
JARM_FEEDS_EOF

    chmod 644 config/*.csv

    # Create empty whitelist.conf (SLIPS requires this file)
    touch config/whitelist.conf
    chmod 644 config/whitelist.conf

    success "SLIPS configuration created at config/slips.yaml"
}

download_geoip_databases() {
    log "Downloading MaxMind GeoLite2 databases for IP enrichment..."

    cd "$SLIPS_DIR" || error_exit "Failed to change to SLIPS directory"
    
    mkdir -p databases
    cd databases

    local asn_url="https://git.io/GeoLite2-ASN.mmdb"
    local country_url="https://git.io/GeoLite2-Country.mmdb"
    
    if [[ ! -f GeoLite2-ASN.mmdb ]]; then
        log "Downloading GeoLite2-ASN database..."
        if wget -q -O GeoLite2-ASN.mmdb "$asn_url" 2>/dev/null || \
           curl -sL -o GeoLite2-ASN.mmdb "$asn_url" 2>/dev/null; then
            success "GeoLite2-ASN database downloaded"
        else
            warn "Failed to download GeoLite2-ASN database - ASN info will be unavailable"
        fi
    else
        log "GeoLite2-ASN database already exists"
    fi
    
    if [[ ! -f GeoLite2-Country.mmdb ]]; then
        log "Downloading GeoLite2-Country database..."
        if wget -q -O GeoLite2-Country.mmdb "$country_url" 2>/dev/null || \
           curl -sL -o GeoLite2-Country.mmdb "$country_url" 2>/dev/null; then
            success "GeoLite2-Country database downloaded"
        else
            warn "Failed to download GeoLite2-Country database - Country info will be unavailable"
        fi
    else
        log "GeoLite2-Country database already exists"
    fi
    
    chmod 644 *.mmdb 2>/dev/null || true
    cd "$SLIPS_DIR"
    
    success "GeoIP databases configured"
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
    [ -f slips.py ] && chmod +x slips.py || warn "slips.py not found, skipping chmod"

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
    if [ -f config/slips.yaml ]; then
        # Add web interface configuration to YAML
        cat >> config/slips.yaml << EOF

webinterface:
  web_interface_ip: $mgmt_ip
  web_interface_port: 55000
EOF
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

    # Create webinterface directory if it doesn't exist
    mkdir -p "$webinterface_dir"

    if [[ -d "$source_webinterface_dir/ml_detector" ]]; then
        log "Installing ML detector web interface blueprint..."
        cp -r "$source_webinterface_dir/ml_detector" "$webinterface_dir/" && \
        chown -R root:root "$webinterface_dir/ml_detector" && \
        chmod 755 "$webinterface_dir/ml_detector" && \
        find "$webinterface_dir/ml_detector" -type f -name "*.py" -exec chmod 644 {} \;
        success "ML detector blueprint installed"
    else
        warn "ML detector blueprint not found at $source_webinterface_dir/ml_detector"
    fi
    
    # Copy Suricata config webinterface integration
    if [[ -d "$source_webinterface_dir/suricata_config" ]]; then
        log "Installing Suricata configuration web interface blueprint..."
        cp -r "$source_webinterface_dir/suricata_config" "$webinterface_dir/" && \
        chown -R root:root "$webinterface_dir/suricata_config" && \
        chmod 755 "$webinterface_dir/suricata_config" && \
        find "$webinterface_dir/suricata_config" -type f -name "*.py" -exec chmod 644 {} \; 2>/dev/null && \
        find "$webinterface_dir/suricata_config" -type f -name "*.html" -exec chmod 644 {} \; 2>/dev/null && \
        find "$webinterface_dir/suricata_config" -type f -name "*.css" -exec chmod 644 {} \; 2>/dev/null && \
        find "$webinterface_dir/suricata_config" -type f -name "*.js" -exec chmod 644 {} \; 2>/dev/null
        success "Suricata configuration blueprint installed"
    else
        warn "Suricata configuration blueprint not found at $source_webinterface_dir/suricata_config"
    fi
    
    # Install our complete app.py with all integrations and static path fixes
    if [[ -f "$source_webinterface_dir/app.py" ]]; then
        log "Installing integrated app.py with authentication and custom modules..."
        cp "$source_webinterface_dir/app.py" "$webinterface_dir/app.py"
        chmod 644 "$webinterface_dir/app.py"
        success "Integrated app.py installed (includes static path duplication fix)"
    else
        warn "app.py not found at $source_webinterface_dir/app.py"
    fi
    
    # Install our app.html template
    if [[ -f "$source_webinterface_dir/templates/app.html" ]]; then
        log "Installing app.html template..."
        cp "$source_webinterface_dir/templates/app.html" "$webinterface_dir/templates/app.html"
        chmod 644 "$webinterface_dir/templates/app.html"
    fi

    # Install auth.py authentication module
    if [[ -f "$source_webinterface_dir/auth.py" ]]; then
        log "Installing authentication module..."
        cp "$source_webinterface_dir/auth.py" "$webinterface_dir/auth.py"
        chmod 644 "$webinterface_dir/auth.py"
        
        # Create password file directory
        mkdir -p /etc/karens-ips
        
        # Generate bcrypt hash for default password if not exists
        if [[ ! -f /etc/karens-ips/.password ]]; then
            log "Generating default password (admin/admin)..."
            # Generate proper bcrypt hash for 'admin'
            python3 -c "import bcrypt; print(bcrypt.hashpw(b'admin', bcrypt.gensalt()).decode())" > /etc/karens-ips/.password
            chmod 600 /etc/karens-ips/.password
            warn "Default credentials: admin / admin"
            warn "Change password immediately after login!"
        fi
        
        success "Authentication module installed"
    else
        warn "auth.py not found at $source_webinterface_dir/auth.py"
    fi

    # Install login templates
    mkdir -p "$webinterface_dir/templates"
    if [[ -f "$source_webinterface_dir/templates/login.html" ]]; then
        log "Installing login template..."
        cp "$source_webinterface_dir/templates/login.html" "$webinterface_dir/templates/login.html"
        chmod 644 "$webinterface_dir/templates/login.html"
    fi

    # Install pre-modified app.html template with ML detector tab
    if [[ -f "$source_webinterface_dir/templates/app.html" ]]; then
        log "Installing ML detector integrated app.html template..."
        # Create templates directory if it doesn't exist
        mkdir -p "$webinterface_dir/templates"
        # Backup existing app.html if it exists
        if [[ -f "$webinterface_dir/templates/app.html" ]]; then
            cp "$webinterface_dir/templates/app.html" "$webinterface_dir/templates/app.html.backup" 2>/dev/null || true
        fi
        cp "$source_webinterface_dir/templates/app.html" "$webinterface_dir/templates/app.html"
        chmod 644 "$webinterface_dir/templates/app.html"
        success "ML detector integrated app.html installed"
    else
        warn "Pre-modified app.html not found at $source_webinterface_dir/templates/app.html"
    fi
    
    # Install SLIPS ↔ Suricata dataset sync
    log "Installing SLIPS ↔ Suricata dataset sync..."
    mkdir -p "$SLIPS_DIR/slips_integration"
    cp "$PROJECT_ROOT/slips_integration/slips_suricata_dataset_sync.py" \
        "$SLIPS_DIR/slips_integration/"
    chmod +x "$SLIPS_DIR/slips_integration/slips_suricata_dataset_sync.py"
    success "SLIPS ↔ Suricata dataset sync installed"

    # Install nftables blocking module (replaces iptables)
    local nftables_blocking_dir="$PROJECT_ROOT/slips_integration/nftables_blocking"
    if [[ -d "$nftables_blocking_dir" ]]; then
        log "Installing nftables blocking module..."
        
        # Backup original blocking module
        if [[ -d "$modules_dir/blocking" ]]; then
            mv "$modules_dir/blocking" "$modules_dir/blocking.iptables.backup" || true
        fi
        
        # Copy nftables blocking module
        cp -r "$nftables_blocking_dir" "$modules_dir/blocking"
        chown -R root:root "$modules_dir/blocking"
        chmod 755 "$modules_dir/blocking"
        find "$modules_dir/blocking" -type f -name "*.py" -exec chmod 644 {} \;
        
        success "nftables blocking module installed (replaces iptables)"
    else
        warn "nftables blocking module not found at $nftables_blocking_dir"
        log "SLIPS will use default iptables blocking module"
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
        warn "Continuing installation despite verification issues"
        return 0
    fi
}

patch_slips_redis_db() {
    log "Installing SLIPS whitelist compatibility patch..."

    local karens_ips_dir
    karens_ips_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    
    local source_file="$karens_ips_dir/patches/database.py"
    local dest_file="$SLIPS_DIR/slips_files/core/database/redis_db/database.py"

    if [[ ! -f "$source_file" ]]; then
        warn "Patched database.py not found at: $source_file"
        warn "Skipping whitelist patch"
        return 0
    fi

    if [[ ! -f "$dest_file" ]]; then
        warn "Destination database.py not found at: $dest_file"
        warn "Skipping whitelist patch"
        return 0
    fi

    # Check if already patched (look for new sadd whitelist method)
    if grep -q "self.rcache.sadd(key, \*org_info)" "$dest_file"; then
        success "SLIPS whitelist patch already applied"
        return 0
    fi

    log "Backing up original database.py..."
    cp "$dest_file" "${dest_file}.backup"

    log "Installing patched database.py with new whitelist methods..."
    if cp "$source_file" "$dest_file"; then
        success "Patched database.py installed successfully"
        if grep -q "self.rcache.sadd(key, \*org_info)" "$dest_file"; then
            success "✓ Whitelist patch verification successful"
        else
            warn "File copied but verification failed (sadd method not found)"
        fi
    else
        warn "Failed to copy patched database.py"
    fi

    return 0
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
        warn "Skipping SLIPS bridge support patch"
        return 0
    fi

    log "Checking destination: $dest_file"

    if [[ ! -f "$dest_file" ]]; then
        warn "Destination file not found at: $dest_file"
        warn "Skipping SLIPS bridge support patch"
        return 0
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
        return 0
    fi

    # TODO: Install Bootstrap 5 compatible files using proper patch or pre-tested versions
    # Leaving SLIPS webinterface in default state for now

    log "═══════════════════════════════════════════════"
    return 0
}

configure_suricata_webui_permissions() {
    log "Configuring web interface permissions for Suricata management..."
    
    local sudoers_file="/etc/sudoers.d/slips-webui"
    local source_file="$PROJECT_ROOT/configs/sudoers.d/slips-webui"
    
    if [[ -f "$source_file" ]]; then
        log "Installing sudoers configuration..."
        cp "$source_file" "$sudoers_file"
        chmod 0440 "$sudoers_file"
        chown root:root "$sudoers_file"
        
        # Validate sudoers file
        if visudo -c -f "$sudoers_file" >/dev/null 2>&1; then
            success "Suricata web UI permissions configured"
        else
            warn "Sudoers file validation failed, removing..."
            rm -f "$sudoers_file"
            warn "Continuing without sudoers configuration"
        fi
    else
        warn "Sudoers configuration not found at $source_file"
        warn "Continuing without sudoers configuration"
    fi
    
    # Ensure custom rules directory exists with proper permissions
    mkdir -p /etc/suricata/rules
    touch /etc/suricata/rules/custom.rules
    chmod 644 /etc/suricata/rules/custom.rules
    
    success "Suricata web UI configuration complete"
}

# Export functions
export -f install_slips
export -f check_zeek_availability
export -f clone_slips_repository
export -f setup_slips_venv
export -f configure_slips
export -f download_geoip_databases
export -f install_kalipso
export -f configure_zeek_integration
export -f setup_slips_directories
export -f configure_slips_webui
export -f install_karens_ips_ml_modules
export -f patch_slips_redis_db
export -f patch_slips_bridge_support
export -f configure_suricata_webui_permissions
export -f verify_slips
