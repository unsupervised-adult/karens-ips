#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: Suricata Installation
# Phase: 4
# Description: Install Suricata IPS engine and suricata-update

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ============================================================================
# SURICATA INSTALLATION
# ============================================================================

install_suricata() {
    log_subsection "Suricata IPS Installation"

    # Check if Suricata installation is enabled
    if [[ "${INSTALL_SURICATA:-true}" != "true" ]]; then
        log "Suricata installation disabled, skipping"
        return 0
    fi

    log "Installing Suricata..."

    # Detect distribution for proper package management
    detect_distribution

    # Install Suricata based on distribution
    install_suricata_package

    # Create suricata user if not exists
    create_suricata_user

    # Create directories with proper permissions
    create_suricata_directories

    # Configure logrotate for Suricata logs
    setup_logrotate

    # Install and configure suricata-update
    setup_suricata_update

    # Enable unix-command socket for dataset operations
    enable_unix_socket

    success "Suricata installed successfully"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

detect_distribution() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="$ID"
        VERSION_CODENAME="${VERSION_CODENAME:-$VERSION_ID}"
        log "Detected distribution: $DISTRO ($VERSION_CODENAME)"
    else
        error_exit "Cannot detect Linux distribution"
    fi
}

install_suricata_package() {
    case "$DISTRO" in
        "ubuntu")
            install_suricata_ubuntu
            ;;
        "debian")
            install_suricata_debian
            ;;
        *)
            install_suricata_generic
            ;;
    esac
}

install_suricata_ubuntu() {
    log "Setting up Suricata PPA for Ubuntu..."
    wait_for_apt_lock
    apt-get update

    wait_for_apt_lock
    apt-get install -y software-properties-common
    add-apt-repository -y ppa:oisf/suricata-stable

    wait_for_apt_lock
    apt-get update

    wait_for_apt_lock
    apt-get install -y suricata || error_exit "Failed to install Suricata"
}

install_suricata_debian() {
    log "Setting up Suricata from Debian backports or OISF repository..."
    wait_for_apt_lock
    apt-get update

    # Try backports first
    if ! grep -q "backports" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
        echo "deb http://deb.debian.org/debian $VERSION_CODENAME-backports main" > /etc/apt/sources.list.d/backports.list
        wait_for_apt_lock
        apt-get update
    fi

    wait_for_apt_lock
    if apt-get install -y -t "$VERSION_CODENAME-backports" suricata 2>/dev/null; then
        log "Suricata installed from backports"
    else
        log "Backports failed, trying OISF repository..."
        wget -qO - https://www.openinfosecfoundation.org/debian.gpg | apt-key add - 2>/dev/null || true
        echo "deb https://www.openinfosecfoundation.org/debian/ $VERSION_CODENAME main" > /etc/apt/sources.list.d/oisf.list
        wait_for_apt_lock
        apt-get update
        wait_for_apt_lock
        apt-get install -y suricata || error_exit "Failed to install Suricata from OISF repository"
    fi
}

install_suricata_generic() {
    log "Unsupported distribution: $DISTRO. Trying generic installation..."
    wait_for_apt_lock
    apt-get update

    if ! apt-get install -y suricata; then
        error_exit "Could not install Suricata on $DISTRO. Please install Suricata manually and re-run this script"
    fi
}

create_suricata_user() {
    if ! getent passwd suricata > /dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin suricata
        log "Created suricata user"
    else
        log "Suricata user already exists"
    fi
}

create_suricata_directories() {
    log "Creating Suricata directories..."

    local directories=(
        "/var/log/suricata"
        "/var/lib/suricata/rules"
        "/var/run/suricata"
        "/etc/suricata"
    )

    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
    done

    # Set ownership
    chown -R suricata:suricata /var/log/suricata /var/lib/suricata /var/run/suricata

    # Set permissions
    chmod 755 /var/log/suricata
    chmod 750 /var/lib/suricata
    chmod 755 /var/run/suricata

    success "Suricata directories created"
}

setup_logrotate() {
    log "Configuring logrotate for Suricata..."

    cat > /etc/logrotate.d/suricata << 'LOGROTATE_EOF'
/var/log/suricata/*.log /var/log/suricata/*.json {
    rotate 7
    daily
    missingok
    notifempty
    nocompress
    sharedscripts
    postrotate
        /bin/kill -HUP `cat /var/run/suricata.pid 2>/dev/null` 2>/dev/null || true
    endscript
}
LOGROTATE_EOF

    success "Logrotate configured"
}

setup_suricata_update() {
    log "Configuring suricata-update..."

    # Install suricata-update if not available
    if ! command -v suricata-update >/dev/null 2>&1; then
        log "Installing suricata-update via pip (bundled version not found)..."
        pip3 install --upgrade --break-system-packages suricata-update || error_exit "Failed to install suricata-update"
    else
        log "suricata-update already installed"
    fi

    # Configure suricata-update for managed public rulesets
    log "Configuring suricata-update for public threat intelligence..."

    # Initialize suricata-update
    suricata-update update-sources || warn "Failed to update sources"

    # Enable OISF TrafficID and Emerging Threats Open
    suricata-update enable-source oisf/trafficid || warn "Failed to enable oisf/trafficid"
    suricata-update enable-source et/open || warn "Failed to enable et/open"

    # Run initial update with proper error handling
    if ! suricata-update --no-test; then
        log "Initial suricata-update failed, trying basic update..."
        suricata-update --force || warn "Suricata rule update encountered issues"
    fi

    success "suricata-update configured"
}

enable_unix_socket() {
    log "Enabling unix-command socket for dataset operations..."
    
    local suricata_yaml="/etc/suricata/suricata.yaml"
    
    # Check if unix-command section exists
    if ! grep -q "^unix-command:" "$suricata_yaml"; then
        log "Adding unix-command configuration to suricata.yaml..."
        
        # Append unix-command section to the end of the file
        cat >> "$suricata_yaml" << 'EOF'

# Unix socket for interactive commands (suricatasc, dataset management)
unix-command:
  enabled: yes
  filename: /var/run/suricata/suricata.socket
EOF
        
        success "Unix-command socket configuration added"
    else
        # Unix-command section exists, ensure it's properly configured
        log "Configuring existing unix-command section..."
        
        # Ensure it's enabled
        sed -i '/^unix-command:/,/^[a-zA-Z]/ s/enabled: no/enabled: yes/g' "$suricata_yaml"
        sed -i '/^unix-command:/,/^[a-zA-Z]/ s/enabled: auto/enabled: yes/g' "$suricata_yaml"
        
        # Uncomment and fix the filename if it's commented
        if grep -A2 "^unix-command:" "$suricata_yaml" | grep -q "^[[:space:]]*#filename:"; then
            log "Uncommenting and setting unix socket filename..."
            sed -i '/^unix-command:/,/^[a-zA-Z]/ s/^[[:space:]]*#filename:.*/  filename: \/var\/run\/suricata\/suricata.socket/' "$suricata_yaml"
        fi
        
        log "Unix-command socket configured"
    fi
    
    # Verify the configuration
    if grep -A3 "^unix-command:" "$suricata_yaml" | grep -q "enabled: yes"; then
        success "Unix-command socket is enabled"
    else
        warn "Could not verify unix-command socket configuration"
    fi
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_suricata() {
    log "Verifying Suricata installation..."

    local errors=0

    # Check if Suricata is installed
    if ! command -v suricata >/dev/null 2>&1; then
        warn "Suricata binary not found"
        ((errors++))
    else
        local suricata_version=$(suricata --version | head -1)
        log "Suricata version: $suricata_version"
    fi

    # Check if suricata-update is installed
    if ! command -v suricata-update >/dev/null 2>&1; then
        warn "suricata-update not found"
        ((errors++))
    fi

    # Check if suricata user exists
    if ! getent passwd suricata >/dev/null; then
        warn "Suricata user not found"
        ((errors++))
    fi

    # Check directories
    local required_dirs=(
        "/var/log/suricata"
        "/var/lib/suricata"
        "/etc/suricata"
    )

    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            warn "Directory not found: $dir"
            ((errors++))
        fi
    done

    if [[ $errors -eq 0 ]]; then
        success "Suricata verification passed"
        return 0
    else
        warn "Suricata verification found $errors issues"
        return 1
    fi
}

# Export functions
export -f install_suricata
export -f detect_distribution
export -f install_suricata_package
export -f install_suricata_ubuntu
export -f install_suricata_debian
export -f install_suricata_generic
export -f create_suricata_user
export -f create_suricata_directories
export -f setup_logrotate
export -f setup_suricata_update
export -f enable_unix_socket
export -f verify_suricata
