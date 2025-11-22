#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: Base System
# Phase: 1
# Description: Install base system packages and Zeek network analyzer

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ============================================================================
# BASE SYSTEM INSTALLATION
# ============================================================================

install_base_system() {
    log_subsection "Base System Installation"

    # Check if base system installation is enabled
    if [[ "${INSTALL_BASE_SYSTEM:-true}" != "true" ]]; then
        log "Base system installation disabled, skipping"
        return 0
    fi

    log "Updating system and installing base packages..."

    # Fix system clock if out of sync (common VM issue)
    sync_system_clock

    # Update system
    log "Running system update..."
    apt-get update || error_exit "Failed to update package lists"
    apt-get upgrade -y || warn "System upgrade had issues, continuing..."

    # Install base dependencies
    log "Installing base packages..."
    install_base_packages

    success "Base system packages installed"

    # Install Zeek with proper repository handling
    install_zeek

    success "Base system installation complete"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

sync_system_clock() {
    log "Synchronizing system clock..."

    if command -v timedatectl >/dev/null 2>&1; then
        timedatectl set-ntp true
        sleep 2
        log "Current time: $(date)"
    fi

    # Also try manual NTP sync as fallback
    if command -v ntpdate >/dev/null 2>&1; then
        ntpdate -s time.nist.gov 2>/dev/null || true
    elif command -v chronyd >/dev/null 2>&1; then
        systemctl restart chronyd 2>/dev/null || true
        sleep 2
    fi
}

install_base_packages() {
    local packages=(
        # Core utilities
        software-properties-common
        apt-transport-https
        ca-certificates
        curl
        gnupg
        lsb-release
        git
        wget
        unzip

        # Monitoring tools
        htop
        iftop
        iotop

        # Text editors and terminal multiplexers
        vim
        tmux
        screen

        # Database and services
        redis-server

        # Time synchronization
        ntpdate
        systemd-timesyncd

        # Python
        python3
        python3-pip
        python3-venv

        # Networking tools
        iproute2
        ethtool
        iptables
        nftables
        iputils-ping
        dnsutils
        net-tools
        tcpdump
        tshark
        jq

        # Development libraries
        libpcap-dev
        build-essential
        rsync
    )

    apt-get install -y "${packages[@]}" || error_exit "Failed to install base packages"
}

# ============================================================================
# ZEEK INSTALLATION
# ============================================================================

install_zeek() {
    log "Installing Zeek network analyzer..."

    # Detect Ubuntu version for proper repository
    . /etc/os-release
    UBUNTU_VERSION="$VERSION_CODENAME"

    # Try multiple installation methods
    if install_zeek_from_repo; then
        success "Zeek installed from official repository"
    elif install_zeek_precompiled; then
        success "Zeek installed from precompiled package"
    else
        warn "Could not install Zeek - SLIPS will work without it but with reduced capabilities"
        return 1
    fi

    # Verify installation - check actual installation location
    if [[ -x /opt/zeek/bin/zeek ]]; then
        # Update PATH for current session
        export PATH="$PATH:/opt/zeek/bin"
        zeek_version=$(/opt/zeek/bin/zeek --version | head -1)
        success "Zeek installed successfully: $zeek_version"
        log "Zeek location: /opt/zeek/bin/zeek"
        return 0
    elif command -v zeek >/dev/null 2>&1; then
        zeek_version=$(zeek --version | head -1)
        success "Zeek installed successfully: $zeek_version"
        return 0
    else
        warn "Zeek installation verification failed - binary not found"
        return 1
    fi
}

install_zeek_from_repo() {
    log "Installing Zeek from opensuse.org repository..."

    # Get Ubuntu version
    local ubuntu_version
    ubuntu_version=$(lsb_release -r | awk '{print $2}')

    if [[ -z "$ubuntu_version" ]]; then
        warn "Could not determine Ubuntu version"
        return 1
    fi

    log "Detected Ubuntu version: $ubuntu_version"

    # Use exact same repository URL construction as proven Docker method
    local zeek_repo_url="download.opensuse.org/repositories/security:/zeek/xUbuntu_${ubuntu_version}"

    log "Adding Zeek repository: http://${zeek_repo_url}/"

    # Add repository
    echo "deb http://${zeek_repo_url}/ /" | tee /etc/apt/sources.list.d/security:zeek.list >/dev/null

    # Add GPG key with modern keyring
    if ! curl -fsSL "https://${zeek_repo_url}/Release.key" | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null; then
        warn "Failed to add Zeek repository GPG key"
        return 1
    fi

    # Update package list
    if ! apt-get update; then
        warn "Failed to update package lists after adding Zeek repository"
        return 1
    fi

    # Install Zeek
    if ! apt-get install -y --no-install-recommends zeek; then
        warn "Failed to install Zeek from repository"
        return 1
    fi

    # Create legacy symlink
    ln -sf /opt/zeek/bin/zeek /usr/local/bin/bro

    # Add to PATH for all users
    echo 'export PATH=$PATH:/opt/zeek/bin' >> /etc/bash.bashrc

    # Also update PATH for current session
    export PATH="$PATH:/opt/zeek/bin"

    log "Zeek installation from repository completed successfully"
    return 0
}

install_zeek_precompiled() {
    log "Attempting Zeek installation from precompiled package..."

    local zeek_version="6.0.4"
    local architecture
    architecture=$(dpkg --print-architecture)

    # Only support common architectures
    case "$architecture" in
        amd64|x86_64)
            local zeek_url="https://download.zeek.org/binary-packages/zeek-${zeek_version}-linux-x86_64.tar.gz"
            ;;
        *)
            log "Unsupported architecture for precompiled Zeek: $architecture"
            return 1
            ;;
    esac

    # Download and install
    local temp_dir
    temp_dir=$(mktemp -d)

    if curl -fsSL "$zeek_url" -o "$temp_dir/zeek.tar.gz" 2>/dev/null; then
        cd "$temp_dir"
        tar -xzf zeek.tar.gz

        # Find extracted directory
        local zeek_dir
        zeek_dir=$(find . -name "zeek-*" -type d | head -1)

        if [[ -d "$zeek_dir" ]]; then
            # Install to /opt/zeek
            cp -r "$zeek_dir" /opt/zeek

            # Create symlinks
            ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek
            ln -sf /opt/zeek/bin/zeek-cut /usr/local/bin/zeek-cut
            ln -sf /opt/zeek/bin/zeek-config /usr/local/bin/zeek-config

            # Set permissions
            chmod +x /opt/zeek/bin/*

            cd /
            rm -rf "$temp_dir"
            success "Zeek installed from precompiled package"
            return 0
        fi
    fi

    rm -rf "$temp_dir"
    warn "Failed to install Zeek from precompiled package"
    return 1
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_base_system() {
    log "Verifying base system installation..."

    local errors=0

    # Check critical packages
    local critical_packages=(
        "git"
        "python3"
        "python3-pip"
        "redis-server"
        "tcpdump"
        "curl"
    )

    for pkg in "${critical_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$pkg"; then
            warn "Critical package not installed: $pkg"
            ((errors++))
        fi
    done

    # Check for Zeek (optional but recommended)
    if ! command -v zeek >/dev/null 2>&1 && [[ ! -x /opt/zeek/bin/zeek ]]; then
        warn "Zeek not found - this is optional but recommended"
    fi

    if [[ $errors -eq 0 ]]; then
        success "Base system verification passed"
        return 0
    else
        warn "Base system verification found $errors issues"
        return 1
    fi
}

# Export functions
export -f install_base_system
export -f sync_system_clock
export -f install_base_packages
export -f install_zeek
export -f install_zeek_from_repo
export -f install_zeek_precompiled
export -f verify_base_system
