#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Utility Functions Library
# General-purpose utility functions for installer

# Source logging functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/logging.sh"

# Ask yes/no question
ask_yes_no() {
    local question="$1"
    local default="${2:-n}"

    if [[ "$default" == "y" ]]; then
        local prompt="[Y/n]"
    else
        local prompt="[y/N]"
    fi

    while true; do
        read -p "$question $prompt " answer
        answer="${answer:-$default}"
        case "${answer,,}" in
            y|yes) return 0 ;;
            n|no) return 1 ;;
            *) echo "Please answer yes or no." ;;
        esac
    done
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if package is installed
package_installed() {
    dpkg -l "$1" 2>/dev/null | grep -q "^ii"
}

# Check if service is running
service_running() {
    systemctl is-active --quiet "$1"
}

# Check if service is enabled
service_enabled() {
    systemctl is-enabled --quiet "$1"
}

# Wait for service to be ready
wait_for_service() {
    local service="$1"
    local timeout="${2:-30}"
    local elapsed=0

    log "Waiting for $service to be ready..."

    while ! service_running "$service"; do
        if [[ $elapsed -ge $timeout ]]; then
            error_exit "$service failed to start within ${timeout}s"
        fi
        sleep 1
        ((elapsed++))
    done

    success "$service is ready"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
}

# Check if running on supported OS
check_os() {
    if [[ ! -f /etc/os-release ]]; then
        error_exit "Cannot determine OS. /etc/os-release not found"
    fi

    source /etc/os-release

    case "$ID" in
        ubuntu|debian)
            log "Detected OS: $PRETTY_NAME"
            ;;
        *)
            warn "Unsupported OS: $PRETTY_NAME"
            ask_yes_no "Continue anyway?" "n" || error_exit "Installation aborted"
            ;;
    esac
}

# Backup file if it exists
backup_file() {
    local file="$1"

    if [[ -f "$file" ]]; then
        local backup="${file}.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$file" "$backup"
        log "Backed up $file to $backup"
    fi
}

# Restore file from backup
restore_file() {
    local file="$1"
    local backup="${file}.backup.*"

    if compgen -G "$backup" > /dev/null; then
        local latest=$(ls -t ${file}.backup.* | head -1)
        cp "$latest" "$file"
        log "Restored $file from $latest"
    else
        warn "No backup found for $file"
    fi
}

# Create directory with proper permissions
create_dir() {
    local dir="$1"
    local owner="${2:-root:root}"
    local perms="${3:-755}"

    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        chown "$owner" "$dir"
        chmod "$perms" "$dir"
        debug "Created directory: $dir"
    fi
}

# Download file with retry
download_file() {
    local url="$1"
    local output="$2"
    local retries="${3:-3}"

    for i in $(seq 1 $retries); do
        if wget -q --show-progress -O "$output" "$url"; then
            success "Downloaded $url"
            return 0
        else
            warn "Download attempt $i failed for $url"
            sleep 2
        fi
    done

    error_exit "Failed to download $url after $retries attempts"
}

# Check internet connectivity
check_internet() {
    local test_urls=(
        "8.8.8.8"
        "1.1.1.1"
        "github.com"
    )

    for url in "${test_urls[@]}"; do
        if ping -c 1 -W 2 "$url" &>/dev/null; then
            debug "Internet connectivity check passed ($url)"
            return 0
        fi
    done

    error_exit "No internet connectivity detected"
}

# Get system memory in MB
get_memory_mb() {
    grep MemTotal /proc/meminfo | awk '{print int($2/1024)}'
}

# Get number of CPU cores
get_cpu_cores() {
    nproc
}

# Check minimum system requirements
check_system_requirements() {
    local min_memory_mb="${1:-2048}"
    local min_cores="${2:-2}"

    local memory=$(get_memory_mb)
    local cores=$(get_cpu_cores)

    log "System: ${memory}MB RAM, ${cores} CPU cores"

    if [[ $memory -lt $min_memory_mb ]]; then
        error_exit "Insufficient memory: ${memory}MB < ${min_memory_mb}MB required"
    fi

    if [[ $cores -lt $min_cores ]]; then
        error_exit "Insufficient CPU cores: ${cores} < ${min_cores} required"
    fi

    success "System requirements met"
}

# Generate random password
generate_password() {
    local length="${1:-16}"
    tr -dc 'A-Za-z0-9!@#$%^&*' < /dev/urandom | head -c "$length"
}

# Validate IP address
is_valid_ip() {
    local ip="$1"
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

    if [[ $ip =~ $regex ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [[ $i -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Validate CIDR notation
is_valid_cidr() {
    local cidr="$1"
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'

    if [[ $cidr =~ $regex ]]; then
        local ip="${cidr%/*}"
        local mask="${cidr##*/}"

        if is_valid_ip "$ip" && [[ $mask -ge 0 ]] && [[ $mask -le 32 ]]; then
            return 0
        fi
    fi
    return 1
}

# Get interface IP address
get_interface_ip() {
    local iface="$1"
    ip addr show "$iface" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1
}

# Check if interface exists
interface_exists() {
    local iface="$1"
    [[ -d "/sys/class/net/$iface" ]]
}

# Get system hostname
get_hostname() {
    hostname -f 2>/dev/null || hostname
}

# Set system timezone
set_timezone() {
    local tz="${1:-UTC}"
    timedatectl set-timezone "$tz" 2>/dev/null || true
}

# Export functions for use in other scripts
export -f log warn error_exit info success debug
export -f ask_yes_no command_exists package_installed
export -f service_running service_enabled wait_for_service
export -f check_root check_os backup_file restore_file
export -f create_dir download_file check_internet
export -f get_memory_mb get_cpu_cores check_system_requirements
export -f generate_password is_valid_ip is_valid_cidr
export -f get_interface_ip interface_exists get_hostname set_timezone
