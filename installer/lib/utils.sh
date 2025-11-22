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
    ip addr show "$iface" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1 || true
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

# =============================================================================
# NETWORK AUTO-DETECTION FUNCTIONS
# =============================================================================

# List all network interfaces (excluding loopback and virtual)
list_network_interfaces() {
    local exclude_pattern="lo|docker|veth|br-|virbr"
    ip -o link show | awk -F': ' '{print $2}' | grep -v '@' | grep -vE "^($exclude_pattern)"
}

# Detect management interface (first interface with IP address)
detect_mgmt_interface() {
    local interfaces=($(list_network_interfaces))

    for iface in "${interfaces[@]}"; do
        if [[ -n "$(get_interface_ip "$iface")" ]]; then
            echo "$iface"
            return 0
        fi
    done

    # Fallback to first interface
    echo "${interfaces[0]}"
}

# Detect available interfaces for bridge (excluding management interface)
detect_bridge_interfaces() {
    local mgmt_iface="$1"
    local interfaces=($(list_network_interfaces))
    local bridge_ifaces=()

    for iface in "${interfaces[@]}"; do
        # Skip management interface
        if [[ "$iface" == "$mgmt_iface" ]]; then
            continue
        fi

        # Skip interfaces with IP addresses (likely in use)
        if [[ -n "$(get_interface_ip "$iface")" ]]; then
            continue
        fi

        bridge_ifaces+=("$iface")
    done

    echo "${bridge_ifaces[@]}"
}

# Interactive interface selection
select_interface() {
    local prompt="$1"
    local interfaces=($(list_network_interfaces))

    if [[ ${#interfaces[@]} -eq 0 ]]; then
        error_exit "No network interfaces found"
    fi

    echo "" >&2
    echo "Available interfaces:" >&2
    local i=1
    for iface in "${interfaces[@]}"; do
        local ip=$(get_interface_ip "$iface")
        local state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")
        if [[ -n "$ip" ]]; then
            echo "  $i) $iface (IP: $ip, state: $state)" >&2
        else
            echo "  $i) $iface (no IP, state: $state)" >&2
        fi
        ((i++))
    done
    echo "" >&2

    while true; do
        read -p "$prompt [1-${#interfaces[@]}]: " selection >&2

        if [[ "$selection" =~ ^[0-9]+$ ]] && [[ $selection -ge 1 ]] && [[ $selection -le ${#interfaces[@]} ]]; then
            local idx=$((selection - 1))
            echo "${interfaces[$idx]}"
            return 0
        else
            echo "Invalid selection. Please choose 1-${#interfaces[@]}" >&2
        fi
    done
}

# Auto-detect HOME_NET from management interface
detect_home_network() {
    local mgmt_iface="$1"

    if [[ -z "$mgmt_iface" ]]; then
        mgmt_iface=$(detect_mgmt_interface)
    fi

    # Get IP and netmask
    local cidr=$(ip addr show "$mgmt_iface" | grep 'inet ' | awk '{print $2}' | head -1)

    if [[ -n "$cidr" ]]; then
        # Extract network address
        local ip="${cidr%/*}"
        local mask="${cidr##*/}"

        # Calculate network address using ipcalc or python
        if command_exists ipcalc; then
            ipcalc -n "$cidr" | grep Network | awk '{print $2}'
        else
            # Fallback: use Python
            python3 -c "import ipaddress; print(ipaddress.ip_network('$cidr', strict=False))" 2>/dev/null || echo "$cidr"
        fi
    fi
}

# Prompt for network configuration
configure_network_interfaces() {
    log_subsection "Network Configuration"

    # Auto-detect or prompt for management interface
    if [[ -z "${MGMT_IFACE}" ]]; then
        local detected_mgmt=$(detect_mgmt_interface)
        log "Auto-detected management interface: $detected_mgmt"

        if [[ "${NON_INTERACTIVE:-0}" != "1" ]]; then
            if ask_yes_no "Use $detected_mgmt as management interface?" "y"; then
                MGMT_IFACE="$detected_mgmt"
            else
                MGMT_IFACE=$(select_interface "Select management interface")
            fi
        else
            MGMT_IFACE="$detected_mgmt"
        fi
    fi

    # Validate management interface
    if ! interface_exists "$MGMT_IFACE"; then
        error_exit "Management interface $MGMT_IFACE does not exist"
    fi

    success "Management interface: $MGMT_IFACE"

    # Auto-detect or prompt for bridge interfaces
    if [[ -z "${IFACE_IN}" ]] || [[ -z "${IFACE_OUT}" ]]; then
        local bridge_ifaces=($(detect_bridge_interfaces "$MGMT_IFACE"))

        if [[ ${#bridge_ifaces[@]} -lt 2 ]]; then
            warn "Found ${#bridge_ifaces[@]} available interfaces for bridge (need 2)"
            warn "You may need to configure additional network interfaces"
        fi

        if [[ "${NON_INTERACTIVE:-0}" != "1" ]]; then
            log "Bridge mode requires two interfaces for traffic inspection"
            IFACE_IN=$(select_interface "Select INPUT interface (traffic from network)")
            IFACE_OUT=$(select_interface "Select OUTPUT interface (traffic to network)")
        else
            # Non-interactive: use first two available
            if [[ ${#bridge_ifaces[@]} -ge 2 ]]; then
                IFACE_IN="${bridge_ifaces[0]}"
                IFACE_OUT="${bridge_ifaces[1]}"
            else
                error_exit "Insufficient interfaces for bridge mode. Need at least 3 interfaces total."
            fi
        fi
    fi

    # Validate bridge interfaces
    if ! interface_exists "$IFACE_IN"; then
        error_exit "Input interface $IFACE_IN does not exist"
    fi

    if ! interface_exists "$IFACE_OUT"; then
        error_exit "Output interface $IFACE_OUT does not exist"
    fi

    if [[ "$IFACE_IN" == "$IFACE_OUT" ]]; then
        error_exit "Input and output interfaces cannot be the same"
    fi

    success "Bridge interfaces: $IFACE_IN <-> $IFACE_OUT"

    # Auto-detect HOME_NET if not set
    if [[ -z "${HOME_NET}" ]]; then
        HOME_NET=$(detect_home_network "$MGMT_IFACE")
        if [[ -n "$HOME_NET" ]]; then
            log "Auto-detected network: $HOME_NET"
        else
            HOME_NET="192.168.1.0/24"
            warn "Could not auto-detect network, using default: $HOME_NET"
        fi
    fi

    success "Protected network: $HOME_NET"

    # Export for use in other modules
    export MGMT_IFACE IFACE_IN IFACE_OUT HOME_NET
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
export -f list_network_interfaces detect_mgmt_interface detect_bridge_interfaces
export -f select_interface detect_home_network configure_network_interfaces
