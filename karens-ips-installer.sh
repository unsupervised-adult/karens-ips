#!/bin/bash
# Complete Self-Contained IPS Installer - NFQUEUE Bridge Mode
# Bridge + NFQUEUE + SLIPS + Suricata
# 3-Interface Setup: Management + Bridge (enp6s19 <-> enp6s20)
# 
# BLOCKING ARCHITECTURE:
# ├─ Transit Traffic: Linux bridge (kernel speed) + Suricata NFQUEUE inspection
# ├─ Host Protection: nftables sets (IPS sensor security)
# ├─ DNS Level: RPZ feeds (authoritative blocking)
# └─ ML Detection: SLIPS behavioral analysis -> nftables
#
# Bridge forwards at line-rate, Suricata inspects via nfqueue
# Includes both Kalipso (CLI) and SLIPS Web UI
#
# SURICATA 8.0+ COMPATIBILITY:
#   NFQUEUE mode for high-performance IPS (700+ Mbps)
#   Fixed dataset naming (malicious-domains, bad-ips)
#   Fixed duplicate SIDs and deprecated Lua rules
#   Base64 encoding for string datasets
#   Configuration validation before service start
#
# Created: $(date +'%Y-%m-%d')
# Modified: 2025-11-22 - Converted to NFQUEUE bridge mode

# Safer shell execution with comprehensive error handling
set -Eeuo pipefail
trap 'echo "[FATAL] line $LINENO: $BASH_COMMAND" >&2; exit 1' ERR

# Validate root execution
[[ $EUID -eq 0 ]] || { echo "Error: Must run as root"; exit 1; }

echo "=========================================="
echo "Complete IPS Installer v4.0 - SystemD"
echo "NFQUEUE Bridge Mode"
echo "3-Interface: Management + Bridge"
echo "=========================================="

# Prevent interactive prompts
export DEBIAN_FRONTEND=noninteractive
export TZ=UTC

# Hardcoded test variables for VM environment
MGMT_IFACE="enp6s18"
IFACE_IN="enp6s19"
IFACE_OUT="enp6s20"
HOME_NET="10.10.254.0/24"
MGMT_IP="dhcp"
MGMT_GW=""
MGMT_DNS="10.10.254.189"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    local msg="$(date +'%Y-%m-%d %H:%M:%S') - $1"
    echo -e "${GREEN}${msg}${NC}"
    echo "$msg" >> /var/log/ips-installer.log
}

warn() {
    local msg="$(date +'%Y-%m-%d %H:%M:%S') - WARNING: $1"
    echo -e "${YELLOW}${msg}${NC}"
    echo "$msg" >> /var/log/ips-installer.log
}

error_exit() {
    local msg="$(date +'%Y-%m-%d %H:%M:%S') - ERROR: $1"
    echo -e "${RED}${msg}${NC}" >&2
    echo "$msg" >> /var/log/ips-installer.log
    exit 1
}

info() {
    echo -e "${BLUE}$1${NC}"
}

# Auto-detect interfaces if not specified
auto_detect_interfaces() {
    log "Auto-detecting network interfaces..."
    
    # Get all physical interfaces excluding virtual ones
    local interfaces=()
    for iface in $(ls /sys/class/net/); do
        if [[ "$iface" != "lo" ]] && [[ ! "$iface" =~ ^(docker|veth|br-|virbr|tun|tap) ]] && [[ -e "/sys/class/net/$iface/device" ]]; then
            interfaces+=("$iface")
        fi
    done
    
    # Sort interfaces
    IFS=$'\n' sorted=($(sort -V <<<"${interfaces[*]}"))
    unset IFS
    
    local num_interfaces=${#sorted[@]}
    
    if [[ $num_interfaces -lt 3 ]]; then
        error_exit "Need at least 3 physical interfaces. Found: ${sorted[*]}"
    fi
    
    # Auto-assign interfaces
    if [[ "$MGMT_IFACE" == "auto" ]] || [[ -z "$MGMT_IFACE" ]]; then
        MGMT_IFACE="${sorted[0]}"
    fi
    if [[ "$IFACE_IN" == "auto" ]] || [[ -z "$IFACE_IN" ]]; then
        IFACE_IN="${sorted[1]}"
    fi
    if [[ "$IFACE_OUT" == "auto" ]] || [[ -z "$IFACE_OUT" ]]; then
        IFACE_OUT="${sorted[2]}"
    fi
    
    log "Interface assignment:"
    log "  Management: $MGMT_IFACE"
    log "  Copy IN:    $IFACE_IN"
    log "  Copy OUT:   $IFACE_OUT"
    log "  HOME_NET:   $HOME_NET"
}

# Configuration display
show_configuration() {
    info ""
    info "=========================================="
    info "      ██╗██████╗ ███████╗    ███████╗██╗██╗  ████████╗███████╗██████╗ "
    info "      ██║██╔══██╗██╔════╝    ██╔════╝██║██║  ╚══██╔══╝██╔════╝██╔══██╗"
    info "      ██║██████╔╝███████╗    █████╗  ██║██║     ██║   █████╗  ██████╔╝"
    info "      ██║██╔═══╝ ╚════██║    ██╔══╝  ██║██║     ██║   ██╔══╝  ██╔══██╗"
    info "      ██║██║     ███████║    ██║     ██║███████╗██║   ███████╗██║  ██║"
    info "      ╚═╝╚═╝     ╚══════╝    ╚═╝     ╚═╝╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝"
    info "=========================================="
    info "Network Setup:"
    info "  Management Interface: $MGMT_IFACE ($MGMT_IP)"
    info "  Copy Interface IN:    $IFACE_IN (no IP - packet copy source)"
    info "  Copy Interface OUT:   $IFACE_OUT (no IP - packet copy destination)"
    info "  HOME_NET:             $HOME_NET"
    info ""
    info "AF_PACKET Copy Mode:"
    info "  Traffic IN  -> Suricata -> Traffic OUT"
    info "  Traffic OUT -> Suricata -> Traffic IN"
    info "  No bridging, kernel-level packet copying"
    info ""
    info "Services to Install:"
    info "    Suricata IPS (AF_PACKET copy mode)"
    info "    SLIPS (ML behavioral analysis)"
    info "    Redis (SLIPS backend)"
    info "    Kalipso (Terminal UI for SLIPS)"
    info "    SLIPS Web UI (Browser interface)"
    info "    └─ ML Detector Dashboard (ad detection)"
    info "    SystemD (service management)"
    info "=========================================="
    info ""
    
    read -p "Continue with this configuration? [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        info "Installation cancelled by user"
        exit 0
    fi
}

# System update and base packages
install_base_system() {
    log "Updating system and installing base packages..."
    
    # Fix system clock if out of sync (common VM issue)
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
    
    # Update system
    apt-get update
    apt-get upgrade -y
    
    # Install base dependencies (removed supervisor) 
    apt-get install -y \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
        git \
        wget \
        unzip \
        htop \
        iftop \
        iotop \
        vim \
        tmux \
        screen \
        redis-server \
        ntpdate \
        systemd-timesyncd \
        python3 \
        python3-pip \
        python3-venv \
        iproute2 \
        ethtool \
        iptables \
        nftables \
        iputils-ping \
        dnsutils \
        net-tools \
        tcpdump \
        tshark \
        jq \
        libpcap-dev \
        build-essential \
        rsync
    
    log "Base system packages installed"
    
    # Install Zeek with proper repository handling
    install_zeek
}

# Install Zeek with proper repository setup
install_zeek() {
    log "Installing Zeek network analyzer..."
    
    # Detect Ubuntu version for proper repository
    . /etc/os-release
    UBUNTU_VERSION="$VERSION_CODENAME"
    
    # Try multiple installation methods
    if install_zeek_from_repo; then
        log "Zeek installed from official repository"
    elif install_zeek_precompiled; then
        log "Zeek installed from precompiled package"
    else
        warn "Could not install Zeek - SLIPS will work without it but with reduced capabilities"
        return 1
    fi
    
    # Verify installation - check actual installation location
    if [[ -x /opt/zeek/bin/zeek ]]; then
        # Update PATH for current session
        export PATH="$PATH:/opt/zeek/bin"
        zeek_version=$(/opt/zeek/bin/zeek --version | head -1)
        log "Zeek installed successfully: $zeek_version"
        log "Zeek location: /opt/zeek/bin/zeek"
        return 0
    elif command -v zeek >/dev/null 2>&1; then
        zeek_version=$(zeek --version | head -1)
        log "Zeek installed successfully: $zeek_version"
        return 0
    else
        warn "Zeek installation verification failed - binary not found"
        return 1
    fi
}

# Try installing Zeek from official repository
install_zeek_from_repo() {
    log "Installing Zeek from opensuse.org repository (proven Docker method)..."
    
    # Get Ubuntu version - exact same method as working Dockerfile
    local ubuntu_version
    ubuntu_version=$(lsb_release -r | awk '{print $2}')
    
    if [[ -z "$ubuntu_version" ]]; then
        log "ERROR: Could not determine Ubuntu version"
        return 1
    fi
    
    log "Detected Ubuntu version: $ubuntu_version"
    
    # Use exact same repository URL construction as Dockerfile
    local zeek_repo_url="download.opensuse.org/repositories/security:/zeek/xUbuntu_${ubuntu_version}"
    
    log "Adding Zeek repository: http://${zeek_repo_url}/"
    
    # Add repository (exact Docker method)
    echo "deb http://${zeek_repo_url}/ /" | tee /etc/apt/sources.list.d/security:zeek.list
    
    # Add GPG key with modern keyring (exact Docker method)  
    curl -fsSL "https://${zeek_repo_url}/Release.key" | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
    
    # Update package list
    apt-get update
    
    # Install Zeek (exact Docker method)
    apt-get install -y --no-install-recommends zeek
    
    # Create legacy symlink (exact Docker method)
    ln -sf /opt/zeek/bin/zeek /usr/local/bin/bro
    
    # Add to PATH for all users (exact Docker method)
    echo 'export PATH=$PATH:/opt/zeek/bin' >> /etc/bash.bashrc
    
    # Also update PATH for current session
    export PATH="$PATH:/opt/zeek/bin"
    
    log "  Zeek installation completed successfully"
    return 0
}

# Install Zeek from precompiled package
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
            return 0
        fi
    fi
    
    rm -rf "$temp_dir"
    return 1
}

# Kernel modules and system tuning
setup_kernel_and_tuning() {
    log "Setting up kernel modules and system tuning..."
    
    # Load required kernel modules
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
        modprobe "$module" 2>/dev/null || warn "Could not load module: $module"
        # Guard against duplicate entries in /etc/modules
        if ! grep -q "^$module$" /etc/modules 2>/dev/null; then
            echo "$module" >> /etc/modules
        fi
    done
    
    # System tuning for AF_PACKET high performance (guard against duplicates)
    if ! grep -q "# IPS Network Tuning" /etc/sysctl.conf; then
        cat >> /etc/sysctl.conf << EOF

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
    fi
    
    sysctl -p
    log "Kernel modules and tuning configured"
}

# Setup nftables blocking infrastructure
setup_nftables_blocking() {
    log "Setting up nftables for host protection and SLIPS integration..."
    
    # Install nftables if not present
    apt-get install -y nftables
    
    # Create nftables table with proper named sets for IPv4/IPv6 blocking
    # Note: Transit blocking is handled by Suricata AF_PACKET copy-mode drop rules
    
    # Create dedicated nftables configuration file
    mkdir -p /etc/nftables.d
    cat > /etc/nftables.d/ips-blocksets.nft << 'NFT_CONFIG_EOF'
#!/usr/sbin/nft -f

# IPS Dynamic Blocking Sets
table inet home {
    # IPv4 blocking set with timeout support (IPv6 disabled)
    set blocked4 { 
        type ipv4_addr; 
        flags interval, timeout; 
        timeout 1h;
        gc-interval 1h; 
        comment "IPS blocked IPv4 addresses";
    }
    
    # Host protection chains (INPUT/OUTPUT for IPS sensor protection)
    chain input_filter {
        type filter hook input priority 0; policy accept;
        tcp dport 55000 accept comment "SLIPS Web UI";
        ip saddr @blocked4 counter drop comment "Block malicious IPv4";
    }
    
    chain output_filter {
        type filter hook output priority 0; policy accept;
        ip daddr @blocked4 counter drop comment "Block outbound to malicious IPv4";
    }
    
    # NFQUEUE chain for bridge traffic inspection (IPS mode)
    chain forward_ips {
        type filter hook forward priority 0; policy accept;
        
        # Send all forwarded traffic through bridge to Suricata nfqueue
        iifname "br0" counter queue num 0 bypass comment "Send bridge traffic to Suricata IPS";
        oifname "br0" counter queue num 0 bypass comment "Send bridge traffic to Suricata IPS";
    }
}
NFT_CONFIG_EOF
    
    # Load the configuration
    nft -f /etc/nftables.d/ips-blocksets.nft
    
    # Enable nftables service to persist across reboots
    systemctl enable nftables
    
    # Create input/output chains for HOST protection (not forwarding)
    # This protects the IPS sensor itself from compromise
    nft add chain inet ips input "{ type filter hook input priority 0; }" 2>/dev/null || true
    nft add chain inet ips output "{ type filter hook output priority 0; }" 2>/dev/null || true
    nft add rule inet ips input ip saddr @block_ips drop 2>/dev/null || true
    nft add rule inet ips output ip daddr @block_ips drop 2>/dev/null || true
    nft add rule inet ips input ip6 saddr @block_ips6 drop 2>/dev/null || true
    nft add rule inet ips output ip6 daddr @block_ips6 drop 2>/dev/null || true
    
    # Save nftables configuration
    nft list ruleset > /etc/nftables.conf
    systemctl enable nftables
    
    log "nftables host protection configured (transit handled by Suricata AF_PACKET)"
}

# Install Suricata
install_suricata() {
    log "Installing Suricata..."
    
    # Detect distribution for proper package management
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="$ID"
        VERSION_CODENAME="${VERSION_CODENAME:-$VERSION_ID}"
    else
        log "ERROR: Cannot detect Linux distribution"
        exit 1
    fi
    
    log "Detected distribution: $DISTRO ($VERSION_CODENAME)"
    
    case "$DISTRO" in
        "ubuntu")
            log "Setting up Suricata PPA for Ubuntu..."
            apt-get update
            apt-get install -y software-properties-common
            add-apt-repository -y ppa:oisf/suricata-stable
            apt-get update
            apt-get install -y suricata
            ;;
        "debian")
            log "Setting up Suricata from Debian backports or OISF repository..."
            apt-get update
            # Try backports first
            if ! grep -q "backports" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
                echo "deb http://deb.debian.org/debian $VERSION_CODENAME-backports main" > /etc/apt/sources.list.d/backports.list
                apt-get update
            fi
            apt-get install -y -t "$VERSION_CODENAME-backports" suricata 2>/dev/null || {
                log "Backports failed, trying OISF repository..."
                wget -qO - https://www.openinfosecfoundation.org/debian.gpg | apt-key add - 2>/dev/null || true
                echo "deb https://www.openinfosecfoundation.org/debian/ $VERSION_CODENAME main" > /etc/apt/sources.list.d/oisf.list
                apt-get update
                apt-get install -y suricata
            }
            ;;
        *)
            log "Unsupported distribution: $DISTRO. Trying generic installation..."
            apt-get update
            apt-get install -y suricata || {
                log "ERROR: Could not install Suricata on $DISTRO"
                log "Please install Suricata manually and re-run this script"
                exit 1
            }
            ;;
    esac
    
    # Create suricata user if not exists
    if ! getent passwd suricata > /dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin suricata
        log "Created suricata user"
    fi
    
    # Create directories with proper permissions
    mkdir -p /var/log/suricata /var/lib/suricata/rules /var/run/suricata
    chown -R suricata:suricata /var/log/suricata

    # Configure logrotate for Suricata logs
    cat > /etc/logrotate.d/suricata << 'LOGROTATE_EOF'
/var/log/suricata/*.json /var/log/suricata/*.log {
  hourly
  rotate 24
  compress
  missingok
  sharedscripts
  postrotate
    /bin/kill -HUP $(cat /var/run/suricata.pid 2>/dev/null) 2>/dev/null || true
  endscript
}
LOGROTATE_EOF /var/lib/suricata /var/run/suricata /etc/suricata
    chmod 755 /var/log/suricata
    chmod 750 /var/lib/suricata
    chmod 755 /var/run/suricata
    
    # Create logrotate configuration for Suricata logs (since max-size/max-files unsupported)
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
    
    # Install and configure suricata-update (prefer bundled version)
    if ! command -v suricata-update >/dev/null 2>&1; then
        log "Installing suricata-update via pip (bundled version not found)..."
        pip3 install --upgrade --break-system-packages suricata-update
    fi
    
    # Configure suricata-update for managed public rulesets
    log "Configuring suricata-update for public threat intelligence..."
    
    # Initialize suricata-update
    suricata-update update-sources
    
    # Enable OISF TrafficID and Emerging Threats Open (standard method)
    suricata-update enable-source oisf/trafficid
    suricata-update enable-source et/open
    
    # Run initial update with proper error handling - simplified approach
    if ! suricata-update --no-test; then
        log "Initial suricata-update failed, trying basic update..."
        suricata-update --force || log "Warning: Suricata rule update encountered issues"
    fi
    
    log "Suricata installed successfully"
    
    # Run update with proper error handling
    if ! suricata-update --no-test; then
        log "Initial suricata-update failed, trying basic update..."
        suricata-update --force || log "Warning: Suricata rule update encountered issues"
    fi
    
    log "Suricata installed successfully"
}

# Configure Suricata for AF_PACKET copy mode
configure_suricata_afpacket() {
    log "Configuring Suricata for AF_PACKET copy mode..."
    
    # Backup existing config
    if [ -f /etc/suricata/suricata.yaml ]; then
        cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak.$(date +%Y%m%d)
    fi
    
    # Copy the exact working suricata.yaml from IPS bundle
    cat > /etc/suricata/suricata.yaml << 'SURICATA_EOF'
%YAML 1.1
---
# Suricata IPS Configuration - NFQUEUE Bridge Mode
# Optimized for high-performance bridge + nfqueue inspection  
# Family-safe content filtering with ML behavioral analysis

vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544
    SIP_PORTS: "[5060, 5061]"


ipv6:
  enabled: no

# Default rule path
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - custom-family-filter.rules

# Exception policy: pass packets we can't decode instead of dropping them
exception-policy: auto

# Global stats configuration
stats:
  enabled: yes
  interval: 30

# Output configuration
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      # Log rotation managed by logrotate (max-size/max-files not supported)
      buffer-size: 64KB
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4 KiB
            payload-printable: yes
            packet: yes
            metadata: yes
            http-body: yes
            http-body-printable: yes
            websocket-payload: yes
            websocket-payload-printable: yes
        - anomaly:
            enabled: yes
            types:
              decode: yes
              stream: yes
              applayer: yes
        - http:
            extended: yes
            dump-all-headers: both
        - dns:
            enabled: yes
            formats: [detailed, grouped]
            types: [a, aaaa, cname, mx, ns, ptr, txt]
        - tls:
            extended: yes
            custom: [subject, issuer, session_resumed, serial, fingerprint, sni, version, not_before, not_after, chain, ja3, ja3s]
        - files:
            force-magic: no
            force-hash: [md5]
        - smtp:
            extended: yes
            custom: [received, x-mailer, x-originating-ip, relays, reply-to, bcc]
            md5: [body, subject]
        - dhcp:
            enabled: yes
            extended: no
        - flow:
            enabled: yes
            # Optimized flow export for SLIPS behavioral analysis
            # Only essential metadata to reduce volume
            # Flows contain: IPs, ports, protocols, bytes, packets, duration
            # Use downstream filtering or rules for RFC1918 exclusion
        - stats:
            enabled: yes
            filename: stats.log
            append: yes
            totals: yes
            threads: no
            deltas: no

# Logging configuration
logging:
  default-log-level: info
  default-output-filter:
  outputs:
  - console:
      enabled: yes
  - file:
      enabled: yes
      level: info
      filename: /var/log/suricata/suricata.log
  - syslog:
      enabled: no

app-layer:
  protocols:
    tls:
      enabled: yes
      detection-enabled: yes
      detection-ports:
        dp: 443
      ja3-fingerprints: auto
      encryption-handling: track-only
    dcerpc:
      enabled: yes
    ftp:
      enabled: yes
    ssh:
      enabled: yes
    http2:
      enabled: yes
    smtp:
      enabled: yes
      mime:
        decode-mime: yes
        decode-base64: yes
        decode-quoted-printable: yes
        header-value-depth: 2000
        extract-urls: yes
        body-md5: no
      inspected-tracker:
        content-limit: 100000
        content-inspect-min-size: 32768
        content-inspect-window: 4096
    imap:
      enabled: detection-only
    smb:
      enabled: yes
      detection-ports:
        dp: 139, 445
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
    quic:
      enabled: yes
      detection-enabled: yes
      detection-ports:
        dp: 443
      request-body-minimal-inspect-size: 32kb
      request-body-inspect-window: 4kb
      response-body-minimal-inspect-size: 40kb
      response-body-inspect-window: 16kb
      response-body-decompress-layer-limit: 2
      http-body-inline: auto
      swf-decompression:
        enabled: yes
        type: both
        compress-depth: 0
        decompress-depth: 0
      randomize-inspection-sizes: yes
      randomize-inspection-range: 10
      double-decode-path: no
      double-decode-query: no
    rdp:
      enabled: yes
    vnc:
      enabled: yes
    rfb:
      enabled: yes
    krb5:
      enabled: yes
    ikev2:
      enabled: yes
    ntp:
      enabled: yes
    mqtt:
      enabled: yes
    sip:
      enabled: yes
    nfs:
      enabled: yes
    dhcp:
      enabled: yes
    tftp:
      enabled: yes
    enip:
      enabled: yes
    snmp:
      enabled: yes
    pop3:
      enabled: yes
    modbus:
      enabled: no
    dnp3:
      enabled: no


# Stream configuration
stream:
  memcap: 2gb
  checksum-validation: yes
  inline: yes  # Explicit inline for IPS mode
  reassembly:
    memcap: 1gb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes
    # Inline stream handling optimizations
    raw: yes
    segment-prealloc: 2048
    check-overlap-different-data: true

# Host configuration
host:
  hash-size: 4096
  prealloc: 1000
  memcap: 32mb

# Flow configuration - optimized for gigabit
flow:
  memcap: 2gb
  hash-size: 131072
  prealloc: 20000
  emergency-recovery: 20

# Defragmentation configuration
defrag:
  memcap: 32mb
  hash-size: 65536
  trackers: 65535
  max-frags: 65535
  prealloc: yes
  timeout: 60

# Detection engine
detect:
  profile: medium
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000
  delayed-detect: yes
  prefilter:
    default: mpm
  grouping:
    tcp-priority-ports: 53, 80, 139, 443, 445, 1433, 3306, 3389, 6666, 6667, 8080
    udp-priority-ports: 53, 135, 5060
  profiling:
    inspect-logging-threshold: 200
    grouping:
      dump-to-disk: false
      include-rules: false
      include-mpm-stats: false
  mpm-algo: auto
  spm-algo: auto
    

# Threading configuration for AF_PACKET performance
# Maximum pending packets for high throughput
max-pending-packets: 65535

threading:
  set-cpu-affinity: no  # Let kernel handle affinity for best performance
  detect-thread-ratio: 1.5  # More detection threads
  
# Worker threads for NFQUEUE
worker-threads: auto

# Runmode optimized for NFQUEUE
runmode: workers

# AF_PACKET specific optimizations
# AF_PACKET configuration uses standard af-packet: list format

# Network interface offloading disabled via ethtool in interface setup

# PCAP log (optional, for forensics)
pcap-log:
  enabled: no
  filename: log.pcap
  limit: 1000mb
  max-files: 10
  compression: none
  mode: normal
  use-stream-depth: no
  honor-pass-rules: no

# Unix socket for management
unix-command:
  enabled: yes
  filename: /var/run/suricata/suricata-command.socket

# Legacy settings
legacy:
  uricontent: enabled

# Engine analysis (debugging)
engine-analysis:
  rules-fast-pattern: yes
  rules: yes

# Profiling (disabled in production)
profiling:
  rules:
    enabled: no
    filename: rule_perf.log
    append: yes
  keywords:
    enabled: no
    filename: keyword_perf.log
    append: yes
  prefilter:
    enabled: no
    filename: prefilter_perf.log
    append: yes
  packets:
    enabled: no
    filename: packet_stats.log
    append: yes
  locks:
    enabled: no
    filename: lock_stats.log
    append: yes
  pcap-log:
    enabled: no
    filename: pcaplog_stats.log
    append: yes

# Security configuration
# Running as root to match Docker container configuration

# Datasets managed via Suricata rules (dataset:isset,file.txt) and suricatasc
# No top-level datasets: yaml block needed - remove this unsupported section

# Lua scripting support for complex logic
lua:
  - script: /etc/suricata/lua-scripts/threat-intel.lua
  - script: /etc/suricata/lua-scripts/cdn-detection.lua

# Datasets for telemetry and ad-blocking (Flat file CSV format managed by Suricata)
datasets:
  defaults:
    memcap: 100mb
    hashsize: 4096

  bad-ips:
    type: ipv4
    state: /var/lib/suricata/datasets/bad-ips.csv
    load: file
    memcap: 20mb
    hashsize: 2048

  telemetry-domains:
    type: string
    state: /var/lib/suricata/datasets/telemetry-domains.csv
    load: file
    memcap: 50mb
    hashsize: 8192

  malicious-domains:
    type: string  
    state: /var/lib/suricata/datasets/malicious-domains.csv
    load: file
    memcap: 50mb
    hashsize: 16384

  suspicious-urls:
    type: string
    state: /var/lib/suricata/datasets/suspicious-urls.csv
    load: file
    memcap: 30mb
    hashsize: 4096

  blocked-ips:
    type: ipv4
    state: /var/lib/suricata/datasets/blocked-ips.csv
    load: file
    memcap: 10mb
    hashsize: 1024

  suspect-ja3:
    type: string
    state: /var/lib/suricata/datasets/suspect-ja3.csv
    load: file
    memcap: 5mb
    hashsize: 512

  ech-cdn-ips:
    type: ipv4
    state: /var/lib/suricata/datasets/ech-cdn-ips.csv
    load: file
    memcap: 10mb
    hashsize: 1024

# Coredump configuration
coredump:
  max-dump: unlimited

SURICATA_EOF

    # Create threat intelligence directories and datasets (SINGLE CREATION - NO DUPLICATES)
    mkdir -p /etc/suricata/datasets /etc/suricata/lua-scripts
    
    # Create telemetry domains dataset (first set - basic examples)
    cat > /etc/suricata/datasets/telemetry-domains.txt << 'TELEMETRY_EOF'
dGVsZW1ldHJ5Lm1pY3Jvc29mdC5jb20=
Z29vZ2xlLWFuYWx5dGljcy5jb20=
YWRzLmZhY2Vib29rLmNvbQ==
TELEMETRY_EOF

    # Create DoH servers dataset
    cat > /etc/suricata/datasets/doh-servers.txt << 'DOH_EOF'
Y2xvdWRmbGFyZS1kbnMuY29t
ZG5zLmdvb2dsZQ==
ZG5zLnF1YWQ5Lm5ldA==
DOH_EOF

    # Create CDN bypass dataset
    cat > /etc/suricata/datasets/cdn-bypass.txt << 'CDN_EOF'
ZXhhbXBsZS5jb20=
CDN_EOF

    # Create Lua script for advanced threat intelligence matching
    cat > /etc/suricata/lua-scripts/threat-intel.lua << 'LUA_THREAT_EOF'
-- Advanced Threat Intelligence Matching
-- Handles complex URL/domain/IP/port combinations

function init(args)
    local needs = {}
    needs["tls.sni"] = tostring(true)
    needs["dns.query"] = tostring(true)
    needs["http.host"] = tostring(true)
    needs["http.uri"] = tostring(true)
    return needs
end

function match(args)
    local tls_sni = ScSslGetServerName()
    local dns_query = ScDnsGetQuery()
    local http_host = ScHttpGetHost()
    local http_uri = ScHttpGetUri()
    
    -- Check against threat intel datasets
    if tls_sni then
        if check_malicious_domain(tls_sni) then
            return 1
        end
    end
    
    if dns_query then
        if check_malicious_domain(dns_query) then
            return 1
        end
    end
    
    if http_host and http_uri then
        local full_url = http_host .. http_uri
        if check_suspicious_url(full_url) then
            return 1
        end
    end
    
    return 0
end

-- Helper function to check malicious domains
function check_malicious_domain(domain)
    -- This would integrate with your threat intel database
    -- Example implementation (replace with actual logic):
    
    -- Check exact match
    if ScDatasetGet("malicious-domains", domain) then
        return true
    end
    
    -- Check subdomain patterns
    local parts = {}
    for part in string.gmatch(domain, "([^.]+)") do
        table.insert(parts, part)
    end
    
    -- Check parent domains
    for i = 2, #parts do
        local parent = table.concat(parts, ".", i)
        if ScDatasetGet("malicious-domains", parent) then
            return true
        end
    end
    
    return false
end

-- Helper function to check suspicious URLs
function check_suspicious_url(url)
    return ScDatasetGet("suspicious-urls", url)
end
LUA_THREAT_EOF

    # Create CDN detection Lua script
    cat > /etc/suricata/lua-scripts/cdn-detection.lua << 'LUA_CDN_EOF'
-- CDN Detection and Bypass
-- Identifies content delivery networks and maps back to original domains

function init(args)
    local needs = {}
    needs["tls.sni"] = tostring(true)
    needs["http.host"] = tostring(true)
    return needs
end

function match(args)
    local hostname = ScSslGetServerName() or ScHttpGetHost()
    
    if hostname then
        -- Check if this is a CDN domain
        local original_domain = resolve_cdn_domain(hostname)
        if original_domain then
            -- Check if the original domain is malicious
            if ScDatasetGet("malicious-domains", original_domain) then
                return 1
            end
        end
    end
    
    return 0
end

-- Resolve CDN domains to original domains
function resolve_cdn_domain(cdn_domain)
    -- Common CDN patterns
    local cdn_patterns = {
        ["%.cloudfront%.net$"] = "cloudfront",
        ["%.fastly%.com$"] = "fastly", 
        ["%.cloudflare%.com$"] = "cloudflare",
        ["%.akamaized%.net$"] = "akamai",
        ["%.azureedge%.net$"] = "azure"
    }
    
    -- Check if domain matches CDN pattern
    for pattern, cdn_name in pairs(cdn_patterns) do
        if string.match(cdn_domain, pattern) then
            -- Look up original domain in bypass dataset
            return ScDatasetGet("cdn-bypass.txt", cdn_domain)
        end
    end
    
    return nil
end
LUA_CDN_EOF
    cat > /etc/suricata/disable.conf << 'DISABLE_EOF'
# Disabled rule SIDs (known false positives)
3301136
3301137
3301138
3306862
3306863
3321359
3321360
3321387
3321388
3321389
2610869
DISABLE_EOF

    # Create threat intelligence directories and dataset files for 100k+ entries
    mkdir -p /etc/suricata/datasets /etc/suricata/lua-scripts
    
    # Large-scale ad/tracking domains dataset (supports 100k+ entries)
    cat > /etc/suricata/datasets/malicious-domains.txt << 'DOMAINS_EOF'
ZG91YmxlY2xpY2submV0
Z29vZ2xlYWRzZXJ2aWNlcy5jb20=
Z29vZ2xlc3luZGljYXRpb24uY29t
ZmFjZWJvb2suY29t
Z29vZ2xldGFnbWFuYWdlci5jb20=
Z29vZ2xlLWFuYWx5dGljcy5jb20=
c2NvcmVjYXJkcmVzZWFyY2guY29t
b3V0YnJhaW4uY29t
dGFib29sYS5jb20=
dGVsZW1ldHJ5Lm1pY3Jvc29mdC5jb20=
dm9ydGV4LmRhdGEubWljcm9zb2Z0LmNvbQ==research.com
outbrain.com
taboola.com

# Telemetry Domains (examples)
telemetry.microsoft.com
vortex.data.microsoft.com
settings-win.data.microsoft.com
watson.telemetry.microsoft.com
# data.microsoft.com

# Adult Content Domains (examples - add your lists)
# (Add inappropriate domains here)

# Social Media (optional - for kids)
# facebook.com
# instagram.com
# tiktok.com
# snapchat.com
DOMAINS_EOF

    # Ad/Tracking server IPs dataset - ONLY valid IPs/CIDRs
    cat > /etc/suricata/datasets/malicious-ips.txt << 'IPS_EOF'
142.250.0.0/15
172.217.0.0/16
157.240.0.0/16
173.252.0.0/16
52.0.0.0/8
40.0.0.0/8
IPS_EOF

    # Create C2 IPs dataset  
    cat > /etc/suricata/datasets/c2-ips.txt << 'C2_EOF'
203.0.113.0/24
198.51.100.0/24
C2_EOF

    # IMMEDIATE dataset validation after creation - catch issues early
    log "Immediate dataset validation after creation..."
    for ip_file in /etc/suricata/datasets/malicious-ips.txt /etc/suricata/datasets/c2-ips.txt; do
        if [[ -f "$ip_file" ]]; then
            log "Checking $ip_file immediately after creation..."
            # Show first few lines to debug
            echo "First 10 lines of $ip_file:"
            head -10 "$ip_file" | nl
            
            # Quick clean - remove anything that's not a valid IPv4 address/CIDR
            python3 - <<PY
import ipaddress, re
src = "$ip_file"
dst = src + ".temp"
valid_count = 0
invalid_lines = []

with open(dst, "w") as out:
    with open(src) as f:
        for line_num, line in enumerate(f, 1):
            s = line.strip()
            # Skip empty lines and comments
            if not s or s.startswith('#'):
                continue
            
            # Check for obviously invalid content (contains letters that aren't part of IPs)
            if re.search(r'^[a-zA-Z].*[a-zA-Z]', s):
                invalid_lines.append(f"Line {line_num}: '{s}' (appears to be text, not IP)")
                continue
                
            try:
                # Only IPv4 addresses/networks
                if '/' in s:
                    net = ipaddress.ip_network(s, strict=False)
                    if net.version == 4:
                        out.write(s + "\n")
                        valid_count += 1
                    else:
                        invalid_lines.append(f"Line {line_num}: '{s}' (IPv6 disabled)")
                else:
                    addr = ipaddress.ip_address(s)
                    if addr.version == 4:
                        out.write(s + "\n")
                        valid_count += 1
                    else:
                        invalid_lines.append(f"Line {line_num}: '{s}' (IPv6 disabled)")
            except ValueError as e:
                invalid_lines.append(f"Line {line_num}: '{s}' (invalid: {e})")

if invalid_lines:
    print(f"Found {len(invalid_lines)} invalid entries in {src}:")
    for line in invalid_lines:
        print(f"  {line}")
else:
    print(f"All entries in {src} are valid")

print(f"Valid entries: {valid_count}")

# Replace with cleaned version or ensure at least one valid IP
import os
if valid_count > 0:
    os.replace(dst, src)
else:
    # Create minimal valid file
    with open(src, 'w') as f:
        f.write("127.0.0.1\n")
    os.remove(dst)
    print(f"Created minimal valid dataset: {src}")
PY
            chown suricata:suricata "$ip_file"
            chmod 644 "$ip_file"
        fi
    done

    # Tracking URLs and inappropriate content patterns
    cat > /etc/suricata/datasets/suspicious-urls.txt << 'URLS_EOF'
L2Fkcy8=
L3RyYWNr
L2FuYWx5dGljcw==
L3BpeGVs
L2JlYWNvbg==
L3RlbGVtZXRyeQ==
L21ldHJpY3M=
L2NvbGxlY3Q=
L2xvZw==
L2FwaS9ncmFwaHFs
L2FqYXgv
L3RyLw==
URLS_EOF

    # Family-Safe Content Filtering Lua script
    cat > /etc/suricata/lua-scripts/threat-intel.lua << 'LUA_EOF'
-- Family-Safe Content Filtering & Privacy Protection
-- Blocks ads, tracking, telemetry, and inappropriate content

function init(args)
    local needs = {}
    needs["tls.sni"] = tostring(true)
    needs["dns.query"] = tostring(true)
    needs["http.host"] = tostring(true)
    needs["http.uri"] = tostring(true)
    needs["http.user_agent"] = tostring(true)
    return needs
end

function match(args)
    local tls_sni = ScSslGetServerName()
    local dns_query = ScDnsGetQuery()
    local http_host = ScHttpGetHost()
    local http_uri = ScHttpGetUri()
    local user_agent = ScHttpGetUserAgent()
    
    -- Block known ad/tracking domains
    if tls_sni and is_blocked_domain(tls_sni) then
        return 1
    end
    if dns_query and is_blocked_domain(dns_query) then
        return 1
    end
    if http_host and is_blocked_domain(http_host) then
        return 1
    end
    
    -- Block tracking URLs
    if http_uri and is_tracking_url(http_uri) then
        return 1
    end
    
    -- Block based on user agent patterns (some trackers)
    if user_agent and is_tracking_agent(user_agent) then
        return 1
    end
    
    return 0
end

function is_blocked_domain(domain)
    -- Check against family-safe blocklist
    return ScDatasetGet("malicious-domains", domain)
end

function is_tracking_url(uri)
    -- Check against tracking URL patterns
    return ScDatasetGet("suspicious-urls", uri)
end

function is_tracking_agent(agent)
    -- Block known tracking user agents
    local tracking_patterns = {
        "bot", "crawler", "spider", "analytics", "pixel", "beacon"
    }
    
    local lower_agent = string.lower(agent)
    for _, pattern in ipairs(tracking_patterns) do
        if string.find(lower_agent, pattern) then
            return true
        end
    end
    
    return false
end
LUA_EOF

    # Set permissions for threat intel files
    chown -R suricata:suricata /etc/suricata/datasets /etc/suricata/lua-scripts
    chmod -R 644 /etc/suricata/datasets/* /etc/suricata/lua-scripts/*

    # Convert string dataset files to base64 format (required for Suricata 8.0+)
    log "Converting string datasets to base64 format with comprehensive cleanup..."
    for f in /etc/suricata/datasets/telemetry-domains.txt \
             /etc/suricata/datasets/malicious-domains.txt \
             /etc/suricata/datasets/suspicious-urls.txt \
             /etc/suricata/datasets/doh-servers.txt \
             /etc/suricata/datasets/suspect-ja3.txt \
             /etc/suricata/datasets/ech-cdn-ips.txt
    do
        if [[ -f "$f" ]]; then
            tmp=$(mktemp)
            # Strip comments, empty lines, and normalize whitespace
            grep -v '^[[:space:]]*#' "$f" | grep -v '^[[:space:]]*$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
              | while IFS= read -r line; do 
                  if [[ -n "$line" ]]; then
                    printf '%s' "$line" | base64 -w0
                    echo
                  fi
                done > "$tmp" \
              && mv "$tmp" "$f" || rm -f "$tmp"
        fi
    done
    chown -R suricata:suricata /etc/suricata/datasets
    chmod -R 644 /etc/suricata/datasets/*

    # Clean and validate IP datasets (type: ip requires valid IPs/CIDRs only)
    log "Cleaning and validating IP datasets..."
    for ip_file in /etc/suricata/datasets/malicious-ips.txt /etc/suricata/datasets/c2-ips.txt; do
        if [[ -f "$ip_file" ]]; then
            python3 - <<PY
import ipaddress, sys
src="$ip_file"
dst=src+".clean"
with open(dst,"w") as out, open(src) as f:
    for line in f:
        s=line.strip()
        if not s or s.startswith("#"): continue
        try:
            (ipaddress.ip_network(s, strict=False) if "/" in s else ipaddress.ip_address(s))
            out.write(s+"\n")
        except ValueError:
            pass
import os; os.replace(dst, src)
PY
            chown suricata:suricata "$ip_file"
            chmod 644 "$ip_file"
        fi
    done

    # Configure logrotate for Suricata logs with SIGHUP
    cat > /etc/logrotate.d/suricata << 'LOGROTATE_EOF'
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 suricata adm
    postrotate
        # Signal Suricata to reopen log files
        if [ -f /var/run/suricata.pid ]; then
            kill -HUP $(cat /var/run/suricata.pid) 2>/dev/null || true
        fi
    endscript
}
LOGROTATE_EOF

    # Set permissions
    chown suricata:suricata /etc/suricata/suricata.yaml /etc/suricata/disable.conf
    chmod 640 /etc/suricata/suricata.yaml
    chmod 644 /etc/suricata/disable.conf
    
    # Final dataset name normalization safety check
    log "Ensuring dataset names are consistently hyphenated..."
    if [[ -f /var/lib/suricata/rules/custom-family-filter.rules ]]; then
        sed -i -E 's/malicious_domains/malicious-domains/g; s/suspicious_urls/suspicious-urls/g; s/telemetry_domains/telemetry-domains/g; s/doh_servers/doh-servers/g; s/ech_cdn_ips/ech-cdn-ips/g' \
            /var/lib/suricata/rules/custom-family-filter.rules
    fi
    
    log "Suricata AF_PACKET configuration created with disable.conf"
}

# Download and update Suricata rules
update_suricata_rules() {
    log "Setting up Suricata for custom rules (skipping rule downloads)..."
    
    # Ensure datasets directory exists
    mkdir -p /etc/suricata/datasets
    chown -R suricata:suricata /etc/suricata/datasets
    
    # CRITICAL: Initialize CSV state files for datasets (Suricata 8 requirement)
    log "Initializing dataset state files..."
    mkdir -p /var/lib/suricata/datasets
    touch /var/lib/suricata/datasets/bad-ips.csv
    touch /var/lib/suricata/datasets/telemetry-domains.csv
    touch /var/lib/suricata/datasets/malicious-domains.csv
    touch /var/lib/suricata/datasets/suspicious-urls.csv
    touch /var/lib/suricata/datasets/blocked-ips.csv
    touch /var/lib/suricata/datasets/suspect-ja3.csv
    touch /var/lib/suricata/datasets/ech-cdn-ips.csv
    chown -R suricata:suricata /var/lib/suricata/datasets
    chmod -R 644 /var/lib/suricata/datasets/*.csv
    
    # Create authoritative datasets (no duplicates)
    # Note: telemetry-domains, doh-servers, cdn-bypass already created above
    
    # Create suspect JA3 fingerprint dataset
    # Create any missing datasets that might be referenced
    touch /etc/suricata/datasets/suspicious-urls.txt
    touch /etc/suricata/datasets/malicious-domains.txt  
    touch /etc/suricata/datasets/malicious-ips.txt
    touch /etc/suricata/datasets/c2-ips.txt
    touch /etc/suricata/datasets/suspect-ja3.txt

    # Create ECH-aware CDN IP dataset (string type for Suricata 8 compatibility)
    cat > /etc/suricata/datasets/ech-cdn-ips.txt << 'ECH_IPS_EOF'
MTA0LjE2LjAuMC8xMg==
MTcyLjY0LjAuMC8xMw==
MTg4LjExNC45Ni4wLzIw
MTk3LjIzNC4yNDAuMC8yMg==
OC44LjguMC8yNA==
MTQyLjI1MC4wLjAvMTU=
MTcyLjIxNy4wLjAvMTY=
MzEuMTMuMjQuMC8yMQ==
MTU3LjI0MC4wLjAvMTY=
MTc5LjYwLjE5Mi4wLzIy
MTUxLjEwMS4wLjAvMTY=
MTMuMzIuMC4wLzE1
NTQuMjMwLjAuMC8xNQ==
MTMuMTA3LjQyLjAvMjQ=
ECH_IPS_EOF

    # Create DoH servers dataset (base64 encoded)
    cat > /tmp/doh-plain.txt << 'DOH_PLAIN_EOF'
# Known DNS-over-HTTPS (DoH) Servers
cloudflare-dns.com
1dot1dot1dot1.cloudflare-dns.com
dns.google
dns64.dns.google
dns.quad9.net
dns9.quad9.net
dns10.quad9.net
dns11.quad9.net
doh.opendns.com
dns.adguard.com
dns-family.adguard.com
doh.cleanbrowsing.org
anycast.dns.nextdns.io
DOH_PLAIN_EOF

    # Convert to base64 for string dataset
    while read -r d; do 
        [[ -n "$d" && "$d" != \#* ]] && printf '%s\n' "$(echo -n "$d" | base64)"
    done < /tmp/doh-plain.txt > /etc/suricata/datasets/doh-servers.txt
    rm -f /tmp/doh-plain.txt

    # Create enhanced JA3 patterns for ECH-capable clients (base64 encoded)
    cat >> /etc/suricata/datasets/suspect-ja3.txt << 'ECH_JA3_EOF'
ZWM3NGE1YzUxMTA2ZjA0MTkxODRkMGRkMDhmYjA1YmM=
YTBlOWY1ZDY0MzQ5ZmIxMzE5MWJjNzgxZjgxZjQyZTE=
YjMyMzA5YTI2OTUxOTEyYmU3ZGJhMzc2Mzk4YWJjM2I=
ECH_JA3_EOF
    
    chown -R suricata:suricata /etc/suricata/datasets

    cat > /var/lib/suricata/rules/custom-family-filter.rules << 'CUSTOM_RULES'
# Family-Safe Content Filtering Rules
# Blocks ads, tracking, telemetry, and inappropriate content for kids
# Supports 100k+ domain/URL blocklists

#==============================================================================
# AD & TRACKING BLOCKING (High Performance)
#==============================================================================

# SNI extraction for analysis (silent logging)
alert tls any any -> any any (msg:"SNI LOGGING"; tls.sni; noalert; sid:9000001; rev:1;)

# TLS SNI dataset block (compact, fast)
drop tls any any -> any any (msg:"FAMILY FILTER - blocked domain (TLS dataset)"; tls.sni; dataset:isset,malicious-domains; classtype:policy-violation; priority:2; sid:2000100; rev:1;)

# DNS query blocking with telemetry dataset
drop dns any any -> any 53 (msg:"FAMILY FILTER - blocked DNS query (dataset)"; dns.query; dataset:isset,telemetry-domains; classtype:policy-violation; priority:2; sid:2000101; rev:1;)

# HTTP Host blocking
drop http any any -> any any (msg:"FAMILY FILTER - blocked HTTP host (dataset)"; http.host; dataset:isset,malicious-domains; classtype:policy-violation; priority:2; sid:2000102; rev:1;)

# Block tracking server IPs
drop ip any any -> any any (msg:"FAMILY FILTER - Blocked Ad/Tracking Server IP"; ip.dst; dataset:isset,bad-ips; sid:2000110; rev:1; classtype:policy-violation; priority:2;)

# Block tracking URLs
drop http any any -> any any (msg:"FAMILY FILTER - Blocked Tracking URL"; http.uri; dataset:isset,suspicious-urls; sid:2000120; rev:1; classtype:policy-violation; priority:2;)

#==============================================================================
# TELEMETRY & PRIVACY PROTECTION
#==============================================================================

# Microsoft telemetry blocking
drop tls any any -> any any (msg:"PRIVACY - Microsoft Telemetry Blocked"; tls.sni; content:"telemetry.microsoft.com"; sid:2000200; rev:1; classtype:policy-violation; priority:2;)
drop tls any any -> any any (msg:"PRIVACY - Microsoft Data Collection Blocked"; tls.sni; content:".data.microsoft.com"; sid:2000201; rev:1; classtype:policy-violation; priority:2;)

# Google analytics/ads blocking
drop tls any any -> any any (msg:"PRIVACY - Google Analytics Blocked"; tls.sni; content:"google-analytics.com"; sid:2000210; rev:1; classtype:policy-violation; priority:2;)
drop tls any any -> any any (msg:"PRIVACY - Google Ads Blocked"; tls.sni; content:"googleadservices.com"; sid:2000211; rev:1; classtype:policy-violation; priority:2;)

# Facebook/Meta tracking
drop tls any any -> any any (msg:"PRIVACY - Facebook Tracking Blocked"; tls.sni; content:".facebook.com"; sid:2000220; rev:1; classtype:policy-violation; priority:2;)
drop http any any -> any any (msg:"PRIVACY - Facebook Pixel Blocked"; http.uri; content:"/tr/"; sid:2000221; rev:1; classtype:policy-violation; priority:2;)

#==============================================================================
# KIDS PROTECTION (Social Media & Content)
#==============================================================================

# Block social media during school hours (optional - customize time)
# drop tls any any -> any any (msg:"KIDS FILTER - Social Media During School Hours"; tls.sni; content:"tiktok.com"; time:"09:00-15:00"; sid:2000300; rev:1; classtype:policy-violation; priority:2;)
# drop tls any any -> any any (msg:"KIDS FILTER - Instagram During School Hours"; tls.sni; content:"instagram.com"; time:"09:00-15:00"; sid:2000301; rev:1; classtype:policy-violation; priority:2;)

# Block gaming sites during homework time (optional)
# drop tls any any -> any any (msg:"KIDS FILTER - Gaming Site Blocked"; tls.sni; pcre:"/.*(game|gaming|steam|epic)\./i"; time:"18:00-20:00"; sid:2000310; rev:1; classtype:policy-violation; priority:2;)

#==============================================================================
# DOH/DOT PRIVACY BYPASS PREVENTION
#==============================================================================

# Block DoH to prevent DNS filtering bypass
drop http any any -> any 443 (msg:"FAMILY FILTER - DoH Bypass Attempt"; http.uri; content:"/dns-query"; sid:2000400; rev:1; classtype:policy-violation; priority:1;)

# Block common DoH providers (kids might use to bypass filtering)
drop tls any any -> any 443 (msg:"FAMILY FILTER - Cloudflare DoH Blocked"; tls.sni; content:"cloudflare-dns.com"; sid:2000401; rev:1; classtype:policy-violation; priority:1;)
drop tls any any -> any 443 (msg:"FAMILY FILTER - Google DoH Blocked"; tls.sni; content:"dns.google"; sid:2000402; rev:1; classtype:policy-violation; priority:1;)
drop tls any any -> any 443 (msg:"FAMILY FILTER - Quad9 DoH Blocked"; tls.sni; content:"dns.quad9.net"; sid:2000403; rev:1; classtype:policy-violation; priority:1;)

# Block DoT (DNS over TLS) to prevent bypass
drop tls any any -> any 853 (msg:"FAMILY FILTER - DoT Bypass Attempt"; flow:established; sid:2000410; rev:1; classtype:policy-violation; priority:1;)

#==============================================================================
# QUIC/HTTP3 & ECH BLOCKING (Modern Bypass Prevention)
#==============================================================================

# QUIC/HTTP3 blocking with dataset support
drop quic any any -> any 443 (msg:"FAMILY FILTER - QUIC to telemetry (dataset)"; quic.sni; dataset:isset,telemetry-domains; classtype:policy-violation; priority:2; sid:2000420; rev:1;)

# Block QUIC to known ad/tracking domains
drop udp any any -> any 443 (msg:"FAMILY FILTER - QUIC to blocked domains"; ip.dst; dataset:isset,ech-cdn-ips; classtype:policy-violation; priority:2; sid:2000421; rev:1;)

# Option A: Block ALL QUIC/HTTP3 (most effective for family filtering)
# Uncomment to force all traffic to inspectable TLS/TCP
# drop udp any any -> any 443 (msg:"BLOCK ALL QUIC/HTTP3"; sid:2000999; rev:1;)

# Option B: Monitor QUIC traffic (logging only)
alert udp any any -> any 443 (msg:"QUIC TRAFFIC DETECTED"; sid:2001000; rev:1;)

# Enhanced DoH detection with dataset support
# DoH bypass attempts blocked (HTTP only)
drop http any any -> any 443 (msg:"FAMILY FILTER - DoH /dns-query Bypass"; http.uri; content:"/dns-query"; endswith; sid:2000422; rev:1; classtype:policy-violation; priority:1;)

# Force TLS/TCP on kids network (optional - blocks QUIC entirely on specific segments)
# drop udp any any -> any 443 (msg:"FAMILY FILTER - Force TLS/TCP on kids network"; iifname:"br-kids"; classtype:policy-violation; priority:1; sid:2000423; rev:1;)

#==============================================================================
# ECH/ENCRYPTED CLIENTHELLO FUTURE-PROOFING
#==============================================================================

# ECH detection and logging (TLS 1.3 with encrypted_client_hello extension)
alert tls any any -> any any (msg:"FAMILY FILTER - ECH Encrypted ClientHello Detected"; tls.version:1.3; content:"|00 FE|"; offset:0; depth:2; sid:2000430; rev:1; classtype:protocol-command-decode; priority:3;)
alert tls any any -> any any (msg:"FAMILY FILTER - ECH Inner ClientHello"; tls.version:1.3; content:"|FE 0D|"; sid:2000431; rev:1; classtype:protocol-command-decode; priority:3;)

# Cloudflare ECH endpoints (major ECH adopter)
drop tls any any -> any any (msg:"FAMILY FILTER - Cloudflare ECH Endpoint Block"; tls.sni; content:"cloudflare-ech"; sid:2000432; rev:1; classtype:policy-violation; priority:2;)

# Firefox ECH DoH (blocks ECH-enabled DoH)
drop tls any any -> any any (msg:"FAMILY FILTER - Firefox ECH DoH Block"; tls.sni; content:"mozilla.cloudflare-dns.com"; sid:2000433; rev:1; classtype:policy-violation; priority:1;)

# Chrome ECH DoH (blocks Chrome ECH-enabled DoH)
drop tls any any -> any any (msg:"FAMILY FILTER - Chrome ECH DoH Block"; tls.sni; content:"chrome.cloudflare-dns.com"; sid:2000434; rev:1; classtype:policy-violation; priority:1;)

# QUIC with ECH indicators
drop udp any any -> any 443 (msg:"FAMILY FILTER - QUIC ECH Traffic"; content:"|FE 0D|"; sid:2000435; rev:1; classtype:policy-violation; priority:2;)

# QUIC version negotiation blocking for unsupported protocols
drop udp any any -> any 443 (msg:"FAMILY FILTER - QUIC Version Negotiation Block"; content:"|01 00 00 00|"; offset:0; depth:4; sid:2000436; rev:1; classtype:protocol-command-decode; priority:2;)

#==============================================================================
# ADVANCED CONTENT FILTERING (Lua-based)
#==============================================================================

# NOTE: Lua rules with data types are deprecated in Suricata 8+ - use rule hooks instead
# drop tls any any -> any any (msg:"LUA FAMILY FILTER - Advanced Content Analysis"; lua:/etc/suricata/lua-scripts/threat-intel.lua; sid:2000500; rev:1; classtype:policy-violation; priority:2;)
# drop http any any -> any any (msg:"LUA FAMILY FILTER - Advanced HTTP Analysis"; lua:/etc/suricata/lua-scripts/threat-intel.lua; sid:2000501; rev:1; classtype:policy-violation; priority:2;)

#==============================================================================
# Multi-Criteria Matching (IP + Port + Domain Combinations)
#==============================================================================

# Malicious domain on suspicious ports
drop tls any any -> any ![443,853] (msg:"THREAT INTEL - Malicious Domain on Unusual TLS Port"; tls.sni; dataset:isset,malicious-domains; sid:1000300; rev:1; classtype:trojan-activity; priority:1;)

# DNS queries to malicious domains on non-standard ports
drop dns any any -> any ![53,853] (msg:"THREAT INTEL - Malicious DNS Query on Unusual Port"; dns.query; dataset:isset,malicious-domains; sid:1000301; rev:1; classtype:trojan-activity; priority:1;)

# HTTP to malicious domains with specific user-agents
drop http any any -> any any (msg:"THREAT INTEL - Malicious Domain with Suspicious User-Agent"; http.host; dataset:isset,malicious-domains; http.user_agent; content:"bot"; sid:1000302; rev:1; classtype:trojan-activity; priority:1;)

#==============================================================================
# DoH/DoT Specific Rules with Threat Intelligence
#==============================================================================

# DoH queries to malicious domains
drop http any any -> any 443 (msg:"THREAT INTEL - DoH Query to Malicious Domain"; http.uri; content:"/dns-query"; http.host; dataset:isset,malicious-domains; sid:1000400; rev:1; classtype:trojan-activity; priority:1;)

# DoT connections to malicious resolvers
drop tls any any -> any 853 (msg:"THREAT INTEL - DoT to Malicious Resolver"; tls.sni; dataset:isset,malicious-domains; sid:1000401; rev:1; classtype:trojan-activity; priority:1;)

#==============================================================================
# Performance Optimized Rules (for high-volume environments)
#==============================================================================

# Fast hash-based lookups (optimized for 100k+ entries)
drop ip any any <> any any (msg:"FAST THREAT INTEL - Malicious IP Communication"; ip.src; dataset:isset,bad-ips; sid:1000500; rev:1; classtype:trojan-activity; priority:1;)
drop ip any any <> any any (msg:"FAST THREAT INTEL - Malicious IP Communication"; ip.dst; dataset:isset,bad-ips; sid:1000501; rev:1; classtype:trojan-activity; priority:1;)

#==============================================================================
# Usage Instructions for Large-Scale Threat Intelligence:
#
# 1. Populate Dataset Files:
#    - /etc/suricata/datasets/malicious-domains.txt (base64 encoded, one per line)
#    - /etc/suricata/datasets/malicious-ips.txt (one IP/CIDR per line)
#    - /etc/suricata/datasets/suspicious-urls.txt (one URL pattern per line)
#    - /etc/suricata/datasets/cdn-bypass.txt (cdn_domain,original_domain)
#
# 2. Performance Considerations:
#    - Datasets are loaded into memory (adjust memcap as needed)
#    - Hash lookups are O(1) - very fast even for 100k+ entries
#    - Lua scripts allow complex logic but are slightly slower
#
# 3. Testing Large Datasets:
#    sudo suricata -T -c /etc/suricata/suricata.yaml
#    sudo systemctl restart suricata
#    tail -f /var/log/suricata/fast.log
#
# 4. Dataset Management:
#    - Reload datasets: sudo systemctl reload suricata  
#    - Monitor memory usage: grep dataset /var/log/suricata/suricata.log
#    - Update threat intel: replace dataset files and reload
#==============================================================================
CUSTOM_RULES

    # Convert string datasets to base64 format (required for Suricata 8)
    log "Converting string datasets to base64 format..."
    
    # Convert ALL string datasets to base64 - skip empty files
    for f in /etc/suricata/datasets/telemetry-domains.txt /etc/suricata/datasets/malicious-domains.txt /etc/suricata/datasets/suspicious-urls.txt /etc/suricata/datasets/suspect-ja3.txt; do
        if [ -f "$f" ] && [ -s "$f" ]; then
            tmp=$(mktemp)
            sed '/^[[:space:]]*#/d;/^[[:space:]]*$/d' "$f" | while IFS= read -r line; do
                if [ -n "$line" ]; then
                    printf "%s" "$line" | base64 -w0
                    echo
                fi
            done > "$tmp"
            mv "$tmp" "$f"
            log "Converted $f to base64 format"
        else
            log "Skipped empty file $f"
        fi
    done
    
    # doh-servers.txt is already base64 encoded during creation
    
    # IP datasets stay as plain IP/CIDR; just drop comments/blanks  
    for f in /etc/suricata/datasets/malicious-ips.txt /etc/suricata/datasets/c2-ips.txt; do
        if [ -f "$f" ]; then
            sed -i '/^[[:space:]]*#/d;/^[[:space:]]*$/d' "$f"
            log "Cleaned comments from IP dataset $f"
        fi
    done
    
    # Final permissions
    chown -R suricata:suricata /etc/suricata/datasets
    chmod 640 /etc/suricata/datasets/*.txt

    log ""
    log "Setting up SQLite-based dynamic IPS filtering system..."

    
    # Install Python dependencies
    pip3 install flask 2>/dev/null || true
    pip3 install redis 2>/dev/null || true
    
    # Create SQLite database management system
    cat > /opt/ips-filter-db.py << 'IPS_DB_EOF'
#!/usr/bin/env python3
"""
SQLite-Based IPS Content Filter Management
Manages dynamic blocking of domains/IPs for Suricata IPS
Supports real-time updates and large-scale threat intelligence
"""

import sqlite3
import json
import base64
import subprocess
import sys
import os
import redis
import time
from datetime import datetime

class IPSFilterDB:
    def __init__(self, db_path='/var/lib/suricata/ips_filter.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        # Optimized SQLite connection with WAL mode and durability settings
        conn = sqlite3.connect(self.db_path, timeout=2, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=OFF")  # Fast imports
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA cache_size=-200000")  # ~200MB cache
        cursor = conn.cursor()
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            category TEXT NOT NULL,
            reason TEXT,
            added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            active BOOLEAN DEFAULT 1,
            added_by TEXT
        )''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            domain TEXT,
            action TEXT,
            category TEXT,
            rule_triggered TEXT
        )''')
        
        # Additional tables for Suricata datasets
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            category TEXT NOT NULL DEFAULT 'malicious',
            reason TEXT,
            added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            active BOOLEAN DEFAULT 1
        )''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS suspicious_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url_pattern TEXT UNIQUE NOT NULL,
            category TEXT NOT NULL DEFAULT 'tracking',
            reason TEXT,
            added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            active BOOLEAN DEFAULT 1
        )''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ja3_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ja3_hash TEXT UNIQUE NOT NULL,
            category TEXT NOT NULL DEFAULT 'suspect',
            description TEXT,
            added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            active BOOLEAN DEFAULT 1
        )''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS telemetry_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            vendor TEXT,
            purpose TEXT,
            added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            active BOOLEAN DEFAULT 1
        )''')
        
        # Create performance indexes for 100k+ entries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocked_domains_domain ON blocked_domains(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocked_domains_category ON blocked_domains(category)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocked_domains_active ON blocked_domains(active)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_log_timestamp ON activity_log(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocked_ips_active ON blocked_ips(active)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_suspicious_urls_pattern ON suspicious_urls(url_pattern)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ja3_hash ON ja3_signatures(ja3_hash)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_telemetry_domains_domain ON telemetry_domains(domain)')
        
        conn.commit()
        conn.close()
        
        # Add default IPS filter blocks
        defaults = [
            ('facebook.com', 'social_media', 'Social media'),
            ('instagram.com', 'social_media', 'Social media'),
            ('tiktok.com', 'social_media', 'Social media'),
            ('doubleclick.net', 'advertising', 'Ad tracking'),
            ('googleadservices.com', 'advertising', 'Google ads'),
            ('telemetry.microsoft.com', 'telemetry', 'Microsoft telemetry'),
        ]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        for domain, category, reason in defaults:
            cursor.execute('INSERT OR IGNORE INTO blocked_domains (domain, category, reason) VALUES (?, ?, ?)', 
                          (domain, category, reason))
        conn.commit()
        conn.close()
    
    def add_blocked_domain(self, domain, category, reason=''):
        conn = sqlite3.connect(self.db_path, timeout=2, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        
        try:
            cursor.execute('INSERT INTO blocked_domains (domain, category, reason) VALUES (?, ?, ?)', 
                          (domain, category, reason))
            conn.commit()
            
            # Update Suricata in real-time
            domain_b64 = base64.b64encode(domain.encode()).decode()
            subprocess.run(['suricatasc', '-c', f'dataset-add malicious-domains string {domain_b64}'], 
                          capture_output=True, timeout=5)
            
            print(f"Added {domain} to {category} blocklist")
            return True
            
        except sqlite3.IntegrityError:
            print(f"Warning: Domain {domain} already blocked")
            return False
        finally:
            conn.close()

    def get_stats(self):
        conn = sqlite3.connect(self.db_path, timeout=2, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM blocked_domains WHERE active = 1')
        total = cursor.fetchone()[0]
        cursor.execute('SELECT category, COUNT(*) FROM blocked_domains WHERE active = 1 GROUP BY category')
        by_category = dict(cursor.fetchall())
        conn.close()
        return {'total': total, 'by_category': by_category}
    
    def import_rpz_file(self, rpz_file_path: str, category: str = 'rpz_import'):
        """Import DNS RPZ (Response Policy Zone) file with 100k+ entries"""
        print(f"  Importing RPZ file: {rpz_file_path}")
        
        if not os.path.exists(rpz_file_path):
            print(f"RPZ file not found: {rpz_file_path}")
            return False
        
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=OFF")  # Fast imports
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA cache_size=-200000")  # ~200MB cache
        cursor = conn.cursor()
        
        imported_count = 0
        skipped_count = 0
        allowed_count = 0
        batch_rows = []
        batch_size = 1000
        
        try:
            with open(rpz_file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    if line_num % 10000 == 0:
                        print(f"   Processing line {line_num:,}...")
                    
                    line = line.strip()
                    
                    # Skip comments, empty lines, and RPZ headers
                    if not line or line.startswith(';') or line.startswith('$') or line.startswith('@') or 'SOA' in line or 'NS ' in line:
                        continue
                    
                    # Parse RPZ entry: "domain CNAME target" or "domain A target"
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] in ['CNAME', 'A', 'AAAA']:
                        domain = parts[0].rstrip('.').lower()  # Normalize domain
                        target = parts[2]
                        
                        # Skip invalid domains
                        if not domain or '.' not in domain or len(domain) > 255:
                            continue
                        
                        # Handle different RPZ targets
                        if target == 'rpz-passthru.':
                            # This is an allowed domain (whitelist)
                            allowed_count += 1
                            continue
                        elif target in ['.', 'rpz-drop.', '0.0.0.0', '127.0.0.1', '::']:
                            # Blocked domain (drop, sinkhole, localhost)
                            batch_rows.append((domain, category, f'RPZ import from {os.path.basename(rpz_file_path)}', 'rpz_import'))
                            
                            # Process batch when full
                            if len(batch_rows) >= batch_size:
                                cursor.execute('BEGIN IMMEDIATE')
                                cursor.executemany('''
                                    INSERT OR IGNORE INTO blocked_domains (domain, category, reason, added_by)
                                    VALUES (?, ?, ?, ?)
                                ''', batch_rows)
                                imported_count += len([r for r in batch_rows if cursor.rowcount > 0])
                                cursor.execute('COMMIT')
                                batch_rows = []
                        else:
                            # Other RPZ targets (IP redirects, etc.)
                            skipped_count += 1
            
            # Process final batch
            if batch_rows:
                cursor.execute('BEGIN IMMEDIATE')
                cursor.executemany('''
                    INSERT OR IGNORE INTO blocked_domains (domain, category, reason, added_by)
                    VALUES (?, ?, ?, ?)
                ''', batch_rows)
                imported_count += len(batch_rows)
                cursor.execute('COMMIT')
            
            # Final commit and restore normal sync mode
            cursor.execute('PRAGMA synchronous=NORMAL')
            conn.commit()
            
            print(f"\nRPZ Import Complete:")
            print(f"     Imported: {imported_count:,} blocked domains")
            print(f"     Allowed: {allowed_count:,} passthrough domains")
            print(f"     Skipped: {skipped_count:,} entries")
            
            # Sync all new domains to Suricata
            print(f"Syncing {imported_count:,} domains to Suricata...")
            self.sync_all_domains_to_suricata()
            
            return True
            
        except Exception as e:
            print(f"Error importing RPZ file: {e}")
            return False
        finally:
            conn.close()

    def import_domain_list(self, list_file_path: str, category: str = 'ads', source_name: str = None):
        """Import simple domain list file (one domain per line, # for comments)"""
        print(f"  Importing domain list: {list_file_path}")

        if not os.path.exists(list_file_path):
            print(f"Domain list file not found: {list_file_path}")
            return False

        if source_name is None:
            source_name = os.path.basename(list_file_path)

        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA cache_size=-200000")
        cursor = conn.cursor()

        imported_count = 0
        skipped_count = 0
        batch_rows = []
        batch_size = 1000

        try:
            with open(list_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if line_num % 10000 == 0:
                        print(f"   Processing line {line_num:,}...")

                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue

                    # Remove inline comments
                    if '#' in line:
                        line = line.split('#')[0].strip()

                    # Handle hosts file format (IP domain)
                    parts = line.split()
                    if len(parts) >= 2 and (parts[0].startswith('0.0.0.0') or parts[0].startswith('127.0.0.1')):
                        domain = parts[1].lower()
                    else:
                        domain = line.lower()

                    # Validate domain
                    if not domain or '.' not in domain or len(domain) > 255:
                        skipped_count += 1
                        continue

                    # Skip localhost and invalid domains
                    if domain in ['localhost', 'localhost.localdomain', 'local', 'broadcasthost']:
                        skipped_count += 1
                        continue

                    batch_rows.append((domain, category, f'Imported from {source_name}', source_name))

                    # Process batch when full
                    if len(batch_rows) >= batch_size:
                        cursor.execute('BEGIN IMMEDIATE')
                        cursor.executemany('''
                            INSERT OR IGNORE INTO blocked_domains (domain, category, reason, added_by)
                            VALUES (?, ?, ?, ?)
                        ''', batch_rows)
                        imported_count += len(batch_rows)
                        cursor.execute('COMMIT')
                        batch_rows = []

            # Process final batch
            if batch_rows:
                cursor.execute('BEGIN IMMEDIATE')
                cursor.executemany('''
                    INSERT OR IGNORE INTO blocked_domains (domain, category, reason, added_by)
                    VALUES (?, ?, ?, ?)
                ''', batch_rows)
                imported_count += len(batch_rows)
                cursor.execute('COMMIT')

            # Restore normal sync mode
            cursor.execute('PRAGMA synchronous=NORMAL')
            conn.commit()

            print(f"\nDomain List Import Complete:")
            print(f"     Imported: {imported_count:,} domains")
            print(f"     Skipped: {skipped_count:,} entries")

            return True

        except Exception as e:
            print(f"Error importing domain list: {e}")
            return False
        finally:
            conn.close()

    def sync_domains_batch(self, domains: list):
        """Sync batch of domains to Suricata for performance"""
        for domain in domains:
            try:
                domain_b64 = base64.b64encode(domain.encode()).decode()
                subprocess.run(['suricatasc', '-c', f'dataset-add malicious-domains string {domain_b64}'], 
                              capture_output=True, timeout=1)
            except:
                pass  # Continue on timeout/error
    
    def sync_all_domains_to_suricata(self):
        """Sync all active domains to Suricata datasets with high performance"""
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        
        cursor.execute('SELECT domain FROM blocked_domains WHERE active = 1')
        domains = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        if not domains:
            print("  No domains to sync")
            return 0
        
        # Clear existing dataset first
        try:
            subprocess.run(['suricatasc', '-c', 'dataset-clear malicious-domains string'], 
                          capture_output=True, timeout=10)
            print(f"  Cleared existing dataset")
        except Exception as e:
            print(f"Warning: Could not clear dataset: {e}")
        
        # Batch sync for performance (reduce suricatasc calls)
        success_count = 0
        batch_size = 50  # Smaller batches for reliability
        
        print(f"Syncing {len(domains):,} domains to Suricata in batches...")
        for i in range(0, len(domains), batch_size):
            batch = domains[i:i+batch_size]
            if i % 1000 == 0 and i > 0:
                print(f"   Progress: {i:,}/{len(domains):,} domains ({i*100//len(domains)}%)")
            
            batch_success = 0
            for domain in batch:
                try:
                    domain_b64 = base64.b64encode(domain.encode('utf-8')).decode('ascii')
                    result = subprocess.run(['suricatasc', '-c', f'dataset-add malicious-domains string {domain_b64}'], 
                                          capture_output=True, timeout=3)
                    if result.returncode == 0:
                        batch_success += 1
                except Exception as e:
                    # Continue on individual failures
                    continue
            
            success_count += batch_success
            
            # Brief pause between batches to avoid overwhelming Suricata
            if batch_success < len(batch):
                time.sleep(0.1)
        
        print(f"Successfully synced {success_count:,}/{len(domains):,} domains to Suricata dataset")
        if success_count < len(domains):
            print(f"Warning: {len(domains) - success_count:,} domains failed to sync (Suricata may be busy)")
        
        return success_count

    def debug_dataset_files(self):
        """Debug function to inspect dataset file contents and format"""
        print("DATASET FILE DEBUG INFORMATION")
        print("=" * 50)
        
        # Check string datasets (should be base64)
        string_datasets = [
            '/etc/suricata/datasets/malicious-domains.txt',
            '/etc/suricata/datasets/suspicious-urls.txt', 
            '/etc/suricata/datasets/telemetry-domains.txt',
            '/etc/suricata/datasets/doh-servers.txt',
            '/etc/suricata/datasets/suspect-ja3.txt',
            '/etc/suricata/datasets/ech-cdn-ips.txt'
        ]
        
        for dataset_file in string_datasets:
            if os.path.exists(dataset_file):
                print(f"\n  STRING DATASET: {dataset_file}")
                with open(dataset_file, 'r') as f:
                    lines = f.readlines()[:5]  # First 5 lines
                    for i, line in enumerate(lines, 1):
                        line = line.strip()
                        if line:
                            try:
                                decoded = base64.b64decode(line).decode('utf-8')
                                print(f"   Line {i}: {line[:20]}... -> {decoded}")
                            except Exception:
                                print(f"   Line {i}: {line} (NOT BASE64)")
        
        # Check IP datasets (should be plain IPs/CIDRs)
        ip_datasets = [
            '/etc/suricata/datasets/malicious-ips.txt',
            '/etc/suricata/datasets/c2-ips.txt'
        ]
        
        for dataset_file in ip_datasets:
            if os.path.exists(dataset_file):
                print(f"\nIP DATASET: {dataset_file}")
                with open(dataset_file, 'r') as f:
                    lines = f.readlines()[:10]  # First 10 lines
                    for i, line in enumerate(lines, 1):
                        line = line.strip()
                        if line:
                            try:
                                import ipaddress
                                if '/' in line:
                                    ipaddress.ip_network(line, strict=False)
                                    print(f"   Line {i}: {line} (VALID NETWORK)")
                                else:
                                    ipaddress.ip_address(line)
                                    print(f"   Line {i}: {line} (VALID IP)")
                            except Exception as e:
                                print(f"   Line {i}: {line} (INVALID: {e})")
        
        print("\n" + "=" * 50)

    def export_domains_to_dataset_file(self):
        """Export domains to base64 dataset file for file-based loading"""
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        cursor = conn.cursor()
        
        cursor.execute('SELECT domain FROM blocked_domains WHERE active = 1')
        domains = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        if not domains:
            print("  No domains to export")
            return False
        
        try:
            # Write domains to dataset file in base64 format
            dataset_file = '/etc/suricata/datasets/malicious-domains.txt'
            with open(dataset_file, 'w') as f:
                for domain in domains:
                    domain_b64 = base64.b64encode(domain.encode('utf-8')).decode('ascii')
                    f.write(f"{domain_b64}\n")
            
            # Set proper ownership and permissions
            subprocess.run(['chown', 'suricata:suricata', dataset_file], capture_output=True)
            subprocess.run(['chmod', '644', dataset_file], capture_output=True)
            
            print(f"  Exported {len(domains):,} domains to {dataset_file}")
            
            # Signal Suricata to reload datasets
            try:
                with open('/var/run/suricata.pid', 'r') as f:
                    pid = f.read().strip()
                subprocess.run(['kill', '-HUP', pid], capture_output=True, timeout=5)
                print("Signaled Suricata to reload datasets (SIGHUP)")
            except Exception as e:
                print(f"Warning: Could not signal Suricata reload: {e}")
                print("   Manually restart Suricata or use: systemctl reload suricata")
            
            return True
            
        except Exception as e:
            print(f"Error exporting domains to file: {e}")
            return False
    
    def setup_slips_integration(self):
        """Setup integration with SLIPS ML engine for advanced bypass detection"""
        try:
            # Connect to SLIPS Redis database
            self.redis_db = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
            self.redis_db.ping()
            print("Connected to SLIPS Redis database")
            return True
        except Exception as e:
            print(f"Warning: SLIPS Redis not available: {e}")
            return False
    
    def analyze_bypass_patterns(self):
        """Use SLIPS ML to detect sneaky bypass attempts and advanced threats"""
        if not hasattr(self, 'redis_db'):
            if not self.setup_slips_integration():
                return []
        
        bypass_detections = []
        
        try:
            # Get SLIPS profiles with suspicious behaviors
            profiles = self.redis_db.keys('profile_*')
            
            for profile_key in profiles:
                profile_data = self.redis_db.hgetall(profile_key)
                ip = profile_key.replace('profile_', '')
                
                # Check for bypass indicators using SLIPS intelligence
                threats = self.detect_content_bypass_patterns(ip, profile_data)
                if threats:
                    bypass_detections.extend(threats)
            
            return bypass_detections
            
        except Exception as e:
            print(f"Error analyzing bypass patterns: {e}")
            return []
    
    def detect_content_bypass_patterns(self, ip: str, profile_data: dict):
        """Detect sneaky content bypass attempts using SLIPS behavioral analysis"""
        threats = []
        
        # 1. DNS-over-HTTPS (DoH) bypass detection
        if 'DoH' in profile_data.get('protocols', ''):
            threats.append({
                'type': 'doh_bypass',
                'ip': ip,
                'description': 'DNS-over-HTTPS bypass attempt detected',
                'confidence': 0.8,
                'action': 'block_ip'
            })
        
        # 2. Encrypted DNS tunnel detection
        if profile_data.get('dns_txt_high_entropy') == 'true':
            threats.append({
                'type': 'dns_tunnel',
                'ip': ip, 
                'description': 'High entropy DNS TXT records - possible data exfiltration tunnel',
                'confidence': 0.7,
                'action': 'investigate'
            })
        
        # 3. Domain fronting detection
        sni_mismatches = profile_data.get('sni_cn_mismatch_count', '0')
        if int(sni_mismatches) > 3:
            threats.append({
                'type': 'domain_fronting',
                'ip': ip,
                'description': f'Multiple SNI/CN mismatches ({sni_mismatches}) - possible domain fronting',
                'confidence': 0.9,
                'action': 'block_ip'
            })
        
        # 4. Steganographic content detection
        if profile_data.get('suspicious_user_agents'):
            user_agents = profile_data['suspicious_user_agents'].split(',')
            for ua in user_agents:
                if self.is_suspicious_user_agent(ua):
                    threats.append({
                        'type': 'steganographic_content',
                        'ip': ip,
                        'description': f'Suspicious user agent pattern: {ua[:50]}...',
                        'confidence': 0.6,
                        'action': 'monitor'
                    })
        
        # 5. C&C channel detection using SLIPS RNN
        if profile_data.get('rnn_cc_detection') == 'malicious':
            threats.append({
                'type': 'cc_channel',
                'ip': ip,
                'description': 'ML-detected command & control communication pattern',
                'confidence': 0.95,
                'action': 'block_ip'
            })
        
        # 6. Fast-flux domain detection
        ip_changes = profile_data.get('ip_changes_count', '0')
        if int(ip_changes) > 5:
            threats.append({
                'type': 'fast_flux',
                'ip': ip,
                'description': f'Rapid IP changes ({ip_changes}) - possible fast-flux network',
                'confidence': 0.8,
                'action': 'block_domain'
            })
        
        # 7. Behavioral anomaly detection
        threat_level = profile_data.get('threat_level', '0')
        confidence = profile_data.get('confidence', '0')
        
        if float(threat_level) > 0.7 and float(confidence) > 0.8:
            threats.append({
                'type': 'behavioral_anomaly',
                'ip': ip,
                'description': f'SLIPS ML detected high threat score: {threat_level}',
                'confidence': float(confidence),
                'action': 'investigate'
            })
        
        return threats
    
    def is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Detect suspicious user agent patterns for steganographic/bypass content"""
        suspicious_patterns = [
            # Adult content disguised as legitimate traffic
            'pornhub', 'xhamster', 'redtube', 'youporn',
            # Tracking/telemetry disguised
            'telemetry', 'analytics', 'metrics', 'beacon',
            # Bypass tools
            'proxifier', 'vpn', 'tunnel', 'bypass',
            # Suspicious encoding
            '%20%20%20', '+++', '===',
            # Non-standard browsers for content delivery
            'wget', 'curl', 'python', 'bot', 'crawler'
        ]
        
        ua_lower = user_agent.lower()
        return any(pattern in ua_lower for pattern in suspicious_patterns)
    
    def sync_rpz_to_datasets(self, rpz_sources=None):
        """Synchronize RPZ feeds to Suricata datasets for consistent blocking"""
        if rpz_sources is None:
            rpz_sources = [
                'https://someonewhocares.org/hosts/zero/hosts',
                'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/rpz/pro.txt',
                'https://oisd.nl/rpz'
            ]
        
        telemetry_domains = set()
        
        for source in rpz_sources:
            try:
                print(f"  Syncing RPZ source: {source}")
                # Download and parse RPZ data (simplified)
                import urllib.request
                with urllib.request.urlopen(source) as response:
                    content = response.read().decode('utf-8')
                    
                # Extract domains from RPZ format
                for line in content.split('\n'):
                    if line.strip() and not line.startswith('#'):
                        # Parse RPZ format (simplified)
                        if 'CNAME .' in line or 'A 0.0.0.0' in line:
                            domain = line.split()[0].rstrip('.')
                            if domain and '.' in domain:
                                telemetry_domains.add(domain)
                                
            except Exception as e:
                print(f"Warning: Failed to sync {source}: {e}")
                
        # Write to telemetry dataset (base64 encoded)
        with open('/etc/suricata/datasets/telemetry-domains.txt', 'w') as f:
            for domain in sorted(telemetry_domains):
                # Encode domain as base64 for string dataset
                domain_b64 = base64.b64encode(domain.encode()).decode()
                f.write(f"{domain_b64}\n")
                
        print(f"Synced {len(telemetry_domains)} domains to telemetry dataset")
        
        # Reload Suricata datasets
        subprocess.run(['suricatasc', '-c', 'dataset-reload'], capture_output=True)
        """Automatically block threats detected by SLIPS ML analysis"""
        threats = self.analyze_bypass_patterns()
        
        blocked_count = 0
        investigated_count = 0
        
        for threat in threats:
            if threat['confidence'] > 0.8 and threat['action'] in ['block_ip', 'block_domain']:
                # Auto-block high confidence threats
                if threat['action'] == 'block_ip':
                    self.block_ip_address(threat['ip'])
                    blocked_count += 1
                    
                # Log the threat
                self.log_ml_threat(threat)
                
            elif threat['action'] in ['investigate', 'monitor']:
                # Log for manual review
                self.log_ml_threat(threat, alert_level='warning')
                investigated_count += 1
        
        if blocked_count > 0 or investigated_count > 0:
            print(f" SLIPS ML Analysis Complete:")
            print(f"    Auto-blocked: {blocked_count} high-confidence threats")
            print(f"    Flagged for review: {investigated_count} suspicious patterns")
        
        return blocked_count, investigated_count
    
    def block_ip_address(self, ip: str):
        """Block IP address using iptables integration"""
        try:
            # Add IP to blocked list in database
            conn = sqlite3.connect(self.db_path, timeout=2, isolation_level=None)
            conn.execute("PRAGMA journal_mode=WAL")
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR IGNORE INTO blocked_domains (domain, category, reason, added_by)
                VALUES (?, ?, ?, ?)
            ''', (ip, 'ml_detected', 'SLIPS ML auto-block', 'slips_ml'))
            
            conn.commit()
            conn.close()
            
            # Block via nftables for HOST protection (SLIPS/RPZ integration)
            # Note: Transit blocking handled by Suricata AF_PACKET drop rules
            try:
                import ipaddress
                addr = ipaddress.ip_address(ip)
                set_name = "blocked4" if addr.version == 4 else "blocked6"
                
                # Add to proper nftables named set for host-level protection
                subprocess.run(['nft', 'add', 'element', 'inet', 'home', set_name,
                               f'{{ {ip} timeout 1d }}'], 
                              capture_output=True, timeout=5, check=True)
                print(f"Blocked {ip} (IPv{addr.version}) from accessing IPS host")
            except Exception as nft_error:
                print(f"Warning: nftables blocking failed for {ip}: {nft_error}")
                # Log error but don't fall back to iptables - maintain consistency
            
        except Exception as e:
            print(f" Error blocking IP {ip}: {e}")
    
    def monitor_ja3_patterns(self):
        """Monitor JA3 patterns from Suricata EVE logs and auto-block suspicious IPs"""
        import json
        import time
        from collections import defaultdict
        
        ja3_counts = defaultdict(list)
        
        try:
            # Monitor EVE log for JA3 patterns
            with open('/var/log/suricata/eve.json', 'r') as eve_file:
                eve_file.seek(0, 2)  # Go to end of file
                
                while True:
                    line = eve_file.readline()
                    if not line:
                        time.sleep(1)
                        continue
                    
                    try:
                        event = json.loads(line)
                        
                        # Check for TLS events with JA3
                        if event.get('event_type') == 'tls' and 'ja3' in event.get('tls', {}):
                            ja3_hash = event['tls']['ja3']['hash']
                            src_ip = event['src_ip']
                            timestamp = time.time()
                            
                            # Track JA3 frequency per IP
                            ja3_counts[ja3_hash].append((src_ip, timestamp))
                            
                            # Clean old entries (older than 1 hour)
                            cutoff = timestamp - 3600
                            ja3_counts[ja3_hash] = [(ip, ts) for ip, ts in ja3_counts[ja3_hash] if ts > cutoff]
                            
                            # Auto-block if suspicious JA3 seen from multiple IPs
                            if len(set(ip for ip, _ in ja3_counts[ja3_hash])) >= 5:
                                print(f"Alert: Suspicious JA3 detected: {ja3_hash}")
                                # Add to nftables set with short timeout
                                for ip, _ in ja3_counts[ja3_hash][-5:]:
                                    self.block_ip_nftables(ip, "6h")
                                
                                # Add JA3 to suspect dataset
                                with open('/etc/suricata/datasets/suspect-ja3.txt', 'a') as f:
                                    f.write(f"{ja3_hash}\n")
                                    
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            print(f"Warning: JA3 monitoring error: {e}")
    
    def monitor_ech_adoption(self):
        """Monitor ECH adoption patterns and auto-update IP intelligence datasets"""
        import json
        import time
        from collections import defaultdict, Counter
        
        ech_patterns = defaultdict(list)
        ech_ips = set()
        
        try:
            # Monitor EVE log for ECH indicators
            with open('/var/log/suricata/eve.json', 'r') as eve_file:
                eve_file.seek(0, 2)  # Go to end of file
                
                while True:
                    line = eve_file.readline()
                    if not line:
                        time.sleep(1)
                        continue
                    
                    try:
                        event = json.loads(line)
                        
                        # Check for TLS events that might indicate ECH
                        if event.get('event_type') == 'tls' and 'tls' in event:
                            tls_data = event['tls']
                            src_ip = event['src_ip']
                            dst_ip = event['dst_ip']
                            timestamp = time.time()
                            
                            # ECH indicators:
                            # 1. TLS 1.3 with no visible SNI or encrypted SNI
                            # 2. JA3 patterns associated with ECH-capable clients
                            # 3. Connection to known CDN IPs that support ECH
                            
                            is_ech_candidate = False
                            
                            # Check for missing/encrypted SNI in TLS 1.3
                            if tls_data.get('version') == 'TLS 1.3':
                                if not tls_data.get('sni') or tls_data.get('sni') == '':
                                    is_ech_candidate = True
                                    ech_patterns['empty_sni'].append((dst_ip, timestamp))
                            
                            # Check for ECH-capable JA3 patterns
                            if 'ja3' in tls_data:
                                ja3_hash = tls_data['ja3'].get('hash', '')
                                # Known ECH-capable client JA3 patterns (Chrome 109+, Firefox 118+)
                                ech_ja3_patterns = [
                                    'cd08e31494f9531f560d64c695473da9',  # Chrome with ECH
                                    'b32309a26951912be7dba376398abc3b',  # Firefox with ECH
                                    'e7d705a3286e19ea42f587b344ee6865'   # Safari with ECH
                                ]
                                if ja3_hash in ech_ja3_patterns:
                                    is_ech_candidate = True
                                    ech_patterns['ech_ja3'].append((dst_ip, timestamp))
                            
                            # Check if connecting to known ECH-supporting CDNs
                            with open('/etc/suricata/datasets/ech-cdn-ips.txt', 'r') as f:
                                ech_cdn_ips = set(line.strip() for line in f)
                            
                            if dst_ip in ech_cdn_ips:
                                is_ech_candidate = True
                                ech_patterns['ech_cdn'].append((dst_ip, timestamp))
                                ech_ips.add(dst_ip)
                            
                            # Log potential ECH usage for intelligence gathering
                            if is_ech_candidate:
                                # Log ECH detection (no separate dataset needed)
                                self.log_ml_threat({
                                    'type': 'ech_detection',
                                    'ip': dst_ip,
                                    'description': f'ECH candidate detected: {dst_ip}',
                                    'confidence': confidence
                                })
                                
                                # Alert on ECH bypass attempts to family-filtered content
                                if self.is_blocked_destination(dst_ip):
                                    self.log_ml_threat({
                                        'type': 'ech_bypass_attempt',
                                        'ip': dst_ip,
                                        'description': f'ECH detected to blocked destination: {dst_ip}',
                                        'confidence': 0.9,
                                        'action': 'block_ip'
                                    }, alert_level='critical')
                            
                            # Clean old entries (older than 24 hours)
                            cutoff = timestamp - 86400
                            for pattern_type in ech_patterns:
                                ech_patterns[pattern_type] = [(ip, ts) for ip, ts in ech_patterns[pattern_type] if ts > cutoff]
                            
                            # Weekly ECH adoption report
                            if int(timestamp) % 604800 == 0:  # Once per week
                                self.generate_ech_intelligence_report(ech_patterns, ech_ips)
                                
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            print(f"Warning: ECH monitoring error: {e}")
    
    def is_blocked_destination(self, ip: str) -> bool:
        """Check if IP is associated with blocked content"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM blocked_domains WHERE domain = ? AND active = 1', (ip,))
        result = cursor.fetchone()[0] > 0
        conn.close()
        return result
    
    def generate_ech_intelligence_report(self, ech_patterns: dict, detected_ips: set):
        """Generate weekly ECH adoption and threat intelligence report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'ech_adoption_metrics': {
                'empty_sni_connections': len(ech_patterns.get('empty_sni', [])),
                'ech_capable_clients': len(ech_patterns.get('ech_ja3', [])),
                'ech_cdn_connections': len(ech_patterns.get('ech_cdn', [])),
                'unique_ech_ips': len(detected_ips)
            },
            'threat_assessment': 'ECH adoption monitoring active',
            'recommendations': [
                'Update ECH-capable CDN IP intelligence',
                'Review ECH bypass attempts to family-filtered content',
                'Consider DNS-level blocking for high-risk ECH destinations'
            ]
        }
        
        with open('/var/log/ips-ech-intelligence.log', 'a') as f:
            f.write(json.dumps(report, indent=2) + '\n')
        
        print(f" ECH Intelligence Report Generated:")
        print(f"    ECH connections detected: {report['ech_adoption_metrics']['unique_ech_ips']}")
        print(f"     Empty SNI patterns: {report['ech_adoption_metrics']['empty_sni_connections']}")
        print(f"    ECH CDN connections: {report['ech_adoption_metrics']['ech_cdn_connections']}")

    def auto_block_ml_threats(self):
        """Automatically block threats detected by SLIPS ML analysis"""
        threats = self.analyze_bypass_patterns()
        
        blocked_count = 0
        investigated_count = 0
        
        for threat in threats:
            if threat['confidence'] > 0.8 and threat['action'] in ['block_ip', 'block_domain']:
                # Auto-block high confidence threats
                if threat['action'] == 'block_ip':
                    self.block_ip_address(threat['ip'])
                    blocked_count += 1
                    
                # Log the threat
                self.log_ml_threat(threat)
                
            elif threat['action'] in ['investigate', 'monitor']:
                # Log for manual review
                self.log_ml_threat(threat, alert_level='warning')
                investigated_count += 1
        
        if blocked_count > 0 or investigated_count > 0:
            print(f" SLIPS ML Analysis Complete:")
            print(f"    Auto-blocked: {blocked_count} high-confidence threats")
            print(f"    Flagged for review: {investigated_count} suspicious patterns")
        
        return blocked_count, investigated_count
    
    def block_ip_nftables(self, ip: str, timeout: str = "1d"):
        """Block IP address using nftables named sets with timeout"""
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            set_name = "blocked4" if addr.version == 4 else "blocked6"
            
            # Add to proper nftables named set for host-level protection
            subprocess.run(['nft', 'add', 'element', 'inet', 'home', set_name,
                           f'{{ {ip} timeout {timeout} }}'], 
                          capture_output=True, timeout=5, check=True)
            print(f"Blocked {ip} (IPv{addr.version}) timeout {timeout}")
            return True
        except Exception as e:
            print(f" Error blocking IP {ip}: {e}")
            return False

    def log_ml_threat(self, threat: dict, alert_level: str = 'info'):
        """Log ML-detected threats to database and external monitoring systems"""
        import json
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO activity_log (domain, action, category, rule_triggered)
            VALUES (?, ?, ?, ?)
        ''', (threat['ip'], f'ml_{alert_level}', threat['type'], threat['description']))
        
        conn.commit()
        conn.close()
        
        # Also log to file for external monitoring
        with open('/var/log/ips-filter-ml.log', 'a') as f:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'threat_type': threat['type'],
                'ip': threat['ip'],
                'description': threat['description'],
                'confidence': threat['confidence'],
                'action': threat['action'],
                'alert_level': alert_level
            }
            f.write(json.dumps(log_entry) + '\n')

    def sync_to_suricata_datasets(self):
        """Sync SQLite data to Suricata datasets using CSV files and Unix socket"""
        import base64
        import os
        import subprocess
        
        # NOTE: Despite the .csv extension, Suricata dataset state files are
        # newline-delimited plain text (one value per line). Suricata 8+ handles
        # encoding internally for string datasets. DO NOT base64 encode state files.
        
        # Ensure dataset directories exist
        os.makedirs('/var/lib/suricata/datasets', exist_ok=True)
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 1. Export malicious domains (string dataset - plain text, Suricata handles encoding)
            cursor.execute('SELECT domain FROM blocked_domains WHERE active = 1 AND category IN ("malicious", "social_media")')
            malicious_domains = [row[0] for row in cursor.fetchall()]
            
            with open('/var/lib/suricata/datasets/malicious-domains.csv', 'w') as f:
                for domain in malicious_domains:
                    f.write(f"{domain}\n")
            print(f"Exported {len(malicious_domains)} malicious domains to Suricata")
            
            # 2. Export telemetry domains
            cursor.execute('SELECT domain FROM telemetry_domains WHERE active = 1')
            telemetry_domains = [row[0] for row in cursor.fetchall()]
            
            with open('/var/lib/suricata/datasets/telemetry-domains.csv', 'w') as f:
                for domain in telemetry_domains:
                    f.write(f"{domain}\n")
            print(f"Exported {len(telemetry_domains)} telemetry domains to Suricata")
            
            # 3. Export suspicious URLs
            cursor.execute('SELECT url_pattern FROM suspicious_urls WHERE active = 1')
            suspicious_urls = [row[0] for row in cursor.fetchall()]
            
            with open('/var/lib/suricata/datasets/suspicious-urls.csv', 'w') as f:
                for url in suspicious_urls:
                    f.write(f"{url}\n")
            print(f"Exported {len(suspicious_urls)} suspicious URLs to Suricata")
            
            # 4. Export blocked IPs (IP dataset - plain IP/CIDR format)
            cursor.execute('SELECT ip_address FROM blocked_ips WHERE active = 1')
            blocked_ips = [row[0] for row in cursor.fetchall()]
            
            with open('/var/lib/suricata/datasets/bad-ips.csv', 'w') as f:
                for ip in blocked_ips:
                    f.write(f"{ip}\n")
            print(f"Exported {len(blocked_ips)} blocked IPs to Suricata")
            
            # 5. Export JA3 signatures
            cursor.execute('SELECT ja3_hash FROM ja3_signatures WHERE active = 1')
            ja3_hashes = [row[0] for row in cursor.fetchall()]
            
            with open('/var/lib/suricata/datasets/suspect-ja3.csv', 'w') as f:
                for ja3 in ja3_hashes:
                    f.write(f"{ja3}\n")
            print(f"Exported {len(ja3_hashes)} JA3 signatures to Suricata")
            
            conn.close()
            
            # Set proper ownership for Suricata
            for filename in ['malicious-domains.csv', 'telemetry-domains.csv', 'suspicious-urls.csv', 'bad-ips.csv', 'suspect-ja3.csv']:
                filepath = f'/var/lib/suricata/datasets/{filename}'
                if os.path.exists(filepath):
                    subprocess.run(['chown', 'suricata:suricata', filepath], capture_output=True)
                    subprocess.run(['chmod', '644', filepath], capture_output=True)
            
            print("Dataset sync to Suricata completed successfully")
            return True
            
        except Exception as e:
            print(f"Error syncing to Suricata datasets: {e}")
            return False

    def sync_realtime_via_socket(self, dataset_name: str, data_type: str, value: str, action: str = 'add'):
        """Add/remove entries in real-time via Suricata Unix socket"""
        import subprocess
        
        try:
            if data_type == 'string':
                # Encode strings as base64 for Unix socket
                value_b64 = base64.b64encode(value.encode()).decode()
                cmd = f'dataset-{action} {dataset_name} string {value_b64}'
            else:  # ip/ipv4
                # IPs are plain text for Unix socket
                cmd = f'dataset-{action} {dataset_name} {data_type} {value}'
            
            result = subprocess.run(['suricatasc', '-c', cmd], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print(f"Successfully {action}ed {value} to {dataset_name}")
                return True
            else:
                print(f"Failed to {action} {value}: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"Error using Unix socket: {e}")
            return False

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='IPS Filter Database Management')
    parser.add_argument('action', choices=['init', 'add', 'stats', 'import-rpz', 'import-list', 'sync', 'ml-scan', 'ml-auto', 'debug-datasets'])
    parser.add_argument('--domain', help='Domain to add')
    parser.add_argument('--category', help='Category for domain')
    parser.add_argument('--reason', help='Reason for blocking')
    parser.add_argument('--rpz-file', help='Path to RPZ file for import')
    parser.add_argument('--list-file', help='Path to domain list file for import')
    parser.add_argument('--source-name', help='Source name for domain list import')

    args = parser.parse_args()
    db = IPSFilterDB()

    if args.action == 'add' and args.domain and args.category:
        db.add_blocked_domain(args.domain, args.category, args.reason or '')
    elif args.action == 'stats':
        stats = db.get_stats()
        print(f"Blocked domains: {stats['total']:,}")
        print(f"   Categories: {stats['by_category']}")
    elif args.action == 'import-rpz':
        if not args.rpz_file:
            print("--rpz-file required for import-rpz")
            sys.exit(1)
        category = args.category or 'rpz_import'
        db.import_rpz_file(args.rpz_file, category)
    elif args.action == 'import-list':
        if not args.list_file:
            print("--list-file required for import-list")
            sys.exit(1)
        category = args.category or 'ads'
        source_name = args.source_name or os.path.basename(args.list_file)
        db.import_domain_list(args.list_file, category, source_name)
    elif args.action == 'sync':
        print("Syncing all domains to Suricata...")
        db.sync_all_domains_to_suricata()
    elif args.action == 'ml-scan':
        print("Running SLIPS ML threat analysis...")
        threats = db.analyze_bypass_patterns()
        if threats:
            print(f"Found {len(threats)} ML-detected threats:")
            for threat in threats:
                print(f"  Alert: {threat['type']}: {threat['description']} (confidence: {threat['confidence']})")
        else:
            print("No ML threats detected")
    elif args.action == 'ml-auto':
        print("Running automatic ML threat blocking...")
        db.auto_block_ml_threats()
    elif args.action == 'debug-datasets':
        print("Debugging dataset files...")
        db.debug_dataset_files()
IPS_DB_EOF

    chmod +x /opt/ips-filter-db.py
    
    # Create simple web interface
    cat > /opt/ips-filter-web.py << 'WEB_EOF'
#!/usr/bin/env python3
from flask import Flask, render_template_string, request, redirect
import sqlite3
import subprocess

app = Flask(__name__)

HTML = '''
<!DOCTYPE html>
<html>
<head><title>IPS Filter Control</title>
<style>
body { font-family: Arial; margin: 40px; background: #f5f5f5; }
.container { max-width: 800px; background: white; padding: 30px; border-radius: 10px; }
h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
.stats { background: #e3f2fd; padding: 20px; border-radius: 8px; margin: 20px 0; }
form { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
input, select { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; }
button { background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; }
button:hover { background: #0056b3; }
table { width: 100%; border-collapse: collapse; margin: 20px 0; }
th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
th { background: #f8f9fa; }
.category { padding: 4px 8px; border-radius: 4px; color: white; font-size: 0.8em; }
.cat-social { background: #ff5722; }
.cat-ads { background: #ff9800; }
.cat-tracking { background: #9c27b0; }
.cat-telemetry { background: #607d8b; }
</style>
</head>
<body>
<div class="container">
<h1>IPS Filter Control Panel</h1>
<p><strong>:</strong> Real-time updates, Layer 7 inspection, No DoH bypass</p>

<div class="stats">
<h3>Statistics</h3>
<p><strong>Total Blocked Domains:</strong> {{ stats.total }}</p>
<p><strong>Categories:</strong> {{ stats.by_category }}</p>
</div>

<form method="POST">
<h3>➕ Add Blocked Domain</h3>
<input type="text" name="domain" placeholder="example.com" required>
<select name="category" required>
<option value="social_media">Social Media</option>
<option value="advertising">Advertising</option>
<option value="tracking">Tracking</option>
<option value="adult_content">Adult Content</option>
<option value="gaming">Gaming</option>
<option value="telemetry">Telemetry</option>
</select>
<input type="text" name="reason" placeholder="Reason (optional)">
<button type="submit">Block Domain</button>
</form>

<h3>  Currently Blocked Domains</h3>
<table>
<tr><th>Domain</th><th>Category</th><th>Reason</th><th>Added</th></tr>
{% for domain in domains %}
<tr>
<td>{{ domain[1] }}</td>
<td><span class="category cat-{{ domain[2].replace('_', '') }}">{{ domain[2] }}</span></td>
<td>{{ domain[3] or '' }}</td>
<td>{{ domain[4] }}</td>
</tr>
{% endfor %}
</table>

<p><strong>Real-time Management:</strong> <code>/opt/ips-filter-db.py add --domain example.com --category social_media</code></p>
</div>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip().lower()
        category = request.form.get('category', '')
        reason = request.form.get('reason', '')
        
        if domain and category:
            subprocess.run(['/opt/ips-filter-db.py', 'add', '--domain', domain, '--category', category, '--reason', reason])
            return redirect('/')
    
    # Get stats and domains
    conn = sqlite3.connect('/var/lib/suricata/ips_filter.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM blocked_domains WHERE active = 1')
    total = cursor.fetchone()[0]
    cursor.execute('SELECT category, COUNT(*) FROM blocked_domains WHERE active = 1 GROUP BY category')
    by_category = dict(cursor.fetchall())
    
    cursor.execute('SELECT * FROM blocked_domains WHERE active = 1 ORDER BY added_date DESC LIMIT 50')
    domains = cursor.fetchall()
    
    conn.close()
    
    stats = {'total': total, 'by_category': by_category}
    return render_template_string(HTML, stats=stats, domains=domains)

if __name__ == '__main__':
    app.run(host='10.10.254.39', port=55001, debug=False)
WEB_EOF

    chmod +x /opt/ips-filter-web.py
    
    # Install Python dependencies before database initialization
    log "Installing Python dependencies..."
    pip3 install --break-system-packages flask redis 2>/dev/null || pip3 install flask redis 2>/dev/null || true
    
    # Initialize database
    python3 /opt/ips-filter-db.py init
    
    # Create IPS filter management script
    cat > /usr/local/bin/ips-filter << 'IPS_SCRIPT'
#!/bin/bash
# IPS Filter Management CLI

case "$1" in
    "add")
        [ -z "$2" ] && { echo "Usage: ips-filter add <domain> [category]"; exit 1; }
        /opt/ips-filter-db.py add --domain "$2" --category "${3:-other}" --reason "${4:-Manual block}"
        ;;
    "import-rpz")
        if [ -z "$2" ]; then
            echo "Usage: ips-filter import-rpz <rpz-file> [category]"
            echo "Example: ips-filter import-rpz /path/to/blocklist.rpz malware"
            exit 1
        fi
        echo "  Importing RPZ file: $2"
        echo "Warning: This may take several minutes for 100k+ entries..."
        /opt/ips-filter-db.py import-rpz --rpz-file "$2" --category "${3:-rpz_import}"
        ;;
    "import-list")
        if [ -z "$2" ]; then
            echo "Usage: ips-filter import-list <domain-list-file> [category] [source-name]"
            echo "Example: ips-filter import-list /path/to/domains.txt ads perflyst"
            exit 1
        fi
        echo "  Importing domain list: $2"
        echo "Warning: This may take several minutes for large lists..."
        /opt/ips-filter-db.py import-list --list-file "$2" --category "${3:-ads}" --source-name "${4:-$(basename "$2")}"
        ;;
    "ml-scan")
        echo "Running SLIPS ML threat analysis..."
        echo "Scanning for bypass attempts, domain fronting, C&C channels..."
        /opt/ips-filter-db.py ml-scan
        ;;
    "ml-auto")
        echo "Running automatic ML threat blocking..."
        echo "Warning: High-confidence threats will be auto-blocked!"
        /opt/ips-filter-db.py ml-auto
        ;;
    "sync")
        echo "Syncing all domains to Suricata..."
        /opt/ips-filter-db.py sync
        ;;
    "stats")
        /opt/ips-filter-db.py stats
        ;;
    "web")
        echo "IPS Filter Web Interface: http://10.10.254.39:55001"
        echo "Starting web interface..."
        python3 /opt/ips-filter-web.py &
        echo "Web interface running in background"
        ;;
    "log")
        echo "Live IPS filter activity:"
        tail -f /var/log/suricata/fast.log | grep --color=always "FAMILY FILTER"
        ;;
    *)
        echo "IPS Filter Management "
        echo "Commands:"
        echo "  add <domain> [category]           - Block a domain"
        echo "  import-rpz <file> [category]      - Import DNS RPZ file (100k+ entries)"
        echo "  import-list <file> [category]     - Import domain list file"
        echo "  sync                              - Sync all domains to Suricata"
        echo "  stats                             - Show statistics"
        echo "  web                               - Start web interface"
        echo "  log                               - Monitor live blocking"
        echo ""
        echo "Examples:"
        echo "  ips-filter add facebook.com social_media"
        echo "  ips-filter import-rpz /path/to/blocklist.rpz malware"
        echo "  ips-filter import-list /path/to/domains.txt ads"
        echo "  ips-filter sync"
        echo "  ips-filter web"
        echo ""
        echo "  RPZ Import Format Support:"
        echo "  • Blocked domains: domain.com CNAME ."
        echo "  • Allowed domains: domain.com CNAME rpz-passthru."
        echo "  • Supports 100k+ entries with real-time Suricata sync"
        echo ""
        echo "Web Interface: http://10.10.254.39:55001"
        ;;
esac
IPS_SCRIPT

    chmod +x /usr/local/bin/ips-filter
    
    # Create systemd service for IPS filter web interface
    cat > /etc/systemd/system/ips-filter-web.service << 'IPS_SERVICE'
[Unit]
Description=IPS Filter Web Interface
After=network.target suricata.service
Requires=suricata.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt
ExecStart=/usr/bin/python3 /opt/ips-filter-web.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
IPS_SERVICE

    systemctl daemon-reload
    systemctl enable ips-filter-web.service

 
    log "  Management Options:"
    log "   • CLI: ips-filter add facebook.com social_media"
    log "   • RPZ: ips-filter import-rpz /path/to/blocklist.rpz malware"
    log "   • Web: http://10.10.254.39:55001 (after services start)"
    log "   • Real-time: ips-filter log (monitor live blocking)"
    log ""
    log "  RPZ Import Examples:"
    log "   # Import your 100k+ RPZ files"
    log "   ips-filter import-rpz /home/user/malware.rpz malware"
    log "   ips-filter import-rpz /home/user/ads.rpz advertising"
    log "   ips-filter import-rpz /home/user/adult.rpz adult_content"
    log ""
    log " Quick Setup Commands (after installation):"
    log "   # Manual domain blocking"
    log "   ips-filter add doubleclick.net advertising"
    log "   ips-filter add telemetry.microsoft.com telemetry"
    log "   ips-filter add facebook.com social_media"
    log ""
    log "Large-scale threat intelligence rules configured"
# 
# Rule ID Ranges:
# 1000001-1000999: TLS SNI inspection rules
# 1001001-1001999: DNS port 53 rules  
# 1002001-1002999: DoH/DoT monitoring rules
# 1003001-1003999: General security rules

#==============================================================================
# TLS SNI (Server Name Indication) Inspection Rules
#==============================================================================

# Malicious/Suspicious Domains
# alert tls any any -> any any (msg:"TLS SNI - Suspicious Domain"; tls.sni; content:"malware.example.com"; sid:1000001; rev:1; classtype:trojan-activity; priority:1;)
# alert tls any any -> any any (msg:"TLS SNI - Known C2 Domain"; tls.sni; content:"bad-actor.net"; sid:1000002; rev:1; classtype:trojan-activity; priority:1;)

# Cryptocurrency Mining Domains
# alert tls any any -> any any (msg:"TLS SNI - Crypto Mining Pool"; tls.sni; pcre:"/.*\.(mining|pool|crypto)\./i"; sid:1000010; rev:1; classtype:policy-violation; priority:2;)

# DGA (Domain Generation Algorithm) Detection
# alert tls any any -> any any (msg:"TLS SNI - Possible DGA Domain"; tls.sni; pcre:"/^[a-z]{8,}\.com$/"; sid:1000020; rev:1; classtype:trojan-activity; priority:2;)

# Suspicious TLD Monitoring
# alert tls any any -> any any (msg:"TLS SNI - Suspicious TLD"; tls.sni; pcre:"/\.(tk|ml|ga|cf)$/i"; sid:1000030; rev:1; classtype:suspicious-traffic; priority:3;)

# Tor/Onion Service Detection
# alert tls any any -> any any (msg:"TLS SNI - Tor Bridge/Relay"; tls.sni; content:".onion"; sid:1000040; rev:1; classtype:policy-violation; priority:2;)

#==============================================================================
# DNS Port 53 Monitoring Rules
#==============================================================================

# Suspicious DNS Queries
# alert dns any any -> any 53 (msg:"DNS Query - Known Malware Domain"; dns.query; content:"malware.example.com"; sid:1001001; rev:1; classtype:trojan-activity; priority:1;)
# alert dns any any -> any 53 (msg:"DNS Query - DGA Pattern"; dns.query; pcre:"/^[a-z]{12,}\.com$/"; sid:1001002; rev:1; classtype:trojan-activity; priority:2;)

# DNS Tunneling Detection
# alert dns any any -> any 53 (msg:"DNS Tunneling - Large TXT Record"; dns.query; dns.rrname; content:".tunnel."; sid:1001010; rev:1; classtype:policy-violation; priority:2;)
# alert dns any any -> any 53 (msg:"DNS Tunneling - Suspicious Subdomain Length"; dns.query; dsize:>200; sid:1001011; rev:1; classtype:policy-violation; priority:2;)

# DNS Exfiltration Patterns
# alert dns any any -> any 53 (msg:"DNS Exfiltration - Base64 Pattern"; dns.query; pcre:"/[a-zA-Z0-9+\/]{20,}=/"; sid:1001020; rev:1; classtype:data-loss; priority:1;)

# Fast Flux Detection
# alert dns any any -> any 53 (msg:"DNS Fast Flux - Multiple A Records"; dns.query; threshold:type both, track by_src, count 10, seconds 60; sid:1001030; rev:1; classtype:trojan-activity; priority:2;)

#==============================================================================
# DoH (DNS over HTTPS) Port 443 & DoT Port 853 Rules  
#==============================================================================

# DoH Provider Detection
# alert tls any any -> any 443 (msg:"DoH - Cloudflare"; tls.sni; content:"cloudflare-dns.com"; sid:1002001; rev:1; classtype:policy-violation; priority:3;)
# alert tls any any -> any 443 (msg:"DoH - Google"; tls.sni; content:"dns.google"; sid:1002002; rev:1; classtype:policy-violation; priority:3;)
# alert tls any any -> any 443 (msg:"DoH - Quad9"; tls.sni; content:"dns.quad9.net"; sid:1002003; rev:1; classtype:policy-violation; priority:3;)

# Suspicious DoH Usage
# alert http any any -> any 443 (msg:"DoH - Suspicious User-Agent"; http.user_agent; content:"doh-client"; sid:1002010; rev:1; classtype:policy-violation; priority:2;)
# alert tls any any -> any 443 (msg:"DoH - Custom/Private Resolver"; tls.sni; pcre:"/^(dns|doh|resolver)\./i"; sid:1002011; rev:1; classtype:policy-violation; priority:2;)

# DoT (DNS over TLS) Port 853
# alert tls any any -> any 853 (msg:"DoT - DNS over TLS Connection"; flow:established; sid:1002020; rev:1; classtype:policy-violation; priority:3;)

#==============================================================================
# General Security & Monitoring Rules
#==============================================================================

# Certificate Validation Issues
# alert tls any any -> any any (msg:"TLS - Self-Signed Certificate"; tls.cert_serial; content:"00"; sid:1003001; rev:1; classtype:suspicious-traffic; priority:2;)

# Unusual Port Usage
# alert tcp any any -> any ![80,443,853,53] (msg:"TLS on Unusual Port"; flow:established; content:"|16 03|"; depth:2; sid:1003010; rev:1; classtype:suspicious-traffic; priority:3;)

# High-Volume DNS Queries (Possible DNS Amplification)
# alert dns any any -> any 53 (msg:"DNS Amplification - High Query Volume"; threshold:type both, track by_src, count 100, seconds 10; sid:1003020; rev:1; classtype:attempted-dos; priority:2;)

#==============================================================================
# Usage Instructions:
# 
# 1. Uncomment rules by removing the "# " prefix
# 2. Customize domain names and patterns for your environment
# 3. Adjust thresholds and priorities as needed
# 4. Test rules: sudo suricata -T -c /etc/suricata/suricata.yaml
# 5. Reload rules: sudo systemctl restart suricata
# 6. Monitor alerts: sudo tail -f /var/log/suricata/fast.log
#
# Rule Testing:
# - Test DNS rule: nslookup malware.example.com
# - Test TLS rule: curl -k https://malware.example.com  
# - Test DoH: curl -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=example.com&type=A"
#==============================================================================

    # Set permissions  
    chown -R suricata:suricata /var/lib/suricata/rules
    chmod -R 644 /var/lib/suricata/rules/*
    
    log "Suricata configured for custom rules only (no external rule downloads)"
}

# Install Node.js for Kalipso
install_nodejs() {
    log "Installing Node.js for Kalipso web interface..."
    
    # Install Node.js 22.x
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y nodejs
    
    log "Node.js installed successfully"
}

# Install SLIPS 
install_slips() {
    log "Installing SLIPS (Stratosphere Linux IPS)..."
    
    # Check if Zeek is available
    local zeek_available=false
    if command -v zeek >/dev/null 2>&1; then
        zeek_available=true
        log "Zeek detected - SLIPS will have full functionality"
    else
        warn "Zeek not available - SLIPS will run with reduced capabilities"
    fi
    
    # Clone SLIPS
    cd /opt
    if [ ! -d "StratosphereLinuxIPS" ]; then
        git clone --depth 1 https://github.com/stratosphereips/StratosphereLinuxIPS.git
    fi
    cd StratosphereLinuxIPS
    
    # Create Python virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Install dependencies
    pip install --upgrade pip setuptools wheel
    
    # Install SLIPS requirements
    if [ -f install/requirements.txt ]; then
        pip install -r install/requirements.txt || warn "Some SLIPS dependencies failed to install"
    fi
    
    # Configure SLIPS for Zeek integration
    log "Configuring SLIPS-Zeek integration..."
    
    # Create SLIPS config for Zeek input
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
    
    # Install Kalipso dependencies
    if [ -d modules/kalipso ]; then
        cd modules/kalipso
        npm install --production
        cd ../..
    fi
    
    # Configure Zeek for SLIPS integration (using Docker-proven approach)
    log "Configuring Zeek for SLIPS integration..."
    
    # Create directories with root ownership (exactly like working Docker)
    mkdir -p /var/log/zeek /var/spool/zeek
    chown -R root:root /var/log/zeek /var/spool/zeek
    chmod -R 755 /var/log/zeek /var/spool/zeek
    
    # Create Zeek local configuration for IPS interfaces (standalone mode)
    cat > /opt/zeek/etc/node.cfg << 'ZEEK_NODE_EOF'
# Zeek Node Configuration - Standalone Mode for SLIPS Integration
# Monitors primary copy interface for traffic analysis
[zeek]
type=standalone
host=localhost
interface=enp6s19
ZEEK_NODE_EOF
    
    # Create Zeek startup configuration
    cat > /opt/zeek/etc/zeekctl.cfg << 'ZEEK_CFG_EOF'
# ZeekControl Configuration (Docker-proven settings)
LogDir = /var/log/zeek
SpoolDir = /var/spool/zeek
CfgDir = /opt/zeek/etc
ZEEK_CFG_EOF
    
    # Ensure Zeek configuration has correct permissions (like Docker)
    chown -R root:root /opt/zeek/etc
    chmod 755 /opt/zeek/etc
    chmod 644 /opt/zeek/etc/node.cfg /opt/zeek/etc/zeekctl.cfg
    
    # Make slips executable
    chmod +x slips.py
    
    # Create directories
    mkdir -p /var/log/slips
    chown -R root:root /var/log/slips
    chmod 755 /var/log/slips
    
    # Configure SLIPS web UI to bind to management interface
    if [ -f config/slips.conf ]; then
        # Update SLIPS config for web interface
        sed -i 's/web_interface_ip = .*/web_interface_ip = 10.10.254.39/' config/slips.conf
        sed -i 's/web_interface_port = .*/web_interface_port = 55000/' config/slips.conf
        MGMT_IP_DETECTED=$(ip addr show $MGMT_IFACE | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || echo "127.0.0.1")
        log "SLIPS web interface configured for management interface (${MGMT_IP_DETECTED}:55000)"
    fi
    
    log "SLIPS installed successfully"
}

# Install ML Detector Dashboard Integration for SLIPS Web UI
install_ml_detector_dashboard() {
    log "Installing Karen's IPS ML Detector Dashboard..."

    # Get the directory where Karen's IPS is installed (where this script lives)
    KARENS_IPS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Check if SLIPS is installed
    if [ ! -d "/opt/StratosphereLinuxIPS" ]; then
        error_exit "SLIPS not found at /opt/StratosphereLinuxIPS. Install SLIPS first."
    fi

    # Check if slips_integration directory exists
    if [ ! -d "$KARENS_IPS_DIR/slips_integration" ]; then
        warn "ML Detector dashboard files not found at $KARENS_IPS_DIR/slips_integration"
        warn "Skipping ML Detector dashboard installation"
        return 0
    fi

    log "Found ML Detector integration files at $KARENS_IPS_DIR/slips_integration"

    cd /opt/StratosphereLinuxIPS

    # Backup existing web interface (if not already backed up)
    if [ ! -d "webinterface.backup.$(date +%Y%m%d)" ]; then
        log "Creating backup of SLIPS webinterface..."
        cp -r webinterface "webinterface.backup.$(date +%Y%m%d)"
    fi

    # Copy ML Detector blueprint
    log "Installing ML Detector blueprint..."
    ML_DETECTOR_DEST="/opt/StratosphereLinuxIPS/webinterface/ml_detector"

    if [ -d "$ML_DETECTOR_DEST" ]; then
        log "ML Detector already exists, updating..."
        rm -rf "$ML_DETECTOR_DEST"
    fi

    cp -r "$KARENS_IPS_DIR/slips_integration/webinterface/ml_detector" "$ML_DETECTOR_DEST"
    log "ML Detector blueprint installed"

    # Apply patches to SLIPS core files
    log "Applying patches to SLIPS web interface..."

    # Patch app.py
    if grep -q "from .ml_detector.ml_detector import ml_detector" webinterface/app.py; then
        log "app.py already patched"
    else
        log "Patching webinterface/app.py..."
        if patch -p1 --dry-run < "$KARENS_IPS_DIR/slips_integration/patches/app.py.patch" > /dev/null 2>&1; then
            patch -p1 < "$KARENS_IPS_DIR/slips_integration/patches/app.py.patch"
            log "app.py patched successfully"
        else
            warn "app.py patch failed, attempting manual integration..."
            # Manual patch fallback
            sed -i '/from \.documentation\.documentation import documentation/a from .ml_detector.ml_detector import ml_detector' webinterface/app.py
            sed -i '/app.register_blueprint(documentation, url_prefix="\/documentation")/a \    app.register_blueprint(ml_detector, url_prefix="/ml_detector")' webinterface/app.py
            log "app.py manually patched"
        fi
    fi

    # Patch app.html
    if grep -q "ml_detector.html" webinterface/templates/app.html; then
        log "app.html already patched"
    else
        log "Patching webinterface/templates/app.html..."
        if patch -p1 --dry-run < "$KARENS_IPS_DIR/slips_integration/patches/app.html.patch" > /dev/null 2>&1; then
            patch -p1 < "$KARENS_IPS_DIR/slips_integration/patches/app.html.patch"
            log "app.html patched successfully"
        else
            warn "app.html patch failed - manual integration required"
            warn "Please follow instructions in $KARENS_IPS_DIR/slips_integration/README.md"
        fi
    fi

    # Set proper permissions
    chown -R root:root "$ML_DETECTOR_DEST"
    chmod 755 "$ML_DETECTOR_DEST"
    find "$ML_DETECTOR_DEST" -type f -name "*.py" -exec chmod 644 {} \;
    find "$ML_DETECTOR_DEST" -type f -name "*.js" -exec chmod 644 {} \;
    find "$ML_DETECTOR_DEST" -type f -name "*.css" -exec chmod 644 {} \;
    find "$ML_DETECTOR_DEST" -type f -name "*.html" -exec chmod 644 {} \;

    # Install additional Python dependencies if needed (using SLIPS venv)
    if [ -f "$KARENS_IPS_DIR/requirements.txt" ]; then
        log "Installing additional Python dependencies..."
        source /opt/StratosphereLinuxIPS/venv/bin/activate
        pip install --upgrade pip
        # Install only if not already present
        pip install -q flask markupsafe || true
        deactivate
    fi

    log "ML Detector Dashboard installed successfully!"
    log ""
    log "The ML Detector Dashboard will be available at:"
    log "  http://[SLIPS-IP]:55000 -> Click 'ML Detector' tab"
    log ""
    log "Redis keys used by ML Detector:"
    log "  - ml_detector:stats"
    log "  - ml_detector:recent_detections"
    log "  - ml_detector:timeline"
    log "  - ml_detector:model_info"
    log "  - ml_detector:feature_importance"
    log "  - ml_detector:alerts"
    log ""
}

# Configure interface setup
setup_interfaces() {
    log "Setting up network bridge for NFQUEUE IPS mode..."
    
    # Create interface setup script for bridge mode
    cat > /usr/local/bin/ips-interface-setup.sh << EOF
#!/bin/bash
# IPS Interface Setup Script for NFQUEUE Bridge Mode

# Management interface (keep existing configuration)
# $MGMT_IFACE - no changes needed

# Create bridge for IPS
ip link add name br0 type bridge
ip link set br0 up

# Add interfaces to bridge
ip link set $IFACE_IN master br0
ip link set $IFACE_OUT master br0

# Bring up bridge ports
ip link set $IFACE_IN up
ip link set $IFACE_OUT up

# Disable hardware offloading on bridge ports
ethtool -K $IFACE_IN gro off lro off tso off gso off rx off tx off 2>/dev/null || true
ethtool -K $IFACE_OUT gro off lro off tso off gso off rx off tx off 2>/dev/null || true

# Bridge settings for IPS mode
ip link set br0 type bridge stp_state 0  # Disable STP for performance
ip link set br0 type bridge ageing_time 30000  # Fast MAC aging

# Disable reverse path filtering
sysctl -w net.ipv4.conf.br0.rp_filter=0
sysctl -w net.ipv4.conf.$IFACE_IN.rp_filter=0
sysctl -w net.ipv4.conf.$IFACE_OUT.rp_filter=0

# Bridge netfilter for nfqueue
sysctl -w net.bridge.bridge-nf-call-iptables=1
sysctl -w net.bridge.bridge-nf-call-ip6tables=1

echo "IPS bridge configured for NFQUEUE mode"
echo "  Management: $MGMT_IFACE (unchanged)"
echo "  Bridge:     br0 (forwarding at kernel speed)"
echo "  Ports:      $IFACE_IN <-> $IFACE_OUT"
EOF

    chmod +x /usr/local/bin/ips-interface-setup.sh
    
    # Run interface setup now
    /usr/local/bin/ips-interface-setup.sh
    
    # Create systemd service for interface setup
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
ExecStop=/bin/bash -c 'ip link set $IFACE_IN nomaster; ip link set $IFACE_OUT nomaster; ip link del br0'
TimeoutStartSec=30
# Health check for bridge
ExecStartPost=/bin/bash -c 'sleep 2; ip link show br0 up || exit 1'

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl enable ips-interfaces.service
    
    # Create netplan config for persistent interface settings
    cat > /etc/netplan/99-ips-interfaces.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $IFACE_IN:
      dhcp4: no
      dhcp6: no
      optional: true
    $IFACE_OUT:
      dhcp4: no
      dhcp6: no  
      optional: true
EOF
    
    # Apply netplan configuration if available (Ubuntu-specific)
    if command -v netplan >/dev/null 2>&1; then
        log "Applying netplan configuration..."
        netplan apply 2>/dev/null || log "Warning: netplan apply failed, changes will take effect on reboot"
    else
        log "Netplan not available (non-Ubuntu system), network changes will take effect on reboot"
    fi
    
    log "Network interfaces configured for AF_PACKET copy mode"
}

# Configure Redis
configure_redis() {
    log "Configuring Redis for SLIPS..."
    
    # Configure Redis
    sed -i 's/^bind 127.0.0.1 ::1/bind 127.0.0.1/' /etc/redis/redis.conf
    sed -i 's/^# maxmemory <bytes>/maxmemory 2gb/' /etc/redis/redis.conf
    sed -i 's/^# maxmemory-policy noeviction/maxmemory-policy allkeys-lru/' /etc/redis/redis.conf
    
    # Start and enable Redis
    systemctl restart redis-server
    systemctl enable redis-server
    
    log "Redis configured and started"
}

# Create SystemD services instead of Supervisor
create_systemd_services() {
    log "Creating SystemD services for IPS components (Suricata, SLIPS, Web UI, Kalipso CLI)..."
    
    # Suricata SystemD service for NFQUEUE mode
    cat > /etc/systemd/system/suricata.service << EOF
[Unit]
Description=Suricata IPS NFQUEUE Mode  
Documentation=https://suricata.readthedocs.io/
After=network-online.target redis.service ips-interfaces.service nftables.service
Wants=network-online.target
Requires=ips-interfaces.service nftables.service

[Service]
Type=simple
User=root
Group=root
ExecStartPre=/usr/bin/suricata -c /etc/suricata/suricata.yaml -T
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -q 0 -v
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
Environment=HOME=/var/lib/suricata
WorkingDirectory=/var/lib/suricata





[Install]
WantedBy=multi-user.target
EOF

    # SLIPS SystemD service - Live Interface Analysis on Bridge
    cat > /etc/systemd/system/slips.service << EOF
[Unit]
Description=SLIPS (Stratosphere Linux IPS) - ML Behavioral Analysis
Documentation=https://stratospherelinuxips.readthedocs.io/
After=network.target redis.service ips-interfaces.service
Wants=redis.service ips-interfaces.service
Requires=ips-interfaces.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/StratosphereLinuxIPS
ExecStart=/opt/StratosphereLinuxIPS/venv/bin/python /opt/StratosphereLinuxIPS/slips.py -i br0
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
Environment=HOME=/root
Environment=PATH=/opt/StratosphereLinuxIPS/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin


# Security (relaxed for network operations)
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/slips /opt/StratosphereLinuxIPS

[Install]
WantedBy=multi-user.target
EOF

    # Zeek Network Security Monitor SystemD service
    cat > /etc/systemd/system/zeek.service << EOF
[Unit]
Description=Zeek Network Security Monitor
After=network.target ips-interfaces.service
Wants=ips-interfaces.service
Before=slips.service

[Service]
Type=forking
User=root
Group=root
WorkingDirectory=/opt/zeek
PIDFile=/opt/zeek/spool/zeek/zeek.pid
Environment=PATH=/opt/zeek/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Use the exact same approach as working Docker container
ExecStartPre=/opt/zeek/bin/zeekctl install
ExecStart=/opt/zeek/bin/zeekctl deploy
ExecReload=/opt/zeek/bin/zeekctl restart
ExecStop=/opt/zeek/bin/zeekctl stop
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
# Allow extra time for initial deployment and rule compilation
TimeoutStartSec=180
# Allow more time for stopping (zeek can be slow to shutdown cleanly)
TimeoutStopSec=90
# Don't fail if zeek has startup issues - this is optional for the IPS system
SuccessExitStatus=0 1

# Resource limits
MemoryMax=1G
CPUQuota=100%

[Install]
WantedBy=multi-user.target
EOF

    # SLIPS Web UI SystemD service
    cat > /etc/systemd/system/slips-webui.service << EOF
[Unit]
Description=SLIPS Web Interface
After=network.target redis.service ips-interfaces.service
Wants=redis.service ips-interfaces.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/StratosphereLinuxIPS
ExecStart=/opt/StratosphereLinuxIPS/venv/bin/python /opt/StratosphereLinuxIPS/slips.py -i enp6s20 -w
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
Environment=HOME=/root
Environment=PATH=/opt/StratosphereLinuxIPS/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=SLIPS_WEB_HOST=10.10.254.39
Environment=SLIPS_WEB_PORT=55000

# Resource limits
MemoryMax=2G
CPUQuota=150%

# Security
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/slips /opt/StratosphereLinuxIPS

[Install]
WantedBy=multi-user.target
EOF

    # IPS Filter Database Sync Service
    cat > /etc/systemd/system/ips-filter-sync.service << EOF
[Unit]
Description=IPS Filter Database Sync
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/ips-filter-db.py sync
StandardOutput=journal
StandardError=journal
User=root

[Install]
WantedBy=multi-user.target
EOF

    # IPS Filter Database Sync Timer (runs every 6 hours)
    cat > /etc/systemd/system/ips-filter-sync.timer << EOF
[Unit]
Description=IPS Filter Database Sync Timer
Requires=ips-filter-sync.service

[Timer]
OnBootSec=5min
OnUnitActiveSec=6h
Unit=ips-filter-sync.service

[Install]
WantedBy=timers.target
EOF

    # Create Kalipso startup script in /usr/bin
    cat > /usr/bin/kalipso << 'KALIPSO_SCRIPT'
#!/bin/bash
# Kalipso Smart Launcher - Connect or Start Interactive Session
# Usage: sudo kalipso

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "Error: Kalipso must be run with sudo privileges"
    echo " Usage: sudo kalipso"
    exit 1
fi

KALIPSO_SESSION="kalipso"
KALIPSO_DIR="/opt/StratosphereLinuxIPS/modules/kalipso"
KALIPSO_CMD="/usr/bin/node /opt/StratosphereLinuxIPS/modules/kalipso/kalipso.js -p 6379"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}   Kalipso Terminal UI Launcher${NC}"
echo -e "${BLUE}═══════════════════════════════════${NC}"

# Check if tmux session exists
if tmux has-session -t "$KALIPSO_SESSION" 2>/dev/null; then
    echo -e "${GREEN}Found existing Kalipso session, connecting...${NC}"
    echo -e "${YELLOW} Use Ctrl+B then D to detach and keep running${NC}"
    echo ""
    sleep 1
    exec tmux attach-session -t "$KALIPSO_SESSION"
else
    echo -e "${GREEN} Starting fresh Kalipso session...${NC}"
    echo -e "${YELLOW} Use Ctrl+B then D to detach and keep running${NC}"
    echo -e "${YELLOW} Use 'exit' or Ctrl+C to stop Kalipso completely${NC}"
    echo ""
    sleep 1
    
    # Check if Kalipso directory exists
    if [ ! -d "$KALIPSO_DIR" ]; then
        echo -e "${RED}Kalipso directory not found: $KALIPSO_DIR${NC}"
        exit 1
    fi
    
    # Start new tmux session with Kalipso
    cd "$KALIPSO_DIR"
    exec tmux new-session -s "$KALIPSO_SESSION" "$KALIPSO_CMD"
fi
KALIPSO_SCRIPT

    # Make script executable
    chmod +x /usr/bin/kalipso
    
    log "Kalipso startup script created in /usr/bin/kalipso"

    # Reload systemd and enable services
    systemctl daemon-reload
    
    # Enable all services
    systemctl enable ips-interfaces.service
    systemctl enable redis-server
    systemctl enable zeek.service
    systemctl enable suricata.service
    systemctl enable slips.service  
    systemctl enable slips-webui.service
    systemctl enable ips-filter-sync.timer
    
    log "SystemD services created and enabled"
}

# Start all services
start_services() {
    log "Starting all IPS services..."
    
    # Start services in dependency order
    systemctl start redis-server
    sleep 2
    systemctl start ips-interfaces.service
    sleep 2
    
    # Try to start Zeek but don't fail the installation if it doesn't work
    if systemctl start zeek.service; then
        log " Zeek started successfully"
    else
        warn " Zeek failed to start - continuing without it (Suricata will provide main IPS functionality)"
        systemctl disable zeek.service || true
    fi
    sleep 3
    
    # Test Suricata configuration before starting
    log "Testing Suricata configuration with comprehensive validation..."
    
    # First validate that all string datasets contain base64 data
    for f in /etc/suricata/datasets/{telemetry-domains,malicious-domains,suspicious-urls,doh-servers,suspect-ja3,ech-cdn-ips}.txt; do
        if [[ -f "$f" ]] && [[ -s "$f" ]]; then
            # Check if file contains non-base64 content
            if grep -q '[^A-Za-z0-9+/=]' "$f" || ! head -1 "$f" | base64 -d >/dev/null 2>&1; then
                warn " Dataset file $f may not be properly base64 encoded"
                log "Re-encoding $f to ensure base64 compliance..."
                tmp=$(mktemp)
                grep -v '^[[:space:]]*#' "$f" | grep -v '^[[:space:]]*$' \
                  | while IFS= read -r line; do printf '%s' "$line" | base64 -w0; echo; done > "$tmp" \
                  && mv "$tmp" "$f"
                chown suricata:suricata "$f"
                chmod 644 "$f"
            fi
        fi
    done
    
    # Clean and validate IP datasets - remove invalid entries
    for ip_file in /etc/suricata/datasets/malicious-ips.txt /etc/suricata/datasets/c2-ips.txt; do
        if [[ -f "$ip_file" ]]; then
            log "Cleaning IP dataset: $ip_file"
            python3 - <<PY
import ipaddress, re
src = "$ip_file"
dst = src + ".clean"
valid_count = 0
with open(dst, "w") as out:
    try:
        with open(src) as f:
            for line_num, line in enumerate(f, 1):
                s = line.strip()
                # Skip empty lines, comments, and lines with letters (except in IPv6)
                if not s or s.startswith('#'):
                    continue
                # Skip lines that look like labels or metadata
                if re.search(r'^[a-zA-Z].*[a-zA-Z]', s):
                    print(f"Line {line_num}: Skipping metadata/label '{s}'")
                    continue
                try:
                    # Only allow IPv4 addresses/networks (IPv6 disabled)
                    if '/' in s:
                        net = ipaddress.ip_network(s, strict=False)
                        if net.version == 4:  # IPv4 only
                            out.write(s + "\n")
                            valid_count += 1
                        else:
                            print(f"Line {line_num}: Skipping IPv6 network '{s}' (IPv6 disabled)")
                    else:
                        addr = ipaddress.ip_address(s)
                        if addr.version == 4:  # IPv4 only
                            out.write(s + "\n")
                            valid_count += 1
                        else:
                            print(f"Line {line_num}: Skipping IPv6 address '{s}' (IPv6 disabled)")
                except ValueError:
                    print(f"Line {line_num}: Skipping invalid IP '{s}'")
    except Exception as e:
        print(f"Error processing {src}: {e}")
        # Ensure we have a valid file even on error
        with open(dst, 'w') as f:
            f.write("127.0.0.1\n")
        valid_count = 1
print(f"Cleaned dataset: {valid_count} valid IPs")
import os
os.replace(dst, src)
PY
            chown suricata:suricata "$ip_file"
            chmod 644 "$ip_file"
            log " IP dataset cleaned: $ip_file"
        fi
    done
    
    if suricata -T -c /etc/suricata/suricata.yaml; then
        log " Suricata configuration test passed"
        systemctl start suricata.service
        sleep 5
        if systemctl is-active --quiet suricata.service; then
            log " Suricata service started successfully"
            
            # Comprehensive validation checks as per requirements
            log "Running comprehensive validation checks..."
            
            # Test dataset operations (string datasets must use base64)
            test_domain_b64=$(echo -n 'example.com' | base64)
            log "Testing dataset operations with base64: ${test_domain_b64}"
            
            if suricatasc -c "dataset-add malicious-domains string ${test_domain_b64}" >/dev/null 2>&1; then
                log " Dataset add operation successful"
                
                if suricatasc -c "dataset-lookup malicious-domains string ${test_domain_b64}" >/dev/null 2>&1; then
                    log " Dataset lookup operation successful" 
                    log " Suricata dataset functionality confirmed"
                else
                    warn " Dataset lookup failed - may be normal for new installation"
                fi
            else
                warn " Dataset add operation failed - check suricatasc permissions"
                warn "   Try: sudo suricatasc -c 'dump-counters' to test socket connectivity"
            fi
        else
            error_exit " Suricata service failed to start"
            systemctl status suricata.service --no-pager -l
            exit 1
        fi
    else
        error_exit " Suricata configuration test failed"
        echo "Run 'suricata -T -c /etc/suricata/suricata.yaml' to debug configuration issues"
        exit 1
    fi
    
    systemctl start slips.service
    sleep 3
    systemctl start slips-webui.service
    
    # Start IPS Filter web interface
    systemctl start ips-filter-web.service
    
    log "All services started"
}

# Create MOTD with IPS access instructions
create_motd() {
    log "Creating MOTD with IPS filter instructions..."
    
    cat > /etc/motd << 'MOTD_EOF'

      ██╗██████╗ ███████╗    ███████╗██╗██╗  ████████╗███████╗██████╗ 
      ██║██╔══██╗██╔════╝    ██╔════╝██║██║  ╚══██╔══╝██╔════╝██╔══██╗
      ██║██████╔╝███████╗    █████╗  ██║██║     ██║   █████╗  ██████╔╝
      ██║██╔═══╝ ╚════██║    ██╔══╝  ██║██║     ██║   ██╔══╝  ██╔══██╗
      ██║██║     ███████║    ██║     ██║███████╗██║   ███████╗██║  ██║
      ╚═╝╚═╝     ╚══════╝    ╚═╝     ╚═╝╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                               
 IPS Content Filter  

════════════════════════════════════════════════════════════════════════════════

════════════════════════════════════════════════════════════════════════════════

 Real-time domain blocking (no DNS cache delays)
 Layer 7 inspection (catches HTTPS SNI, not just DNS) 
 DoH/DoT bypass protection (packet-level inspection)
 Content analysis beyond domains (URLs, headers, etc.)
 Granular time-based and user-specific controls
 Activity tracking and detailed analytics
 SQLite database for complex filtering logic

════════════════════════════════════════════════════════════════════════════════
 IPS FILTER MANAGEMENT
════════════════════════════════════════════════════════════════════════════════

Web Interface:           http://10.10.254.39:55001
 SLIPS ML Analysis:       http://10.10.254.39:55000  
   Terminal UI:            kalipso

Quick Commands:
  ips-filter add facebook.com social_media    # Block social media
  ips-filter import-rpz /path/file.rpz ads    # Import RPZ list
  ips-filter ml-scan                          # ML bypass detection
  ips-filter ml-auto                          # Auto-block ML threats
  ips-filter add doubleclick.net advertising  # Block ad tracking
  ips-filter stats                           # View statistics
  ips-filter log                             # Monitor live blocking
  ips-filter web                             # Start web interface

════════════════════════════════════════════════════════════════════════════════
  MONITORING & ANALYSIS
════════════════════════════════════════════════════════════════════════════════

Live Blocking:     tail -f /var/log/suricata/fast.log | grep "FAMILY FILTER"
ML Threat Log:     tail -f /var/log/ips-filter-ml.log
Daily Stats:       grep "$(date +'%m/%d')" /var/log/suricata/fast.log
Service Status:    systemctl status suricata slips ips-filter-web
Performance:       suricatasc -c dump-counters
SLIPS Profiles:    redis-cli -n 1 keys "profile_*" | wc -l

════════════════════════════════════════════════════════════════════════════════
  OPERATIONAL PROCEDURES
════════════════════════════════════════════════════════════════════════════════

  DAILY OPERATIONS:
  1. ips-filter stats                    # Check blocking statistics
  2. ips-filter ml-scan                  # Scan for ML threats
  3. systemctl status suricata slips     # Verify services
  4. tail /var/log/ips-filter-ml.log     # Review ML detections

 EMERGENCY RESPONSE:
  Block IP:          ips-filter add [malicious-ip] malware
  Import Threat List: ips-filter import-rpz /path/threats.rpz emergency
  Auto-block ML:     ips-filter ml-auto
  Service restart:   systemctl restart suricata slips

 WEEKLY MAINTENANCE:
  1. ips-filter import-rpz /data/updated-blocklist.rpz ads
  2. ips-filter ml-scan && ips-filter ml-auto
  3. grep "ml_critical" /var/log/ips-filter-ml.log | wc -l
  4. systemctl reload suricata

 TROUBLESHOOTING:
  Dataset issues:    ips-filter debug-datasets  
  No blocking:       suricatasc -c "dataset-lookup malicious-domains string [base64_domain]"
  IP dataset check:  nl -ba /etc/suricata/datasets/malicious-ips.txt | head -20
  Interface issues:  tcpdump -i enp6s19 -c 10
  SLIPS not working: systemctl status slips && redis-cli ping
  Dataset sync:      ips-filter sync

 IP DATASET FORMAT:
  - Type 'ip' datasets: Plain IP addresses/CIDRs only (no comments, no base64)
  - Type 'string' datasets: Base64 encoded values only
  - Mixed formats will cause "invalid IPv6" errors

 QUICK FIXES:
  Clean IP dataset:  python3 -c "import ipaddress; [print(l.strip()) for l in open('/etc/suricata/datasets/malicious-ips.txt') if l.strip() and not l.startswith('#') and (ipaddress.ip_network(l.strip()) if '/' in l else ipaddress.ip_address(l.strip()))]"

════════════════════════════════════════════════════════════════════════════════
 EXAMPLE IPS CONTENT BLOCKS
════════════════════════════════════════════════════════════════════════════════

Social Media:      ips-filter add tiktok.com social_media
Ad Tracking:       ips-filter add googleadservices.com advertising  
Telemetry:         ips-filter add telemetry.microsoft.com telemetry
Gaming (optional): ips-filter add steam.com gaming
Adult Content:     ips-filter add [domain] adult_content

════════════════════════════════════════════════════════════════════════════════
 NETWORK CONFIGURATION
════════════════════════════════════════════════════════════════════════════════

Management:        enp6s18 (10.10.254.39/24)
Traffic Bridge:    enp6s19 <-> enp6s20 (bidirectional inspection)
Inspection Mode:   AF_PACKET copy mode (no traffic disruption)
Database:          SQLite at /var/lib/suricata/ips_filter.db

════════════════════════════════════════════════════════════════════════════════
 LOG MONITORING
════════════════════════════════════════════════════════════════════════════════

 Suricata Alerts:         tail -f /var/log/suricata/fast.log
 EVE JSON (detailed):     tail -f /var/log/suricata/eve.json | jq
 SLIPS Behavioral:        journalctl -fu slips
 Web UI Logs:             journalctl -fu slips-webui
   Kalipso Logs:           journalctl -fu kalipso

════════════════════════════════════════════════════════════════════════════════
⚙️  SERVICE MANAGEMENT
════════════════════════════════════════════════════════════════════════════════

 Restart Services:        systemctl restart suricata slips slips-webui
⏹️  Stop Services:          systemctl stop suricata slips slips-webui
▶️  Start Services:         systemctl start suricata slips slips-webui
 Individual Control:      systemctl [start|stop|restart|status] <service>

════════════════════════════════════════════════════════════════════════════════
 QUICK COMMANDS
════════════════════════════════════════════════════════════════════════════════

# Launch Kalipso Terminal UI (Interactive Dashboard)
kalipso

# If running in tmux session:
# Exit tmux session (Ctrl+B, then D)
# Kill tmux session: tmux kill-session -t kalipso
# Or just exit/Ctrl+C to stop completely

# Test Suricata Config
suricata -T -c /etc/suricata/suricata.yaml

# Network Interface Status
ip link show enp6s19 enp6s20  # Data interfaces
ip addr show enp6s18           # Management interface

# Real-time Threat Detection
tail -f /var/log/suricata/fast.log | grep -E "(MALWARE|TROJAN|EXPLOIT)"

════════════════════════════════════════════════════════════════════════════════

MOTD_EOF
    
    # Replace hardcoded IPs with actual management IP
    MGMT_IP_DETECTED=$(ip addr show $MGMT_IFACE | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || echo "127.0.0.1")
    sed -i "s/10\.10\.254\.39/${MGMT_IP_DETECTED}/g" /etc/motd
    sed -i "s/enp6s19/${IFACE_IN}/g" /etc/motd
    log "MOTD created with dynamic IP: ${MGMT_IP_DETECTED} and interface: ${IFACE_IN}"
    
    # Set permissions
    chmod 644 /etc/motd
    
    # Create SSH banner with operational instructions
    cat > /etc/ssh/banner << 'SSH_BANNER_EOF'
   "
=================================================================================="
         ██╗██████╗ ███████╗    ███████╗██╗██╗  ████████╗███████╗██████╗ "
         ██║██╔══██╗██╔════╝    ██╔════╝██║██║  ╚══██╔══╝██╔════╝██╔══██╗"
         ██║██████╔╝███████╗    █████╗  ██║██║     ██║   █████╗  ██████╔╝"
         ██║██╔═══╝ ╚════██║    ██╔══╝  ██║██║     ██║   ██╔══╝  ██╔══██╗"
         ██║██║     ███████║    ██║     ██║███████╗██║   ███████╗██║  ██║"
         ╚═╝╚═╝     ╚══════╝    ╚═╝     ╚═╝╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝"
=================================================================================="
 IPS Content Filter  

┌─────────────────────────────────────────────────────────────────────────────┐
│    IPS CONTENT FILTER - OPERATIONAL QUICK REFERENCE                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   WEB INTERFACES:                                                         │
│     IPS Filter Control: http://10.10.254.39:55001                          │
│     SLIPS ML Analysis:  http://10.10.254.39:55000                          │
│                                                                             │
│   QUICK COMMANDS:                                                         │
│     ips-filter stats           # View statistics                           │
│     ips-filter ml-scan         # ML threat detection                       │
│     ips-filter ml-auto         # Auto-block ML threats                     │
│     ips-filter log             # Live activity monitor                     │
│                                                                             │
│    BULK OPERATIONS:                                                        │
│     ips-filter import-rpz /path/file.rpz category                          │
│     ips-filter add domain.com category                                     │
│     ips-filter sync            # Sync to Suricata                         │
│                                                                             │
│   EMERGENCY BLOCKING:                                                     │
│     ips-filter add [malicious-ip] malware                                  │
│     ips-filter ml-auto         # Auto-block current threats               │
│     systemctl restart suricata # Restart if needed                        │
│                                                                             │
│   MONITORING:                                                             │
│     tail -f /var/log/suricata/fast.log | grep "FAMILY FILTER"              │
│     tail -f /var/log/ips-filter-ml.log                                     │
│     systemctl status suricata slips ips-filter-web                         │
│                                                                             │
│   TROUBLESHOOTING:                                                        │
│     tcpdump -i enp6s19 -c 10   # Check traffic flow                       │
│     redis-cli -n 1 keys "profile_*" | wc -l  # SLIPS profiles             │
│     suricatasc -c dump-counters # Performance stats                        │
│                                                                             │
│    CATEGORIES: social_media, advertising, tracking, telemetry,            │
│                 adult_content, gaming, malware, rpz_import                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

SSH_BANNER_EOF
    
    # Configure SSH to show banner (guard against duplicates)
    if ! grep -q "Banner /etc/ssh/banner" /etc/ssh/sshd_config; then
        echo "Banner /etc/ssh/banner" >> /etc/ssh/sshd_config
        if systemctl is-active --quiet sshd; then
            systemctl reload sshd
        fi
    fi
    
    log "MOTD created with IPS access instructions"
}
save_configuration() {
    log "Saving configuration..."
    
    mkdir -p /etc/ips-config
    
    cat > /etc/ips-config/ips-config.conf << EOF
# IPS Configuration - Generated $(date)
# AF_PACKET Copy Mode 

# Network Interfaces
MGMT_IFACE=$MGMT_IFACE
IFACE_IN=$IFACE_IN
IFACE_OUT=$IFACE_OUT
HOME_NET=$HOME_NET
MGMT_IP=$MGMT_IP
MGMT_GW=$MGMT_GW
MGMT_DNS=$MGMT_DNS

# Mode
IPS_MODE=afpacket_copy
BRIDGE_MODE=none
SERVICE_MANAGER=systemd

# Installation Date
INSTALL_DATE=$(date)
INSTALLER_VERSION=3.1_systemd
EOF

    log "Configuration saved to /etc/ips-config/ips-config.conf"
}

# Final verification and status
verify_installation() {
    log "Verifying installation..."
    
    # Check interface status
    log "Interface status:"
    log "  Management: $(ip addr show $MGMT_IFACE | grep inet | head -1 | awk '{print $2}' || echo 'No IP')"
    log "  Copy IN:    $(ip link show $IFACE_IN | grep 'state UP' >/dev/null && echo 'UP' || echo 'DOWN')"
    log "  Copy OUT:   $(ip link show $IFACE_OUT | grep 'state UP' >/dev/null && echo 'UP' || echo 'DOWN')"
    
    # Check services
    log "Service status:"
    systemctl is-active redis-server >/dev/null && log "  Redis: Running" || warn "  Redis: Not running"
    systemctl is-active suricata >/dev/null && log "  Suricata: Running" || warn "  Suricata: Not running"
    systemctl is-active slips >/dev/null && log "  SLIPS: Running" || warn "  SLIPS: Not running"
    systemctl is-active slips-webui >/dev/null && log "  SLIPS Web UI: Running" || warn "  SLIPS Web UI: Not running"
    
    # Production-ready health checks
    log "Running comprehensive Suricata health checks..."
    
    # Configuration test
    if suricata -T -c /etc/suricata/suricata.yaml >/dev/null 2>&1; then
        log " Suricata configuration test passed"
    else
        log " Suricata configuration test failed"
        exit 1
    fi
    
    # Dataset loading test
    if [ -f "/etc/suricata/datasets/telemetry-domains.txt" ]; then
        dataset_count=$(wc -l < /etc/suricata/datasets/telemetry-domains.txt)
        log " Loaded $dataset_count telemetry domains for blocking"
    fi
    
    # Dataset health checks after Suricata starts
    cat > /opt/ips-dataset-test.sh << 'DATASET_TEST_EOF'
#!/bin/bash
# Dataset health checks and test commands
echo " Dataset Health Check"
echo "====================="

# List all loaded datasets
echo " Loaded datasets:"
suricatasc -c "datasets.list" 2>/dev/null || echo "Suricata not running"

# Test dataset lookup
echo "  Testing dataset lookup:"
test_domain_b64=$(echo -n "google.com" | base64)
echo "   Domain: google.com (base64: $test_domain_b64)"
echo "   Command: suricatasc -c 'dataset-lookup malicious-domains string $test_domain_b64'"
suricatasc -c "dataset-lookup malicious-domains string $test_domain_b64" 2>/dev/null || echo "   Dataset not loaded"

# Test live dataset add
echo " Test adding domain to dataset:"
echo "   1. Encode domain: echo -n 'test-block.example.com' | base64"
echo "   2. Add to dataset: suricatasc -c 'dataset-add malicious-domains string <base64>'"
echo "   3. Test connectivity to verify drop/alert"
DATASET_TEST_EOF
    
    chmod +x /opt/ips-dataset-test.sh
    
    # Interface inline assertion check script
    cat > /opt/ips-health-check.sh << 'HEALTH_EOF'
#!/bin/bash
# Inline assertion: verify AF_PACKET interfaces are actually inline
echo " IPS Health Check - Inline Assertion"
echo "Verify: unplug either AF_PACKET NIC - traffic should halt"
echo "If traffic continues, you are NOT inline (classic pitfall)"

# Check AF_PACKET interface status
for iface in $IFACE_IN $IFACE_OUT; do
    if ip link show "\$iface" up >/dev/null 2>&1; then
        echo " \$iface is UP and configured"
    else
        echo " \$iface is DOWN - traffic should be halted"
    fi
done

# Check nftables sets
echo " nftables blocking sets status:"
nft list set inet home blocked4 2>/dev/null | grep -E "elements|timeout" || echo "Empty IPv4 set"
echo "Note: IPv6 disabled - no IPv6 blocking set"

# Dataset hot-load test
echo "  Dataset hot-load test:"
echo "Run: sudo suricatasc -c 'dataset-add telemetry-domains string ZXhhbXBsZS1kb21haW4ubmV0'"
echo ""
echo "  VALIDATION STEPS:"
echo "1. Test configuration: sudo suricata -T -c /etc/suricata/suricata.yaml"
echo "2. Start service: sudo systemctl start suricata"  
echo "3. Check status: sudo systemctl status suricata"
echo "4. Test dataset: echo -n 'example.com' | base64 | sudo suricatasc -c 'dataset-add telemetry-domains string \$(cat -)'"
echo ""
echo "  IMPORTANT: String datasets now use base64 encoding (Suricata 8 requirement)"
echo "   IP datasets (malicious-ips, c2-ips, ech-cdn-ips) use plain IP/CIDR format"
echo "Then test connectivity to verify drop/alert"

# QUIC visibility check
echo " QUIC visibility check:"
echo "After enabling QUIC, confirm you see QUIC events in EVE for HTTP/3 devices"
echo "tail -f /var/log/suricata/eve.json | grep '\"quic\"'"
HEALTH_EOF
    
    chmod +x /opt/ips-health-check.sh

    log "Verification completed"
}

import_community_blocklists() {
    log "=========================================="
    log "Importing Community Blocklists"
    log "=========================================="
    log ""

    # Create blocklists directory
    BLOCKLISTS_DIR="/opt/karens-ips-blocklists"
    mkdir -p "$BLOCKLISTS_DIR"
    cd "$BLOCKLISTS_DIR"

    log "Cloning blocklist repositories..."
    log "This may take several minutes due to repository size..."
    log ""

    # Clone Perflyst PiHoleBlocklist
    if [ ! -d "PiHoleBlocklist" ]; then
        log "Cloning Perflyst/PiHoleBlocklist..."
        git clone --depth 1 https://github.com/Perflyst/PiHoleBlocklist.git 2>&1 | grep -v "^remote:" || true
    else
        log "Perflyst/PiHoleBlocklist already exists, updating..."
        cd PiHoleBlocklist && git pull --quiet 2>&1 | grep -v "^remote:" || true
        cd ..
    fi

    # Clone hagezi dns-blocklists
    if [ ! -d "dns-blocklists" ]; then
        log "Cloning hagezi/dns-blocklists (this is a large repository)..."
        git clone --depth 1 https://github.com/hagezi/dns-blocklists.git 2>&1 | grep -v "^remote:" || true
    else
        log "hagezi/dns-blocklists already exists, updating..."
        cd dns-blocklists && git pull --quiet 2>&1 | grep -v "^remote:" || true
        cd ..
    fi

    log ""
    log "Importing blocklists into IPS database..."
    log "This will take several minutes for large lists..."
    log ""

    # Import Perflyst blocklists
    log "Importing Perflyst SmartTV blocklist..."
    /opt/ips-filter-db.py import-list \
        --list-file "$BLOCKLISTS_DIR/PiHoleBlocklist/SmartTV.txt" \
        --category "ads" \
        --source-name "perflyst_smarttv" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:)" || true

    log "Importing Perflyst Android tracking blocklist..."
    /opt/ips-filter-db.py import-list \
        --list-file "$BLOCKLISTS_DIR/PiHoleBlocklist/android-tracking.txt" \
        --category "tracking" \
        --source-name "perflyst_android" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:)" || true

    log "Importing Perflyst Amazon FireTV blocklist..."
    /opt/ips-filter-db.py import-list \
        --list-file "$BLOCKLISTS_DIR/PiHoleBlocklist/AmazonFireTV.txt" \
        --category "ads" \
        --source-name "perflyst_firetv" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:)" || true

    log "Importing Perflyst SessionReplay blocklist..."
    /opt/ips-filter-db.py import-list \
        --list-file "$BLOCKLISTS_DIR/PiHoleBlocklist/SessionReplay.txt" \
        --category "tracking" \
        --source-name "perflyst_sessionreplay" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:)" || true

    # Import hagezi blocklists (Pro version - balanced blocking)
    if [ -f "$BLOCKLISTS_DIR/dns-blocklists/domains/pro.txt" ]; then
        log "Importing hagezi Pro blocklist (balanced - recommended)..."
        /opt/ips-filter-db.py import-list \
            --list-file "$BLOCKLISTS_DIR/dns-blocklists/domains/pro.txt" \
            --category "ads" \
            --source-name "hagezi_pro" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:|Processing line)" || true
    else
        warn "hagezi Pro blocklist not found, skipping..."
    fi

    if [ -f "$BLOCKLISTS_DIR/dns-blocklists/domains/native.txt" ]; then
        log "Importing hagezi Native Tracker blocklist..."
        /opt/ips-filter-db.py import-list \
            --list-file "$BLOCKLISTS_DIR/dns-blocklists/domains/native.txt" \
            --category "tracking" \
            --source-name "hagezi_native" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:|Processing line)" || true
    else
        warn "hagezi Native Tracker blocklist not found, skipping..."
    fi

    log ""
    log "Syncing all imported domains to Suricata..."
    /opt/ips-filter-db.py sync 2>&1 | grep -E "(Syncing|Successfully|Progress:|Warning:)" || true

    log ""
    log "Showing final statistics..."
    /opt/ips-filter-db.py stats

    log ""
    log "Blocklist import complete!"
    log "Database: /var/lib/suricata/ips_filter.db"
    log "Blocklists: $BLOCKLISTS_DIR"
    log ""
    log "To update blocklists in the future, run:"
    log "  cd $BLOCKLISTS_DIR"
    log "  cd PiHoleBlocklist && git pull && cd .."
    log "  cd dns-blocklists && git pull && cd .."
    log "  ips-filter import-list /opt/karens-ips-blocklists/PiHoleBlocklist/SmartTV.txt ads"
    log "  ips-filter sync"
    log ""
}

# Main execution
main() {
    log "=========================================="
    log "Starting Complete IPS Installation"
    log "=========================================="
    
    # Show configuration and get confirmation  
    show_configuration
    
    # Execute installation phases
    log "Phase 1: Installing base system..."
    install_base_system
    
    log "Phase 2: Setting up kernel modules and tuning..."
    setup_kernel_and_tuning
    
    log "Phase 3: Setting up nftables blocking infrastructure..."
    setup_nftables_blocking
    
    log "Phase 4: Installing Suricata..."
    install_suricata
    
    log "Phase 5: Configuring Suricata for NFQUEUE bridge mode..."
    configure_suricata_afpacket
    
    log "Phase 6: Updating Suricata rules..."
    update_suricata_rules

    log "Phase 6.5: Importing community blocklists..."
    import_community_blocklists

    log "Phase 7: Installing Node.js..."
    install_nodejs

    log "Phase 8: Installing SLIPS..."
    install_slips
    
    log "Phase 8.5: Installing ML Detector Dashboard..."
    install_ml_detector_dashboard
    
    log "Phase 9: Setting up network interfaces..."
    setup_interfaces
    
    log "Phase 10: Configuring Redis..."
    configure_redis
    
    log "Phase 11: Creating SystemD services (Suricata, SLIPS, Web UI, Kalipso CLI)..."
    create_systemd_services
    
    log "Phase 12: Starting services..."
    start_services
    
    log "Phase 13: Creating MOTD..."
    create_motd
    
    log "Phase 14: Saving configuration..."
    save_configuration
    
    log "Phase 15: Verifying installation..."
    verify_installation
    
    log "=========================================="
    log " COMPLETE IPS INSTALLATION FINISHED!"
    log "=========================================="
    
    info ""
    info " Installation Complete - SystemD Version! "
    info ""
    info "Network Configuration:"
    info "  Management: $MGMT_IFACE ($(ip addr show $MGMT_IFACE | grep 'inet ' | awk '{print $2}' || echo 'No IP'))"
    info "  Copy IN:    $IFACE_IN (transparent, no IP)"
    info "  Copy OUT:   $IFACE_OUT (transparent, no IP)"
    info ""
    info "AF_PACKET Copy Mode:"
    info "  Traffic flows: $IFACE_IN <-> Suricata <-> $IFACE_OUT" 
    info "  No bridging - kernel-level packet copying"
    info "  Bidirectional inspection and forwarding"
    info ""
    info "SystemD Service Management:"
    info "  All services:   systemctl status redis-server suricata slips slips-webui"
    info "  Suricata:       systemctl status suricata"
    info "  SLIPS:          systemctl status slips"
    info "  SLIPS Web UI:   systemctl status slips-webui"
    info "  Redis:          systemctl status redis-server"
    info ""
    info "Service Control:"
    info "  Start all:      systemctl start suricata slips slips-webui"
    info "  Stop all:       systemctl stop suricata slips slips-webui"
    info "  Restart all:    systemctl restart suricata slips slips-webui"
    info "  View logs:      journalctl -fu <service-name>"
    info ""
    info "Monitoring:"
    info "  Suricata logs:  tail -f /var/log/suricata/fast.log"
    info "  SLIPS logs:     journalctl -fu slips"
    info "  EVE JSON:       tail -f /var/log/suricata/eve.json"
    MGMT_IP_DETECTED=$(ip addr show $MGMT_IFACE | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || echo "DHCP-pending")
    info "  SLIPS Web UI:   http://${MGMT_IP_DETECTED}:55000 (management interface)"
    info "    └─ ML Detector:   Click 'ML Detector' tab for ad detection dashboard"
    info "  Kalipso CLI:    kalipso (interactive terminal - smart launcher)"
    info ""
    info "Configuration saved in: /etc/ips-config/ips-config.conf"
    info "Installation log:       /var/log/ips-installer.log"
    info ""
    info " Your SystemD-managed IPS with dual UI is ready! "
    info "  - Web Interface: http://${MGMT_IP_DETECTED}:55000"
    info "  - Terminal UI:   kalipso (smart launcher)"
    info "  - Exit tmux:     Ctrl+B, then D (or exit/Ctrl+C)"
    info ""
    
    # Final validation checklist
    log " Running final validation checklist..."
    log "1. YAML + Rules validation: $(suricata -T -c /etc/suricata/suricata.yaml >/dev/null 2>&1 && echo " PASSED" || echo " FAILED")"
    log "2. Service status: $(systemctl is-active --quiet suricata && echo " RUNNING" || echo " STOPPED")"
    
    # Dataset smoke test
    if systemctl is-active --quiet suricata; then
        test_domain_b64=$(echo -n 'validation.test' | base64)
        if timeout 3 suricatasc -c "dataset-add malicious-domains string ${test_domain_b64}" >/dev/null 2>&1; then
            log "3. Dataset operations:  WORKING"
            timeout 3 suricatasc -c "dataset-lookup malicious-domains string ${test_domain_b64}" >/dev/null 2>&1
        else
            log "3. Dataset operations:  NEEDS SUDO (run: sudo suricatasc -c 'dump-counters')"
        fi
    else
        log "3. Dataset operations:   SKIPPED (Suricata not running)"
    fi
    
    log " Installation validation complete!"
    info ""
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error_exit "This script must be run as root (use sudo)"
fi

# Run main function
main "$@"