#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# DNS Blackhole Module
# Implements DNS-based blocking of malicious domains

module_name="DNS Blackhole"
module_description="DNS blackhole for domain-based blocking"
module_version="1.0.0"
module_dependencies=("base-system")

# Source common functions
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

dns_blackhole_install() {
    log_info "Installing DNS blackhole components..."

    # Install dnsmasq for DNS blackhole
    if ! command_exists dnsmasq; then
        log_info "Installing dnsmasq..."
        apt-get update -qq
        apt-get install -y dnsmasq dnsutils
    fi

    # Create dnsmasq configuration directory
    mkdir -p /etc/dnsmasq.d
    mkdir -p /var/lib/karens-ips/dns

    # Create dnsmasq configuration for DNS blackhole
    cat > /etc/dnsmasq.d/karens-ips-blackhole.conf << 'EOF'
# Karen's IPS DNS Blackhole Configuration
# Listen only on management interface to avoid conflicts with system DNS
listen-address=127.0.0.53
port=5353
bind-interfaces

# Blackhole configuration
addn-hosts=/var/lib/karens-ips/dns/blackhole-hosts
conf-dir=/var/lib/karens-ips/dns,*.dns

# Logging
log-queries
log-facility=/var/log/karens-ips/dns-blackhole.log

# Cache settings
cache-size=10000
neg-ttl=3600

# Security
stop-dns-rebind
rebind-localhost-ok
EOF

    # Create DNS blackhole hosts file
    touch /var/lib/karens-ips/dns/blackhole-hosts
    
    # Create log directory
    mkdir -p /var/log/karens-ips
    touch /var/log/karens-ips/dns-blackhole.log

    # Create systemd service for DNS blackhole
    cat > /etc/systemd/system/karens-ips-dns.service << 'EOF'
[Unit]
Description=Karen's IPS DNS Blackhole
After=network.target
Wants=network.target

[Service]
Type=forking
PIDFile=/var/run/karens-ips-dns.pid
ExecStartPre=/usr/bin/dnsmasq --test --conf-file=/etc/dnsmasq.d/karens-ips-blackhole.conf
ExecStart=/usr/bin/dnsmasq --conf-file=/etc/dnsmasq.d/karens-ips-blackhole.conf --pid-file=/var/run/karens-ips-dns.pid
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable karens-ips-dns
    
    log_success "DNS blackhole components installed"
}

dns_blackhole_configure() {
    log_info "Configuring DNS blackhole..."
    
    # Create DNS blackhole management script
    cat > /usr/local/bin/karens-ips-dns-blackhole << 'EOF'
#!/bin/bash
# Karen's IPS DNS Blackhole Management

BLACKHOLE_HOSTS="/var/lib/karens-ips/dns/blackhole-hosts"
SERVICE_NAME="karens-ips-dns"

case "$1" in
    add-domain)
        if [ -z "$2" ]; then
            echo "Usage: $0 add-domain <domain>"
            exit 1
        fi
        domain="$2"
        # Add domain to blackhole (redirect to localhost)
        if ! grep -q "^127.0.0.1 $domain$" "$BLACKHOLE_HOSTS"; then
            echo "127.0.0.1 $domain" >> "$BLACKHOLE_HOSTS"
            echo "Added $domain to blackhole"
            systemctl reload "$SERVICE_NAME" 2>/dev/null || true
        else
            echo "Domain $domain already blackholed"
        fi
        ;;
    remove-domain)
        if [ -z "$2" ]; then
            echo "Usage: $0 remove-domain <domain>"
            exit 1
        fi
        domain="$2"
        if grep -q "^127.0.0.1 $domain$" "$BLACKHOLE_HOSTS"; then
            sed -i "/^127.0.0.1 $domain$/d" "$BLACKHOLE_HOSTS"
            echo "Removed $domain from blackhole"
            systemctl reload "$SERVICE_NAME" 2>/dev/null || true
        else
            echo "Domain $domain not in blackhole"
        fi
        ;;
    load-list)
        if [ -z "$2" ]; then
            echo "Usage: $0 load-list <file>"
            exit 1
        fi
        if [ ! -f "$2" ]; then
            echo "File $2 not found"
            exit 1
        fi
        count=0
        while IFS= read -r domain; do
            # Skip empty lines and comments
            [[ -z "$domain" || "$domain" =~ ^[[:space:]]*# ]] && continue
            # Clean domain (remove protocols, paths, etc.)
            domain=$(echo "$domain" | sed 's|^.*://||' | sed 's|/.*$||' | tr -d '\r')
            if [[ "$domain" =~ ^[a-zA-Z0-9.-]+$ ]]; then
                if ! grep -q "^127.0.0.1 $domain$" "$BLACKHOLE_HOSTS"; then
                    echo "127.0.0.1 $domain" >> "$BLACKHOLE_HOSTS"
                    ((count++))
                fi
            fi
        done < "$2"
        echo "Added $count domains to blackhole"
        systemctl reload "$SERVICE_NAME" 2>/dev/null || true
        ;;
    status)
        if systemctl is-active "$SERVICE_NAME" >/dev/null; then
            echo "DNS blackhole is running"
            domain_count=$(grep -c "^127.0.0.1" "$BLACKHOLE_HOSTS" 2>/dev/null || echo "0")
            echo "Blackholed domains: $domain_count"
        else
            echo "DNS blackhole is not running"
        fi
        ;;
    reload)
        systemctl reload "$SERVICE_NAME"
        echo "DNS blackhole reloaded"
        ;;
    *)
        echo "Usage: $0 {add-domain|remove-domain|load-list|status|reload}"
        exit 1
        ;;
esac
EOF

    chmod +x /usr/local/bin/karens-ips-dns-blackhole
    
    log_success "DNS blackhole configured"
}

dns_blackhole_start() {
    log_info "Starting DNS blackhole service..."
    
    if systemctl start karens-ips-dns; then
        log_success "DNS blackhole started successfully"
    else
        log_error "Failed to start DNS blackhole"
        return 1
    fi
}

# Main function called by installer
install_dns_blackhole() {
    log_info "Installing $module_name..."
    dns_blackhole_install
    dns_blackhole_configure
    dns_blackhole_start
    log_success "$module_name installation completed"
}

# Module execution
case "${1:-install}" in
    install)
        install_dns_blackhole
        ;;
    configure)
        dns_blackhole_configure
        ;;
    start)
        dns_blackhole_start
        ;;
    *)
        log_error "Unknown action: $1"
        exit 1
        ;;
esac