#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Active Blocking Module
# Implements packet-level blocking via Suricata DROP rules

module_name="Active Blocking"
module_description="Packet-level blocking via Suricata DROP rules"
module_version="1.0.0"
module_dependencies=("base-system" "suricata")

# Source common functions
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

active_blocking_install() {
    log "Installing active blocking components..."

    # Create directories
    mkdir -p /var/lib/karens-ips/rules
    mkdir -p /etc/karens-ips
    
    # Install dependencies
    if ! command_exists python3; then
        apt-get update -qq
        apt-get install -y python3
    fi

    # Install required Python packages via system package manager
    apt-get install -y python3-dnspython python3-requests

    success "Active blocking components installed"
}

active_blocking_configure() {
    log "Configuring active blocking..."
    
    # Create the blocklist-to-rules converter
    cat > /usr/local/bin/karens-ips-rules-generator << 'EOF'
#!/usr/bin/env python3
"""
Karen's IPS Rules Generator
Converts domain blocklists to Suricata DROP rules
"""

import sys
import re
import socket
import ipaddress
from pathlib import Path
import argparse

def is_valid_domain(domain):
    """Check if domain is valid"""
    if not domain or len(domain) > 253:
        return False
    
    # Remove trailing dot
    if domain.endswith('.'):
        domain = domain[:-1]
    
    # Check for valid characters and structure
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    return bool(domain_regex.match(domain))

def is_valid_ip(ip):
    """Check if IP address is valid"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def domain_to_ip_rule(domain, sid_start=9000000):
    """Convert domain to IP-based DROP rule by resolving DNS"""
    rules = []
    try:
        # Resolve domain to IP addresses
        result = socket.getaddrinfo(domain, None)
        ips = set()
        for res in result:
            ip = res[4][0]
            if is_valid_ip(ip):
                ips.add(ip)
        
        # Generate DROP rules for each IP
        for i, ip in enumerate(sorted(ips)):
            sid = sid_start + i
            rule = f'drop ip any any -> {ip} any (msg:"KARENS-IPS: Block ad server {domain} ({ip})"; sid:{sid}; rev:1; classtype:policy-violation;)'
            rules.append(rule)
            
    except Exception as e:
        # If DNS resolution fails, create a content-based rule
        sid = sid_start
        rule = f'drop tcp any any -> any 80 (msg:"KARENS-IPS: Block HTTP to {domain}"; content:"{domain}"; http_host; sid:{sid}; rev:1; classtype:policy-violation;)'
        rules.append(rule)
        rule_https = f'drop tcp any any -> any 443 (msg:"KARENS-IPS: Block HTTPS to {domain}"; content:"{domain}"; tls_sni; sid:{sid + 1}; rev:1; classtype:policy-violation;)'
        rules.append(rule_https)
    
    return rules

def process_blocklist(input_file, output_file, max_domains=1000):
    """Process a blocklist file and generate Suricata rules"""
    rules = []
    domain_count = 0
    sid_counter = 9000000
    
    print(f"Processing blocklist: {input_file}")
    
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            if domain_count >= max_domains:
                print(f"Reached maximum domain limit ({max_domains})")
                break
                
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            
            # Extract domain from various formats
            domain = None
            
            # Handle different blocklist formats
            if line.startswith('||') and line.endswith('^'):
                # AdBlock format: ||example.com^
                domain = line[2:-1]
            elif line.startswith('0.0.0.0 ') or line.startswith('127.0.0.1 '):
                # Hosts format: 0.0.0.0 example.com
                parts = line.split()
                if len(parts) >= 2:
                    domain = parts[1]
            elif ' ' not in line and '/' not in line:
                # Plain domain format
                domain = line
            else:
                continue
            
            # Clean and validate domain
            if domain:
                domain = domain.lower().strip()
                # Remove protocols and paths
                domain = re.sub(r'^https?://', '', domain)
                domain = re.sub(r'/.*$', '', domain)
                
                if is_valid_domain(domain) and not domain.startswith('.'):
                    try:
                        # Generate rules for this domain
                        domain_rules = domain_to_ip_rule(domain, sid_counter)
                        rules.extend(domain_rules)
                        domain_count += 1
                        sid_counter += 10  # Leave gap for multiple IPs per domain
                        
                        if domain_count % 100 == 0:
                            print(f"Processed {domain_count} domains...")
                            
                    except Exception as e:
                        print(f"Error processing domain {domain}: {e}")
                        continue
    
    # Write rules to output file
    with open(output_file, 'w') as f:
        f.write("# Karen's IPS Generated DROP Rules\n")
        f.write(f"# Generated from: {input_file}\n")
        f.write(f"# Total domains processed: {domain_count}\n")
        f.write(f"# Total rules generated: {len(rules)}\n\n")
        
        for rule in rules:
            f.write(rule + '\n')
    
    print(f"Generated {len(rules)} rules from {domain_count} domains")
    return len(rules)

def main():
    parser = argparse.ArgumentParser(description='Convert blocklist to Suricata DROP rules')
    parser.add_argument('input_file', help='Input blocklist file')
    parser.add_argument('output_file', help='Output Suricata rules file')
    parser.add_argument('--max-domains', type=int, default=1000, 
                       help='Maximum domains to process (default: 1000)')
    
    args = parser.parse_args()
    
    if not Path(args.input_file).exists():
        print(f"Error: Input file {args.input_file} not found")
        sys.exit(1)
    
    try:
        rule_count = process_blocklist(args.input_file, args.output_file, args.max_domains)
        print(f"Successfully generated {rule_count} rules in {args.output_file}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
EOF

    chmod +x /usr/local/bin/karens-ips-rules-generator
    
    # Create the active blocking manager
    cat > /usr/local/bin/karens-ips-active-blocking << 'EOF'
#!/bin/bash
# Karen's IPS Active Blocking Manager

RULES_DIR="/var/lib/karens-ips/rules"
SURICATA_RULES_DIR="/etc/suricata/rules"
BLOCKLISTS_DIR="/opt/karens-ips-blocklists"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

generate_rules_from_blocklists() {
    log "Generating Suricata DROP rules from blocklists..."
    
    mkdir -p "$RULES_DIR"
    
    # Process key blocklists
    rule_files=()
    
    # Process Perflyst SmartTV blocklist
    if [ -f "$BLOCKLISTS_DIR/PiHoleBlocklist/SmartTV.txt" ]; then
        log "Processing Perflyst SmartTV blocklist..."
        output_file="$RULES_DIR/perflyst-smarttv-drop.rules"
        /usr/local/bin/karens-ips-rules-generator \
            "$BLOCKLISTS_DIR/PiHoleBlocklist/SmartTV.txt" \
            "$output_file" \
            --max-domains 500
        rule_files+=("$output_file")
    fi
    
    # Process hagezi Pro blocklist
    if [ -f "$BLOCKLISTS_DIR/dns-blocklists/domains/pro.txt" ]; then
        log "Processing hagezi Pro blocklist..."
        output_file="$RULES_DIR/hagezi-pro-drop.rules"
        /usr/local/bin/karens-ips-rules-generator \
            "$BLOCKLISTS_DIR/dns-blocklists/domains/pro.txt" \
            "$output_file" \
            --max-domains 500
        rule_files+=("$output_file")
    fi
    
    # Process custom blocklist
    if [ -f "$BLOCKLISTS_DIR/dns-blocklists/domains/blocklist-referral.txt" ]; then
        log "Processing custom blocklist..."
        output_file="$RULES_DIR/custom-drop.rules"
        /usr/local/bin/karens-ips-rules-generator \
            "$BLOCKLISTS_DIR/dns-blocklists/domains/blocklist-referral.txt" \
            "$output_file" \
            --max-domains 100
        rule_files+=("$output_file")
    fi
    
    # Combine all rules into a single file
    combined_file="$SURICATA_RULES_DIR/karens-ips-drop.rules"
    log "Combining rules into $combined_file..."
    
    cat > "$combined_file" << 'HEADER'
# Karen's IPS Active Blocking Rules
# Auto-generated from community blocklists
# DO NOT EDIT MANUALLY - will be overwritten

HEADER

    for rule_file in "${rule_files[@]}"; do
        if [ -f "$rule_file" ]; then
            echo "# Rules from $(basename "$rule_file")" >> "$combined_file"
            cat "$rule_file" >> "$combined_file"
            echo "" >> "$combined_file"
        fi
    done
    
    # Update Suricata configuration to include our rules
    if ! grep -q "karens-ips-drop.rules" /etc/suricata/suricata.yaml; then
        log "Adding karens-ips-drop.rules to Suricata configuration..."
        sed -i '/rule-files:/a \ \ - karens-ips-drop.rules' /etc/suricata/suricata.yaml
    fi
    
    # Reload Suricata rules
    log "Reloading Suricata rules..."
    if command -v suricatasc >/dev/null; then
        suricatasc -c "reload-rules" || log "Warning: Could not reload rules via suricatasc"
    fi
    
    # Restart Suricata to ensure rules are loaded
    if systemctl is-active suricata >/dev/null; then
        log "Restarting Suricata to load new rules..."
        systemctl restart suricata
    fi
    
    rule_count=$(grep -c "^drop " "$combined_file" 2>/dev/null || echo "0")
    log "Active blocking setup complete. Generated $rule_count DROP rules."
}

case "$1" in
    generate)
        generate_rules_from_blocklists
        ;;
    status)
        combined_file="$SURICATA_RULES_DIR/karens-ips-drop.rules"
        if [ -f "$combined_file" ]; then
            rule_count=$(grep -c "^drop " "$combined_file" 2>/dev/null || echo "0")
            echo "Active blocking rules: $rule_count DROP rules loaded"
            
            # Check if Suricata is using the rules
            if systemctl is-active suricata >/dev/null; then
                echo "Suricata status: Running"
                if command -v suricatasc >/dev/null; then
                    echo "Checking rule loading..."
                    suricatasc -c 'dump-counters' | grep -A 1 rules_loaded || echo "Could not get rule count"
                fi
            else
                echo "Suricata status: Not running"
            fi
        else
            echo "No active blocking rules found"
        fi
        ;;
    *)
        echo "Usage: $0 {generate|status}"
        echo "  generate - Generate DROP rules from blocklists"
        echo "  status   - Show current blocking rule status"
        exit 1
        ;;
esac
EOF

    chmod +x /usr/local/bin/karens-ips-active-blocking
    
    success "Active blocking configured"
}

active_blocking_enable() {
    log "Enabling active blocking..."
    
    # Generate initial rules from existing blocklists
    if /usr/local/bin/karens-ips-active-blocking generate; then
        success "Active blocking rules generated and loaded"
    else
        warn "Could not generate initial rules - blocklists may not be available yet"
    fi
}

# Main function called by installer
install_active_blocking() {
    log "Installing $module_name..."
    active_blocking_install
    active_blocking_configure
    active_blocking_enable
    success "$module_name installation completed"
}

# Module execution
case "${1:-install}" in
    install)
        install_active_blocking
        ;;
    configure)
        active_blocking_configure
        ;;
    enable)
        active_blocking_enable
        ;;
    *)
        error_exit "Unknown action: $1"
        exit 1
        ;;
esac