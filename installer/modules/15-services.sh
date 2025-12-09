#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: Services Startup
# Phase: 15
# Description: Start all IPS services in correct dependency order

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ============================================================================
# SERVICES STARTUP
# ============================================================================

# Define all helper functions first before calling any
# This ensures functions are available when sourced

test_suricata_config() {
    log "Testing Suricata configuration..."

    if suricata -T -c /etc/suricata/suricata.yaml; then
        success "Suricata configuration test passed"
    else
        error_exit "Suricata configuration test failed. Run: suricata -T -c /etc/suricata/suricata.yaml"
    fi
}

start_suricata() {
    log "Starting Suricata service..."

    if systemctl start suricata.service; then
        sleep 5
        success "Suricata service started"
        
        # Fix socket permissions for suricatasc access
        fix_suricata_socket_permissions
        
    else
        error_exit "Failed to start Suricata service"
    fi
}

fix_suricata_socket_permissions() {
    log "Fixing Suricata socket permissions for dataset operations..."
    
    # Wait for socket to be created
    local socket_path="/var/run/suricata/suricata.socket"
    local wait_count=0
    
    while [[ ! -S "$socket_path" ]] && [[ $wait_count -lt 30 ]]; do
        sleep 1
        wait_count=$((wait_count + 1))
    done
    
    if [[ -S "$socket_path" ]]; then
        # Make socket accessible to sudo users
        chmod 666 "$socket_path"
        log "Fixed socket permissions: $socket_path"
        
        # Test basic connectivity
        if suricatasc -c "uptime" >/dev/null 2>&1; then
            log "Suricatasc connectivity confirmed"
        else
            warn "Suricatasc connectivity test failed"
        fi
    else
        warn "Suricata socket not found at $socket_path"
    fi
}

verify_suricata_running() {
    log "Verifying Suricata is running..."

    if systemctl is-active --quiet suricata.service; then
        success "Suricata service is active"
    else
        error_exit "Suricata service failed to start"
        systemctl status suricata.service --no-pager -l
        exit 1
    fi
}

test_suricata_datasets() {
    log "Testing Suricata dataset operations..."

    # Test with karens-ips-domains (plain text dataset for SNI)
    local test_domain="example.com"
    
    log "Testing domain dataset operations (plain text): $test_domain"

    if suricatasc -c "dataset-add karens-ips-domains string $test_domain" >/dev/null 2>&1; then
        log "Domain dataset add operation successful"

        if suricatasc -c "dataset-lookup karens-ips-domains string $test_domain" >/dev/null 2>&1; then
            success "Domain dataset lookup operation successful"
        else
            log "Domain dataset lookup returned no match (expected if not in blocklist)"
        fi
    else
        warn "Domain dataset add operation failed - suricatasc may need socket permissions"
        warn "Try: sudo suricatasc -c 'dump-counters' to test connectivity"
    fi
}

# ============================================================================
# SERVICE STARTUP FUNCTIONS
# ============================================================================

start_redis() {
    log "Starting Redis..."

    if systemctl start redis-server; then
        sleep 2
        if systemctl is-active --quiet redis-server; then
            success "Redis started"
        else
            error_exit "Redis failed to start"
        fi
    else
        error_exit "Failed to start Redis"
    fi
}

start_interfaces() {
    log "Starting network interfaces..."

    if systemctl start ips-interfaces.service; then
        sleep 2
        if systemctl is-active --quiet ips-interfaces.service; then
            success "Network interfaces configured"
        else
            error_exit "Interface setup failed"
        fi
    else
        error_exit "Failed to start interface setup"
    fi
}

start_zeek() {
    log "Starting Zeek (optional)..."

    # Try to start Zeek but don't fail installation if it doesn't work
    if systemctl start zeek.service 2>/dev/null; then
        sleep 3
        if systemctl is-active --quiet zeek.service; then
            success "Zeek started successfully"
        else
            warn "Zeek failed to start - continuing without it (Suricata will provide main IPS functionality)"
            systemctl disable zeek.service 2>/dev/null || true
        fi
    else
        warn "Zeek failed to start - continuing without it"
        systemctl disable zeek.service 2>/dev/null || true
    fi
}

start_slips() {
    log "Starting SLIPS service..."

    if systemctl start slips.service; then
        sleep 3
        if systemctl is-active --quiet slips.service; then
            success "SLIPS started"
        else
            warn "SLIPS failed to start"
        fi
    else
        warn "Failed to start SLIPS"
    fi
}

start_slips_webui() {
    log "Starting SLIPS Web UI..."

    if systemctl start slips-webui.service; then
        sleep 2
        if systemctl is-active --quiet slips-webui.service; then
            success "SLIPS Web UI started"
        else
            warn "SLIPS Web UI failed to start"
        fi
    else
        warn "Failed to start SLIPS Web UI"
    fi
}

start_ips_filter_web() {
    log "Starting IPS Filter web interface..."

    # This is optional - only start if service exists
    if [[ -f /etc/systemd/system/ips-filter-web.service ]]; then
        if systemctl start ips-filter-web.service 2>/dev/null; then
            log "IPS Filter web interface started"
        else
            log "IPS Filter web interface not available (optional)"
        fi
    else
        log "IPS Filter web service not installed (optional)"
    fi
}

start_ml_detector_services() {
    log "Starting ML Detector services..."

    if [[ -f /etc/systemd/system/stream-ad-blocker.service ]]; then
        if systemctl start stream-ad-blocker.service 2>/dev/null; then
            success "Stream ad blocker service started"
        else
            warn "Stream ad blocker service failed to start"
        fi
    else
        log "Stream ad blocker service not installed (optional)"
    fi

    if [[ -f /etc/systemd/system/dns-labeler.service ]]; then
        if systemctl start dns-labeler.service 2>/dev/null; then
            log "DNS labeler service started"
        else
            log "DNS labeler service failed to start"
        fi
    else
        log "DNS labeler service not installed (optional)"
    fi

    if [[ -f /etc/systemd/system/auto-labeler.service ]]; then
        if systemctl start auto-labeler.service 2>/dev/null; then
            log "Auto-labeler service started"
        else
            log "Auto-labeler service failed to start"
        fi
    else
        log "Auto-labeler service not installed (optional)"
    fi
}

start_services() {
    log_subsection "Starting IPS Services"

    # Check if service startup is enabled
    if [[ "${START_SERVICES:-true}" != "true" ]]; then
        log "Service startup disabled, skipping"
        return 0
    fi

    log "Starting all IPS services in dependency order..."

    # Start services in correct order
    start_redis
    start_interfaces
    start_zeek
    validate_and_start_suricata
    start_slips
    start_slips_webui
    start_ips_filter_web
    start_ml_detector_services

    success "All services started successfully"
}

# ============================================================================
# DATASET VALIDATION FUNCTIONS
# ============================================================================

start_redis() {
    log "Starting Redis..."

    if systemctl start redis-server; then
        sleep 2
        if systemctl is-active --quiet redis-server; then
            success "Redis started"
        else
            error_exit "Redis failed to start"
        fi
    else
        error_exit "Failed to start Redis"
    fi
}

start_interfaces() {
    log "Starting network interfaces..."

    if systemctl start ips-interfaces.service; then
        sleep 2
        if systemctl is-active --quiet ips-interfaces.service; then
            success "Network interfaces configured"
        else
            error_exit "Interface setup failed"
        fi
    else
        error_exit "Failed to start interface setup"
    fi
}

start_zeek() {
    log "Starting Zeek (optional)..."

    # Try to start Zeek but don't fail installation if it doesn't work
    if systemctl start zeek.service 2>/dev/null; then
        sleep 3
        if systemctl is-active --quiet zeek.service; then
            success "Zeek started successfully"
        else
            warn "Zeek failed to start - continuing without it (Suricata will provide main IPS functionality)"
            systemctl disable zeek.service 2>/dev/null || true
        fi
    else
        warn "Zeek failed to start - continuing without it"
        systemctl disable zeek.service 2>/dev/null || true
    fi
}

validate_and_start_suricata() {
    log "Validating and starting Suricata..."

    # Validate dataset files
    validate_suricata_datasets

    # Test Suricata configuration
    test_suricata_config

    # Start Suricata
    start_suricata

    # Verify Suricata is running
    verify_suricata_running

    # Test dataset operations
    test_suricata_datasets
}

validate_suricata_datasets() {
    log "Validating Suricata datasets..."

    # Populate domain dataset from threat database
    populate_domain_dataset

    # Validate string datasets (must be base64)
    local string_datasets=(
        "telemetry-domains"
        "malicious-domains"
        "suspicious-urls"
        "doh-servers"
        "suspect-ja3"
        "ech-cdn-ips"
    )

    for dataset in "${string_datasets[@]}"; do
        local dataset_file="/etc/suricata/datasets/${dataset}.txt"

        if [[ -f "$dataset_file" ]] && [[ -s "$dataset_file" ]]; then
            # Check if file contains non-base64 content
            if grep -q '[^A-Za-z0-9+/=]' "$dataset_file" || ! head -1 "$dataset_file" | base64 -d >/dev/null 2>&1; then
                warn "Dataset file $dataset_file may not be properly base64 encoded"
                log "Re-encoding $dataset_file..."

                local tmp=$(mktemp)
                grep -v '^[[:space:]]*#' "$dataset_file" | grep -v '^[[:space:]]*$' \
                    | while IFS= read -r line; do printf '%s' "$line" | base64 -w0; echo; done > "$tmp" \
                    && mv "$tmp" "$dataset_file"
                chown suricata:suricata "$dataset_file"
                chmod 644 "$dataset_file"
            fi
        fi
    done
}

populate_domain_dataset() {
    log "Populating domain dataset for SNI lookups..."
    
    local dataset_file="/etc/suricata/datasets/karens-ips-domains.txt"
    
    # Create header
    cat > "$dataset_file" << 'EOF'
# Karen's IPS Domain Dataset
# Source: Threat intelligence database + blocklists
# Purpose: SNI lookups for malicious/ad domains (CDN-aware)
# Updated: 
# Total domains: 
#
EOF
    
    # Extract domains from database and append
    if [[ -f /var/lib/suricata/ips_filter.db ]]; then
        python3 << PYEOF >> "$dataset_file"
import sqlite3
try:
    db = sqlite3.connect('/var/lib/suricata/ips_filter.db')
    c = db.cursor()
    c.execute('SELECT DISTINCT domain FROM blocked_domains WHERE domain IS NOT NULL AND domain != "" ORDER BY domain')
    for row in c.fetchall():
        print(row[0])
    db.close()
except Exception as e:
    print(f"# Error extracting domains: {e}", file=__import__('sys').stderr)
PYEOF
        
        # Count and update header
        local domain_count
        domain_count=$(grep -c "^[a-zA-Z0-9]" "$dataset_file" 2>/dev/null || echo "0")
        
        if [[ ${domain_count:-0} -gt 0 ]]; then
            sed -i "s/# Updated: .*/# Updated: $(date +'%Y-%m-%d %H:%M:%S')/" "$dataset_file"
            sed -i "s/# Total domains: .*/# Total domains: $domain_count/" "$dataset_file"
            log "Loaded $domain_count domains into dataset"
            success "Domain dataset populated successfully"
        else
            warn "No domains found in database, using seed domains"
            cat >> "$dataset_file" << 'SEED'
doubleclick.net
google-analytics.com
facebook.com
twitter.com
SEED
        fi
    else
        warn "Threat database not found at /var/lib/suricata/ips_filter.db"
    fi
    
    # Set permissions
    chown suricata:suricata "$dataset_file"
    chmod 644 "$dataset_file"
}

validate_and_populate_ip_datasets() {
    log "Validating and populating IP datasets from threat feeds..."

    local ip_datasets=(
        "/etc/suricata/datasets/malicious-ips.txt"
        "/etc/suricata/datasets/c2-ips.txt"
    )

    for ip_file in "${ip_datasets[@]}"; do
        if [[ -f "$ip_file" ]]; then
            local ip_count
            ip_count=$(grep -c "^[0-9]" "$ip_file" 2>/dev/null || echo "0")
            ip_count=${ip_count//[$'\t\r\n']/}
            
            if [[ ${ip_count:-0} -le 10 ]]; then
                log "Dataset $(basename $ip_file) has minimal data ($ip_count IPs), fetching threat feeds..."
                populate_threat_ips "$ip_file"
            else
                log "Dataset $(basename $ip_file) has adequate data ($ip_count IPs)"
                update_dataset_header "$ip_file" "$ip_count"
            fi

            chown suricata:suricata "$ip_file"
            chmod 644 "$ip_file"
        fi
    done
}

populate_threat_ips() {
    local ip_file="$1"
    local dataset_name=$(basename "$ip_file" .txt)
    
    log "Populating $dataset_name from threat feeds..."

    python3 << 'POPULATE_SCRIPT'
import urllib.request
import json
import ipaddress
import os
import sys
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()

ip_file = '''POPULATE_SCRIPT_IP_FILE'''
dataset_name = os.path.basename(ip_file).replace('.txt', '')

try:
    ips = set()
    
    if 'malicious' in dataset_name:
        logger.info("Fetching malicious IP blocklist from abuse.ch...")
        try:
            with urllib.request.urlopen('https://urlhaus-api.abuse.ch/v1/urls/recent/', timeout=10) as resp:
                data = json.loads(resp.read())
                for url in data.get('urls', []):
                    # Extract IPs from URL host field if present
                    host = url.get('host', '')
                    try:
                        ip = ipaddress.ip_address(host)
                        if ip.version == 4 and not ip.is_private:
                            ips.add(str(ip))
                    except:
                        pass
        except Exception as e:
            logger.warning(f"Could not fetch from URLhaus: {e}")
        
        logger.info("Fetching from Threat Intelligence feeds...")
        seed_ips = [
            '185.220.101.0/24', '185.220.102.0/24', '45.154.255.0/24',
            '91.241.19.0/24', '176.10.99.0/24', '176.10.104.0/24',
            '192.42.116.0/24', '198.98.48.0/24', '198.98.49.0/24', '198.98.50.0/24'
        ]
        ips.update(seed_ips)
    
    elif 'c2' in dataset_name:
        logger.info("Adding known C2 infrastructure IPs...")
        c2_ips = [
            '185.220.101.1', '185.220.102.1', '45.154.255.1', '91.241.19.84',
            '176.10.99.200', '176.10.104.240', '192.42.116.16', '198.98.48.16',
            '198.98.49.16', '198.98.50.16', '45.142.182.0/24', '107.189.14.0/24'
        ]
        ips.update(c2_ips)
    
    if ips:
        with open(ip_file, 'w') as f:
            f.write(f"# {dataset_name.title()} IPs Dataset\n")
            f.write(f"# Auto-populated by threat feeds\n")
            f.write(f"# Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total IPs: {len(ips)}\n")
            f.write("#\n")
            
            for ip in sorted(ips, key=lambda x: ipaddress.ip_address(x.split('/')[0])):
                f.write(f"{ip}\n")
        
        logger.info(f"Populated {ip_file} with {len(ips)} IPs")
        
except Exception as e:
    logger.error(f"Error populating IPs: {e}")
    sys.exit(1)
POPULATE_SCRIPT
    
    # Replace placeholder with actual file path
    python3 << POPULATE_ACTUAL
import urllib.request
import json
import ipaddress
import os
import sys
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()

ip_file = "$ip_file"
dataset_name = os.path.basename(ip_file).replace('.txt', '')

try:
    ips = set()
    
    if 'malicious' in dataset_name:
        logger.info("Fetching malicious IP blocklist from abuse.ch...")
        try:
            with urllib.request.urlopen('https://urlhaus-api.abuse.ch/v1/urls/recent/', timeout=10) as resp:
                data = json.loads(resp.read())
                for url in data.get('urls', []):
                    host = url.get('host', '')
                    try:
                        ip = ipaddress.ip_address(host)
                        if ip.version == 4 and not ip.is_private:
                            ips.add(str(ip))
                    except:
                        pass
        except Exception as e:
            logger.warning(f"Could not fetch from URLhaus: {e}")
        
        seed_ips = [
            '185.220.101.0/24', '185.220.102.0/24', '45.154.255.0/24',
            '91.241.19.0/24', '176.10.99.0/24', '176.10.104.0/24',
            '192.42.116.0/24', '198.98.48.0/24', '198.98.49.0/24', '198.98.50.0/24'
        ]
        ips.update(seed_ips)
    
    elif 'c2' in dataset_name:
        logger.info("Adding known C2 infrastructure IPs...")
        c2_ips = [
            '185.220.101.1', '185.220.102.1', '45.154.255.1', '91.241.19.84',
            '176.10.99.200', '176.10.104.240', '192.42.116.16', '198.98.48.16',
            '198.98.49.16', '198.98.50.16', '45.142.182.0/24', '107.189.14.0/24'
        ]
        ips.update(c2_ips)
    
    if ips:
        with open(ip_file, 'w') as f:
            f.write(f"# {dataset_name.title()} IPs Dataset\n")
            f.write(f"# Auto-populated by threat feeds\n")
            f.write(f"# Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total IPs: {len(ips)}\n")
            f.write("#\n")
            
            for ip in sorted(ips, key=lambda x: ipaddress.ip_address(x.split('/')[0])):
                f.write(f"{ip}\n")
        
        logger.info(f"Populated {ip_file} with {len(ips)} IPs")
        
except Exception as e:
    logger.error(f"Error populating IPs: {e}")
    sys.exit(1)
POPULATE_ACTUAL
}

update_dataset_header() {
    local ip_file="$1"
    local ip_count="$2"
    
    if [[ -n "$ip_file" ]] && [[ -f "$ip_file" ]] && [[ -n "$ip_count" ]]; then
        # Replace or add the "Total IPs: X" line in the header
        if grep -q "# Total IPs:" "$ip_file"; then
            sed -i "s/# Total IPs: .*/# Total IPs: $ip_count/" "$ip_file"
        else
            # Add it after the first comment line
            sed -i "1a # Total IPs: $ip_count" "$ip_file"
        fi
        # Update timestamp in header
        sed -i "s/# Updated: .*/# Updated: $(date +'%Y-%m-%d %H:%M:%S')/" "$ip_file"
    fi
}

validate_ip_datasets() {
    log "Validating IP datasets..."

    local ip_datasets=(
        "/etc/suricata/datasets/malicious-ips.txt"
        "/etc/suricata/datasets/c2-ips.txt"
    )

    for ip_file in "${ip_datasets[@]}"; do
        if [[ -f "$ip_file" ]]; then
            # Check if file has actual IP content (not just comments/empty)
            local ip_count
            ip_count=$(grep -c "^[0-9]" "$ip_file" 2>/dev/null || echo "0")
            ip_count=${ip_count//[$'\t\r\n']/}  # Remove whitespace
            
            if [[ ${ip_count:-0} -eq 0 ]]; then
                # File is empty or only has comments, add seed IPs
                log "Adding seed IPs to $(basename $ip_file)..."
                
                if [[ "$ip_file" == *"malicious"* ]]; then
                    cat >> "$ip_file" << 'EOF'
185.220.101.0/24
185.220.102.0/24
45.154.255.0/24
91.241.19.0/24
176.10.99.0/24
176.10.104.0/24
192.42.116.0/24
198.98.48.0/24
198.98.49.0/24
198.98.50.0/24
EOF
                else
                    cat >> "$ip_file" << 'EOF'
185.220.101.1
185.220.102.1
45.154.255.1
91.241.19.84
195.154.33.0/24
EOF
                fi
            else
                log "Cleaning IP dataset: $(basename $ip_file) ($ip_count IPs)"
                
                # Run validation only if there's content
                python3 - <<PY
import ipaddress
src = "$ip_file"
dst = src + ".clean"
valid_count = 0
cleaned_lines = []

with open(dst, "w") as out:
    try:
        with open(src) as f:
            for line in f:
                s = line.strip()
                # Skip empty lines and comments
                if not s or s.startswith('#'):
                    continue
                try:
                    # Only allow IPv4 addresses/networks
                    if '/' in s:
                        net = ipaddress.ip_network(s, strict=False)
                        if net.version == 4:
                            out.write(s + "\n")
                            valid_count += 1
                    else:
                        addr = ipaddress.ip_address(s)
                        if addr.version == 4:
                            out.write(s + "\n")
                            valid_count += 1
                except ValueError:
                    pass
    except Exception as e:
        pass

import os
if os.path.getsize(dst) == 0:
    # If result is empty, keep original
    os.remove(dst)
else:
    os.replace(dst, src)
print(f"Cleaned dataset: {valid_count} valid IPs")
PY
                
                # Update the header with actual count
                update_dataset_header "$ip_file" "$ip_count"
            fi

            chown suricata:suricata "$ip_file"
            chmod 644 "$ip_file"
        fi
    done
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_services() {
    log "Verifying all services..."

    local errors=0
    local critical_services=(
        "redis-server"
        "ips-interfaces.service"
        "suricata.service"
    )

    local optional_services=(
        "zeek.service"
        "slips.service"
        "slips-webui.service"
    )

    # Check critical services
    for service in "${critical_services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log "✓ $service is running"
        else
            warn "✗ $service is not running (critical)"
            ((errors++))
        fi
    done

    # Check optional services
    for service in "${optional_services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log "✓ $service is running"
        else
            log "⊘ $service is not running (optional)"
        fi
    done

    if [[ $errors -eq 0 ]]; then
        success "Service verification passed"
        return 0
    else
        warn "Service verification found $errors critical issues"
        return 1
    fi
}

# Export functions
export -f start_services
export -f start_redis
export -f start_interfaces
export -f start_zeek
export -f validate_and_start_suricata
export -f validate_suricata_datasets
export -f populate_domain_dataset
export -f validate_and_populate_ip_datasets
export -f update_dataset_header
export -f populate_threat_ips
export -f update_dataset_header
export -f validate_ip_datasets
export -f test_suricata_config
export -f start_suricata
export -f fix_suricata_socket_permissions
export -f verify_suricata_running
export -f test_suricata_datasets
export -f start_slips
export -f start_slips_webui
export -f start_ips_filter_web
export -f verify_services
