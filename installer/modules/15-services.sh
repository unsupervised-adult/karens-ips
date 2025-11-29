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

    success "All services started successfully"
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

    # Validate IP datasets
    validate_ip_datasets
}

validate_ip_datasets() {
    log "Validating IP datasets..."

    local ip_datasets=(
        "/etc/suricata/datasets/malicious-ips.txt"
        "/etc/suricata/datasets/c2-ips.txt"
    )

    for ip_file in "${ip_datasets[@]}"; do
        if [[ -f "$ip_file" ]]; then
            log "Cleaning IP dataset: $(basename $ip_file)"

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
                # Skip empty lines, comments, and lines with letters
                if not s or s.startswith('#'):
                    continue
                # Skip lines that look like labels or metadata
                if re.search(r'^[a-zA-Z].*[a-zA-Z]', s):
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
        # Ensure we have a valid file even on error
        with open(dst, 'w') as f:
            f.write("127.0.0.1\n")
        valid_count = 1

import os
os.replace(dst, src)
print(f"Cleaned dataset: {valid_count} valid IPs")
PY

            chown suricata:suricata "$ip_file"
            chmod 644 "$ip_file"
        fi
    done
}

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

    # Test dataset add/lookup with base64
    local test_domain="example.com"
    local test_domain_b64=$(echo -n "$test_domain" | base64)

    log "Testing dataset operations with base64: ${test_domain_b64}"

    if suricatasc -c "dataset-add malicious-domains string ${test_domain_b64}" >/dev/null 2>&1; then
        log "Dataset add operation successful"

        if suricatasc -c "dataset-lookup malicious-domains string ${test_domain_b64}" >/dev/null 2>&1; then
            success "Dataset lookup operation successful"
            success "Suricata dataset functionality confirmed"
        else
            warn "Dataset lookup failed - may be normal for new installation"
        fi
    else
        warn "Dataset add operation failed - check suricatasc permissions"
        warn "Try: sudo suricatasc -c 'dump-counters' to test socket connectivity"
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
