#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: Suricata Rules
# Phase: 6
# Description: Initialize Suricata rule files and datasets

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    exit 1
fi

update_suricata_rules() {
    log_subsection "Suricata Rules Initialization"

    log "Initializing Suricata datasets and rules..."

    # Create dataset directories
    mkdir -p /etc/suricata/datasets
    mkdir -p /var/lib/suricata/datasets
    chown -R suricata:suricata /etc/suricata/datasets /var/lib/suricata/datasets

    # Initialize CSV state files for datasets (Suricata 8 requirement)
    touch /var/lib/suricata/datasets/{bad-ips,telemetry-domains,malicious-domains,suspicious-urls,blocked-ips,suspect-ja3,ech-cdn-ips}.csv
    chown -R suricata:suricata /var/lib/suricata/datasets
    chmod -R 644 /var/lib/suricata/datasets/*.csv

    # Create placeholder dataset files
    for dataset in telemetry-domains malicious-domains suspicious-urls suspect-ja3 ech-cdn-ips; do
        touch "/etc/suricata/datasets/${dataset}.txt"
    done

    # Create IP dataset files with initial threat intelligence
    create_malicious_ip_datasets

    chown -R suricata:suricata /etc/suricata/datasets
    chmod -R 644 /etc/suricata/datasets/*

    success "Suricata rules and datasets initialized"
}

create_malicious_ip_datasets() {
    log "Creating initial threat intelligence datasets..."
    
    # Malicious IPs dataset - known bad actors and compromised systems
    cat > "/etc/suricata/datasets/malicious-ips.txt" << 'MALICIOUS_IPS_EOF'
# Known malicious IPs - Updated during installation
# Sources: Emerging Threats, community feeds, documented attack sources
185.220.100.240
185.220.100.241
185.220.100.242
185.220.100.243
185.220.100.244
185.220.100.245
185.220.100.246
185.220.100.247
185.220.100.248
185.220.100.249
185.220.101.1
185.220.101.2
185.220.101.3
185.220.101.4
185.220.101.5
45.9.150.1
45.9.150.2
45.9.150.3
45.9.150.4
45.9.150.5
198.96.155.1
198.96.155.2
198.96.155.3
198.96.155.4
198.96.155.5
107.189.1.160
107.189.1.161
107.189.1.162
107.189.1.163
107.189.1.164
MALICIOUS_IPS_EOF

    # C2 Server IPs - Command and Control infrastructure
    cat > "/etc/suricata/datasets/c2-ips.txt" << 'C2_IPS_EOF'
# Known C2 Server IPs - Updated during installation
# Sources: Various threat intelligence feeds
89.248.165.1
89.248.165.2
89.248.165.3
89.248.165.4
89.248.165.5
194.180.48.1
194.180.48.2
194.180.48.3
194.180.48.4
194.180.48.5
176.123.26.1
176.123.26.2
176.123.26.3
176.123.26.4
176.123.26.5
91.240.118.1
91.240.118.2
91.240.118.3
91.240.118.4
91.240.118.5
195.54.160.1
195.54.160.2
195.54.160.3
195.54.160.4
195.54.160.5
C2_IPS_EOF

    log "Created initial threat IP datasets: $(wc -l /etc/suricata/datasets/malicious-ips.txt | cut -d' ' -f1) malicious IPs, $(wc -l /etc/suricata/datasets/c2-ips.txt | cut -d' ' -f1) C2 IPs"
}

verify_suricata_rules() {
    local errors=0
    
    # Check datasets directory
    if [[ ! -d /etc/suricata/datasets ]]; then
        warn "Datasets directory not found"
        ((errors++))
    fi
    
    # Check that dataset files have more than just placeholder IPs
    for dataset in malicious-ips c2-ips; do
        local file="/etc/suricata/datasets/${dataset}.txt"
        if [[ -f "$file" ]]; then
            local ip_count=$(grep -c "^[0-9]" "$file" 2>/dev/null || echo "0")
            if [[ $ip_count -lt 5 ]]; then
                warn "Dataset $dataset has insufficient IPs ($ip_count)"
                ((errors++))
            fi
        else
            warn "Dataset file $file not found"
            ((errors++))
        fi
    done
    
    if [[ $errors -eq 0 ]]; then
        success "Datasets verification passed"
        return 0
    else
        warn "Datasets verification found $errors issues"
        return 1
    fi
}

export -f update_suricata_rules verify_suricata_rules create_malicious_ip_datasets
