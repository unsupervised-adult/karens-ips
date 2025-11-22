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

    # Create IP dataset files
    for dataset in malicious-ips c2-ips; do
        echo "127.0.0.1" > "/etc/suricata/datasets/${dataset}.txt"
    done

    chown -R suricata:suricata /etc/suricata/datasets
    chmod -R 644 /etc/suricata/datasets/*

    success "Suricata rules and datasets initialized"
}

verify_suricata_rules() {
    [[ -d /etc/suricata/datasets ]] && success "Datasets directory verified" && return 0 || { warn "Datasets directory not found"; return 1; }
}

export -f update_suricata_rules verify_suricata_rules
