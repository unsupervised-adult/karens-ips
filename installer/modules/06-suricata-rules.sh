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
    log "Creating IP dataset extraction and sync system..."
    
    # Create dataset extraction script that pulls IPs from SQLite
    create_dataset_extraction_script
    
    # Create initial empty dataset files with proper headers
    cat > "/etc/suricata/datasets/malicious-ips.txt" << 'MALICIOUS_IPS_EOF'
# Malicious IPs Dataset
# Auto-populated by: /usr/local/bin/extract-threat-ips.py
# Sources: Hagezi blocklists, Perflyst blocklists, SLIPS detections
# Updated by: ips-dataset-sync.timer (every 6 hours)
MALICIOUS_IPS_EOF

    cat > "/etc/suricata/datasets/c2-ips.txt" << 'C2_IPS_EOF'
# Command & Control Server IPs Dataset  
# Auto-populated by: /usr/local/bin/extract-threat-ips.py
# Sources: Threat intelligence feeds, SLIPS C2 detections
# Updated by: ips-dataset-sync.timer (every 6 hours)
C2_IPS_EOF

    log "Created IP dataset files with automatic SQLite extraction system"
}

create_dataset_extraction_script() {
    log "Creating threat IP extraction script..."
    
    cat > /usr/local/bin/extract-threat-ips.py << 'EXTRACT_SCRIPT_EOF'
#!/usr/bin/env python3
"""
Threat IP Extraction Script
Extracts IPs from Hagezi/Perflyst SQLite database and populates Suricata datasets
"""
import sqlite3
import ipaddress
import re
import os
import sys
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/extract-threat-ips.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('threat-ip-extractor')

class ThreatIPExtractor:
    def __init__(self, db_path='/var/lib/suricata/ips_filter.db'):
        self.db_path = db_path
        self.malicious_ips_file = '/etc/suricata/datasets/malicious-ips.txt'
        self.c2_ips_file = '/etc/suricata/datasets/c2-ips.txt'
        
    def extract_ips_from_domains(self):
        """Extract IP addresses from blocked domains in SQLite database"""
        if not os.path.exists(self.db_path):
            logger.warning(f"Database not found: {self.db_path}")
            return set(), set()
            
        malicious_ips = set()
        c2_ips = set()
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get all blocked domains
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            
            if 'domains' in tables:
                cursor.execute("SELECT domain, category FROM domains WHERE blocked = 1;")
                domains = cursor.fetchall()
                
                logger.info(f"Processing {len(domains)} blocked domains from database")
                
                for domain, category in domains:
                    # Extract IPs that might be embedded in domains or resolve them
                    ips = self.extract_ips_from_domain(domain)
                    
                    # Categorize based on domain category or patterns
                    if category and ('c2' in category.lower() or 'command' in category.lower()):
                        c2_ips.update(ips)
                    else:
                        malicious_ips.update(ips)
                        
            conn.close()
            
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
        except Exception as e:
            logger.error(f"Error extracting IPs: {e}")
            
        return malicious_ips, c2_ips
    
    def extract_ips_from_domain(self, domain):
        """Extract IP addresses from domain strings"""
        ips = set()
        
        # Look for IP addresses embedded in domain names
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        matches = re.findall(ip_pattern, domain)
        
        for match in matches:
            try:
                ip = ipaddress.ip_address(match)
                if not ip.is_private and not ip.is_loopback:
                    ips.add(str(ip))
            except ValueError:
                continue
                
        return ips
    
    def load_existing_dynamic_ips(self):
        """Load IPs that were dynamically added (not from blocklists)"""
        dynamic_malicious = set()
        dynamic_c2 = set()
        
        # Load existing files and extract non-blocklist IPs
        for ip_file, ip_set in [(self.malicious_ips_file, dynamic_malicious), 
                               (self.c2_ips_file, dynamic_c2)]:
            if os.path.exists(ip_file):
                try:
                    with open(ip_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                # Check if this looks like a dynamic IP (from SLIPS/Redis)
                                if self.is_valid_ip(line):
                                    ip_set.add(line)
                except Exception as e:
                    logger.warning(f"Error reading {ip_file}: {e}")
        
        return dynamic_malicious, dynamic_c2
    
    def is_valid_ip(self, ip_str):
        """Validate IP address"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return not ip.is_private and not ip.is_loopback
        except ValueError:
            return False
    
    def update_dataset_files(self):
        """Update Suricata dataset files with IPs from SQLite + dynamic IPs"""
        logger.info("Updating Suricata IP datasets...")
        
        # Extract IPs from blocklist database
        blocklist_malicious, blocklist_c2 = self.extract_ips_from_domains()
        
        # Load existing dynamic IPs (from SLIPS/Redis blocking)
        dynamic_malicious, dynamic_c2 = self.load_existing_dynamic_ips()
        
        # Combine blocklist and dynamic IPs
        all_malicious = blocklist_malicious | dynamic_malicious
        all_c2 = blocklist_c2 | dynamic_c2
        
        # Update malicious IPs file
        self.write_ip_file(self.malicious_ips_file, all_malicious, 
                          "Malicious IPs", "Hagezi/Perflyst blocklists + SLIPS detections")
        
        # Update C2 IPs file  
        self.write_ip_file(self.c2_ips_file, all_c2,
                          "Command & Control IPs", "Threat intelligence + SLIPS C2 detection")
        
        logger.info(f"Updated datasets: {len(all_malicious)} malicious IPs, {len(all_c2)} C2 IPs")
    
    def write_ip_file(self, filepath, ips, title, description):
        """Write IP addresses to dataset file"""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with open(filepath, 'w') as f:
                f.write(f"# {title} Dataset\n")
                f.write(f"# Source: {description}\n")
                f.write(f"# Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total IPs: {len(ips)}\n")
                f.write("#\n")
                
                for ip in sorted(ips):
                    f.write(f"{ip}\n")
            
            # Set proper permissions
            os.chown(filepath, 0, 0)  # root:root
            os.chmod(filepath, 0o644)
            
        except Exception as e:
            logger.error(f"Error writing {filepath}: {e}")

def main():
    extractor = ThreatIPExtractor()
    extractor.update_dataset_files()

if __name__ == '__main__':
    main()
EXTRACT_SCRIPT_EOF

    chmod +x /usr/local/bin/extract-threat-ips.py
    chown root:root /usr/local/bin/extract-threat-ips.py
    
    log "Created threat IP extraction script: /usr/local/bin/extract-threat-ips.py"
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

export -f update_suricata_rules verify_suricata_rules create_malicious_ip_datasets create_dataset_extraction_script
