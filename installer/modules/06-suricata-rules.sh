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
#
# Initial seed IPs - known malicious infrastructure
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
MALICIOUS_IPS_EOF

    cat > "/etc/suricata/datasets/c2-ips.txt" << 'C2_IPS_EOF'
# Command & Control Server IPs Dataset  
# Auto-populated by: /usr/local/bin/extract-threat-ips.py
# Sources: Threat intelligence feeds, SLIPS C2 detections
# Updated by: ips-dataset-sync.timer (every 6 hours)
#
# Initial seed IPs - known C2 infrastructure
185.220.101.1
185.220.102.1
45.154.255.1
91.241.19.84
176.10.99.200
176.10.104.240
192.42.116.16
C2_IPS_EOF

    log "Created IP dataset files with automatic SQLite extraction system"
}

create_dataset_extraction_script() {
    log "Creating threat IP extraction script..."
    
    # First create comprehensive update script that handles the full chain
    create_comprehensive_update_script
    
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

create_comprehensive_update_script() {
    log "Creating comprehensive threat intelligence update script..."
    
    cat > /usr/local/bin/update-threat-intelligence.sh << 'UPDATE_SCRIPT_EOF'
#!/bin/bash
# Comprehensive Threat Intelligence Update Script
# Complete chain: Repos → SQLite → Suricata Datasets

set -euo pipefail

LOG_FILE="/var/log/threat-intelligence-update.log"
LOCK_FILE="/var/run/threat-intelligence-update.lock"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

# Check for lock file to prevent concurrent runs
if [[ -f "$LOCK_FILE" ]]; then
    log "Update already in progress (lock file exists), exiting"
    exit 0
fi

# Create lock file
echo $$ > "$LOCK_FILE"

# Cleanup function
cleanup() {
    rm -f "$LOCK_FILE"
}
trap cleanup EXIT

log "Starting comprehensive threat intelligence update"

# Step 1: Update blocklist repositories (if ips-filter-db.py exists)
if [[ -x "/opt/ips-filter-db.py" ]]; then
    log "Step 1: Updating blocklist repositories and SQLite database..."
    if /opt/ips-filter-db.py --db-path /var/lib/suricata/ips_filter.db --sync 2>&1 | tee -a "$LOG_FILE"; then
        log "Successfully updated SQLite database from repositories"
    else
        log "WARNING: Failed to update SQLite database from repositories"
        # Continue anyway - may have existing data
    fi
else
    log "WARNING: /opt/ips-filter-db.py not found, skipping repository update"
fi

# Step 2: Extract IPs from SQLite to Suricata datasets  
log "Step 2: Extracting threat IPs from SQLite to Suricata datasets..."
if /usr/local/bin/extract-threat-ips.py 2>&1 | tee -a "$LOG_FILE"; then
    log "Successfully extracted threat IPs to Suricata datasets"
else
    log "ERROR: Failed to extract IPs to datasets"
    exit 1
fi

# Step 3: Reload Suricata datasets (if Suricata is running)
if systemctl is-active --quiet suricata.service; then
    log "Step 3: Reloading Suricata to pick up new datasets..."
    if suricatasc -c "reload-rules" >/dev/null 2>&1; then
        log "Successfully reloaded Suricata rules and datasets"
    else
        log "WARNING: Failed to reload Suricata rules"
    fi
else
    log "Suricata not running, skipping rule reload"
fi

# Step 4: Show statistics
log "Step 4: Showing final statistics..."
if [[ -f "/etc/suricata/datasets/malicious-ips.txt" ]]; then
    malicious_count=$(grep -c "^[0-9]" /etc/suricata/datasets/malicious-ips.txt 2>/dev/null || echo "0")
    log "Malicious IPs dataset: $malicious_count entries"
fi

if [[ -f "/etc/suricata/datasets/c2-ips.txt" ]]; then
    c2_count=$(grep -c "^[0-9]" /etc/suricata/datasets/c2-ips.txt 2>/dev/null || echo "0")
    log "C2 IPs dataset: $c2_count entries"  
fi

log "Threat intelligence update completed successfully"
UPDATE_SCRIPT_EOF

    chmod +x /usr/local/bin/update-threat-intelligence.sh
    chown root:root /usr/local/bin/update-threat-intelligence.sh
    
    log "Created comprehensive update script: /usr/local/bin/update-threat-intelligence.sh"
}

verify_suricata_rules() {
    local errors=0
    
    # Check datasets directory
    if [[ ! -d /etc/suricata/datasets ]]; then
        warn "Datasets directory not found"
        ((errors++))
    fi
    
    # Check that dataset files exist (IP count validation is optional during install)
    for dataset in malicious-ips c2-ips; do
        local file="/etc/suricata/datasets/${dataset}.txt"
        if [[ -f "$file" ]]; then
            local ip_count=$(grep -c "^[0-9]" "$file" 2>/dev/null || echo "0")
            if [[ $ip_count -eq 0 ]]; then
                log "Dataset $dataset is empty ($ip_count IPs) - will be populated by timer or manual run"
            else
                log "Dataset $dataset contains $ip_count IPs"
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

extract_initial_threat_ips() {
    log_subsection "Initial Threat IP Extraction"
    
    log "Extracting threat IPs from SQLite database to populate Suricata datasets..."
    
    # Check if SQLite database exists
    if [[ ! -f "/var/lib/suricata/ips_filter.db" ]]; then
        warn "SQLite database not found - datasets will remain empty until first timer run"
        return 0
    fi
    
    # Check if extraction script exists
    if [[ ! -x "/usr/local/bin/extract-threat-ips.py" ]]; then
        warn "IP extraction script not found - datasets will remain empty"
        return 0
    fi
    
    # Run the extraction script to populate datasets
    log "Running initial threat IP extraction..."
    if /usr/local/bin/extract-threat-ips.py; then
        
        # Show results
        local malicious_count=0
        local c2_count=0
        
        if [[ -f "/etc/suricata/datasets/malicious-ips.txt" ]]; then
            malicious_count=$(grep -c "^[0-9]" "/etc/suricata/datasets/malicious-ips.txt" 2>/dev/null || echo "0")
        fi
        
        if [[ -f "/etc/suricata/datasets/c2-ips.txt" ]]; then
            c2_count=$(grep -c "^[0-9]" "/etc/suricata/datasets/c2-ips.txt" 2>/dev/null || echo "0")
        fi
        
        success "Threat IP extraction completed: $malicious_count malicious IPs, $c2_count C2 IPs"
        
    else
        warn "Failed to extract threat IPs - check logs"
        return 1
    fi
}

export -f update_suricata_rules verify_suricata_rules create_malicious_ip_datasets create_dataset_extraction_script create_comprehensive_update_script extract_initial_threat_ips
