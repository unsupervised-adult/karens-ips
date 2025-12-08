#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: nftables Configuration
# Phase: 3
# Description: Set up nftables for host protection and NFQUEUE integration

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ============================================================================
# NFTABLES SETUP
# ============================================================================

setup_nftables_blocking() {
    log_subsection "nftables Host Protection and NFQUEUE Integration"

    # Check if nftables setup is enabled
    if [[ "${SETUP_NFTABLES:-true}" != "true" ]]; then
        log "nftables setup disabled, skipping"
        return 0
    fi

    log "Setting up nftables for host protection and SLIPS integration..."

    # Install nftables
    install_nftables

    # Create nftables configuration
    create_nftables_config

    # Load configuration
    load_nftables_config

    # Enable nftables service
    enable_nftables_service

    success "nftables host protection configured"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

install_nftables() {
    log "Installing nftables..."

    if ! command -v nft >/dev/null 2>&1; then
        wait_for_apt_lock
        apt-get install -y nftables || error_exit "Failed to install nftables"
        success "nftables installed"
    else
        log "nftables already installed"
    fi
}

create_nftables_config() {
    log "Creating nftables configuration..."

    # Create configuration directory
    mkdir -p /etc/nftables.d

    # Create IPS blocking sets configuration
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
    }

    chain output_filter {
        type filter hook output priority 0; policy accept;
    }

    # NFQUEUE chain for bridge traffic inspection (IPS mode)
    chain forward_ips {
        type filter hook forward priority 0; policy accept;

        # Block malicious IPs on bridge traffic only (not management)
        iifname "br0" ip saddr @blocked4 counter drop comment "Block malicious sources on bridge";
        oifname "br0" ip daddr @blocked4 counter drop comment "Block malicious destinations on bridge";

        # Send remaining bridge traffic to Suricata nfqueue
        iifname "br0" counter queue num 0 bypass comment "Send bridge traffic to Suricata IPS";
        oifname "br0" counter queue num 0 bypass comment "Send bridge traffic to Suricata IPS";
    }
}
NFT_CONFIG_EOF

    chmod +x /etc/nftables.d/ips-blocksets.nft
    success "nftables configuration created"
}

load_nftables_config() {
    log "Loading nftables configuration..."

    if nft -f /etc/nftables.d/ips-blocksets.nft; then
        success "nftables configuration loaded"
    else
        error_exit "Failed to load nftables configuration"
    fi

    # Save ruleset for persistence
    nft list ruleset > /etc/nftables.conf
}

enable_nftables_service() {
    log "Enabling nftables service..."

    if systemctl enable nftables; then
        success "nftables service enabled"
    else
        warn "Failed to enable nftables service"
    fi
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_nftables() {
    log "Verifying nftables configuration..."

    local errors=0

    # Check if nft command exists
    if ! command -v nft >/dev/null 2>&1; then
        warn "nft command not found"
        ((errors++))
    fi

    # Check if configuration file exists
    if [[ ! -f /etc/nftables.d/ips-blocksets.nft ]]; then
        warn "nftables configuration file not found"
        ((errors++))
    fi

    # Check if nftables service is enabled
    if ! systemctl is-enabled --quiet nftables 2>/dev/null; then
        warn "nftables service not enabled"
        ((errors++))
    fi

    # Check if blocked4 set exists
    if nft list set inet home blocked4 >/dev/null 2>&1; then
        log "blocked4 set exists"
    else
        warn "blocked4 set not found"
        ((errors++))
    fi

    if [[ $errors -eq 0 ]]; then
        success "nftables verification passed"
        return 0
    else
        warn "nftables verification found $errors issues"
        return 1
    fi
}

install_active_blocking() {
    log_subsection "Active Threat Blocking Setup"
    
    if [[ "${SETUP_ACTIVE_BLOCKING:-true}" != "true" ]]; then
        log "Active blocking setup disabled, skipping"
        return 0
    fi
    
    log "Setting up automatic threat blocking integration..."
    
    # Create SLIPS blocking script
    create_slips_blocking_script
    
    # Create suricatasc blocking script  
    create_suricatasc_blocking_script
    
    # Set up Redis-based blocking automation
    create_redis_blocking_automation
    
    # Configure sudo permissions for blocking scripts
    configure_blocking_permissions
    
    success "Active threat blocking configured"
}

create_slips_blocking_script() {
    log "Creating SLIPS threat blocking script..."
    
    cat > /usr/local/bin/slips-block-threat.sh << 'SLIPS_BLOCK_EOF'
#!/bin/bash
# SLIPS Threat Blocking Script
# Called when SLIPS detects high-confidence threats

IP="$1"
REASON="$2"
CONFIDENCE="${3:-0.8}"

# Validate IP address format
if [[ ! "$IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "Invalid IP address: $IP" >&2
    exit 1
fi

# Skip private/local RFC addresses
if [[ "$IP" =~ ^10\. ]] || \
   [[ "$IP" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || \
   [[ "$IP" =~ ^192\.168\. ]] || \
   [[ "$IP" =~ ^127\. ]] || \
   [[ "$IP" =~ ^169\.254\. ]] || \
   [[ "$IP" =~ ^22[4-9]\. ]] || \
   [[ "$IP" =~ ^23[0-9]\. ]]; then
    logger -t slips-blocking "Skipping private/local IP: $IP"
    echo "Skipping private/local IP: $IP"
    exit 0
fi

# Block IP in nftables
logger -t slips-blocking "Blocking IP $IP (confidence: $CONFIDENCE, reason: $REASON)"

# Add to blocked4 set
nft add element inet filter blocked4 { $IP } 2>/dev/null || {
    echo "Failed to add $IP to nftables blocked set" >&2
    exit 1
}

# Also add to Suricata datasets for detection enhancement
echo "$IP" | base64 -w 0 | xargs -I {} suricatasc -c "dataset-add malicious-ips ip {}" 2>/dev/null

# Log successful blocking
logger -t slips-blocking "Successfully blocked IP $IP"
echo "IP $IP blocked successfully"
SLIPS_BLOCK_EOF

    chmod +x /usr/local/bin/slips-block-threat.sh
    chown root:root /usr/local/bin/slips-block-threat.sh
}

create_suricatasc_blocking_script() {
    log "Creating Suricata dataset blocking script..."
    
    cat > /usr/local/bin/suricata-block-ip.sh << 'SURICATA_BLOCK_EOF'
#!/bin/bash
# Suricata Dynamic IP Blocking Script

IP="$1"
DATASET="${2:-malicious-ips}"

if [[ -z "$IP" ]]; then
    echo "Usage: $0 <IP> [dataset_name]" >&2
    exit 1
fi

# Validate IP format
if [[ ! "$IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "Invalid IP address: $IP" >&2
    exit 1
fi

# Skip private/local RFC addresses
if [[ "$IP" =~ ^10\. ]] || \
   [[ "$IP" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || \
   [[ "$IP" =~ ^192\.168\. ]] || \
   [[ "$IP" =~ ^127\. ]] || \
   [[ "$IP" =~ ^169\.254\. ]] || \
   [[ "$IP" =~ ^22[4-9]\. ]] || \
   [[ "$IP" =~ ^23[0-9]\. ]]; then
    logger -t suricata-blocking "Skipping private/local IP: $IP"
    echo "Skipping private/local IP: $IP"
    exit 0
fi

# Encode IP for suricatasc
ENCODED_IP=$(echo "$IP" | base64 -w 0)

# Add to Suricata dataset
if suricatasc -c "dataset-add $DATASET ip $ENCODED_IP" >/dev/null 2>&1; then
    logger -t suricata-blocking "Added $IP to dataset $DATASET"
    echo "IP $IP added to Suricata dataset $DATASET"
else
    echo "Failed to add $IP to Suricata dataset $DATASET" >&2
    exit 1
fi
SURICATA_BLOCK_EOF

    chmod +x /usr/local/bin/suricata-block-ip.sh
    chown root:root /usr/local/bin/suricata-block-ip.sh
}

create_redis_blocking_automation() {
    log "Creating Redis-based blocking automation..."
    
    # Create Python script that monitors Redis for SLIPS alerts and blocks threats
    cat > /usr/local/bin/redis-threat-blocker.py << 'REDIS_BLOCKER_EOF'
#!/usr/bin/env python3
"""
Redis Threat Blocker
Monitors SLIPS alerts in Redis and automatically blocks high-confidence threats
"""
import redis
import json
import subprocess
import time
import logging
import signal
import sys
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/redis-threat-blocker.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('threat-blocker')

class ThreatBlocker:
    def __init__(self, redis_host='localhost', redis_port=6379):
        self.redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
        self.blocked_ips = set()
        self.running = True
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)
        
    def shutdown(self, signum, frame):
        logger.info("Shutting down threat blocker...")
        self.running = False
        
    def block_ip(self, ip_address, reason, confidence):
        """Block an IP address using multiple methods"""
        if ip_address in self.blocked_ips:
            logger.debug(f"IP {ip_address} already blocked")
            return
            
        try:
            # Use SLIPS blocking script
            result = subprocess.run([
                '/usr/local/bin/slips-block-threat.sh',
                ip_address, reason, str(confidence)
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.blocked_ips.add(ip_address)
                logger.info(f"Successfully blocked {ip_address} (reason: {reason}, confidence: {confidence})")
            else:
                logger.error(f"Failed to block {ip_address}: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout blocking {ip_address}")
        except Exception as e:
            logger.error(f"Error blocking {ip_address}: {e}")
    
    def process_slips_alerts(self):
        """Process SLIPS alerts from Redis"""
        try:
            # Check for new evidence 
            for key in self.redis_client.scan_iter(match="profile_*_evidence"):
                evidence_data = self.redis_client.hgetall(key)
                for evidence_id, evidence_json in evidence_data.items():
                    try:
                        evidence = json.loads(evidence_json)
                        threat_level = evidence.get('threat_level', 'low')
                        confidence = evidence.get('confidence', 0.0)
                        
                        # Block high-confidence threats
                        if threat_level in ['high', 'critical'] or confidence > 0.8:
                            attacker = evidence.get('attacker', {})
                            ip = attacker.get('value', '')
                            description = evidence.get('description', 'SLIPS detection')
                            
                            if ip and self.is_valid_ip(ip):
                                self.block_ip(ip, description, confidence)
                                
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            logger.error(f"Error processing SLIPS alerts: {e}")
    
    def process_ml_alerts(self):
        """Process ML detector alerts from Redis"""
        try:
            # Check ML detector alerts
            alerts = self.redis_client.lrange('ml_detector:alerts', 0, -1)
            for alert_json in alerts:
                try:
                    alert = json.loads(alert_json)
                    if alert.get('severity') in ['high', 'critical']:
                        ip = alert.get('source_ip', '')
                        description = alert.get('description', 'ML detection')
                        
                        if ip and self.is_valid_ip(ip):
                            self.block_ip(ip, f"ML: {description}", 0.85)
                            
                except json.JSONDecodeError:
                    continue
                    
        except Exception as e:
            logger.error(f"Error processing ML alerts: {e}")
            
    def is_private_ip(self, ip):
        """Check if IP is RFC1918 private or non-routable"""
        try:
            parts = [int(x) for x in ip.split('.')]
            if len(parts) != 4:
                return True
            
            # RFC1918 private
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            
            # Loopback, link-local, multicast
            if parts[0] in [127, 169] or parts[0] >= 224:
                return True
                
            return False
        except (ValueError, IndexError):
            return True
    
    def is_valid_ip(self, ip):
        """Validate IP address format and ensure it's not private"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            if not all(0 <= int(part) <= 255 for part in parts):
                return False
            return not self.is_private_ip(ip)
        except ValueError:
            return False
    
    def run(self):
        """Main blocking loop"""
        logger.info("Starting Redis threat blocker...")
        
        while self.running:
            try:
                self.process_slips_alerts()
                self.process_ml_alerts()
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(30)
                
        logger.info("Threat blocker stopped")

if __name__ == '__main__':
    blocker = ThreatBlocker()
    blocker.run()
REDIS_BLOCKER_EOF

    chmod +x /usr/local/bin/redis-threat-blocker.py
    chown root:root /usr/local/bin/redis-threat-blocker.py
}

configure_blocking_permissions() {
    log "Configuring sudo permissions for blocking scripts..."
    
    # Allow specific users to run blocking scripts without password
    cat > /etc/sudoers.d/karens-ips-blocking << 'SUDO_EOF'
# Karen's IPS Blocking Permissions
%sudo ALL=(root) NOPASSWD: /usr/local/bin/slips-block-threat.sh
%sudo ALL=(root) NOPASSWD: /usr/local/bin/suricata-block-ip.sh
%sudo ALL=(root) NOPASSWD: /usr/local/bin/redis-threat-blocker.py
%sudo ALL=(root) NOPASSWD: /usr/sbin/nft add element inet filter blocked4 *
%sudo ALL=(root) NOPASSWD: /usr/bin/suricatasc
SUDO_EOF

    chmod 440 /etc/sudoers.d/karens-ips-blocking

    # Validate sudoers file to prevent syntax errors from breaking sudo
    if visudo -c -f /etc/sudoers.d/karens-ips-blocking >/dev/null 2>&1; then
        success "Sudoers file validated successfully"
    else
        error_exit "Sudoers file validation failed - syntax error detected. Removing invalid file."
        rm -f /etc/sudoers.d/karens-ips-blocking
    fi

    # Fix suricatasc socket permissions (only if socket exists)
    if [[ -S /var/run/suricata/suricata.socket ]]; then
        chmod 666 /var/run/suricata/suricata.socket
    fi
}

# Export functions
export -f setup_nftables_blocking
export -f install_nftables
export -f create_nftables_config
export -f load_nftables_config
export -f enable_nftables_service
export -f verify_nftables
export -f install_active_blocking
export -f create_slips_blocking_script
export -f create_suricatasc_blocking_script
export -f create_redis_blocking_automation
export -f configure_blocking_permissions
