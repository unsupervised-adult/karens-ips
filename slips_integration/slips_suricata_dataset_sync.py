#!/usr/bin/env python3
"""
SLIPS ↔ Suricata Dataset Synchronization
Bidirectional sync between SLIPS behavioral detections and Suricata datasets

SLIPS Blocking Flow:
1. SLIPS detects malicious behavior (C&C, port scans, malware)
2. Evidence accumulates → Alert triggered → Blocking request
3. This script captures blocking requests from Redis
4. Adds malicious IPs to Suricata dataset: /var/lib/suricata/datasets/slips-blocked-ips.lst
5. Suricata rules drop traffic matching dataset entries
6. nftables blocked4 set also blocks at kernel level (dual-layer blocking)

Suricata → SLIPS Flow:
1. Suricata detects signature matches (ET rules, TrafficID)
2. EVE JSON logs contain malicious IPs
3. This script reads eve.json for high-priority alerts
4. Notifies SLIPS about malicious IPs via Redis
5. SLIPS correlates with behavioral analysis
6. Combined confidence → More accurate blocking decisions

Dataset Structure:
/var/lib/suricata/datasets/
├── slips-blocked-ips.lst      # IPs blocked by SLIPS behavioral analysis
├── blocked-domains.lst         # Domains from blocklist DB (existing)
└── suricata-detected-ips.lst   # IPs from Suricata signature hits (new)
"""

import redis
import json
import time
import os
import base64
from datetime import datetime
from collections import defaultdict
import subprocess

class SLIPSSuricataSync:
    def __init__(self):
        # Connect to SLIPS Redis (DB 0)
        self.r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
        
        # Dataset paths
        self.slips_blocked_dataset = '/var/lib/suricata/datasets/slips-blocked-ips.lst'
        self.suricata_detected_dataset = '/var/lib/suricata/datasets/suricata-detected-ips.lst'
        
        # Stats
        self.stats = {
            'slips_to_suricata': 0,
            'suricata_to_slips': 0,
            'dataset_entries': 0,
            'slips_blocks': 0
        }
        
        # Track processed IPs to avoid duplicates
        self.slips_blocked_ips = set()
        self.suricata_detected_ips = set()
        
        # Load existing datasets
        self._load_existing_datasets()
        
        # Initialize datasets if needed
        self._init_datasets()
        
        print(f"✅ SLIPS ↔ Suricata Dataset Sync initialized")
        print(f"   SLIPS blocked IPs: {len(self.slips_blocked_ips)}")
        print(f"   Suricata detected IPs: {len(self.suricata_detected_ips)}")

    def _load_existing_datasets(self):
        """Load existing dataset files into memory"""
        if os.path.exists(self.slips_blocked_dataset):
            with open(self.slips_blocked_dataset, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            ip = base64.b64decode(line).decode('utf-8').strip().strip('"')
                            self.slips_blocked_ips.add(ip)
                        except:
                            pass
        
        if os.path.exists(self.suricata_detected_dataset):
            with open(self.suricata_detected_dataset, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            ip = base64.b64decode(line).decode('utf-8').strip().strip('"')
                            self.suricata_detected_ips.add(ip)
                        except:
                            pass

    def _init_datasets(self):
        """Initialize dataset files if they don't exist"""
        os.makedirs(os.path.dirname(self.slips_blocked_dataset), exist_ok=True)
        
        # Create empty dataset files without comments (Suricata parses all lines as data)
        if not os.path.exists(self.slips_blocked_dataset):
            with open(self.slips_blocked_dataset, 'w') as f:
                pass  # Empty file
        
        if not os.path.exists(self.suricata_detected_dataset):
            with open(self.suricata_detected_dataset, 'w') as f:
                pass  # Empty file

    def _is_private_ip(self, ip):
        """Check if IP is RFC1918 private or non-routable"""
        try:
            octets = [int(x) for x in ip.split('.')]
            if len(octets) != 4:
                return True
            
            # RFC1918 private
            if octets[0] == 10:
                return True
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            if octets[0] == 192 and octets[1] == 168:
                return True
            
            # Loopback, link-local, multicast
            if octets[0] in [127, 169] or octets[0] >= 224:
                return True
            
            return False
        except (ValueError, IndexError):
            return True

    def add_ip_to_dataset(self, ip, dataset_file, ip_set):
        """Add IP to dataset file (base64 encoded) and memory set"""
        if not ip or self._is_private_ip(ip):
            return False
        
        if ip in ip_set:
            return False
        
        try:
            # Encode IP as base64 for Suricata dataset format
            encoded_ip = base64.b64encode(f'"{ip}"'.encode('utf-8')).decode('utf-8')
            
            with open(dataset_file, 'a') as f:
                f.write(f'{encoded_ip}\n')
            
            ip_set.add(ip)
            return True
        except Exception as e:
            print(f"⚠️  Error adding {ip} to dataset: {e}")
            return False

    def sync_slips_blocks_to_suricata(self):
        """
        Monitor SLIPS blocking decisions and add to Suricata dataset
        Subscribes to SLIPS new_blocking channel
        """
        pubsub = self.r.pubsub()
        pubsub.subscribe('new_blocking')
        
        print("📡 Monitoring SLIPS blocking decisions...")
        
        for message in pubsub.listen():
            if message['type'] == 'message':
                try:
                    data = json.loads(message['data'])
                    ip = data.get('ip')
                    block = data.get('block', False)
                    
                    if block and ip:
                        if self.add_ip_to_dataset(ip, self.slips_blocked_dataset, self.slips_blocked_ips):
                            self.stats['slips_to_suricata'] += 1
                            self.stats['dataset_entries'] = len(self.slips_blocked_ips)
                            print(f"✅ SLIPS → Suricata dataset: {ip} (total: {len(self.slips_blocked_ips)})")
                            
                            # Update stats in Redis for dashboard
                            self.r.hincrby('slips_suricata_sync:stats', 'slips_to_suricata', 1)
                            self.r.hset('slips_suricata_sync:stats', 'dataset_size', len(self.slips_blocked_ips))
                            self.r.hset('slips_suricata_sync:stats', 'last_sync', datetime.now().isoformat())
                
                except Exception as e:
                    print(f"⚠️  Error processing SLIPS block: {e}")

    def parse_suricata_eve_alerts(self):
        """
        Monitor Suricata EVE JSON for high-priority alerts
        Extract malicious IPs and add to dataset for SLIPS correlation
        """
        eve_file = '/var/log/suricata/eve.json'
        
        if not os.path.exists(eve_file):
            print(f"⚠️  Suricata EVE log not found: {eve_file}")
            return
        
        print("📡 Monitoring Suricata EVE alerts...")
        
        # Tail the EVE log
        cmd = f"tail -F {eve_file}"
        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        for line in process.stdout:
            try:
                line = line.decode('utf-8').strip()
                if not line:
                    continue
                
                event = json.loads(line)
                
                # Only process alerts
                if event.get('event_type') != 'alert':
                    continue
                
                alert = event.get('alert', {})
                severity = alert.get('severity', 3)
                
                # High priority alerts only (severity 1-2)
                if severity > 2:
                    continue
                
                # Extract source and dest IPs
                src_ip = event.get('src_ip')
                dest_ip = event.get('dest_ip')
                
                # Add external IPs to dataset
                for ip in [src_ip, dest_ip]:
                    if ip and not self._is_private_ip(ip):
                        if self.add_ip_to_dataset(ip, self.suricata_detected_dataset, self.suricata_detected_ips):
                            self.stats['suricata_to_slips'] += 1
                            print(f"✅ Suricata → Dataset: {ip} (severity {severity})")
                            
                            # Notify SLIPS about this IP for correlation
                            self._notify_slips_about_malicious_ip(ip, alert)
            
            except Exception as e:
                continue

    def _notify_slips_about_malicious_ip(self, ip, alert_data):
        """
        Notify SLIPS about Suricata-detected malicious IP
        SLIPS can correlate this with behavioral analysis
        """
        try:
            notification = {
                'ip': ip,
                'source': 'suricata',
                'signature': alert_data.get('signature', 'Unknown'),
                'category': alert_data.get('category', 'Unknown'),
                'severity': alert_data.get('severity', 3),
                'timestamp': datetime.now().isoformat()
            }
            
            # Store in Redis for SLIPS modules to consume
            self.r.lpush('suricata_detections', json.dumps(notification))
            self.r.ltrim('suricata_detections', 0, 999)  # Keep last 1000
            
            # Update stats
            self.r.hincrby('slips_suricata_sync:stats', 'suricata_to_slips', 1)
        
        except Exception as e:
            print(f"⚠️  Error notifying SLIPS: {e}")

    def generate_suricata_rules(self):
        """
        Generate Suricata rules that use the SLIPS blocked IPs dataset
        Creates rules for dataset:isset matching
        """
        rules_file = '/var/lib/suricata/rules/slips-integration.rules'
        
        rules_content = """# SLIPS ↔ Suricata Integration Rules
# Auto-generated by slips_suricata_dataset_sync.py

# Drop traffic from SLIPS-blocked IPs (behavioral analysis)
drop ip $EXTERNAL_NET any -> $HOME_NET any (msg:"SLIPS Blocked IP (Behavioral)"; ip.src; dataset:isset,slips-blocked-ips,type ip,load ../datasets/slips-blocked-ips.lst; classtype:trojan-activity; sid:9000001; rev:1; priority:1;)
drop ip $HOME_NET any -> $EXTERNAL_NET any (msg:"SLIPS Blocked IP Destination"; ip.dst; dataset:isset,slips-blocked-ips,type ip,load ../datasets/slips-blocked-ips.lst; classtype:trojan-activity; sid:9000002; rev:1; priority:1;)

# Alert on Suricata-detected IPs correlated with SLIPS
alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"Suricata + SLIPS Correlated Threat"; ip.src; dataset:isset,suricata-detected-ips,type ip,load ../datasets/suricata-detected-ips.lst; classtype:trojan-activity; sid:9000003; rev:1; priority:1;)
"""
        
        try:
            os.makedirs(os.path.dirname(rules_file), exist_ok=True)
            with open(rules_file, 'w') as f:
                f.write(rules_content)
            print(f"✅ Generated Suricata integration rules: {rules_file}")
        except Exception as e:
            print(f"⚠️  Error generating rules: {e}")

    def print_stats(self):
        """Print sync statistics"""
        print("\n📊 SLIPS ↔ Suricata Sync Statistics")
        print(f"   SLIPS → Suricata: {self.stats['slips_to_suricata']} IPs")
        print(f"   Suricata → SLIPS: {self.stats['suricata_to_slips']} IPs")
        print(f"   Dataset entries: {self.stats['dataset_entries']}")
        print(f"   SLIPS blocks: {len(self.slips_blocked_ips)}")

    def run(self):
        """Main sync loop - monitors both SLIPS and Suricata"""
        import threading
        
        # Generate Suricata rules
        self.generate_suricata_rules()
        
        # Start SLIPS blocking monitor in thread
        slips_thread = threading.Thread(target=self.sync_slips_blocks_to_suricata, daemon=True)
        slips_thread.start()
        
        # Start Suricata EVE monitor in main thread
        try:
            self.parse_suricata_eve_alerts()
        except KeyboardInterrupt:
            print("\n🛑 Shutting down sync service...")
            self.print_stats()


if __name__ == '__main__':
    sync = SLIPSSuricataSync()
    sync.run()
