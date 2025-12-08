#!/usr/bin/env python3
"""
Dynamic IP Blocker for ML Detections
Monitors Redis for ML detections and updates Suricata dataset (no reload needed)
Uses Suricata's dataset feature for zero-downtime IP blocking
"""
import redis
import json
import time
import subprocess
import os
from datetime import datetime, timedelta
from collections import defaultdict

class DynamicRuleGenerator:
    def __init__(self):
        self.r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
        self.blocked_ips_file = '/var/lib/suricata/ml-blocked-ips.txt'
        self.rules_file = '/etc/suricata/rules/ml-dynamic-blocks.rules'
        self.confidence_threshold = 0.70
        self.active_blocks = {}
        self.processed_detections = set()
        self.last_cleanup = datetime.now()
        self.cleanup_interval = timedelta(hours=1)
        self.block_max_age = timedelta(hours=24)
        
        self.initialize_dataset_rule()
        self.initialize_blocked_ips_file()
        
    def initialize_dataset_rule(self):
        """Create single rule that checks dataset - no reloads needed when IPs change"""
        try:
            os.makedirs(os.path.dirname(self.rules_file), exist_ok=True)
            
            rule = (
                f"drop ip any any -> $HOME_NET any "
                f"(msg:\"ML-Dynamic: Block ad traffic from dataset\"; "
                f"ip.src; dataset:isset,ml-blocked-ips,type ip,state {self.blocked_ips_file}; "
                f"priority:1; "
                f"sid:8000000; "
                f"rev:1;)"
            )
            
            with open(self.rules_file, 'w') as f:
                f.write("# ML Dynamic Blocks - Dataset Rule\n")
                f.write("# This rule uses a dataset that auto-reloads from file\n")
                f.write("# No Suricata reload required when IPs are added/removed\n\n")
                f.write(rule + '\n')
            
            subprocess.run(['sudo', 'chmod', '644', self.rules_file], check=False)
            print(f"[+] Initialized dataset rule in {self.rules_file}")
            print(f"[+] IPs will be managed in {self.blocked_ips_file}")
            
        except Exception as e:
            print(f"[!] Error initializing dataset rule: {e}")
    
    def initialize_blocked_ips_file(self):
        """Create blocked IPs file if it doesn't exist"""
        try:
            os.makedirs(os.path.dirname(self.blocked_ips_file), exist_ok=True)
            
            if not os.path.exists(self.blocked_ips_file):
                with open(self.blocked_ips_file, 'w') as f:
                    pass
            
            subprocess.run(['sudo', 'chmod', '644', self.blocked_ips_file], check=False)
            print(f"[+] Initialized blocked IPs file: {self.blocked_ips_file}")
            
        except Exception as e:
            print(f"[!] Error initializing blocked IPs file: {e}")
    
    def update_blocked_ips_file(self):
        """Update the dataset file - Suricata will auto-reload it"""
        try:
            with open(self.blocked_ips_file, 'w') as f:
                for ip in sorted(self.active_blocks.keys()):
                    f.write(f"{ip}\n")
            
            print(f"[+] Updated blocked IPs file with {len(self.active_blocks)} entries (no reload needed)")
            
        except Exception as e:
            print(f"[!] Error updating blocked IPs file: {e}")
    
    def monitor_detections(self):
        """Monitor Redis for new ML detections"""
        print(f"[{datetime.now()}] Starting dynamic IP blocker...")
        print(f"Monitoring Redis DB 0 for ML detections")
        print(f"Confidence threshold: {self.confidence_threshold * 100}%")
        print(f"Using Suricata dataset - no reloads required")
        
        while True:
            try:
                self.process_new_detections()
                
                if datetime.now() - self.last_cleanup > self.cleanup_interval:
                    self.cleanup_old_blocks()
                    self.last_cleanup = datetime.now()
                
                time.sleep(10)
                
            except KeyboardInterrupt:
                print("\n[!] Shutting down IP blocker...")
                break
            except Exception as e:
                print(f"[!] Error in monitor loop: {e}")
                time.sleep(30)
    
    def process_new_detections(self):
        """Check Redis for new high-confidence detections and add to block list"""
        try:
            detections = self.r.lrange('ml_detector:recent_detections', 0, -1)
            new_blocks = []
            
            for detection_json in detections:
                try:
                    detection = json.loads(detection_json)
                    detection_id = f"{detection.get('dest_ip')}_{detection.get('timestamp')}"
                    
                    if detection_id in self.processed_detections:
                        continue
                    
                    confidence = detection.get('confidence', 0)
                    classification = detection.get('classification', '')
                    dest_ip = detection.get('dest_ip')
                    
                    if confidence >= self.confidence_threshold and classification == 'ad' and dest_ip:
                        if dest_ip not in self.active_blocks:
                            self.active_blocks[dest_ip] = {
                                'timestamp': datetime.now(),
                                'confidence': confidence,
                                'detection': detection
                            }
                            new_blocks.append(dest_ip)
                            print(f"[+] Added {dest_ip} to block list (confidence: {confidence:.2f})")
                    
                    self.processed_detections.add(detection_id)
                    
                    if len(self.processed_detections) > 10000:
                        oldest = list(self.processed_detections)[:5000]
                        self.processed_detections = self.processed_detections - set(oldest)
                    
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"[!] Error processing detection: {e}")
                    continue
            
            if new_blocks:
                self.update_blocked_ips_file()
                    
        except Exception as e:
            print(f"[!] Error fetching detections: {e}")
    
    def cleanup_old_blocks(self):
        """Remove blocks older than 24 hours"""
        try:
            current_time = datetime.now()
            expired_ips = []
            
            for ip, block_data in self.active_blocks.items():
                if current_time - block_data['timestamp'] > self.block_max_age:
                    expired_ips.append(ip)
            
            if expired_ips:
                print(f"[+] Cleaning up {len(expired_ips)} expired blocks")
                
                for ip in expired_ips:
                    del self.active_blocks[ip]
                
                self.update_blocked_ips_file()
                
        except Exception as e:
            print(f"[!] Error during cleanup: {e}")
    
    def get_stats(self):
        """Return current blocking statistics"""
        return {
            'total_blocks': len(self.active_blocks),
            'oldest_block': min((b['timestamp'] for b in self.active_blocks.values()), default=None),
            'newest_block': max((b['timestamp'] for b in self.active_blocks.values()), default=None),
            'processed_detections': len(self.processed_detections)
        }

if __name__ == '__main__':
    generator = DynamicRuleGenerator()
    generator.monitor_detections()
