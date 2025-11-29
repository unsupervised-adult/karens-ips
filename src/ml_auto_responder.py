#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Karen's IPS ML Auto Responder
# SPDX-License-Identifier: GPL-2.0-only

"""
ML Auto Responder - Automated response to ML ad detections

Takes ML detection results and automatically:
1. Blocks detected ad IPs in nftables
2. Generates new Suricata rules for patterns
3. Adjusts thresholds based on accuracy
4. Reports to dashboard
"""

import json
import time
import redis
import subprocess
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
from pathlib import Path
from threading import Thread, Event
import ipaddress
from .exception_manager import ExceptionManager

class MLAutoResponder:
    def __init__(self, 
                 redis_host: str = "localhost",
                 redis_port: int = 6379,
                 redis_db: int = 2):
        """Initialize ML Auto Responder"""
        
        self.redis_client = redis.Redis(host=redis_host, port=redis_port, db=redis_db, decode_responses=True)
        self.logger = logging.getLogger(__name__)
        
        # Initialize exception manager
        self.exception_manager = ExceptionManager()
        
        # Configuration
        self.blocking_threshold = 0.75  # ML confidence threshold for auto-blocking
        self.learning_threshold = 0.60  # Threshold for learning new patterns
        self.max_blocks_per_hour = 100  # Safety limit
        
        # Blocking policy
        self.ip_block_hours = 24        # IPs auto-unblock after 24h (temporary)
        self.domain_block_permanent = True  # Domains stay blocked forever
        self.permanent_ip_lists = {     # IPs that get permanently blocked
            'known_ad_servers', 
            'malware_c2', 
            'samsung_telemetry',
            'netflix_ads'
        }
        
        # State tracking
        self.blocked_ips: Set[str] = set()
        self.detection_counts: Dict[str, int] = {}
        self.last_block_time: Dict[str, float] = {}
        self.false_positive_ips: Set[str] = set()
        
        # Threading
        self.running = Event()
        self.monitoring_thread: Optional[Thread] = None
        
        # Stats
        self.stats = {
            'total_detections': 0,
            'auto_blocks': 0,
            'auto_rules': 0,
            'false_positives': 0,
            'accuracy': 0.0
        }
        
        self.logger.info("ML Auto Responder initialized")
    
    def start_monitoring(self):
        """Start monitoring ML detections for automated response"""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.logger.warning("Monitoring already running")
            return
        
        self.running.set()
        self.monitoring_thread = Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        self.logger.info("ML monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.running.clear()
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5.0)
        self.logger.info("ML monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.running.is_set():
            try:
                # Check for new ML detections
                self._process_ml_detections()
                
                # Check for auto-unblocking
                self._check_auto_unblock()
                
                # Update stats
                self._update_stats()
                
                # Sleep before next check
                time.sleep(10)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(30)
    
    def _process_ml_detections(self):
        """Process new ML detections from Redis"""
        try:
            # Get recent ML detections
            detections = self.redis_client.lrange("ml_detector:recent_detections", 0, 99)
            
            for detection_str in detections:
                try:
                    detection = json.loads(detection_str)
                    self._handle_detection(detection)
                    
                except json.JSONDecodeError as e:
                    self.logger.warning(f"Invalid detection format: {e}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Error processing ML detections: {e}")
    
    def _handle_detection(self, detection: Dict):
        """Handle a single ML detection"""
        try:
            ip = detection.get('dst_ip')
            confidence = float(detection.get('confidence', 0.0))
            detection_type = detection.get('type', 'unknown')
            timestamp = detection.get('timestamp', datetime.now().isoformat())
            
            if not ip or not self._is_valid_ip(ip):
                return
            
            self.stats['total_detections'] += 1
            
            # Check if IP is excepted from blocking
            excepted, reason = self.exception_manager.is_ip_excepted(ip)
            if excepted:
                self.logger.info(f"Skipping {ip} - excepted: {reason}")
                return
            
            # Skip if already blocked or known false positive
            if ip in self.blocked_ips or ip in self.false_positive_ips:
                return
            
            # Track detection frequency
            self.detection_counts[ip] = self.detection_counts.get(ip, 0) + 1
            
            # Auto-block if confidence is high enough
            if confidence >= self.blocking_threshold:
                self._auto_block_ip(ip, confidence, detection_type)
            
            # Learn new patterns if confidence is moderate
            elif confidence >= self.learning_threshold:
                self._learn_pattern(detection)
            
            # Update ML feedback
            self._update_ml_feedback(ip, confidence, detection_type)
            
        except Exception as e:
            self.logger.error(f"Error handling detection: {e}")
    
    def _auto_block_ip(self, ip: str, confidence: float, detection_type: str):
        """Automatically block an IP based on ML detection"""
        try:
            current_time = time.time()
            
            # Rate limiting - check blocks per hour
            recent_blocks = sum(1 for t in self.last_block_time.values() 
                              if current_time - t < 3600)
            
            if recent_blocks >= self.max_blocks_per_hour:
                self.logger.warning(f"Rate limit reached, skipping block for {ip}")
                return
            
            # Determine if this should be permanent or temporary block
            is_permanent = detection_type in self.permanent_ip_lists
            
            # Block IP in nftables (with or without timeout)
            if self._add_nftables_block(ip, is_permanent):
                self.blocked_ips.add(ip)
                self.last_block_time[ip] = current_time
                self.stats['auto_blocks'] += 1
                
                block_type = "permanently" if is_permanent else f"for {self.ip_block_hours}h"
                self.logger.info(f"Auto-blocked {ip} {block_type} (confidence: {confidence:.2f}, type: {detection_type})")
                
                # Log to SLIPS
                self._log_to_slips(ip, confidence, detection_type, f"AUTO_BLOCKED_{block_type.upper()}")
                
                # Generate Suricata rule for this pattern (domains stay forever)
                self._generate_pattern_rule(ip, detection_type, confidence, permanent_domain=True)
        
        except Exception as e:
            self.logger.error(f"Error auto-blocking {ip}: {e}")
    
    def _add_nftables_block(self, ip: str) -> bool:
        """Add IP to nftables blocked4 set"""
        try:
            # Add to blocked4 set with timeout
            cmd = ['nft', 'add', 'element', 'inet', 'home', 'blocked4', 
                   f'{{{ip} timeout 24h}}']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.logger.debug(f"Added {ip} to nftables blocked4 set")
                return True
            else:
                self.logger.error(f"Failed to block {ip}: {result.stderr}")
                return False
        
        except Exception as e:
            self.logger.error(f"Error adding nftables block for {ip}: {e}")
            return False
    
    def _generate_pattern_rule(self, ip: str, detection_type: str, confidence: float):
        """Generate Suricata rule for detected pattern"""
        try:
            # Generate rule based on detection type
            rule_id = int(time.time()) % 1000000 + 9900000  # Dynamic SID
            
            if detection_type == "short_burst_ad":
                rule = (f'alert tcp any any -> {ip} any '
                       f'(msg:"KARENS-IPS ML Auto: Ad pattern to {ip}"; '
                       f'flow:established; threshold: type both, track by_dst, seconds 60, count 3; '
                       f'classtype:policy-violation; sid:{rule_id}; rev:1;)')
            
            elif detection_type == "samsung_telemetry":
                rule = (f'alert tcp any any -> {ip} any '
                       f'(msg:"KARENS-IPS ML Auto: Samsung telemetry to {ip}"; '
                       f'flow:established; flowbits:set,samsung.telemetry; '
                       f'classtype:policy-violation; sid:{rule_id}; rev:1;)')
            
            elif detection_type == "netflix_ad":
                rule = (f'alert tcp any any -> {ip} any '
                       f'(msg:"KARENS-IPS ML Auto: Netflix ad pattern to {ip}"; '
                       f'flow:established; threshold: type both, track by_dst, seconds 30, count 2; '
                       f'classtype:policy-violation; sid:{rule_id}; rev:1;)')
            
            else:
                rule = (f'alert tcp any any -> {ip} any '
                       f'(msg:"KARENS-IPS ML Auto: Detected ad pattern to {ip}"; '
                       f'flow:established; threshold: type both, track by_dst, seconds 60, count 1; '
                       f'classtype:policy-violation; sid:{rule_id}; rev:1;)')
            
            # Write rule to auto-generated rules file
            rules_file = "/etc/suricata/rules/karens-ips-ml-auto.rules"
            Path(rules_file).parent.mkdir(parents=True, exist_ok=True)
            
            with open(rules_file, 'a') as f:
                f.write(f"{rule}\n")
            
            self.stats['auto_rules'] += 1
            self.logger.info(f"Generated auto-rule for {ip} ({detection_type})")
            
            # Reload Suricata rules
            self._reload_suricata_rules()
        
        except Exception as e:
            self.logger.error(f"Error generating pattern rule: {e}")
    
    def _learn_pattern(self, detection: Dict):
        """Learn from detection to improve future accuracy"""
        try:
            # Store learning data in Redis for model retraining
            learning_data = {
                'timestamp': datetime.now().isoformat(),
                'detection': detection,
                'action': 'learned',
                'confidence_threshold': self.learning_threshold
            }
            
            self.redis_client.lpush("ml_detector:learning_data", 
                                   json.dumps(learning_data))
            
            # Keep only last 1000 learning samples
            self.redis_client.ltrim("ml_detector:learning_data", 0, 999)
            
        except Exception as e:
            self.logger.error(f"Error storing learning data: {e}")
    
    def _check_auto_unblock(self):
        """Check for IPs that should be auto-unblocked (only if confirmed false positive)"""
        try:
            current_time = time.time()
            unblock_threshold = self.auto_unblock_hours * 3600
            
            to_unblock = []
            for ip in list(self.blocked_ips):
                last_block = self.last_block_time.get(ip, 0)
                
                # Only auto-unblock if:
                # 1. More than 7 days old
                # 2. Marked as false positive by user feedback
                # 3. OR if it's a critical service IP that got blocked by mistake
                if current_time - last_block > unblock_threshold:
                    
                    # Check if marked as false positive
                    if ip in self.false_positive_ips:
                        to_unblock.append(ip)
                        self.logger.info(f"Auto-unblocking {ip} - confirmed false positive")
                    
                    # Check if it's a critical service (DNS, etc)
                    elif self._is_critical_service_ip(ip):
                        to_unblock.append(ip)
                        self.logger.warning(f"Auto-unblocking {ip} - critical service")
                        # Add to exception list to prevent re-blocking
                        self.exception_manager.add_ip_exception(ip, "Critical service auto-recovery", "auto_responder")
                    
                    # Otherwise keep it blocked - ads should stay blocked
                    else:
                        self.logger.debug(f"Keeping {ip} blocked - not confirmed as false positive")
            
            for ip in to_unblock:
                self._auto_unblock_ip(ip)
        
        except Exception as e:
            self.logger.error(f"Error in auto-unblock check: {e}")
    
    def _auto_unblock_ip(self, ip: str):
        """Automatically unblock an IP"""
        try:
            # Remove from nftables
            cmd = ['nft', 'delete', 'element', 'inet', 'home', 'blocked4', f'{{{ip}}}']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.blocked_ips.discard(ip)
                self.detection_counts.pop(ip, None)
                self.last_block_time.pop(ip, None)
                
                self.logger.info(f"Auto-unblocked {ip} after timeout")
                self._log_to_slips(ip, 0.0, "timeout", "AUTO_UNBLOCKED")
        
        except Exception as e:
            self.logger.error(f"Error auto-unblocking {ip}: {e}")
    
    def _update_ml_feedback(self, ip: str, confidence: float, detection_type: str):
        """Provide feedback to ML system"""
        try:
            feedback = {
                'ip': ip,
                'confidence': confidence,
                'type': detection_type,
                'action_taken': ip in self.blocked_ips,
                'timestamp': datetime.now().isoformat()
            }
            
            self.redis_client.lpush("ml_detector:feedback", json.dumps(feedback))
            self.redis_client.ltrim("ml_detector:feedback", 0, 499)
        
        except Exception as e:
            self.logger.error(f"Error updating ML feedback: {e}")
    
    def _log_to_slips(self, ip: str, confidence: float, detection_type: str, action: str):
        """Log action to SLIPS for tracking"""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'ip': ip,
                'confidence': confidence,
                'type': detection_type,
                'action': action,
                'source': 'ml_auto_responder'
            }
            
            self.redis_client.lpush("alerts", json.dumps(log_entry))
        
        except Exception as e:
            self.logger.error(f"Error logging to SLIPS: {e}")
    
    def _reload_suricata_rules(self):
        """Reload Suricata rules"""
        try:
            result = subprocess.run(['systemctl', 'reload', 'suricata'], 
                                   capture_output=True, timeout=30)
            if result.returncode != 0:
                self.logger.warning("Failed to reload Suricata rules")
        except Exception as e:
            self.logger.error(f"Error reloading Suricata: {e}")
    
    def _update_stats(self):
        """Update statistics in Redis"""
        try:
            # Calculate accuracy based on feedback
            feedbacks = self.redis_client.lrange("ml_detector:feedback", 0, 99)
            if feedbacks:
                correct_predictions = 0
                total_predictions = len(feedbacks)
                
                for feedback_str in feedbacks:
                    try:
                        feedback = json.loads(feedback_str)
                        # Simple accuracy: high confidence + action taken = correct
                        if (feedback.get('confidence', 0) > self.blocking_threshold and 
                            feedback.get('action_taken', False)):
                            correct_predictions += 1
                    except:
                        continue
                
                if total_predictions > 0:
                    self.stats['accuracy'] = correct_predictions / total_predictions
            
            # Store stats in Redis
            self.redis_client.hset("ml_detector:auto_responder_stats", 
                                  mapping=self.stats)
        
        except Exception as e:
            self.logger.error(f"Error updating stats: {e}")
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def get_stats(self) -> Dict:
        """Get current statistics"""
        return self.stats.copy()
    
    def manual_block(self, ip: str, reason: str = "manual"):
        """Manually block an IP"""
        if self._add_nftables_block(ip):
            self.blocked_ips.add(ip)
            self.last_block_time[ip] = time.time()
            self.logger.info(f"Manually blocked {ip}: {reason}")
            return True
        return False
    
    def manual_unblock(self, ip: str):
        """Manually unblock an IP"""
        try:
            cmd = ['nft', 'delete', 'element', 'inet', 'home', 'blocked4', f'{{{ip}}}']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.blocked_ips.discard(ip)
                self.detection_counts.pop(ip, None)
                self.last_block_time.pop(ip, None)
                self.logger.info(f"Manually unblocked {ip}")
                return True
        except Exception as e:
            self.logger.error(f"Error manually unblocking {ip}: {e}")
        
        return False


def main():
    """Run ML Auto Responder as standalone service"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/var/log/karens-ips/ml-auto-responder.log'),
            logging.StreamHandler()
        ]
    )
    
    responder = MLAutoResponder()
    
    try:
        print("Starting ML Auto Responder...")
        responder.start_monitoring()
        
        # Keep running
        while True:
            time.sleep(60)
            stats = responder.get_stats()
            print(f"Stats: {stats}")
    
    except KeyboardInterrupt:
        print("\nShutting down...")
        responder.stop_monitoring()


if __name__ == '__main__':
    main()