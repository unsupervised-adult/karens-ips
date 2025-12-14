#!/usr/bin/env python3
"""
Ad Flow Blocker - Slips IPS Module for In-Stream Ad Detection & Blocking

Integrates with Slips behavioral analysis to detect and block in-stream ads
at the flow level using conntrack, without blocking entire IPs.

Architecture:
- Subscribes to Slips flow events (new_flow, new_dns)
- Uses ML classification from stream_ad_blocker ML model
- Performs surgical flow-level blocking via conntrack
- Coordinates with Slips blocking module (avoids duplicate IP blocks)

Detection Strategy:
1. Monitor flows from video platforms (YouTube, Twitch, etc)
2. Classify flows using ML model (duration, bytes, timing patterns)
3. Block flows exceeding confidence thresholds via conntrack
4. Preserve content streams while killing ad streams
"""
import json
import subprocess
import time
import os
import sys
from datetime import datetime
from collections import defaultdict
from typing import Dict, Optional, Tuple

from slips_files.common.abstracts.imodule import IModule


class AdFlowBlocker(IModule):
    name = "Ad Flow Blocker"
    description = "Block in-stream ads at flow level using conntrack and ML classification"
    authors = ["Karen's IPS"]

    def init(self):
        self.c1 = self.db.subscribe("new_flow")
        self.c2 = self.db.subscribe("new_dns")
        self.channels = {
            "new_flow": self.c1,
            "new_dns": self.c2,
        }
        
        import redis
        self.stats_db = redis.Redis(host='localhost', port=self.redis_port, db=1, decode_responses=True)
        
        self._verify_conntrack()
        self._load_ml_classifier()
        self._load_thresholds()
        
        self.flows_analyzed = 0
        self.flows_blocked = 0
        self.flows_allowed = 0
        
        self.video_platforms = {
            'youtube.com', 'googlevideo.com', 'ytimg.com',
            'twitch.tv', 'ttvnw.net',
            'vimeo.com', 'vimeocdn.com',
            'dailymotion.com', 'dmcdn.net',
            'roku.com',
            'pluto.tv'
        }
        
        self.ad_domains = {
            'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
            'adservice.google.com', 'googleads.g.doubleclick.net',
            'pubads.g.doubleclick.net', 'pagead2.googlesyndication.com',
            'tpc.googlesyndication.com', 'video-ad-stats.googlesyndication.com'
        }
        
        self.domain_cache = {}
        self.flow_stats = defaultdict(lambda: {'bytes': 0, 'packets': 0, 'start_time': None})
        
        self.print(f"Ad Flow Blocker initialized. ML model loaded.", 1, 0)

    def _verify_conntrack(self):
        """Verify conntrack is installed and available"""
        try:
            result = subprocess.run(
                ['which', 'conntrack'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5
            )
            if result.returncode != 0:
                self.print("ERROR: conntrack not found. Install with: sudo apt-get install conntrack", 0, 1)
                sys.exit(1)
            self.print("conntrack verified", 6, 0)
        except Exception as e:
            self.print(f"ERROR: Failed to verify conntrack: {e}", 0, 1)
            sys.exit(1)

    def _load_ml_classifier(self):
        """Load the ML classifier from stream_ad_blocker"""
        try:
            ml_detector_path = '/opt/StratosphereLinuxIPS/webinterface/ml_detector'
            if ml_detector_path not in sys.path:
                sys.path.insert(0, ml_detector_path)
            
            from ml_ad_classifier import MLAdClassifier
            self.ml_classifier = MLAdClassifier()
            self.print("ML classifier loaded successfully", 3, 0)
        except Exception as e:
            self.print(f"ERROR: Failed to load ML classifier: {e}", 0, 1)
            self.ml_classifier = None

    def _load_thresholds(self):
        """Load blocking thresholds from Redis or use defaults"""
        try:
            self.youtube_threshold = float(self.stats_db.hget('stream_ad_blocker:thresholds', 'youtube_threshold') or 0.60)
            self.cdn_threshold = float(self.stats_db.hget('stream_ad_blocker:thresholds', 'cdn_threshold') or 0.85)
            self.control_plane_threshold = float(self.stats_db.hget('stream_ad_blocker:thresholds', 'control_plane_threshold') or 0.70)
            self.print(f"Thresholds: YouTube={self.youtube_threshold}, CDN={self.cdn_threshold}, ControlPlane={self.control_plane_threshold}", 3, 0)
        except Exception as e:
            self.print(f"Failed to load thresholds from Redis, using defaults: {e}", 2, 0)
            self.youtube_threshold = 0.60
            self.cdn_threshold = 0.85
            self.control_plane_threshold = 0.70

    def _is_video_platform(self, domain: str) -> bool:
        """Check if domain belongs to a video streaming platform"""
        if not domain:
            return False
        for platform in self.video_platforms:
            if platform in domain.lower():
                return True
        return False

    def _is_ad_domain(self, domain: str) -> bool:
        """Check if domain is a known ad/tracking domain"""
        if not domain:
            return False
        domain_lower = domain.lower()
        for ad_domain in self.ad_domains:
            if ad_domain in domain_lower:
                return True
        return False

    def _classify_flow(self, flow_data: Dict) -> Tuple[float, str, bool, bool]:
        """
        Classify flow using ML model and domain heuristics
        Returns: (confidence, method, is_video_platform, is_ad)
        """
        domain = flow_data.get('domain', '')
        dst_ip = flow_data.get('daddr', '')
        duration = flow_data.get('duration', 0)
        bytes_sent = flow_data.get('bytes', 0)
        packets = flow_data.get('pkts', 0)
        
        is_video = self._is_video_platform(domain)
        is_ad = self._is_ad_domain(domain)
        
        if is_ad:
            return 0.95, 'domain_blocklist', is_video, True
        
        if not is_video or not self.ml_classifier:
            return 0.0, 'none', is_video, False
        
        features = {
            'duration': duration,
            'bytes': bytes_sent,
            'packets': packets,
            'domain': domain,
            'dst_ip': dst_ip
        }
        
        try:
            confidence = self.ml_classifier.predict_single(features)
            return confidence, 'ml_classification', is_video, confidence > 0.30
        except Exception as e:
            self.print(f"ML classification failed: {e}", 2, 0)
            return 0.0, 'ml_error', is_video, False

    def _block_flow(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> bool:
        """
        Block specific flow using conntrack
        Returns True if successfully blocked
        """
        try:
            proto_arg = protocol.lower()
            if proto_arg not in ['tcp', 'udp']:
                proto_arg = 'tcp'
            
            cmd = [
                'sudo', 'conntrack', '-D',
                '-p', proto_arg,
                '--orig-dst', dst_ip,
                '--dst-port', str(dst_port),
                '--src', src_ip
            ]
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5
            )
            
            if result.returncode == 0:
                self.flows_blocked += 1
                self._update_stats('flows_dropped')
                return True
            else:
                stderr = result.stderr.decode('utf-8', errors='ignore')
                if '0 flow entries' not in stderr:
                    self.print(f"conntrack delete failed: {stderr}", 2, 0)
                return False
                
        except subprocess.TimeoutExpired:
            self.print(f"conntrack command timeout for {src_ip} -> {dst_ip}:{dst_port}", 2, 0)
            return False
        except Exception as e:
            self.print(f"Flow blocking error: {e}", 2, 0)
            return False

    def _update_stats(self, key: str, increment: int = 1):
        """Update blocking statistics in Redis"""
        try:
            self.stats_db.hincrby('stream_ad_blocker:stats', key, increment)
        except Exception as e:
            self.print(f"Stats update failed: {e}", 4, 0)

    def _should_block(self, confidence: float, is_video_platform: bool, is_cdn: bool) -> bool:
        """
        Determine if flow should be blocked based on confidence and thresholds
        """
        if is_video_platform:
            return confidence >= self.youtube_threshold
        elif is_cdn:
            return confidence >= self.cdn_threshold
        else:
            return confidence >= self.control_plane_threshold

    def _process_flow(self, flow_msg: Dict):
        """Process a new flow message from Slips"""
        try:
            flow_data = json.loads(flow_msg.get('data', '{}'))
            
            profileid = flow_data.get('profileid', '')
            twid = flow_data.get('twid', '')
            
            if not profileid or not twid:
                return
            
            flow_dict = flow_data.get('flow', {})
            if not flow_dict:
                return
            
            src_ip = flow_dict.get('saddr', '')
            dst_ip = flow_dict.get('daddr', '')
            dst_port = flow_dict.get('dport', 0)
            protocol = flow_dict.get('proto', 'TCP')
            
            domain = self.domain_cache.get(dst_ip, '')
            
            flow_dict['domain'] = domain
            
            confidence, method, is_video, is_ad = self._classify_flow(flow_dict)
            
            self.flows_analyzed += 1
            
            if is_ad:
                is_cdn = 'cdn' in domain.lower() or 'cloudfront' in domain.lower()
                
                if self._should_block(confidence, is_video, is_cdn):
                    blocked = self._block_flow(src_ip, dst_ip, dst_port, protocol)
                    
                    if blocked:
                        self.flows_blocked += 1
                        self.print(
                            f"[FLOW BLOCKED] {domain or dst_ip} "
                            f"({src_ip} -> {dst_ip}:{dst_port}) "
                            f"confidence={confidence:.2f} method={method}",
                            1, 0
                        )
                        
                        self._update_stats('ads_detected')
                    else:
                        self.flows_allowed += 1
                else:
                    self.flows_allowed += 1
                    self.print(
                        f"[AD DETECTED] {domain or dst_ip} confidence={confidence:.2f} "
                        f"(below threshold, not blocking)",
                        3, 0
                    )
            else:
                self.flows_allowed += 1
                
        except json.JSONDecodeError:
            self.print("Failed to parse flow JSON", 4, 0)
        except Exception as e:
            self.print(f"Flow processing error: {e}", 2, 0)

    def _process_dns(self, dns_msg: Dict):
        """Process DNS resolution to build domain cache"""
        try:
            dns_data = json.loads(dns_msg.get('data', '{}'))
            domain = dns_data.get('query', '')
            answers = dns_data.get('answers', [])
            
            for answer in answers:
                if answer.get('type') == 'A':
                    ip = answer.get('data')
                    if ip and domain:
                        self.domain_cache[ip] = domain
                        
        except json.JSONDecodeError:
            pass
        except Exception as e:
            self.print(f"DNS processing error: {e}", 4, 0)

    def pre_main(self):
        """Called before main loop"""
        utils.drop_root_privs()

    def main(self):
        """Main module loop"""
        if msg := self.get_msg("new_flow"):
            self._process_flow(msg)
        
        if msg := self.get_msg("new_dns"):
            self._process_dns(msg)
