#!/usr/bin/env python3
"""
Stream Ad Blocker - Real-time detection and blocking of in-stream ads
Monitors SLIPS flow data and automatically blocks detected ad traffic
Cross-references with blocklist database (338K+ domains) and SLIPS behavioral analysis

MODERN AD DELIVERY ARCHITECTURE (2024+):
-----------------------------------------
YouTube SSAI (Server-Side Ad Insertion) - REGIONAL ROLLOUT:
  - SSAI regions: Ads stitched into same *.googlevideo.com stream as content
    → Cannot distinguish ad segments from content at network level
    → Must block ad control plane only (doubleclick, googlesyndication)
  
  - Non-SSAI regions (CURRENT): Ads are separate video streams
    → Ad flows have distinct characteristics (6s bumpers, 15-30s ads)
    → ML can identify by duration + byte patterns + timing
    → Flow-level blocking works perfectly - kills ad without affecting content
    → This is what we're detecting and blocking!

Generic HTTP/3 Sites:
  - Control: Small JSON/protobuf ad auction requests (1-10KB) to SSP endpoints
  - Media: Banner creatives (20-300KB) and video segments from CDNs
  - Header bidding fires parallel requests over single QUIC connection
  
DETECTION STRATEGY (Non-SSAI regions):
  1. Block ad decisioning control plane (doubleclick, googlesyndication, etc)
  2. Use ML to identify separate ad streams from googlevideo.com
  3. Drop flows matching ad patterns: 6s bumpers, 15-30s skippable, ad pods
  4. Track connection patterns: short duration + specific byte ranges = ad
  5. Flow-level drops preserve content stream, kill only ad stream
"""
import redis
import json
import time
import subprocess
import sqlite3
from datetime import datetime
from collections import defaultdict
import sys
import os
import threading
import queue

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ml_ad_classifier import MLAdClassifier

class StreamAdBlocker:
    def __init__(self):
        # Connect to DB 0 to read SLIPS data (DomainsResolved)
        self.r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
        # Separate connection to DB 1 for writing stats (avoids conflicts with SLIPS)
        self.r_stats = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
        self.classifier = None
        self.detected_ads = set()
        self.blocked_ips = set()
        self.blocked_urls = set()
        self.blocked_flows = set()
        self.stats = {
            'ads_detected': 0,
            'ips_blocked': 0,
            'urls_blocked': 0,
            'flows_dropped': 0,
            'total_analyzed': 0,
            'blocklist_hits': 0,
            'ml_detections': 0,
            'slips_correlated': 0,
            'cdn_flow_blocks': 0,
            'ad_server_blocks': 0,
            'llm_enhanced_detections': 0,
            'llm_queue_size': 0,
            'llm_processed': 0
        }
        
        # LLM background processing queue
        self.llm_queue = queue.Queue()
        self.llm_thread = None
        self.llm_running = False
        
        # Load detection thresholds from Redis or use defaults
        self.load_thresholds()
        
        # Initialize detection history database
        self.init_detection_history_db()
        
        # Connect to blocklist database
        self.blocklist_db = None
        try:
            self.blocklist_db = sqlite3.connect('/var/lib/suricata/ips_filter.db', check_same_thread=False)
            domain_count = self.blocklist_db.execute("SELECT COUNT(*) FROM blocked_domains").fetchone()[0]
            print(f"[+] Connected to blocklist DB: {domain_count:,} domains", flush=True)
        except Exception as e:
            print(f"[!] Blocklist DB unavailable: {e}", flush=True)

        # Initialize ML classifier
        try:
            self.classifier = MLAdClassifier(self.llm_min_threshold, self.llm_max_threshold)
            print("[+] ML classifier loaded", flush=True)
        except Exception as e:
            print(f"[!] ML classifier failed, using pattern-only mode: {e}", flush=True)

        # Known ad & telemetry domains for quick filtering
        self.ad_patterns = [
            # Ad networks
            'doubleclick', 'googlesyndication', 'googleadservices',
            'advertising', 'adservice', 'pagead', 'adnxs', 'adsrvr',
            'criteo', 'taboola', 'outbrain', 'amazon-adsystem',
            'googletagmanager', 'googletagservices', 'imasdk',
            'scorecardresearch', 'moatads', 'addthis', 'sharethis',

            # Telemetry & tracking (corpo spyware)
            'telemetry', 'analytics', 'tracking', 'metrics', 'stats',
            'google-analytics', 'googleanalytics', 'ga.js', 'gtag',
            'mixpanel', 'segment.io', 'amplitude', 'heap.io',
            'hotjar', 'fullstory', 'logrocket', 'sentry.io',
            'bugsnag', 'newrelic', 'datadog', 'splunk',
            'adobe.com/data', 'adobedtm', 'omtrdc', 'demdex',
            'facebook.com/tr', 'connect.facebook.net', 'fbcdn',
            'twitter.com/i/adsct', 'ads-twitter', 't.co/i/adsct',
            'linkedin.com/px', 'snap.licdn.com',
            'reddit.com/api/v1/pixel', 'redditmedia.com/gtm',
            'tiktok.com/i18n/pixel', 'analytics.tiktok',
            'clarity.ms', 'c.bing.com', 'bat.bing.com',
            'quantserve', 'quantcast', 'chartbeat', 'kissmetrics'
        ]

        # CDN domains that may carry both ads and content
        # For regions WITHOUT SSAI: ads are separate streams (flow blocking works!)
        # For regions WITH SSAI: ads stitched in same stream (flow blocking breaks content)
        # Currently: SSAI not rolled out in user's region - enable flow blocking
        self.cdn_whitelist = [
            # 'googlevideo.com',  # DISABLED: SSAI not active, ads are separate flows
            # 'youtube.com',      # Safe to flow-block with ML detection
            # 'youtu.be',
            'cloudfront.net',     # Keep whitelisted (SSAI common on AWS)
            'akamaihd.net',       # Keep whitelisted (Akamai often uses SSAI)
            'fastly.net',
            'nflxvideo.net',
            'ttvnw.net'
        ]
        
        # Ad control plane domains (safe to block - only affect ad decisioning)
        self.ad_control_plane = [
            'doubleclick.net',
            'googlesyndication.com',
            'googleadservices.com',
            'googletagmanager.com',
            'googletagservices.com',
            'google-analytics.com',
            'pagead2.googlesyndication.com',
            'adnxs.com',
            'adsrvr.org',
            'criteo.com',
            'taboola.com',
            'outbrain.com'
        ]

        # Streaming service patterns - all platforms with video ads
        self.streaming_services = [
            ('youtube', ['googlevideo.com', 'youtube.com', 'youtu.be']),
            ('twitch', ['twitch.tv', 'ttvnw.net', 'twitchcdn.net']),
            ('netflix', ['netflix.com', 'nflxvideo.net']),
            ('hulu', ['hulu.com', 'hulustream.com']),
            ('prime', ['primevideo.com', 'amazon.com/gp/video']),
            ('vimeo', ['vimeo.com', 'vimeocdn.com']),
            ('dailymotion', ['dailymotion.com', 'dmcdn.net']),
            ('roku', ['roku.com', 'rokutime.com']),
            ('pluto', ['pluto.tv', 'plutotv.net']),
            ('peacock', ['peacocktv.com', 'nbcuni.com'])
        ]

        # YouTube ad learning: Track connection patterns
        # NOTE: "YouTube" variable naming preserved for backward compatibility
        # Actually tracks ALL video platform flows (YouTube, Twitch, Vimeo, etc)
        # Key: IP address, Value: {'flows': [], 'classified_as_ad': bool, 'confidence': float}
        self.youtube_connection_cache = {}

        # Track video session context for better ad detection across all platforms
        # Key: source_ip, Value: {'last_content_flow': timestamp, 'content_duration': seconds, 'ad_count': int}
        self.video_sessions = {}
        
        # Track ad pods (consecutive ads like 2x30s YouTube pre-roll)
        # Key: (src_ip, dst_ip), Value: [{'timestamp': ts, 'duration': dur, 'bytes': bytes}]
        self.ad_pod_tracking = defaultdict(list)
        self.AD_POD_WINDOW = 60  # seconds - track ads within 60s window
        self.AD_POD_MIN_COUNT = 2  # Flag as ad pod if 2+ ads in sequence

        # YouTube 2025 ad pattern knowledge
        # Based on May 2025 update: ads at "natural breakpoints"
        self.youtube_ad_types = {
            'bumper': {'min_dur': 0, 'max_dur': 6, 'skippable': False},
            'skippable': {'min_dur': 5, 'max_dur': 180, 'forced_watch': 5},  # Can be long but skip after 5s
            'non_skippable_standard': {'min_dur': 15, 'max_dur': 20, 'skippable': False},
            'non_skippable_tv': {'min_dur': 20, 'max_dur': 30, 'skippable': False},
            'mid_roll': {'min_dur': 5, 'max_dur': 120, 'location': 'during_video'},
            'pre_roll': {'min_dur': 5, 'max_dur': 60, 'location': 'video_start'},
            'post_roll': {'min_dur': 5, 'max_dur': 30, 'location': 'video_end'}
        }

    def load_thresholds(self):
        """Load detection thresholds from Redis or use defaults"""
        try:
            thresholds = self.r_stats.hgetall("stream_ad_blocker:thresholds")
            self.youtube_threshold = float(thresholds.get("youtube_threshold", "0.60"))
            self.cdn_threshold = float(thresholds.get("cdn_threshold", "0.85"))
            self.control_plane_threshold = float(thresholds.get("control_plane_threshold", "0.70"))
            self.llm_min_threshold = float(thresholds.get("llm_min_threshold", "0.30"))
            self.llm_max_threshold = float(thresholds.get("llm_max_threshold", "0.90"))
            print(f"[+] Thresholds: YouTube={self.youtube_threshold}, CDN={self.cdn_threshold}, ControlPlane={self.control_plane_threshold}")
            print(f"[+] LLM Range: {self.llm_min_threshold} - {self.llm_max_threshold}")
        except Exception as e:
            print(f"[!] Error loading thresholds, using defaults: {e}")
            self.youtube_threshold = 0.60
            self.cdn_threshold = 0.85
            self.control_plane_threshold = 0.70
            self.llm_min_threshold = 0.30
            self.llm_max_threshold = 0.90

    def init_detection_history_db(self):
        """Initialize SQLite database for detection history"""
        try:
            self.history_db = sqlite3.connect('/var/lib/stream_ad_blocker/detection_history.db', check_same_thread=False)
            self.history_db.execute('''
                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    domain TEXT NOT NULL,
                    dst_ip TEXT,
                    src_ip TEXT,
                    confidence REAL,
                    method TEXT,
                    block_type TEXT,
                    duration REAL,
                    bytes INTEGER,
                    packets INTEGER,
                    platform TEXT,
                    blocked INTEGER DEFAULT 0
                )
            ''')
            self.history_db.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON detections(timestamp)')
            self.history_db.execute('CREATE INDEX IF NOT EXISTS idx_domain ON detections(domain)')
            self.history_db.execute('CREATE INDEX IF NOT EXISTS idx_platform ON detections(platform)')
            self.history_db.commit()
            
            # Check if logging is enabled
            logging_enabled = self.r_stats.get("stream_ad_blocker:logging_enabled")
            self.logging_enabled = logging_enabled != "0" if logging_enabled else True
            
            print(f"[+] Detection history DB initialized (logging: {'enabled' if self.logging_enabled else 'disabled'})")
        except Exception as e:
            print(f"[!] Failed to initialize history DB: {e}")
            self.history_db = None
    
    def start_llm_background_processor(self):
        """Start background thread to process LLM queue"""
        if self.llm_thread is not None and self.llm_thread.is_alive():
            return
        
        self.llm_running = True
        self.llm_thread = threading.Thread(target=self._llm_processing_loop, daemon=True)
        self.llm_thread.start()
        print("[+] LLM background processor started", flush=True)
    
    def stop_llm_background_processor(self):
        """Stop background LLM processor"""
        self.llm_running = False
        if self.llm_thread:
            self.llm_thread.join(timeout=5)
        print("[+] LLM background processor stopped", flush=True)
    
    def _llm_processing_loop(self):
        """Background thread that processes LLM queue one-by-one"""
        print("[LLM] Processing thread started", flush=True)
        
        while self.llm_running:
            try:
                # Block for 1 second waiting for queue item
                detection_data = self.llm_queue.get(timeout=1.0)
                
                # Update queue size stat
                self.stats['llm_queue_size'] = self.llm_queue.qsize()
                
                # Process with LLM
                try:
                    domain = detection_data['domain']
                    flow_data = detection_data['flow_data']
                    dst_ip = detection_data['dst_ip']
                    dns_history = detection_data.get('dns_history')
                    
                    print(f"[LLM] Processing queued detection: {domain} ({dst_ip})", flush=True)
                    
                    # Call LLM classification
                    is_ad_llm, llm_confidence, llm_method, llm_reasoning = self.classifier.classify_with_llm(
                        domain, flow_data, dst_ip, 443, dns_history
                    )
                    
                    # Save LLM-labeled sample to training dataset
                    if llm_reasoning:
                        features = self.classifier.extract_flow_features(flow_data, dst_ip, 443)
                        self.classifier.save_training_sample(
                            domain=domain,
                            features=features,
                            label=1 if is_ad_llm else 0,
                            confidence=llm_confidence,
                            method=llm_method,
                            reasoning=llm_reasoning
                        )
                        
                        self.stats['llm_enhanced_detections'] += 1
                        self.stats['llm_processed'] += 1
                        
                        print(f"[LLM] ✓ Labeled {domain}: {llm_method} (confidence={llm_confidence:.2f})", flush=True)
                        print(f"[LLM] Reasoning: {llm_reasoning[:100]}...", flush=True)
                    
                    # Update stats in Redis
                    self.r_stats.set('ml_detector:stats', json.dumps(self.stats))
                    
                except Exception as e:
                    print(f"[LLM] Error processing detection: {e}", flush=True)
                
                self.llm_queue.task_done()
                
                # Small delay to avoid overwhelming LLM
                time.sleep(0.5)
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[LLM] Processing loop error: {e}", flush=True)
                time.sleep(1)
        
        print("[LLM] Processing thread stopped", flush=True)

    def log_detection(self, domain, detection_data, flow_data, confidence, method, blocked=False):
        """Log detection to history database"""
        if not self.history_db or not self.logging_enabled:
            return
        
        try:
            platform = 'unknown'
            for service_name, patterns in self.streaming_services:
                if any(p in domain.lower() for p in patterns):
                    platform = service_name
                    break
            
            self.history_db.execute('''
                INSERT INTO detections 
                (domain, dst_ip, src_ip, confidence, method, block_type, duration, bytes, packets, platform, blocked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                domain,
                detection_data.get('dst_ip'),
                flow_data.get('src_ip') or flow_data.get('saddr'),
                confidence,
                method,
                detection_data.get('block_type', 'detection_only'),
                flow_data.get('dur', 0),
                flow_data.get('sbytes', 0),
                flow_data.get('spkts', 0),
                platform,
                1 if blocked else 0
            ))
            self.history_db.commit()
        except Exception as e:
            print(f"[!] Failed to log detection: {e}")

    def check_blocklist_db(self, domain):
        """
        Query blocklist database for domain
        Returns: (is_blocked, category, confidence)
        """
        if not self.blocklist_db:
            return False, None, 0.0
        
        try:
            # Check exact match first
            cursor = self.blocklist_db.execute(
                "SELECT category FROM blocked_domains WHERE domain = ? LIMIT 1",
                (domain,)
            )
            result = cursor.fetchone()
            if result:
                self.stats['blocklist_hits'] += 1
                return True, result[0], 0.95
            
            # Check subdomain matches (e.g., ads.example.com matches example.com)
            parts = domain.split('.')
            for i in range(len(parts) - 1):
                parent = '.'.join(parts[i+1:])
                cursor = self.blocklist_db.execute(
                    "SELECT category FROM blocked_domains WHERE domain = ? LIMIT 1",
                    (parent,)
                )
                result = cursor.fetchone()
                if result:
                    self.stats['blocklist_hits'] += 1
                    return True, result[0], 0.85
            
            return False, None, 0.0
        except Exception as e:
            print(f"[!] Blocklist DB query failed: {e}")
            return False, None, 0.0
    
    def get_slips_evidence(self, src_ip, dst_ip):
        """
        Query SLIPS for behavioral evidence about this traffic
        Returns: (threat_level, evidence_list, confidence)
        """
        try:
            # Check if SLIPS has flagged this IP
            evidence = []
            threat_level = 0.0
            
            # Check for alerts on source IP
            src_alerts = self.r.get(f"alerts:{src_ip}")
            if src_alerts:
                evidence.append(f"Source IP has alerts")
                threat_level += 0.3
            
            # Check for alerts on destination IP
            dst_alerts = self.r.get(f"alerts:{dst_ip}")
            if dst_alerts:
                evidence.append(f"Destination IP has alerts")
                threat_level += 0.4
            
            # Check timeline for this profile
            profile_key = f"profile_{src_ip}"
            timeline = self.r.hgetall(f"{profile_key}_timeline")
            if timeline:
                # Parse timeline for suspicious activities
                suspicious_count = sum(1 for k, v in timeline.items() if 'malicious' in str(v).lower())
                if suspicious_count > 0:
                    evidence.append(f"{suspicious_count} malicious activities")
                    threat_level += min(0.3, suspicious_count * 0.1)
            
            if evidence:
                self.stats['slips_correlated'] += 1
            
            return threat_level, evidence, min(threat_level, 1.0)
        except Exception as e:
            return 0.0, [], 0.0
    
    def is_cdn_whitelist(self, domain):
        """
        Check if domain is a CDN that carries both ads and content (SSAI)
        These should NEVER be blocked as it breaks content delivery
        """
        domain_lower = domain.lower()
        return any(cdn in domain_lower for cdn in self.cdn_whitelist)
    
    def is_ad_control_plane(self, domain):
        """
        Check if domain is ad decisioning/auction control plane
        These are safe to block - only affect ad loading, not content
        """
        domain_lower = domain.lower()
        return any(ad_domain in domain_lower for ad_domain in self.ad_control_plane)
    
    def is_ad_domain(self, domain):
        """Check if domain matches ad patterns (legacy method)"""
        domain_lower = domain.lower()
        return any(pattern in domain_lower for pattern in self.ad_patterns)

    def check_ad_pod(self, src_ip, dst_ip, duration, bytes_sent, confidence):
        """
        Detect ad pods (consecutive ads like 2x30s YouTube pre-rolls)
        Boosts confidence when multiple ads detected in sequence
        Returns: (is_pod, pod_confidence_boost)
        """
        current_time = time.time()
        flow_key = (src_ip, dst_ip)
        
        # Clean old entries outside time window
        self.ad_pod_tracking[flow_key] = [
            ad for ad in self.ad_pod_tracking[flow_key]
            if current_time - ad['timestamp'] < self.AD_POD_WINDOW
        ]
        
        # Add current potential ad
        if confidence > 0.5:
            self.ad_pod_tracking[flow_key].append({
                'timestamp': current_time,
                'duration': duration,
                'bytes': bytes_sent,
                'confidence': confidence
            })
        
        # Check if this is part of an ad pod
        recent_ads = self.ad_pod_tracking[flow_key]
        if len(recent_ads) >= self.AD_POD_MIN_COUNT:
            # Multiple ads in sequence - likely an ad pod (2x30s, etc.)
            total_duration = sum(ad['duration'] for ad in recent_ads)
            avg_confidence = sum(ad['confidence'] for ad in recent_ads) / len(recent_ads)
            
            # Classic YouTube 2x30s pre-roll pattern
            if len(recent_ads) == 2 and 25 <= total_duration <= 70:
                return True, 0.25
            
            # Multi-ad pod (3+ ads)
            if len(recent_ads) >= 3:
                return True, 0.30
            
            # Generic ad pod boost
            return True, 0.15
        
        return False, 0.0

    def analyze_flow_pattern(self, flow_data):
        """
        Analyze flow characteristics to detect in-stream ads
        Includes QUIC-specific detection for YouTube/streaming ads
        Returns: (is_ad, confidence, reason)
        """
        try:
            packets = int(flow_data.get('pkts', 0))
            bytes_sent = int(flow_data.get('bytes', 0))
            duration = float(flow_data.get('dur', 0.1))
            protocol = flow_data.get('proto', '').upper()
            dst_port = int(flow_data.get('dport', 0))
            src_ip = flow_data.get('saddr', '')
            dst_ip = flow_data.get('daddr', '')

            # Calculate flow characteristics
            avg_packet_size = bytes_sent / max(packets, 1)
            packet_rate = packets / max(duration, 0.1)
            byte_rate = bytes_sent / max(duration, 0.1)

            # Ad detection heuristics based on flow patterns
            reasons = []
            confidence = 0.0
            is_quic = (protocol == 'UDP' and dst_port == 443)

            # QUIC-specific detection (YouTube, modern streaming)
            # Based on 2025 YouTube ad patterns research
            if is_quic:
                # QUIC ads have distinct patterns vs content

                # 1. Bumper ads (≤6 seconds, non-skippable)
                if duration <= 6 and bytes_sent > 50000:
                    confidence += 0.35
                    reasons.append(f"quic_bumper:{duration:.1f}s")

                # 2. Skippable ads (forced 5s minimum view, total 15-30s)
                if 5 <= duration <= 30 and byte_rate > 100000:
                    confidence += 0.3
                    reasons.append(f"quic_skippable:{duration:.1f}s")

                # 3. Non-skippable ads (15-20s standard, 30s on TV)
                if 15 <= duration <= 30 and 1000000 < bytes_sent < 15000000:
                    confidence += 0.35
                    reasons.append(f"quic_unskippable:{duration:.1f}s")

                # 4. Long forced ads (30s+ on smart TVs)
                if 30 < duration <= 60 and bytes_sent < 25000000:
                    confidence += 0.3
                    reasons.append(f"quic_long_ad:{duration:.1f}s")

                # 5. Mid-roll ad breaks (multiple ads, variable duration)
                if 10 < duration < 120 and 500000 < bytes_sent < 50000000:
                    confidence += 0.25
                    reasons.append(f"quic_midroll:{bytes_sent/1024/1024:.1f}MB")

                # 6. Pre-roll ad sequences (may include multiple ads)
                if duration < 180 and packet_rate > 50:
                    confidence += 0.2
                    reasons.append(f"quic_preroll_seq:{packet_rate:.0f}pps")

                # 7. Ad beacons & tracking (tiny flows for analytics)
                if bytes_sent < 50000 and packets < 20:
                    confidence += 0.2
                    reasons.append(f"quic_beacon")

                # 8. Bitrate analysis: Ads use lower bitrate encoding
                # Ads: ~1100-1300 bytes/packet (lower quality to save bandwidth)
                # Content: ~1350-1500 bytes/packet (higher quality)
                if 1000 < avg_packet_size < 1300 and duration <= 60:
                    confidence += 0.15
                    reasons.append(f"quic_ad_bitrate:{avg_packet_size:.0f}b/pkt")

            # Standard TCP/HTTP detection
            else:
                # 1. Short duration flows (3-60 seconds) - typical for ads
                if 3 < duration < 60:
                    confidence += 0.2
                    reasons.append(f"ad_duration:{duration:.1f}s")

                # 2. Moderate data size (5KB - 50MB) - typical ad size
                if 5000 < bytes_sent < 50000000:
                    confidence += 0.15
                    reasons.append(f"ad_size:{bytes_sent/1024:.1f}KB")

                # 3. High packet rate indicates streaming, but short = ad
                if packet_rate > 10 and duration < 45:
                    confidence += 0.2
                    reasons.append(f"burst_pattern")

            # 4. Small packet count but high data rate = preroll ad
            if packets < 100 and byte_rate > 10000:
                confidence += 0.25
                reasons.append(f"preroll_pattern")

            # 5. Typical ad byte patterns (compressed video ads)
            if 100000 < bytes_sent < 10000000 and 5 < duration < 30:
                confidence += 0.2
                reasons.append(f"video_ad_pattern")

            # Check for ad pod (consecutive ads like 2x30s YouTube pre-rolls)
            is_pod, pod_boost = self.check_ad_pod(src_ip, dst_ip, duration, bytes_sent, confidence)
            if is_pod:
                confidence += pod_boost
                reasons.append(f"ad_pod:{len(self.ad_pod_tracking.get((src_ip, dst_ip), []))}ads")

            is_ad = confidence > 0.5

            return is_ad, min(confidence, 0.95), ', '.join(reasons) if reasons else 'no_match'

        except Exception as e:
            return False, 0.0, f"error:{e}"

    def get_blocking_status(self):
        """Check if live blocking is enabled"""
        enabled = self.r_stats.get('ml_detector:blocking_enabled')
        if enabled:
            enabled = enabled.decode() if isinstance(enabled, bytes) else enabled
            return enabled == '1'
        return False

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

    def block_flow(self, src_ip, dst_ip, dst_port, protocol, confidence, reason):
        """
        Block specific flow using conntrack - surgical strike on ad flows only
        Doesn't block entire IP, just drops this specific connection
        Perfect for CDN IPs where legitimate content shares same IP as ads
        """
        if confidence < 0.40:
            return False
        
        # Skip private IPs
        if self.is_private_ip(dst_ip):
            return False
        
        try:
            # Use conntrack to drop this specific flow
            # This terminates the connection without blocking future connections to same IP
            proto_arg = 'udp' if protocol.upper() == 'UDP' else 'tcp'
            cmd = f'sudo conntrack -D -p {proto_arg} --orig-dst {dst_ip} --dst-port {dst_port} --src {src_ip} 2>/dev/null'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0 or 'flow entries' in result.stdout:
                self.stats['flows_dropped'] += 1
                self.stats['cdn_flow_blocks'] += 1
                
                # Log the flow drop
                log_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'action': 'drop_flow',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'confidence': confidence,
                    'reason': reason
                }
                self.r_stats.lpush('ml_detector:flow_drops', json.dumps(log_entry))
                self.r_stats.ltrim('ml_detector:flow_drops', 0, 499)
                
                print(f"[*] DROPPED FLOW: {src_ip} -> {dst_ip}:{dst_port} ({confidence:.0%} confidence - {reason})")
                return True
            
            return False
        except Exception as e:
            print(f"[!] Flow drop failed: {e}")
            return False
    
    def block_flow_via_suricata(self, src_ip, src_port, dst_ip, dst_port, proto='udp', reason='LLM-detected video ad'):
        """
        Block specific flow tuple via Suricata dynamic dataset injection
        CRITICAL: Blocks FLOW not IP - prevents CDN collateral damage
        
        Flow tuple format: src_ip:src_port->dst_ip:dst_port:protocol
        Uses suricatasc socket command for runtime dataset injection
        """
        flow_tuple = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{proto}"
        
        # Check if flow already blocked
        if flow_tuple in self.blocked_flows:
            return True
        
        try:
            # Create dataset directory if needed
            dataset_dir = '/var/lib/suricata/datasets'
            dataset_file = f'{dataset_dir}/llm-blocked-flows.lst'
            
            # Ensure directory exists
            subprocess.run(['sudo', 'mkdir', '-p', dataset_dir], 
                          capture_output=True, text=True, check=False)
            
            # Add flow to persistent dataset file
            append_cmd = f'echo "{flow_tuple}" | sudo tee -a {dataset_file}'
            result = subprocess.run(append_cmd, shell=True, 
                                  capture_output=True, text=True, check=False)
            
            # Inject into live Suricata via suricatasc
            dataset_add_cmd = {
                "command": "dataset-add",
                "arguments": {
                    "setname": "llm-blocked-flows",
                    "settype": "md5",
                    "datavalue": flow_tuple
                }
            }
            
            inject_cmd = f"echo '{json.dumps(dataset_add_cmd)}' | sudo suricatasc -c"
            inject_result = subprocess.run(inject_cmd, shell=True,
                                          capture_output=True, text=True, check=False)
            
            if inject_result.returncode == 0 or 'already exists' in inject_result.stdout.lower():
                self.blocked_flows.add(flow_tuple)
                self.stats['flows_dropped'] += 1
                self.stats['cdn_flow_blocks'] += 1
                
                # Store in Redis for monitoring
                self.r_stats.sadd('stream_blocker:blocked_flows', flow_tuple)
                
                # Log the flow block
                log_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'action': 'suricata_flow_block',
                    'flow': flow_tuple,
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'protocol': proto,
                    'reason': reason
                }
                self.r_stats.lpush('ml_detector:flow_blocks', json.dumps(log_entry))
                self.r_stats.ltrim('ml_detector:flow_blocks', 0, 999)
                
                print(f"[-] FLOW BLOCKED (Suricata): {flow_tuple} ({reason})")
                return True
            else:
                print(f"[!] Suricata flow injection warning: {inject_result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Error blocking flow via Suricata: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def block_ip(self, ip, reason):
        """
        Block entire IP using nftables (uses blocked4 set from main IPS config)
        Reserved for persistent ad servers, not CDN IPs with mixed content
        """
        if ip in self.blocked_ips:
            return True

        # Skip private IPs
        if self.is_private_ip(ip):
            return False

        try:
            # Use the main blocked4 set (not ml_detector_blacklist)
            cmd = f'sudo nft add element inet home blocked4 "{{ {ip} }}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode == 0 or "already exists" in result.stderr.lower():
                self.blocked_ips.add(ip)
                self.stats['ips_blocked'] += 1
                self.stats['ad_server_blocks'] += 1

                # Add to Redis blacklist
                self.r_stats.sadd('ml_detector:blacklist:ip', ip)

                # Log the action
                log_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'action': 'auto_block_ip',
                    'ip': ip,
                    'reason': reason
                }
                self.r_stats.lpush('ml_detector:action_logs', json.dumps(log_entry))
                self.r_stats.ltrim('ml_detector:action_logs', 0, 499)

                print(f"[-] BLOCKED IP: {ip} ({reason})")
                return True
            else:
                print(f"[!] Failed to block {ip}: {result.stderr}")
                return False

        except Exception as e:
            print(f"❌ Error blocking {ip}: {e}")
            return False

    def block_url(self, domain, reason):
        """Block URL using Suricata HTTP inspection"""
        if domain in self.blocked_urls:
            return True

        try:
            # Generate unique SID for this rule
            sid = 9000000 + len(self.blocked_urls)

            # Create Suricata rule to drop traffic to this domain
            rule = f'drop http any any -> any any (msg:"ML Detector - Auto-blocked ad domain {domain}"; content:"Host: {domain}"; http_header; nocase; classtype:policy-violation; sid:{sid}; rev:1;)\n'

            # Append to custom rules file
            rules_file = '/etc/suricata/rules/ml-detector-blocking.rules'
            with open(rules_file, 'a') as f:
                f.write(rule)

            # Reload Suricata rules
            subprocess.run(['sudo', 'suricatasc', '-c', 'reload-rules'],
                         capture_output=True, text=True)

            self.blocked_urls.add(domain)
            self.stats['urls_blocked'] += 1

            # Add to Redis blacklist
            self.r_stats.sadd('ml_detector:blacklist:url', domain)

            # Log the action
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'action': 'auto_block_url',
                'url': domain,
                'reason': reason
            }
            self.r_stats.lpush('ml_detector:action_logs', json.dumps(log_entry))
            self.r_stats.ltrim('ml_detector:action_logs', 0, 499)

            print(f"[-] BLOCKED URL: {domain} ({reason})")
            return True

        except Exception as e:
            print(f"❌ Error blocking {domain}: {e}")
            return False

    def learn_youtube_pattern(self, dst_ip, flow_data, is_ad, confidence):
        """
        Learn YouTube ad patterns for future detection
        Stores connection characteristics to improve QUIC ad detection
        """
        try:
            # Only learn from YouTube/QUIC connections
            protocol = flow_data.get('proto', '').upper()
            dst_port = int(flow_data.get('dport', 0))

            if protocol == 'UDP' and dst_port == 443:
                # Extract features
                pattern = {
                    'ip': dst_ip,
                    'duration': float(flow_data.get('dur', 0)),
                    'bytes': int(flow_data.get('bytes', 0)),
                    'packets': int(flow_data.get('pkts', 0)),
                    'avg_pkt_size': int(flow_data.get('bytes', 0)) / max(int(flow_data.get('pkts', 1)), 1),
                    'byte_rate': int(flow_data.get('bytes', 0)) / max(float(flow_data.get('dur', 0.1)), 0.1),
                    'is_ad': is_ad,
                    'confidence': confidence,
                    'timestamp': datetime.now().isoformat()
                }

                # Store in Redis for ML retraining
                self.r_stats.lpush('ml_detector:youtube_quic_patterns', json.dumps(pattern))
                self.r_stats.ltrim('ml_detector:youtube_quic_patterns', 0, 9999)  # Keep last 10k patterns

                # Cache locally for immediate use
                if dst_ip not in self.youtube_connection_cache:
                    self.youtube_connection_cache[dst_ip] = []

                self.youtube_connection_cache[dst_ip].append(pattern)

                # Keep cache size reasonable (max 100 IPs, 50 patterns each)
                if len(self.youtube_connection_cache) > 100:
                    # Remove oldest IP
                    oldest_ip = list(self.youtube_connection_cache.keys())[0]
                    del self.youtube_connection_cache[oldest_ip]

                if len(self.youtube_connection_cache[dst_ip]) > 50:
                    self.youtube_connection_cache[dst_ip] = self.youtube_connection_cache[dst_ip][-50:]

        except Exception as e:
            print(f"[!] Error learning pattern: {e}")

    def process_detection(self, domain, dst_ip, confidence, method, flow_data):
        """Process a detected ad and optionally block it"""
        now = datetime.now()

        # Create detection record
        detection = {
            'timestamp': now.isoformat(),
            'timestamp_formatted': now.strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': flow_data.get('src_ip', 'Unknown'),
            'dst_ip': dst_ip,
            'dst_port': flow_data.get('dport', 443),
            'protocol': flow_data.get('proto', 'HTTPS'),
            'classification': f'Ad: {domain}',
            'confidence': round(confidence, 2),
            'bytes': flow_data.get('bytes', 0),
            'packets': flow_data.get('pkts', 0),
            'duration': flow_data.get('dur', 0),
            'detection_method': method,
            'threat_level': 'MEDIUM' if confidence > 0.8 else 'INFO'
        }

        # Store detection
        self.r_stats.lpush('ml_detector:recent_detections', json.dumps(detection))
        self.r_stats.ltrim('ml_detector:recent_detections', 0, 99)
        
        # Store timeline entry for chart
        timeline_entry = {
            'timestamp': now.isoformat(),
            'hour': now.strftime('%H:00'),
            'classification': 'ad',
            'confidence': round(confidence, 2),
            'method': method
        }
        self.r_stats.lpush('ml_detector:timeline', json.dumps(timeline_entry))
        self.r_stats.ltrim('ml_detector:timeline', 0, 999)

        self.stats['ads_detected'] += 1

        # Check if blocking is enabled
        blocking_enabled = self.get_blocking_status()

        blocked = False
        if blocking_enabled:
            # Check if whitelisted
            if self.r.sismember('ml_detector:whitelist:ip', dst_ip):
                print(f"⚪ Skipping block - IP {dst_ip} is whitelisted")
                return detection

            if self.r.sismember('ml_detector:whitelist:url', domain):
                print(f"⚪ Skipping block - URL {domain} is whitelisted")
                return detection

            # Check CDN whitelist (for SSAI-enabled CDNs only)
            if self.is_cdn_whitelist(domain):
                print(f"⚪ CDN WHITELIST: {domain} uses SSAI - detection logged only")
                return detection
            
            # Determine domain type
            is_control_plane = self.is_ad_control_plane(domain)
            # Check if this is ANY video streaming platform (not just YouTube)
            is_video_platform = any(
                any(pattern in domain.lower() for pattern in patterns)
                for service_name, patterns in self.streaming_services
            )
            is_cdn = any(cdn in domain.lower() for cdn in ['cloudfront', 'akamai', 'fastly', 'edgecast'])
            
            # Verbose logging for video platform flows
            if is_video_platform:
                platform = next((name for name, patterns in self.streaming_services 
                               if any(p in domain.lower() for p in patterns)), 'unknown')
                print(f"[VIDEO/{platform.upper()}] {domain} | dur={flow_data.get('dur', 0):.1f}s bytes={flow_data.get('sbytes', 0)} pkts={flow_data.get('spkts', 0)} | confidence={confidence:.2%} method={method}")
            
            # Strategy 1: IP-level block for ad control plane (prevents ad auctions)
            # Control plane = small payloads for ad decisioning, safe to block
            if is_control_plane and confidence >= self.control_plane_threshold:
                if self.block_ip(dst_ip, f"ad_control_plane:{method}"):
                    blocked = True
                    detection['block_type'] = 'ip_control_plane'
                    print(f"[-] AD CONTROL BLOCK: {domain} ({confidence:.0%} confidence - blocks ad auctions)")
            
            # Strategy 2: Flow-level blocking for video streaming platforms
            # Detects ad streams on YouTube, Twitch, Vimeo, etc by flow characteristics
            # Uses Suricata flow-based blocking for surgical precision (NO SSAI regions)
            elif is_video_platform and confidence >= self.youtube_threshold:
                if self.block_flow_via_suricata(
                    flow_data.get('src_ip', '0.0.0.0'),
                    flow_data.get('sport', 0),
                    dst_ip,
                    flow_data.get('dport', 443),
                    flow_data.get('proto', 'udp').lower(),
                    f"video_ad_flow:{method}:{confidence:.2f}"
                ):
                    blocked = True
                    detection['block_type'] = 'suricata_flow_video_ad'
                    print(f"[-] VIDEO AD FLOW BLOCKED: {domain} ({confidence:.0%} - ad stream detected)")
                    self.log_detection(domain, detection, flow_data, confidence, method, blocked=True)
            elif is_video_platform and confidence >= 0.40:
                print(f"[i] Video flow below threshold: {domain} confidence={confidence:.2%} dur={flow_data.get('dur', 0):.1f}s bytes={flow_data.get('sbytes', 0)}")
                self.log_detection(domain, detection, flow_data, confidence, method, blocked=False)
            
            # Strategy 3: Flow-level blocking for other CDNs
            # Higher confidence threshold for non-YouTube CDNs
            elif is_cdn and confidence >= self.cdn_threshold:
                # Use Suricata flow blocking (prevents CDN collateral damage)
                if self.block_flow_via_suricata(
                    flow_data.get('src_ip', '0.0.0.0'),
                    flow_data.get('sport', 0),
                    dst_ip,
                    flow_data.get('dport', 443),
                    flow_data.get('proto', 'udp').lower(),
                    f"cdn_ad_flow:{method}:{confidence:.2f}"
                ):
                    blocked = True
                    detection['block_type'] = 'suricata_flow_cdn'
                    print(f"[-] CDN AD FLOW BLOCKED (Suricata): {domain} ({confidence:.0%} confidence)")
            
            # Strategy 4: Hybrid approach - try flow first, fallback to IP if very high confidence
            elif confidence >= 0.90:
                # Try flow-level first (less aggressive)
                if self.block_flow(
                    flow_data.get('src_ip', '0.0.0.0'),
                    dst_ip,
                    flow_data.get('dport', 443),
                    flow_data.get('proto', 'HTTPS'),
                    confidence,
                    method
                ):
                    blocked = True
                    detection['block_type'] = 'flow'
                else:
                    # Very high confidence + flow block failed = block IP
                    if self.block_ip(dst_ip, method):
                        blocked = True
                        detection['block_type'] = 'ip_fallback'
            
            # Always try URL blocking via Suricata (HTTP inspection)
            if self.block_url(domain, method):
                blocked = True
                detection['block_type'] = detection.get('block_type', 'url') + '+url'

        status = "BLOCKED" if blocked else "DETECTED"
        print(f"[*] {status}: {domain} → {dst_ip} (confidence: {confidence:.2f}, method: {method})")

        return detection

    def monitor_flows(self):
        """Main monitoring loop - subscribes to SLIPS new_flow channel (Zeek flows)"""
        # Force unbuffered output
        import sys
        sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)
        sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', buffering=1)
        
        print("[*] Starting Stream Ad Blocker & Telemetry Filter...", flush=True)
        print(f"   ML Classifier: {'Enabled' if self.classifier else 'Disabled'}", flush=True)
        
        # Start LLM background processor
        if self.classifier:
            self.start_llm_background_processor()
            print(f"   LLM Queue Processor: Started (threshold range: {self.llm_min_threshold}-{self.llm_max_threshold})", flush=True)
        
        # Report blocking pattern counts
        blocklist_count = 0
        if self.blocklist_db:
            try:
                blocklist_count = self.blocklist_db.execute("SELECT COUNT(*) FROM blocked_domains").fetchone()[0]
            except:
                pass
        
        if blocklist_count > 0:
            print(f"   Blocklist Database: {blocklist_count:,} domains", flush=True)
        print(f"   Hardcoded Patterns: {len(self.ad_patterns)} ad/telemetry domains", flush=True)
        total_patterns = blocklist_count + len(self.ad_patterns)
        print(f"   Total Blocking Patterns: {total_patterns:,}", flush=True)
        print(f"   Streaming Services: {len(self.streaming_services)} services monitored", flush=True)
        print(f"   Flow-based QUIC/HTTP3 analysis via Zeek", flush=True)
        print(f"   Subscribing to SLIPS 'new_flow' channel", flush=True)
        print()

        seen_flows = set()
        iteration = 0

        # Create pubsub connection
        pubsub = self.r.pubsub()
        pubsub.subscribe('new_flow')
        print("[+] Subscribed to 'new_flow' channel", flush=True)

        blocking_enabled = self.get_blocking_status()
        status_icon = "[*]" if blocking_enabled else "[!]"
        print(f"{status_icon} Live Blocking: {'ENABLED' if blocking_enabled else 'DISABLED'}\n", flush=True)

        for message in pubsub.listen():
            try:
                if message['type'] != 'message':
                    continue

                iteration += 1
                
                # Update blocking status periodically
                if iteration % 100 == 0:
                    blocking_enabled = self.get_blocking_status()
                    status_icon = "[*]" if blocking_enabled else "[!]"
                    print(f"\n{status_icon} Stats: {self.stats['total_analyzed']} flows analyzed, "
                          f"{self.stats['ads_detected']} ads detected, "
                          f"{self.stats['flows_dropped']} flows dropped", flush=True)

                # Parse flow data from SLIPS
                flow_data_raw = message['data']
                if isinstance(flow_data_raw, bytes):
                    flow_data_raw = flow_data_raw.decode('utf-8')
                
                flow_info = json.loads(flow_data_raw)
                
                # Extract flow details
                # SLIPS flow format: profileid, twid, flow data
                profileid = flow_info.get('profileid', '')
                flow = flow_info.get('flow', {})
                
                # Extract port and protocol
                dport = flow.get('dport', 0)
                proto = flow.get('proto', '').lower()
                
                # Skip DNS queries (we only want data flows)
                if dport == 53:
                    continue

                self.stats['total_analyzed'] += 1
                # Extract relevant fields
                src_ip = profileid.split('_')[0] if '_' in profileid else flow.get('saddr', '')
                dst_ip = flow.get('daddr', '')
                src_port = flow.get('sport', 0)
                pkts = flow.get('spkts', 0) + flow.get('dpkts', 0)
                bytes_sent = flow.get('sbytes', 0) + flow.get('dbytes', 0)
                duration = flow.get('dur', 0)
                
                # Create flow identifier
                flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dport}"
                
                # Skip if already analyzed recently
                if flow_id in seen_flows:
                    continue
                seen_flows.add(flow_id)
                
                # Construct flow_data for analysis
                flow_data = {
                    'src_ip': src_ip,
                    'sport': src_port,
                    'dport': dport,
                    'proto': 'udp',
                    'pkts': pkts,
                    'bytes': bytes_sent,
                    'dur': duration
                }
                
                # Try to resolve IP to domain via SLIPS data
                domain = None
                try:
                    # Check DomainsResolved
                    for resolved_domain in self.r.hkeys('DomainsResolved'):
                        ip_data = self.r.hget('DomainsResolved', resolved_domain)
                        if dst_ip in str(ip_data):
                            domain = resolved_domain
                            break
                except:
                    pass
                
                # If no domain found, use IP
                if not domain:
                    domain = dst_ip
                
                # Multi-source detection pipeline
                detection_sources = []
                confidence_scores = []
                
                # 1. Check blocklist database (if domain resolved)
                if domain != dst_ip:
                    is_blocklisted, bl_category, bl_confidence = self.check_blocklist_db(domain)
                    if is_blocklisted:
                        detection_sources.append(f"Blocklist:{bl_category}")
                        confidence_scores.append(bl_confidence)
                
                # 2. Analyze flow pattern (CRITICAL for QUIC ad detection)
                is_ad_flow, flow_confidence, flow_reason = self.analyze_flow_pattern(flow_data)
                if is_ad_flow:
                    detection_sources.append(f"Flow:{flow_reason}")
                    confidence_scores.append(flow_confidence)
                
                # 3. Query SLIPS behavioral analysis
                slips_threat, slips_evidence, slips_confidence = self.get_slips_evidence(
                    src_ip, dst_ip
                )
                if slips_threat > 0:
                    detection_sources.append(f"SLIPS:{'+'.join(slips_evidence)}")
                    confidence_scores.append(slips_confidence)
                
                # 4. Use ML classifier with optional background LLM enhancement
                # Run ML on all flows for better detection and LLM training data
                if self.classifier:
                    # Get DNS history
                    dns_history = []
                    try:
                        dns_key = f"profile_{src_ip}_dns"
                        dns_records = self.r.lrange(dns_key, 0, 10)
                        dns_history = [r.decode('utf-8') if isinstance(r, bytes) else r for r in dns_records]
                    except:
                        pass
                    
                    # Use fast ML classification (no LLM blocking)
                    is_ad_ml, ml_confidence, ml_method = self.classifier.classify_flow(
                        domain, flow_data, dst_ip, 443
                    )
                    
                    # Queue for background LLM labeling if in threshold range
                    if (self.llm_min_threshold <= ml_confidence <= self.llm_max_threshold):
                        try:
                            # Add to queue for async LLM processing
                            detection_data = {
                                'domain': domain,
                                'flow_data': flow_data,
                                'dst_ip': dst_ip,
                                'dns_history': dns_history,
                                'ml_confidence': ml_confidence,
                                'ml_method': ml_method,
                                'timestamp': time.time(),
                                'flow_id': flow_id
                            }
                            self.llm_queue.put_nowait(detection_data)
                            self.stats['llm_queue_size'] = self.llm_queue.qsize()
                            print(f"[→ LLM Queue] {domain} (conf={ml_confidence:.2f}, queue_size={self.llm_queue.qsize()})", flush=True)
                        except queue.Full:
                            print(f"[!] LLM queue full, skipping {domain}", flush=True)
                        except Exception as e:
                            print(f"[!] Failed to queue for LLM: {e}", flush=True)
                    
                    if is_ad_ml:
                        detection_sources.append(f"ML:{ml_method}")
                        confidence_scores.append(ml_confidence)
                        self.stats['ml_detections'] += 1
                
                # Process detection if confidence threshold met
                if confidence_scores:
                    avg_confidence = sum(confidence_scores) / len(confidence_scores)
                    # Boost confidence if multiple sources agree
                    multi_source_boost = min(0.15, (len(detection_sources) - 1) * 0.05)
                    combined_confidence = min(1.0, avg_confidence + multi_source_boost)
                    
                    method = " + ".join(detection_sources)
                    
                    # Learn from YouTube/QUIC patterns
                    if 'google' in dst_ip or (domain and 'google' in domain.lower()):
                        self.learn_youtube_pattern(dst_ip, flow_data, True, combined_confidence)
                    
                    self.process_detection(domain, dst_ip, combined_confidence, method, flow_data)
                
                # Periodically update stats (every 10 flows)
                if self.stats['total_analyzed'] % 10 == 0:
                    stats_update = {
                        'total_analyzed': str(self.stats['total_analyzed']),
                        'ads_detected': str(self.stats['ads_detected']),
                        'stream_ads_detected': str(self.stats['ads_detected']),
                        'ips_blocked': str(self.stats['ips_blocked']),
                        'urls_blocked': str(self.stats['urls_blocked']),
                        'flows_dropped': str(self.stats['flows_dropped']),
                        'cdn_flow_blocks': str(self.stats['cdn_flow_blocks']),
                        'legitimate_traffic': str(self.stats['total_analyzed'] - self.stats['ads_detected']),
                        'legitimate_streams': str(self.stats['total_analyzed'] - self.stats['ads_detected']),
                        'last_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'blocking_status': 'Active' if blocking_enabled else 'Monitoring Only',
                        'llm_enhanced_detections': str(self.stats.get('llm_enhanced_detections', 0)),
                        'llm_queue_size': str(self.stats.get('llm_queue_size', 0)),
                        'llm_processed': str(self.stats.get('llm_processed', 0))
                    }
                    self.r_stats.hset('stream_ad_blocker:stats', mapping=stats_update)
                
                # Clean seen_flows cache periodically
                if len(seen_flows) > 10000:
                    seen_flows = set(list(seen_flows)[-5000:])

            except KeyboardInterrupt:
                raise
            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"❌ Error processing flow: {e}", flush=True)
                import traceback
                traceback.print_exc()

if __name__ == '__main__':
    blocker = None
    try:
        blocker = StreamAdBlocker()
        blocker.monitor_flows()
    except KeyboardInterrupt:
        print("\n\n[*] Stream Ad Blocker stopped")
        if blocker:
            print("[*] Stopping LLM background processor...")
            blocker.stop_llm_background_processor()
            if hasattr(blocker, 'classifier'):
                print(f"[*] Flushing training samples... (LLM processed: {blocker.stats.get('llm_processed', 0)})")
                blocker.classifier.flush_training_samples()
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        if blocker:
            blocker.stop_llm_background_processor()
            if hasattr(blocker, 'classifier'):
                blocker.classifier.flush_training_samples()
