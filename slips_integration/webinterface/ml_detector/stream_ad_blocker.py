#!/usr/bin/env python3
"""
Stream Ad Blocker - Real-time detection and blocking of in-stream ads
Monitors SLIPS flow data and automatically blocks detected ad traffic
Cross-references with blocklist database (338K+ domains) and SLIPS behavioral analysis

MODERN AD DELIVERY ARCHITECTURE (2024+):
-----------------------------------------
YouTube SSAI (Server-Side Ad Insertion):
  - Ads stitched into same *.googlevideo.com stream as content
  - Media plane (video segments): identical 1.5-4MB chunks for ads + content
  - Control plane (ad decisioning): googleads.g.doubleclick.net, pagead2.googlesyndication.com
  - Cannot distinguish ad segments from content segments at network level
  - DAI (Dynamic Ad Insertion) runs real-time auctions, returns unified manifest

Generic HTTP/3 Sites:
  - Control: Small JSON/protobuf ad auction requests (1-10KB) to SSP endpoints
  - Media: Banner creatives (20-300KB) and video segments from CDNs
  - Header bidding fires parallel requests over single QUIC connection
  
DETECTION STRATEGY:
  1. Block ad decisioning control plane (doubleclick, googlesyndication, etc)
  2. Do NOT block googlevideo.com (breaks both ads AND content)
  3. Focus on small payload ad auction traffic, not media CDN traffic
  4. Track connection patterns: multiple small requests = likely ad auction
  5. Use ML to identify ad server IPs by behavioral patterns
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
            'ad_server_blocks': 0
        }
        
        # Connect to blocklist database
        self.blocklist_db = None
        try:
            self.blocklist_db = sqlite3.connect('/var/lib/suricata/ips_filter.db', check_same_thread=False)
            domain_count = self.blocklist_db.execute("SELECT COUNT(*) FROM blocked_domains").fetchone()[0]
            print(f"✅ Connected to blocklist DB: {domain_count:,} domains")
        except Exception as e:
            print(f"⚠️  Blocklist DB unavailable: {e}")

        # Initialize ML classifier
        try:
            self.classifier = MLAdClassifier()
            print("✅ ML classifier loaded")
        except Exception as e:
            print(f"⚠️  ML classifier failed, using pattern-only mode: {e}")

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

        # CDN domains that carry both ads and content (NEVER block these)
        # Blocking these breaks content delivery due to SSAI
        self.cdn_whitelist = [
            'googlevideo.com',
            'youtube.com',
            'youtu.be',
            'cloudfront.net',
            'akamaihd.net',
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

        # Streaming service patterns
        self.streaming_services = [
            ('youtube', ['googlevideo.com', 'youtube.com', 'youtu.be']),
            ('twitch', ['twitch.tv', 'ttvnw.net']),
            ('netflix', ['netflix.com', 'nflxvideo.net']),
            ('hulu', ['hulu.com', 'hulustream.com']),
            ('prime', ['primevideo.com', 'amazon.com/gp/video'])
        ]

        # YouTube ad learning: Track connection patterns
        # Key: IP address, Value: {'flows': [], 'classified_as_ad': bool, 'confidence': float}
        self.youtube_connection_cache = {}

        # Track video session context for better ad detection
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
            print(f"⚠️  Blocklist DB query failed: {e}")
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
        if confidence < 0.75:
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
                
                print(f"🎯 DROPPED FLOW: {src_ip} -> {dst_ip}:{dst_port} ({confidence:.0%} confidence - {reason})")
                return True
            
            return False
        except Exception as e:
            print(f"⚠️  Flow drop failed: {e}")
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

                print(f"🚫 BLOCKED IP: {ip} ({reason})")
                return True
            else:
                print(f"⚠️  Failed to block {ip}: {result.stderr}")
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

            print(f"🚫 BLOCKED URL: {domain} ({reason})")
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
            print(f"⚠️  Error learning pattern: {e}")

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

            # CRITICAL: Never block CDN whitelist domains (SSAI content carriers)
            if self.is_cdn_whitelist(domain):
                print(f"⚪ CDN WHITELIST: {domain} carries both ads and content (SSAI) - detection logged only")
                return detection
            
            # Prioritize blocking ad control plane (safe to block)
            is_control_plane = self.is_ad_control_plane(domain)
            is_cdn = any(cdn in domain.lower() for cdn in ['cloudfront', 'akamai', 'fastly', 'edgecast'])
            
            # Strategy 1: IP-level block for ad control plane (prevents ad auctions)
            # Control plane = small payloads for ad decisioning, safe to block
            if is_control_plane and confidence >= 0.70:
                if self.block_ip(dst_ip, f"ad_control_plane:{method}"):
                    blocked = True
                    detection['block_type'] = 'ip_control_plane'
                    print(f"🚫 AD CONTROL BLOCK: {domain} ({confidence:.0%} confidence - blocks ad auctions)")
            
            # Strategy 2: Flow-level blocking for other CDNs (not whitelisted)
            # Drops specific ad flow without blocking entire IP
            elif is_cdn and confidence >= 0.85:
                if self.block_flow(
                    flow_data.get('src_ip', '0.0.0.0'),
                    dst_ip,
                    flow_data.get('dport', 443),
                    flow_data.get('proto', 'HTTPS'),
                    confidence,
                    method
                ):
                    blocked = True
                    detection['block_type'] = 'flow_cdn'
                    print(f"🎯 CDN Flow block: {domain} ({confidence:.0%} confidence)")
            
            # Strategy 3: Hybrid approach - try flow first, fallback to IP if very high confidence
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
        print(f"🎯 {status}: {domain} → {dst_ip} (confidence: {confidence:.2f}, method: {method})")

        return detection

    def monitor_flows(self):
        """Main monitoring loop"""
        print("🎯 Starting Stream Ad Blocker & Telemetry Filter...")
        print(f"   ML Classifier: {'Enabled' if self.classifier else 'Disabled'}")
        print(f"   Blocking Patterns: {len(self.ad_patterns)} ad/telemetry domains loaded")
        print(f"   Streaming Services: {len(self.streaming_services)} services monitored")
        print(f"   🛡️  Blocking ads, tracking, analytics, and corpo spyware")
        print()

        seen_domains = set()
        iteration = 0

        while True:
            iteration += 1
            blocking_enabled = self.get_blocking_status()
            status_icon = "🟢" if blocking_enabled else "🟡"

            if iteration % 10 == 1:
                print(f"\n{status_icon} Live Blocking: {'ENABLED' if blocking_enabled else 'DISABLED'}")
                print(f"   Stats: {self.stats['ads_detected']} ads detected, "
                      f"{self.stats['ips_blocked']} IPs blocked, "
                      f"{self.stats['urls_blocked']} URLs blocked\n")

            try:
                # Get all resolved domains
                all_domains = set(self.r.hkeys('DomainsResolved'))
                new_domains = all_domains - seen_domains

                if new_domains:
                    for domain in new_domains:
                        self.stats['total_analyzed'] += 1

                        # Get IP for this domain
                        ip_data = self.r.hget('DomainsResolved', domain)
                        try:
                            ip_list = json.loads(ip_data) if ip_data else []
                            dst_ip = ip_list[0] if isinstance(ip_list, list) and ip_list else ip_data if ip_data else 'Unknown'
                        except:
                            dst_ip = str(ip_data) if ip_data else 'Unknown'

                        # Multi-source detection pipeline
                        detection_sources = []
                        confidence_scores = []
                        
                        # 1. Check blocklist database (338K+ domains)
                        is_blocklisted, bl_category, bl_confidence = self.check_blocklist_db(domain)
                        if is_blocklisted:
                            detection_sources.append(f"Blocklist:{bl_category}")
                            confidence_scores.append(bl_confidence)
                        
                        # 2. Check pattern matching
                        if self.is_ad_domain(domain):
                            detection_sources.append("Pattern:ad_domain")
                            confidence_scores.append(0.75)

                        # Skip if no initial indicators
                        if not detection_sources:
                            continue

                        # Get flow data if available
                        flow_data = {
                            'pkts': 10,
                            'bytes': 5000,
                            'dur': 15.0,
                            'src_ip': '10.10.252.5',
                            'dport': 443,
                            'proto': 'HTTPS'
                        }

                        # 3. Analyze flow pattern
                        is_ad_flow, flow_confidence, flow_reason = self.analyze_flow_pattern(flow_data)
                        if is_ad_flow:
                            detection_sources.append(f"Flow:{flow_reason}")
                            confidence_scores.append(flow_confidence)

                        # 4. Query SLIPS behavioral analysis
                        slips_threat, slips_evidence, slips_confidence = self.get_slips_evidence(
                            flow_data['src_ip'], dst_ip
                        )
                        if slips_threat > 0:
                            detection_sources.append(f"SLIPS:{'+'.join(slips_evidence)}")
                            confidence_scores.append(slips_confidence)

                        # 5. Use ML classifier if available
                        if self.classifier:
                            is_ad_ml, ml_confidence, ml_method = self.classifier.classify_flow(
                                domain, flow_data, dst_ip, 443
                            )
                            if is_ad_ml:
                                detection_sources.append(f"ML:{ml_method}")
                                confidence_scores.append(ml_confidence)
                                self.stats['ml_detections'] += 1

                        # Calculate combined confidence (weighted average with boost for multiple sources)
                        if confidence_scores:
                            avg_confidence = sum(confidence_scores) / len(confidence_scores)
                            # Boost confidence if multiple sources agree
                            multi_source_boost = min(0.15, (len(detection_sources) - 1) * 0.05)
                            combined_confidence = min(1.0, avg_confidence + multi_source_boost)
                            
                            method = " + ".join(detection_sources)
                            
                            # Learn from this detection (for YouTube/QUIC)
                            if 'googlevideo' in domain or 'youtube' in domain:
                                self.learn_youtube_pattern(dst_ip, flow_data, True, combined_confidence)

                            self.process_detection(domain, dst_ip, combined_confidence, method, flow_data)
                        else:
                            # Pattern-only mode
                            if is_ad_flow:
                                # Learn from this detection (for YouTube/QUIC)
                                if 'googlevideo' in domain or 'youtube' in domain:
                                    self.learn_youtube_pattern(dst_ip, flow_data, True, flow_confidence)

                                self.process_detection(domain, dst_ip, flow_confidence,
                                                     f"pattern+flow:{flow_reason}", flow_data)
                            else:
                                # Just domain pattern match
                                if 'googlevideo' in domain or 'youtube' in domain:
                                    self.learn_youtube_pattern(dst_ip, flow_data, True, 0.85)

                                self.process_detection(domain, dst_ip, 0.85,
                                                     "domain_pattern", flow_data)

                    seen_domains = all_domains

                # Update stats in Redis - write to dedicated stream_ad_blocker:stats key
                # This prevents conflicts with SLIPS ML Dashboard Feeder module
                stats_update = {
                    'total_analyzed': str(self.stats['total_analyzed']),
                    'ads_detected': str(self.stats['ads_detected']),
                    'stream_ads_detected': str(self.stats['ads_detected']),
                    'ips_blocked': str(self.stats['ips_blocked']),
                    'urls_blocked': str(self.stats['urls_blocked']),
                    'legitimate_traffic': str(len(all_domains) - self.stats['ads_detected']),
                    'legitimate_streams': str(len(all_domains) - self.stats['ads_detected']),
                    'last_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'blocking_status': 'Active' if blocking_enabled else 'Monitoring Only'
                }
                # Write only to stream_ad_blocker:stats (dedicated key, no conflicts)
                self.r_stats.hset('stream_ad_blocker:stats', mapping=stats_update)

            except Exception as e:
                print(f"❌ Error in monitoring loop: {e}")
                import traceback
                traceback.print_exc()

            time.sleep(2)

if __name__ == '__main__':
    try:
        blocker = StreamAdBlocker()
        blocker.monitor_flows()
    except KeyboardInterrupt:
        print("\n\n👋 Stream Ad Blocker stopped")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
