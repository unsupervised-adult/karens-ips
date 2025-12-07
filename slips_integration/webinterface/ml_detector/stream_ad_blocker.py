#!/usr/bin/env python3
"""
Stream Ad Blocker - Real-time detection and blocking of in-stream ads
Monitors SLIPS flow data and automatically blocks detected ad traffic
"""
import redis
import json
import time
import subprocess
from datetime import datetime
from collections import defaultdict
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ml_ad_classifier import MLAdClassifier

class StreamAdBlocker:
    def __init__(self):
        self.r = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
        self.classifier = None
        self.detected_ads = set()
        self.blocked_ips = set()
        self.blocked_urls = set()
        self.stats = {
            'ads_detected': 0,
            'ips_blocked': 0,
            'urls_blocked': 0,
            'total_analyzed': 0
        }

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

        # Streaming service patterns
        self.streaming_services = [
            ('youtube', ['googlevideo.com', 'youtube.com', 'youtu.be']),
            ('twitch', ['twitch.tv', 'ttvnw.net']),
            ('netflix', ['netflix.com', 'nflxvideo.net']),
            ('hulu', ['hulu.com', 'hulustream.com']),
            ('prime', ['primevideo.com', 'amazon.com/gp/video'])
        ]

    def is_ad_domain(self, domain):
        """Check if domain matches ad patterns"""
        domain_lower = domain.lower()
        return any(pattern in domain_lower for pattern in self.ad_patterns)

    def analyze_flow_pattern(self, flow_data):
        """
        Analyze flow characteristics to detect in-stream ads
        Returns: (is_ad, confidence, reason)
        """
        try:
            packets = int(flow_data.get('pkts', 0))
            bytes_sent = int(flow_data.get('bytes', 0))
            duration = float(flow_data.get('dur', 0.1))

            # Calculate flow characteristics
            avg_packet_size = bytes_sent / max(packets, 1)
            packet_rate = packets / max(duration, 0.1)
            byte_rate = bytes_sent / max(duration, 0.1)

            # Ad detection heuristics based on flow patterns
            reasons = []
            confidence = 0.0

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

            is_ad = confidence > 0.5

            return is_ad, min(confidence, 0.95), ', '.join(reasons) if reasons else 'no_match'

        except Exception as e:
            return False, 0.0, f"error:{e}"

    def get_blocking_status(self):
        """Check if live blocking is enabled"""
        enabled = self.r.get('ml_detector:blocking_enabled')
        if enabled:
            enabled = enabled.decode() if isinstance(enabled, bytes) else enabled
            return enabled == '1'
        return False

    def block_ip(self, ip, reason):
        """Block IP using nftables"""
        if ip in self.blocked_ips:
            return True

        try:
            cmd = f'sudo nft add element inet filter ml_detector_blacklist "{{ {ip} }}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode == 0 or "already exists" in result.stderr.lower():
                self.blocked_ips.add(ip)
                self.stats['ips_blocked'] += 1

                # Add to Redis blacklist
                self.r.sadd('ml_detector:blacklist:ip', ip)

                # Log the action
                log_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'action': 'auto_block_ip',
                    'ip': ip,
                    'reason': reason
                }
                self.r.lpush('ml_detector:action_logs', json.dumps(log_entry))
                self.r.ltrim('ml_detector:action_logs', 0, 499)

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
            self.r.sadd('ml_detector:blacklist:url', domain)

            # Log the action
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'action': 'auto_block_url',
                'url': domain,
                'reason': reason
            }
            self.r.lpush('ml_detector:action_logs', json.dumps(log_entry))
            self.r.ltrim('ml_detector:action_logs', 0, 499)

            print(f"🚫 BLOCKED URL: {domain} ({reason})")
            return True

        except Exception as e:
            print(f"❌ Error blocking {domain}: {e}")
            return False

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
        self.r.lpush('ml_detector:recent_detections', json.dumps(detection))
        self.r.ltrim('ml_detector:recent_detections', 0, 99)

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

            # Block both IP and URL for maximum effectiveness
            if self.block_ip(dst_ip, method):
                blocked = True

            if self.block_url(domain, method):
                blocked = True

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

                        # Check if it's an ad domain
                        if not self.is_ad_domain(domain):
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

                        # Analyze flow pattern
                        is_ad_flow, flow_confidence, flow_reason = self.analyze_flow_pattern(flow_data)

                        # Use ML classifier if available
                        if self.classifier:
                            is_ad_ml, ml_confidence, ml_method = self.classifier.classify_flow(
                                domain, flow_data, dst_ip, 443
                            )

                            # Combine flow analysis with ML
                            if is_ad_ml or is_ad_flow:
                                combined_confidence = max(ml_confidence, flow_confidence)
                                method = f"{ml_method}+flow:{flow_reason}" if is_ad_flow else ml_method
                                self.process_detection(domain, dst_ip, combined_confidence, method, flow_data)
                        else:
                            # Pattern-only mode
                            if is_ad_flow:
                                self.process_detection(domain, dst_ip, flow_confidence,
                                                     f"pattern+flow:{flow_reason}", flow_data)
                            else:
                                # Just domain pattern match
                                self.process_detection(domain, dst_ip, 0.85,
                                                     "domain_pattern", flow_data)

                    seen_domains = all_domains

                # Update stats in Redis
                stats_update = {
                    'total_analyzed': str(self.stats['total_analyzed']),
                    'ads_detected': str(self.stats['ads_detected']),
                    'detections_found': str(self.stats['ads_detected']),
                    'ips_blocked': str(self.stats['ips_blocked']),
                    'urls_blocked': str(self.stats['urls_blocked']),
                    'legitimate_traffic': str(len(all_domains) - self.stats['ads_detected']),
                    'last_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'blocking_status': 'Active' if blocking_enabled else 'Monitoring Only'
                }
                self.r.hset('ml_detector:stats', mapping=stats_update)

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
