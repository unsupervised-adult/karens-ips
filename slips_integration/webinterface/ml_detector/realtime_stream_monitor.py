#!/usr/bin/env python3
"""
Real-time Stream Ad Monitor
Continuously monitors SLIPS for ad injection patterns and updates dashboard live
"""
import redis
import json
import time
from datetime import datetime
from collections import defaultdict
import signal
import sys

class RealtimeStreamMonitor:
    def __init__(self):
        self.r = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
        self.running = True
        self.seen_profiles = set()
        self.flow_history = defaultdict(list)
        self.dns_cache = {}
        
        self.streaming_threshold_bytes = 15000
        self.streaming_threshold_packets = 20
        self.streaming_min_duration = 120.0
        
        self.ad_duration_max = 120.0
        self.ad_duration_min = 5.0
        
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)
    
    def handle_shutdown(self, signum, frame):
        """Graceful shutdown handler"""
        print("\n🛑 Shutting down monitor...")
        self.running = False
        sys.exit(0)
    
    def load_dns_cache(self):
        """Load DNS resolutions from SLIPS"""
        try:
            domains_data = self.r.hgetall('DomainsResolved')
            for domain, ips_json in domains_data.items():
                try:
                    ips = json.loads(ips_json)
                    if isinstance(ips, list):
                        for ip in ips:
                            self.dns_cache[ip] = domain
                except:
                    continue
        except Exception as e:
            pass
    
    def extract_flow_data(self, profile_key):
        """Extract flows from SLIPS profile"""
        try:
            out_tuples_raw = self.r.hget(profile_key, 'OutTuples')
            if not out_tuples_raw:
                return []
            
            out_tuples = json.loads(out_tuples_raw)
            flows = []
            
            for flow_key, flow_data in out_tuples.items():
                try:
                    parts = flow_key.split('-')
                    if len(parts) < 3:
                        continue
                    
                    dst_ip = parts[0]
                    dst_port = parts[1]
                    protocol = parts[2].upper()
                    
                    if not isinstance(flow_data, list) or len(flow_data) < 2:
                        continue
                    
                    letters_sequence = flow_data[0]
                    timestamps = flow_data[1]
                    
                    if not isinstance(timestamps, list) or len(timestamps) < 2:
                        continue
                    
                    if isinstance(timestamps[0], bool):
                        continue
                    
                    start_time = float(timestamps[0])
                    end_time = float(timestamps[1])
                    duration = end_time - start_time
                    
                    packets = max(1, letters_sequence.count(',') + letters_sequence.count('+') + letters_sequence.count('.') + 1)
                    total_bytes = packets * 500
                    
                    flows.append({
                        'dst_ip': dst_ip,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'packets': packets,
                        'bytes': total_bytes,
                        'duration': duration,
                        'start_time': start_time,
                        'flow_key': flow_key
                    })
                
                except (ValueError, IndexError, KeyError):
                    continue
            
            return sorted(flows, key=lambda x: x['start_time'])
        
        except Exception as e:
            return []
    
    def is_streaming_flow(self, flow):
        """Check if flow is video streaming"""
        return (flow['bytes'] > self.streaming_threshold_bytes and 
                flow['packets'] > self.streaming_threshold_packets and
                flow['duration'] > self.streaming_min_duration)
    
    def is_potential_ad(self, flow):
        """Check if flow matches ad duration/size"""
        return (self.ad_duration_min < flow['duration'] < self.ad_duration_max and
                flow['bytes'] > 5000 and
                flow['packets'] > 10)
    
    def calculate_flow_features(self, flow):
        """Extract behavioral features"""
        duration = max(flow['duration'], 0.1)
        
        byte_rate = flow['bytes'] / duration
        packet_rate = flow['packets'] / duration
        avg_packet_size = flow['bytes'] / max(flow['packets'], 1)
        
        is_https = flow['dst_port'] == '443'
        is_http = flow['dst_port'] == '80'
        
        return {
            'byte_rate': byte_rate,
            'packet_rate': packet_rate,
            'avg_packet_size': avg_packet_size,
            'duration': duration,
            'is_https': is_https,
            'is_http': is_http,
            'total_bytes': flow['bytes']
        }
    
    def analyze_for_ads(self, src_ip, flows):
        """Analyze flows for ad injection patterns"""
        detected_ads = []
        
        if len(flows) < 2:
            return []
        
        streaming_flows = [f for f in flows if self.is_streaming_flow(f)]
        
        if len(streaming_flows) < 2:
            return []
        
        for i in range(len(flows)):
            current_flow = flows[i]
            
            if not self.is_potential_ad(current_flow):
                continue
            
            flow_id = f"{current_flow['dst_ip']}:{current_flow['dst_port']}:{current_flow['start_time']}"
            if flow_id in self.flow_history[src_ip]:
                continue
            
            features = self.calculate_flow_features(current_flow)
            
            nearby_streams = []
            for stream in streaming_flows:
                time_diff = abs(current_flow['start_time'] - stream['start_time'])
                if time_diff < 300:
                    nearby_streams.append((time_diff, stream))
            
            if len(nearby_streams) < 2:
                continue
            
            nearby_streams.sort(key=lambda x: x[0])
            closest_stream = nearby_streams[0][1]
            second_stream = nearby_streams[1][1]
            
            duration_ratio_1 = current_flow['duration'] / closest_stream['duration']
            duration_ratio_2 = current_flow['duration'] / second_stream['duration']
            
            if duration_ratio_1 < 0.3 and duration_ratio_2 < 0.3:
                
                confidence = 0.75
                
                if duration_ratio_1 < 0.15 or duration_ratio_2 < 0.15:
                    confidence += 0.10
                
                byte_rate_ratio = features['byte_rate'] / (closest_stream['bytes'] / max(closest_stream['duration'], 1))
                if 0.5 < byte_rate_ratio < 2.0:
                    confidence += 0.05
                
                if features['is_https']:
                    confidence += 0.03
                
                same_port_as_content = (current_flow['dst_port'] == closest_stream['dst_port'])
                if same_port_as_content:
                    confidence += 0.05
                
                different_ip = (current_flow['dst_ip'] != closest_stream['dst_ip'])
                if different_ip:
                    confidence += 0.02
                
                dns_name = self.dns_cache.get(current_flow['dst_ip'], current_flow['dst_ip'])
                
                detection = {
                    'timestamp': datetime.fromtimestamp(current_flow['start_time']).isoformat(),
                    'timestamp_formatted': datetime.fromtimestamp(current_flow['start_time']).strftime('%Y-%m-%d %H:%M:%S'),
                    'src_ip': src_ip,
                    'dst_ip': current_flow['dst_ip'],
                    'dst_port': current_flow['dst_port'],
                    'protocol': 'HTTPS' if current_flow['dst_port'] == '443' else current_flow['protocol'],
                    'classification': f'Ad Injection (Duration-based): {dns_name}',
                    'confidence': min(confidence, 0.97),
                    'bytes': current_flow['bytes'],
                    'packets': current_flow['packets'],
                    'detection_method': 'realtime_behavioral_analysis',
                    'pattern': f"ad({current_flow['duration']:.1f}s) vs content({closest_stream['duration']:.1f}s)",
                    'duration_ratio': f"{duration_ratio_1:.2%}",
                    'byte_rate': f"{features['byte_rate']:.0f} B/s",
                    'avg_packet_size': f"{features['avg_packet_size']:.0f} bytes"
                }
                
                detected_ads.append(detection)
                self.flow_history[src_ip].append(flow_id)
                
                print(f"🎯 LIVE AD DETECTED!")
                print(f"   Time: {detection['timestamp_formatted']}")
                print(f"   Ad: {current_flow['dst_ip']}:{current_flow['dst_port']} - {current_flow['duration']:.1f}s")
                print(f"   Content: {closest_stream['dst_ip']} - {closest_stream['duration']:.1f}s")
                print(f"   Duration ratio: {duration_ratio_1:.1%}")
                print(f"   Confidence: {confidence:.2%}\n")
        
        return detected_ads
    
    def store_detection(self, detection):
        """Store single detection in Redis"""
        try:
            self.r.lpush('ml_detector:recent_detections', json.dumps(detection))
            self.r.ltrim('ml_detector:recent_detections', 0, 99)
            
            current_count = self.r.hget('ml_detector:stats', 'ads_detected')
            new_count = int(current_count or 0) + 1
            
            stats = {
                'detections_found': str(new_count),
                'ads_detected': str(new_count),
                'last_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            self.r.hset('ml_detector:stats', mapping=stats)
            
        except Exception as e:
            print(f"⚠️  Failed to store detection: {e}")
    
    def monitor_loop(self):
        """Main monitoring loop"""
        print("🎬 Real-time Stream Ad Monitor Started")
        print("=" * 80)
        print("Monitoring for ad injection patterns...")
        print("Press Ctrl+C to stop\n")
        
        scan_count = 0
        total_detections = 0
        
        while self.running:
            try:
                scan_count += 1
                
                if scan_count % 10 == 0:
                    self.load_dns_cache()
                
                all_profiles = self.r.keys('profile_*_timewindow*')
                profiles = [p for p in all_profiles if not ('_evidence' in p or '_timeline' in p)]
                
                new_profiles = [p for p in profiles if p not in self.seen_profiles]
                
                if new_profiles:
                    print(f"📊 Scan #{scan_count}: Found {len(new_profiles)} new profiles")
                
                for profile in new_profiles:
                    try:
                        profile_parts = profile.split('_')
                        src_ip = profile_parts[1] if len(profile_parts) > 1 else 'unknown'
                        
                        flows = self.extract_flow_data(profile)
                        
                        if len(flows) >= 2:
                            detections = self.analyze_for_ads(src_ip, flows)
                            
                            for detection in detections:
                                self.store_detection(detection)
                                total_detections += 1
                        
                        self.seen_profiles.add(profile)
                    
                    except Exception as e:
                        continue
                
                if scan_count % 20 == 0:
                    print(f"📈 Status: {scan_count} scans, {total_detections} ads detected, monitoring {len(self.seen_profiles)} profiles")
                
                time.sleep(2)
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"⚠️  Error in monitoring loop: {e}")
                time.sleep(5)
        
        print(f"\n✅ Monitor stopped. Total detections: {total_detections}")

if __name__ == '__main__':
    monitor = RealtimeStreamMonitor()
    monitor.monitor_loop()
