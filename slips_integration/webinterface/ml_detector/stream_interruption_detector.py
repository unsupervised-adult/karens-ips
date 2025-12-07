#!/usr/bin/env python3
"""
Stream Interruption Ad Detector
Detects ads by analyzing stream behavior patterns:
- Video streaming (large sustained transfer)
- Interrupted by small request (ad injection)
- Stream resumes (content continues)
"""
import redis
import json
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np

class StreamInterruptionDetector:
    def __init__(self):
        self.r = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
        
        self.streaming_threshold_bytes = 15000
        self.streaming_threshold_packets = 20
        self.streaming_min_duration = 120.0
        
        self.ad_duration_max = 120.0
        self.ad_duration_min = 5.0
        
        self.known_streaming_ips = set()
        self.flow_sequences = defaultdict(list)
        self.dns_cache = {}
        
    def extract_flow_data(self, profile_key):
        """Extract flow information from SLIPS OutTuples hash field"""
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
                
                except (ValueError, IndexError, KeyError) as e:
                    continue
            
            return sorted(flows, key=lambda x: x['start_time'])
        
        except Exception as e:
            return []
    
    def is_streaming_flow(self, flow):
        """Determine if flow is video streaming based on volume and duration"""
        return (flow['bytes'] > self.streaming_threshold_bytes and 
                flow['packets'] > self.streaming_threshold_packets and
                flow['duration'] > self.streaming_min_duration)
    
    def is_potential_ad(self, flow):
        """Detect if flow duration/size suggests ad (shorter than full content)"""
        return (self.ad_duration_min < flow['duration'] < self.ad_duration_max and
                flow['bytes'] > 5000 and
                flow['packets'] > 10)
    
    def analyze_stream_pattern(self, src_ip, flows):
        """
        Analyze flow sequence for ad/content patterns using behavioral features
        Patterns: ad→video→ad→video OR video→ad→video
        Returns list of detected ad interruptions
        """
        if len(flows) < 2:
            return []
        
        detected_ads = []
        streaming_flows = []
        
        for flow in flows:
            if self.is_streaming_flow(flow):
                streaming_flows.append(flow)
        
        if len(streaming_flows) < 2:
            return []
        
        for i in range(len(flows)):
            current_flow = flows[i]
            
            if not self.is_potential_ad(current_flow):
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
                
                detected_ads.append({
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
                    'detection_method': 'duration_behavioral_analysis',
                    'pattern': f"ad({current_flow['duration']:.1f}s) vs content({closest_stream['duration']:.1f}s)",
                    'duration_ratio': f"{duration_ratio_1:.2%}",
                    'byte_rate': f"{features['byte_rate']:.0f} B/s",
                    'avg_packet_size': f"{features['avg_packet_size']:.0f} bytes"
                })
                
                print(f"🎯 AD DETECTED (Duration-based)!")
    def load_dns_cache(self):
        """Load DNS resolutions from SLIPS DomainsResolved hash"""
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
            print(f"📋 Loaded {len(self.dns_cache)} DNS mappings")
        except Exception as e:
            print(f"⚠️  Could not load DNS cache: {e}")
    
    def scan_all_profiles(self):
        """Scan all active profiles for stream interruption patterns"""
        print("🎬 Scanning for ad injection patterns using behavioral analysis...")
        
        self.load_dns_cache()
        
        all_profiles = self.r.keys('profile_*_timewindow*')
        profiles = [p for p in all_profiles if not ('_evidence' in p or '_timeline' in p)]
        print(f"📊 Found {len(profiles)} timewindow profiles to analyze")
        
        all_detections = []
        profiles_with_streams = 0
        total_flows_analyzed = 0
        
        for profile in profiles[:100]:
            try:
                profile_parts = profile.split('_')
                src_ip = profile_parts[1] if len(profile_parts) > 1 else 'unknown'
                
                flows = self.extract_flow_data(profile)
                total_flows_analyzed += len(flows)
                
                if len(flows) >= 2:
                    streaming_flows = [f for f in flows if self.is_streaming_flow(f)]
                    if len(streaming_flows) >= 2:
                        profiles_with_streams += 1
                        
                        detections = self.analyze_stream_pattern(src_ip, flows)
                        all_detections.extend(detections)
            
            except Exception as e:
                continue
        
        print(f"✅ Analysis complete:")
        print(f"   Profiles with streaming: {profiles_with_streams}")
        print(f"   Total flows analyzed: {total_flows_analyzed}")
        print(f"   Ad injections detected: {len(all_detections)}")
        
        return all_detections

    def store_detections(self, detections):
        """Store detections in Redis for dashboard display"""
        if not detections:
            return
        
        for det in detections:
            self.r.lpush('ml_detector:recent_detections', json.dumps(det))
        
        self.r.ltrim('ml_detector:recent_detections', 0, 99)
        
        stats = {
            'detections_found': str(len(detections)),
            'ads_detected': str(len(detections)),
            'last_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        self.r.hset('ml_detector:stats', mapping=stats)
        
        print(f"✅ Stored {len(detections)} detections in Redis")

if __name__ == '__main__':
    detector = StreamInterruptionDetector()
    detections = detector.scan_all_profiles()
    
    if detections:
        print(f"\n📋 Detected {len(detections)} ad interruptions:")
        for i, det in enumerate(detections[:10], 1):
            print(f"{i}. {det['classification']}")
            print(f"   Time: {det['timestamp_formatted']}")
            print(f"   Pattern: {det.get('pattern', 'N/A')}")
            print(f"   Before: {det.get('stream_before', 'N/A')}")
            print(f"   After: {det.get('stream_after', 'N/A')}")
            print(f"   Confidence: {det['confidence']:.2%}\n")
        
        detector.store_detections(detections)
    else:
        print("\n⚠️ No stream interruption patterns detected yet")
        print("   Watch some YouTube videos with ads to generate traffic patterns!")
