#!/usr/bin/env python3
"""
Stream Diagnostic Tool
Shows what flows are being detected and why they're not classified as ads
"""
import redis
import json
from datetime import datetime

r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

def analyze_profile(profile_key):
    """Show flow details for a profile"""
    try:
        out_tuples_raw = r.hget(profile_key, 'OutTuples')
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
                
                packets = letters_sequence.count(',') + letters_sequence.count('+') + 1
                
                total_bytes = 0
                for char in letters_sequence:
                    if char in 'IHDUA':
                        total_bytes += 1500
                    elif char in 'ihdua':
                        total_bytes += 100
                    elif char in 'YZ':
                        total_bytes += 800
                    elif char in 'yz':
                        total_bytes += 50
                    elif char in 'R':
                        total_bytes += 200
                    elif char in 'r':
                        total_bytes += 80
                
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
        
        return sorted(flows, key=lambda x: x['duration'], reverse=True)
    
    except Exception as e:
        return []

print("🔍 Analyzing your streaming profiles...\n")

all_profiles = r.keys('profile_*_timewindow*')
profiles = [p for p in all_profiles if not ('_evidence' in p or '_timeline' in p)]

target_ip = '10.10.252.5'
my_profiles = [p for p in profiles if target_ip in p]

print(f"Found {len(my_profiles)} profiles for {target_ip}\n")

streaming_threshold = 50000
potential_ads = []
all_flows = []

for profile in my_profiles[:5]:
    flows = analyze_profile(profile)
    all_flows.extend(flows)

all_flows.sort(key=lambda x: x['duration'], reverse=True)

print("=" * 80)
print("TOP 10 LONGEST FLOWS (Potential Video Streaming)")
print("=" * 80)
for i, flow in enumerate(all_flows[:10], 1):
    print(f"{i}. {flow['dst_ip']}:{flow['dst_port']}/{flow['protocol']}")
    print(f"   Duration: {flow['duration']:.1f}s | Bytes: {flow['bytes']:,} | Packets: {flow['packets']}")
    print(f"   Is Streaming: {'✓' if flow['bytes'] > streaming_threshold and flow['duration'] > 10 else '✗'}")
    print()

print("\n" + "=" * 80)
print("POTENTIAL AD FLOWS (5-120s duration, near streaming content)")
print("=" * 80)

for flow in all_flows:
    if 5 < flow['duration'] < 120 and flow['bytes'] > 5000:
        potential_ads.append(flow)

if potential_ads:
    for i, flow in enumerate(potential_ads[:10], 1):
        print(f"{i}. {flow['dst_ip']}:{flow['dst_port']}/{flow['protocol']}")
        print(f"   Duration: {flow['duration']:.1f}s | Bytes: {flow['bytes']:,} | Packets: {flow['packets']}")
        print()
else:
    print("No potential ad flows found")
    print("This might mean:")
    print("  - No ads served recently")
    print("  - Ads delivered differently than expected")
    print("  - Need to adjust detection thresholds")

print("\n" + "=" * 80)
print("FLOW DURATION DISTRIBUTION")
print("=" * 80)
duration_buckets = {
    "0-5s": 0,
    "5-30s": 0,
    "30-60s": 0,
    "60-120s": 0,
    "120s+": 0
}

for flow in all_flows:
    if flow['duration'] < 5:
        duration_buckets["0-5s"] += 1
    elif flow['duration'] < 30:
        duration_buckets["5-30s"] += 1
    elif flow['duration'] < 60:
        duration_buckets["30-60s"] += 1
    elif flow['duration'] < 120:
        duration_buckets["60-120s"] += 1
    else:
        duration_buckets["120s+"] += 1

for bucket, count in duration_buckets.items():
    bar = "█" * (count // 2)
    print(f"{bucket:>10}: {bar} ({count})")
