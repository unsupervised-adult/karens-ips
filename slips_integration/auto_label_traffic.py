#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
import time
from datetime import datetime
from collections import defaultdict

try:
    from slips_files.common.slips_utils import utils
    from slips_files.core.database.database_manager import DBManager
    SLIPS_AVAILABLE = True
except ImportError:
    import redis
    SLIPS_AVAILABLE = False

if SLIPS_AVAILABLE:
    db = DBManager(None, None)
    db.start()
    r = db.rdb.r
    print("Using SLIPS Redis connection")
else:
    r = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
    print("Using standalone Redis connection")

AD_DURATION_MIN = 5
AD_DURATION_MAX_SOLO = 30
AD_DURATION_MAX_MARATHON = 300
CONTENT_DURATION_MIN = 300
INTERRUPTION_GAP_MAX = 2.0

AD_DOMAINS = [
    'googlevideo.com/videoplayback',
    'doubleclick.net',
    'googleadservices.com',
    'youtube.com/pagead',
    'ytimg.com/generate_204'
]

def parse_flow(flow_str, timestamps):
    start_ts, end_ts = timestamps
    duration = end_ts - start_ts
    packet_count = len(flow_str)
    return duration, packet_count

def is_ad_domain(dest_ip, dest_port):
    try:
        profile_key = f"profile_{dest_ip}"
        sni = r.hget(profile_key, "SNI")
        if sni:
            for ad_domain in AD_DOMAINS:
                if ad_domain in sni:
                    return True
    except:
        pass
    return False

def cluster_by_duration(flows):
    durations = [f['duration'] for f in flows if f['duration'] >= AD_DURATION_MIN]
    
    if len(durations) < 3:
        return None, None
    
    durations_sorted = sorted(durations)
    
    median_duration = durations_sorted[len(durations_sorted) // 2]
    q3 = durations_sorted[int(len(durations_sorted) * 0.75)]
    
    long_threshold = max(CONTENT_DURATION_MIN, q3)
    
    return median_duration, long_threshold

def analyze_stream_sequence(flows):
    labeled_flows = []
    
    if len(flows) < 3:
        return labeled_flows
    
    median_dur, long_threshold = cluster_by_duration(flows)
    
    if not median_dur or not long_threshold:
        return labeled_flows
    
    content_flows = []
    potential_ads = []
    
    for i, flow in enumerate(flows):
        duration = flow['duration']
        
        if duration >= long_threshold:
            content_flows.append((i, flow))
        elif duration >= AD_DURATION_MIN:
            potential_ads.append((i, flow))
    
    if len(content_flows) < 1:
        return labeled_flows
    
    for idx, flow in content_flows:
        labeled_flows.append({
            'label': 'content',
            'confidence': 0.95,
            'reason': 'long_duration_clustering',
            'duration_threshold': long_threshold,
            **flow
        })
    
    avg_content_duration = sum(f['duration'] for _, f in content_flows) / len(content_flows)
    
    for idx, flow in potential_ads:
        ad_duration = flow['duration']
        duration_ratio = ad_duration / avg_content_duration if avg_content_duration > 0 else 0
        
        before_content = None
        after_content = None
        
        for c_idx, c_flow in content_flows:
            if c_idx < idx:
                before_content = (c_idx, c_flow)
            elif c_idx > idx and after_content is None:
                after_content = (c_idx, c_flow)
                break
        
        if before_content or after_content:
            confidence = 0.8
            reason = 'interruption_pattern'
            
            if duration_ratio < 0.1:
                confidence = 0.95
                reason = 'short_ad_vs_long_content'
            elif duration_ratio < 0.5:
                confidence = 0.9
                reason = 'medium_ad_between_content'
            elif duration_ratio < 1.0:
                confidence = 0.85
                reason = 'long_unskippable_ad_marathon'
            else:
                confidence = 0.7
                reason = 'very_long_interruption'
            
            labeled_flows.append({
                'label': 'ad',
                'confidence': confidence,
                'reason': reason,
                'duration_ratio_to_content': round(duration_ratio, 3),
                'avg_content_duration': round(avg_content_duration, 1),
                **flow
            })
    
    return labeled_flows

def auto_label_profiles():
    print(f"[{datetime.now()}] Starting automatic traffic labeling...")
    print("Monitoring SLIPS profiles for YouTube traffic patterns...")
    
    labeled_count = {'ad': 0, 'content': 0}
    
    try:
        profiles = r.keys("profile_*")
        print(f"Found {len(profiles)} profiles to analyze")
        
        for profile in profiles:
            try:
                timewindows = r.hkeys(profile)
                
                for tw in timewindows:
                    if tw.startswith("twid"):
                        outtuples_raw = r.hget(profile, tw)
                        if not outtuples_raw:
                            continue
                        
                        try:
                            outtuples = json.loads(outtuples_raw)
                        except:
                            continue
                        
                        flows = []
                        for flow_key, flow_data in outtuples.items():
                            if isinstance(flow_data, list) and len(flow_data) >= 2:
                                letters = flow_data[0]
                                timestamps = flow_data[1]
                                
                                if isinstance(timestamps, list) and len(timestamps) == 2:
                                    duration, packets = parse_flow(letters, timestamps)
                                    
                                    flows.append({
                                        'profile': profile,
                                        'timewindow': tw,
                                        'flow_key': flow_key,
                                        'duration': duration,
                                        'packets': packets,
                                        'timestamp': timestamps[0]
                                    })
                        
                        if flows:
                            flows.sort(key=lambda x: x['timestamp'])
                            
                            labeled = analyze_stream_sequence(flows)
                            
                            for labeled_flow in labeled:
                                training_sample = {
                                    'profile': labeled_flow['profile'],
                                    'timewindow': labeled_flow['timewindow'],
                                    'flow_key': labeled_flow['flow_key'],
                                    'duration': labeled_flow['duration'],
                                    'packets': labeled_flow['packets'],
                                    'label': labeled_flow['label'],
                                    'confidence': labeled_flow['confidence'],
                                    'reason': labeled_flow['reason'],
                                    'labeled_at': time.time(),
                                    'method': 'auto_behavioral'
                                }
                                
                                r.lpush("ml_detector:training_data", json.dumps(training_sample))
                                labeled_count[labeled_flow['label']] += 1
                                
                                if labeled_count['ad'] + labeled_count['content'] % 10 == 0:
                                    print(f"Labeled: {labeled_count['ad']} ads, {labeled_count['content']} content")
            
            except Exception as e:
                print(f"Error processing profile {profile}: {e}")
                continue
        
        print(f"\n{'='*60}")
        print(f"Auto-labeling complete:")
        print(f"  Ads labeled: {labeled_count['ad']}")
        print(f"  Content labeled: {labeled_count['content']}")
        print(f"  Total samples: {labeled_count['ad'] + labeled_count['content']}")
        print(f"{'='*60}")
        
        return labeled_count
    
    except Exception as e:
        print(f"Error in auto-labeling: {e}")
        return labeled_count

def continuous_labeling(interval=300):
    print("Starting continuous auto-labeling (every 5 minutes)")
    print("Press Ctrl+C to stop\n")
    
    while True:
        try:
            counts = auto_label_profiles()
            
            total_samples = r.llen("ml_detector:training_data")
            print(f"\nTotal training samples in Redis: {total_samples}")
            
            if total_samples >= 100:
                print("✓ Sufficient samples for training! Run: python3 train_model.py")
            else:
                print(f"Need {100 - total_samples} more samples for initial training")
            
            print(f"\nWaiting {interval}s before next labeling cycle...\n")
            time.sleep(interval)
        
        except KeyboardInterrupt:
            print("\n\nAuto-labeling stopped by user")
            break
        except Exception as e:
            print(f"Error in continuous labeling: {e}")
            time.sleep(60)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--continuous":
        continuous_labeling()
    else:
        auto_label_profiles()
