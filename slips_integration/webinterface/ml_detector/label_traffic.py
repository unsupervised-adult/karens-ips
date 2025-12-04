#!/usr/bin/env python3
"""
Interactive Traffic Labeling Tool
Label captured flows as ads or content to build training dataset
"""
import redis
import json
from datetime import datetime

class TrafficLabeler:
    def __init__(self):
        self.r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
        self.labeled_count = 0
    
    def get_recent_flows(self, src_ip='10.10.252.5', limit=50):
        """Get recent flows from SLIPS for labeling"""
        flows = []
        
        all_profiles = self.r.keys(f'profile_{src_ip}_timewindow*')
        profiles = [p for p in all_profiles if not ('_evidence' in p or '_timeline' in p)]
        
        for profile in profiles[:10]:
            try:
                out_tuples_raw = self.r.hget(profile, 'OutTuples')
                if not out_tuples_raw:
                    continue
                
                out_tuples = json.loads(out_tuples_raw)
                
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
            
            except Exception:
                continue
        
        flows.sort(key=lambda x: x['duration'], reverse=True)
        return flows[:limit]
    
    def display_flow(self, flow, index):
        """Display flow details for labeling"""
        print(f"\n{'='*80}")
        print(f"Flow #{index + 1}")
        print(f"{'='*80}")
        print(f"Destination:  {flow['dst_ip']}:{flow['dst_port']}/{flow['protocol']}")
        print(f"Duration:     {flow['duration']:.1f} seconds")
        print(f"Bytes:        {flow['bytes']:,} ({flow['bytes']/flow['duration']:.0f} B/s)")
        print(f"Packets:      {flow['packets']} ({flow['packets']/flow['duration']:.1f} packets/s)")
        print(f"Avg Pkt Size: {flow['bytes']/flow['packets']:.0f} bytes")
        print(f"Start Time:   {datetime.fromtimestamp(flow['start_time']).strftime('%Y-%m-%d %H:%M:%S')}")
        
        if flow['duration'] < 30:
            print(f"\n💡 Hint: SHORT duration - likely an AD")
        elif flow['duration'] > 120:
            print(f"\n💡 Hint: LONG duration - likely CONTENT")
        else:
            print(f"\n💡 Hint: Medium duration - could be either")
        
        if flow['protocol'] == 'UDP' and flow['dst_port'] == '443':
            print(f"⚡ Protocol: QUIC detected (encrypted)")
    
    def save_labeled_data(self, flow, label):
        """Save labeled flow to Redis training dataset"""
        training_sample = {
            'flow_data': flow,
            'label': label,
            'labeled_at': datetime.now().isoformat(),
            'labeler': 'manual'
        }
        
        self.r.rpush('ml_detector:training_data', json.dumps(training_sample))
        self.labeled_count += 1
    
    def interactive_labeling(self):
        """Interactive CLI for labeling flows"""
        print("🏷️  Interactive Traffic Labeling Tool")
        print("=" * 80)
        print("\nFetching recent flows from SLIPS...")
        
        flows = self.get_recent_flows()
        
        if not flows:
            print("❌ No flows found to label")
            return
        
        print(f"✅ Found {len(flows)} flows to label")
        print("\nInstructions:")
        print("  a = Ad")
        print("  c = Content (video/legitimate traffic)")
        print("  s = Skip")
        print("  q = Quit")
        print("  b = Go back to previous flow")
        
        i = 0
        history = []
        
        while i < len(flows):
            flow = flows[i]
            self.display_flow(flow, i)
            
            choice = input(f"\nLabel this flow [a/c/s/b/q]: ").lower().strip()
            
            if choice == 'a':
                self.save_labeled_data(flow, 'ad')
                print("✅ Labeled as AD")
                history.append(i)
                i += 1
            elif choice == 'c':
                self.save_labeled_data(flow, 'content')
                print("✅ Labeled as CONTENT")
                history.append(i)
                i += 1
            elif choice == 's':
                print("⏭️  Skipped")
                i += 1
            elif choice == 'b':
                if history:
                    i = history.pop()
                    print("⬅️  Going back...")
                else:
                    print("⚠️  Already at first flow")
            elif choice == 'q':
                break
            else:
                print("⚠️  Invalid choice, try again")
        
        print(f"\n✅ Labeling complete! Labeled {self.labeled_count} flows")
        print(f"   Training dataset size: {self.r.llen('ml_detector:training_data')}")
        print("\nNext: Run 'sudo python3 train_model.py' to train on labeled data")

if __name__ == '__main__':
    labeler = TrafficLabeler()
    labeler.interactive_labeling()
