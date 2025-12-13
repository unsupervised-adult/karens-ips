#!/usr/bin/env python3
"""
Migration script to queue historical detections for LLM labeling.
Processes detections that occurred before the queue system was deployed.
"""
import redis
import json
import sys

def migrate_old_detections():
    """Read old detections from Redis and add them to LLM queue"""
    r = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
    
    # Get configuration thresholds
    try:
        llm_min = float(r.hget('stream_ad_blocker:config', 'llm_min_threshold') or 0.3)
        llm_max = float(r.hget('stream_ad_blocker:config', 'llm_max_threshold') or 0.9)
    except:
        llm_min = 0.3
        llm_max = 0.9
    
    print(f"LLM threshold range: {llm_min} - {llm_max}")
    
    # Get current stats
    total_analyzed = int(r.hget('stream_ad_blocker:stats', 'total_analyzed') or 0)
    ads_detected = int(r.hget('stream_ad_blocker:stats', 'ads_detected') or 0)
    
    print(f"Total flows analyzed: {total_analyzed}")
    print(f"Total ads detected: {ads_detected}")
    
    # Try to find detection history
    detection_keys = r.keys('stream_ad_blocker:detection:*')
    print(f"\nFound {len(detection_keys)} detection records")
    
    if not detection_keys:
        # Check if there's a detection list
        detection_list = r.lrange('stream_ad_blocker:detections', 0, -1)
        print(f"Found {len(detection_list)} detections in list")
        
        # Parse and queue eligible detections
        queued = 0
        for det_json in detection_list:
            try:
                det = json.loads(det_json)
                confidence = det.get('confidence', 0)
                
                if llm_min <= confidence <= llm_max:
                    # Create detection data for queue
                    detection_data = {
                        'domain': det.get('domain', 'unknown'),
                        'dst_ip': det.get('dst_ip', ''),
                        'ml_confidence': confidence,
                        'flow_data': {
                            'duration': det.get('duration', 0),
                            'bytes': det.get('bytes', 0),
                            'packets': det.get('packets', 0),
                            'proto': det.get('proto', '')
                        },
                        'dns_history': []
                    }
                    
                    # Add to queue
                    r.rpush('stream_ad_blocker:llm_queue', json.dumps(detection_data))
                    queued += 1
                    print(f"Queued: {det.get('domain')} (conf={confidence:.2f})")
            except json.JSONDecodeError:
                continue
        
        print(f"\n✓ Queued {queued} detections for LLM processing")
        
        # Update queue size stat
        r.hset('stream_ad_blocker:stats', 'llm_queue_size', queued)
        
        return queued
    else:
        # Process individual detection records
        queued = 0
        for key in detection_keys:
            det_json = r.get(key)
            if not det_json:
                continue
            
            try:
                det = json.loads(det_json)
                confidence = det.get('confidence', 0)
                
                if llm_min <= confidence <= llm_max:
                    detection_data = {
                        'domain': det.get('domain', 'unknown'),
                        'dst_ip': det.get('dst_ip', ''),
                        'ml_confidence': confidence,
                        'flow_data': {
                            'duration': det.get('duration', 0),
                            'bytes': det.get('bytes', 0),
                            'packets': det.get('packets', 0),
                            'proto': det.get('proto', '')
                        },
                        'dns_history': []
                    }
                    
                    r.rpush('stream_ad_blocker:llm_queue', json.dumps(detection_data))
                    queued += 1
                    print(f"Queued: {det.get('domain')} (conf={confidence:.2f})")
            except json.JSONDecodeError:
                continue
        
        print(f"\n✓ Queued {queued} detections for LLM processing")
        r.hset('stream_ad_blocker:stats', 'llm_queue_size', queued)
        
        return queued

if __name__ == '__main__':
    try:
        count = migrate_old_detections()
        sys.exit(0 if count > 0 else 1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
