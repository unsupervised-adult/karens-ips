#!/usr/bin/env python3
"""
Real-time Video Ad Monitor
Continuously monitors SLIPS DNS queries and detects ad domains in real-time
"""
import redis
import json
import time
from datetime import datetime
from collections import defaultdict

KNOWN_AD_DOMAINS = [
    'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
    'scorecardresearch.com', 'advertising.com', 'adservice.google.com',
    'googletagmanager.com', 'googletagservices.com', 'youtube.com/get_video_info',
    'imasdk.googleapis.com', 'static.doubleclick.net', 'pagead2.googlesyndication.com'
]

STREAMING_DOMAINS = [
    'youtube.com', 'youtu.be', 'googlevideo.com',
    'twitch.tv', 'ttvnw.net',
    'netflix.com', 'nflxvideo.net',
    'hulu.com', 'hulustream.com',
    'primevideo.com', 'amazon.com/gp/video'
]

def is_ad_domain(domain):
    domain_lower = domain.lower()
    return any(x in domain_lower for x in ['doubleclick', 'googlesyndication', 'googleadservices', 'advertising', 'adservice', 'pagead'])

def is_streaming_domain(domain):
    domain_lower = domain.lower()
    return any(x in domain_lower for x in ['googlevideo.com', 'youtube.com', 'youtu.be', 'twitch.tv', 'netflix.com', 'nflxvideo.net'])

def monitor_realtime():
    r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    
    print("🎯 Starting real-time ad monitoring...")
    print("   Watching for new DNS queries...")
    
    seen_domains = set(r.hkeys('DomainsResolved'))
    print(f"   Already tracking {len(seen_domains)} domains")
    
    ad_count = 0
    streaming_count = 0
    
    local_ips = set()
    profiles = r.keys('profile_10.*')
    for profile in profiles[:50]:
        if '_timewindow' not in profile and '_twid' not in profile:
            ip = profile.replace('profile_', '')
            local_ips.add(ip)
    src_ip = list(local_ips)[0] if local_ips else '10.10.252.5'
    
    print(f"   Monitoring from source IP: {src_ip}\n")
    
    while True:
        current_domains = set(r.hkeys('DomainsResolved'))
        new_domains = current_domains - seen_domains
        
        if new_domains:
            for domain in new_domains:
                now = datetime.now()
                
                if is_streaming_domain(domain):
                    streaming_count += 1
                    print(f"📺 Streaming: {domain}")
                
                if is_ad_domain(domain):
                    ad_count += 1
                    
                    ip_data = r.hget('DomainsResolved', domain)
                    try:
                        ip_list = json.loads(ip_data) if ip_data else []
                        dst_ip = ip_list[0] if isinstance(ip_list, list) and ip_list else ip_data if ip_data else 'Unknown'
                    except:
                        dst_ip = str(ip_data) if ip_data else 'Unknown'
                    
                    detection = {
                        'timestamp': now.isoformat(),
                        'timestamp_formatted': now.strftime('%Y-%m-%d %H:%M:%S'),
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'dst_port': 443,
                        'protocol': 'HTTPS',
                        'classification': f'Ad: {domain}',
                        'confidence': 0.92,
                        'bytes': 0,
                        'packets': 0
                    }
                    
                    r.lpush('ml_detector:recent_detections', json.dumps(detection))
                    r.ltrim('ml_detector:recent_detections', 0, 99)
                    
                    print(f"🚫 AD DETECTED: {domain} → {dst_ip} at {now.strftime('%H:%M:%S')}")
                    
                    stats = {
                        'total_analyzed': str(len(current_domains)),
                        'ads_detected': str(ad_count),
                        'detections_found': str(ad_count),
                        'legitimate_traffic': str(streaming_count),
                        'streaming_sessions': str(streaming_count),
                        'accuracy': '0.1%',
                        'last_update': now.strftime('%Y-%m-%d %H:%M:%S'),
                        'status': 'Active - Monitoring',
                        'total_domains': str(len(current_domains)),
                        'detection_rate': f'{round((ad_count / max(1, len(current_domains))) * 100, 1)}%'
                    }
                    r.hset('ml_detector:stats', mapping=stats)
            
            seen_domains = current_domains
        
        time.sleep(2)

if __name__ == '__main__':
    try:
        monitor_realtime()
    except KeyboardInterrupt:
        print("\n\n✋ Monitoring stopped")
