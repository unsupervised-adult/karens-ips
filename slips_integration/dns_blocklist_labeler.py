#!/usr/bin/env python3
"""
DNS Blocklist-Based Traffic Labeling
Uses Pi-hole/Hagzel DNS blocklists to automatically label ad traffic
Combines with behavioral heuristics for comprehensive labeling
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
import time
import requests
from datetime import datetime
from collections import defaultdict
import re

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
    print("✓ Using SLIPS Redis connection")
else:
    r = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
    print("✓ Using standalone Redis connection")

class DNSBlocklistLabeler:
    """
    Automatic traffic labeling using DNS blocklists from existing SQLite database
    """
    
    def __init__(self, db_path='/var/lib/karens-ips/blocklists.db'):
        self.db_path = db_path
        self.ad_domains = set()
        self.tracking_domains = set()
        self.malware_domains = set()
        self.whitelist_domains = set()
        self.db_conn = None
        
        self.youtube_ad_patterns = [
            r'.*doubleclick\.net',
            r'.*googlesyndication\.com',
            r'.*googleadservices\.com',
            r'.*google-analytics\.com',
            r'.*googletagmanager\.com',
            r'.*googletagservices\.com',
            r'.*youtube\.com/pagead',
            r'.*youtube\.com/ptracking',
            r'.*youtube\.com/api/stats/ads',
            r'.*googlevideo\.com/videoplayback.*&adsid=',
            r'.*imasdk\.googleapis\.com',
            r'.*doubleclick\.com',
            r'.*2mdn\.net',
            r'.*invitemedia\.com',
            r'.*innovid\.com',
            r'.*teads\.tv',
            r'.*moatads\.com',
            r'.*scorecardresearch\.com'
        ]
        
        self.youtube_content_patterns = [
            r'.*googlevideo\.com/videoplayback.*&c=WEB',
            r'.*googlevideo\.com/videoplayback(?!.*&adsid=)',
            r'.*youtube\.com/api/stats/watchtime',
            r'.*i\.ytimg\.com',
            r'.*yt3\.ggpht\.com'
        ]
        
        self.stats = {
            'blocklist_ad_matches': 0,
            'pattern_ad_matches': 0,
            'content_matches': 0,
            'behavioral_labels': 0,
            'total_labeled': 0
        }
        
        self.connect_database()
        self.load_blocklists()
    
    def connect_database(self):
        """Connect to existing SQLite blocklist database"""
        import sqlite3
        try:
            self.db_conn = sqlite3.connect(self.db_path)
            print(f"✓ Connected to blocklist database: {self.db_path}")
        except Exception as e:
            print(f"✗ Failed to connect to database {self.db_path}: {e}")
            print("  Creating in-memory fallback database...")
            self.db_conn = sqlite3.connect(':memory:')
    
    def load_blocklists(self):
        """Load DNS blocklists from SQLite database created by installer"""
        print("\n📋 Loading DNS blocklists from database...")
        
        try:
            cursor = self.db_conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            print(f"  Found {len(tables)} tables: {[t[0] for t in tables]}")
            
            cursor.execute("""
                SELECT bd.domain, bd.category, bs.name, bd.confidence
                FROM blocked_domains bd
                JOIN blocklist_sources bs ON bd.source_id = bs.id
                WHERE bs.enabled = 1
            """)
            rows = cursor.fetchall()
            
            for domain, category, source_name, confidence in rows:
                domain_lower = domain.lower()
                
                if category in ('ads', 'advertising'):
                    self.ad_domains.add(domain_lower)
                elif category in ('tracking', 'analytics'):
                    self.tracking_domains.add(domain_lower)
                elif category == 'malware':
                    self.malware_domains.add(domain_lower)
            
            print(f"\n📊 Blocklist Summary:")
            print(f"  Ad domains:       {len(self.ad_domains):,}")
            print(f"  Tracking domains: {len(self.tracking_domains):,}")
            print(f"  Malware domains:  {len(self.malware_domains):,}")
            print(f"  Total unique:     {len(self.ad_domains | self.tracking_domains | self.malware_domains):,}")
            
        except Exception as e:
            print(f"✗ Error loading from database: {e}")
            print("  Loading fallback YouTube patterns...")
            self._load_fallback_patterns()
    
    def _load_fallback_patterns(self):
        """Load minimal fallback patterns if database unavailable"""
        fallback_ads = [
            'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
            'google-analytics.com', 'googletagmanager.com', 'googletagservices.com',
            'moatads.com', 'scorecardresearch.com', '2mdn.net', 'imasdk.googleapis.com'
        ]
        self.ad_domains.update(fallback_ads)
        print(f"  Loaded {len(fallback_ads)} fallback ad patterns")
    
    def is_ad_by_blocklist(self, domain):
        """Check if domain is in ad blocklists"""
        if not domain:
            return False, None
        
        domain_lower = domain.lower()
        
        if domain_lower in self.ad_domains:
            return True, 'blocklist_exact_match'
        
        parts = domain_lower.split('.')
        for i in range(len(parts)):
            parent = '.'.join(parts[i:])
            if parent in self.ad_domains:
                return True, f'blocklist_parent_match:{parent}'
        
        return False, None
    
    def is_ad_by_pattern(self, domain, url_path=''):
        """Check if domain/URL matches known ad patterns"""
        if not domain:
            return False, None
        
        full_url = f"{domain}{url_path}"
        
        for pattern in self.youtube_ad_patterns:
            if re.match(pattern, full_url, re.IGNORECASE):
                return True, f'youtube_ad_pattern:{pattern[:30]}'
        
        return False, None
    
    def is_content(self, domain, url_path=''):
        """Check if domain/URL is legitimate content"""
        if not domain:
            return False, None
        
        full_url = f"{domain}{url_path}"
        
        for pattern in self.youtube_content_patterns:
            if re.match(pattern, full_url, re.IGNORECASE):
                return True, f'youtube_content_pattern:{pattern[:30]}'
        
        return False, None
    
    def label_flow(self, flow_data):
        """
        Label a single flow using DNS blocklists + patterns + behavior
        Returns: (label, confidence, reason)
        """
        domain = flow_data.get('domain', '')
        url_path = flow_data.get('url_path', '')
        duration = flow_data.get('duration', 0)
        bytes_sent = flow_data.get('bytes', 0)
        
        is_ad_blocklist, blocklist_reason = self.is_ad_by_blocklist(domain)
        if is_ad_blocklist:
            self.stats['blocklist_ad_matches'] += 1
            return 'ad', 0.98, blocklist_reason
        
        is_ad_pattern, pattern_reason = self.is_ad_by_pattern(domain, url_path)
        if is_ad_pattern:
            self.stats['pattern_ad_matches'] += 1
            return 'ad', 0.95, pattern_reason
        
        is_content_pattern, content_reason = self.is_content(domain, url_path)
        if is_content_pattern:
            self.stats['content_matches'] += 1
            
            if duration >= 300:
                return 'content', 0.98, f'{content_reason}+long_duration'
            elif duration >= 60:
                return 'content', 0.90, f'{content_reason}+medium_duration'
            else:
                return 'content', 0.80, content_reason
        
        if duration < 5:
            return None, 0.0, 'too_short_to_classify'
        elif duration > 600:
            return 'content', 0.85, 'very_long_duration'
        elif duration >= 300:
            return 'content', 0.80, 'long_duration_behavioral'
        elif 5 <= duration <= 30 and bytes_sent < 10000:
            self.stats['behavioral_labels'] += 1
            return 'ad', 0.70, 'short_low_bandwidth_behavioral'
        
        return None, 0.0, 'insufficient_evidence'
    
    def extract_domain_from_slips(self, profile, flow_key):
        """Extract domain/SNI from SLIPS profile data"""
        try:
            sni = r.hget(profile, "SNI")
            if sni:
                return sni
            
            dns_queries = r.hget(profile, "DNS")
            if dns_queries:
                dns_data = json.loads(dns_queries)
                if isinstance(dns_data, dict) and dns_data:
                    return list(dns_data.keys())[0]
            
            if 'googlevideo.com' in flow_key:
                return 'googlevideo.com'
            elif 'youtube.com' in flow_key:
                return 'youtube.com'
        
        except Exception as e:
            pass
        
        return None
    
    def label_slips_profiles(self):
        """Label all flows in SLIPS profiles using blocklists + patterns"""
        print(f"\n[{datetime.now()}] Starting DNS blocklist-based labeling...")
        
        labeled_count = {'ad': 0, 'content': 0, 'unlabeled': 0}
        
        try:
            profiles = r.keys("profile_*")
            print(f"📊 Found {len(profiles)} profiles to analyze")
            
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
                            
                            for flow_key, flow_data in outtuples.items():
                                if isinstance(flow_data, list) and len(flow_data) >= 2:
                                    letters = flow_data[0]
                                    timestamps = flow_data[1]
                                    
                                    if isinstance(timestamps, list) and len(timestamps) == 2:
                                        duration = timestamps[1] - timestamps[0]
                                        packets = len(letters)
                                        
                                        domain = self.extract_domain_from_slips(profile, flow_key)
                                        url_path = flow_key if 'videoplayback' in flow_key else ''
                                        
                                        flow_info = {
                                            'domain': domain,
                                            'url_path': url_path,
                                            'duration': duration,
                                            'packets': packets,
                                            'bytes': len(letters) * 1400
                                        }
                                        
                                        label, confidence, reason = self.label_flow(flow_info)
                                        
                                        if label:
                                            training_sample = {
                                                'profile': profile,
                                                'timewindow': tw,
                                                'flow_key': flow_key,
                                                'domain': domain,
                                                'duration': duration,
                                                'packets': packets,
                                                'bytes': flow_info['bytes'],
                                                'label': label,
                                                'confidence': confidence,
                                                'reason': reason,
                                                'labeled_at': time.time(),
                                                'method': 'dns_blocklist'
                                            }
                                            
                                            r.lpush("ml_detector:training_data", json.dumps(training_sample))
                                            labeled_count[label] += 1
                                            self.stats['total_labeled'] += 1
                                        else:
                                            labeled_count['unlabeled'] += 1
                                        
                                        if self.stats['total_labeled'] % 50 == 0:
                                            print(f"  Progress: {labeled_count['ad']} ads, {labeled_count['content']} content")
                
                except Exception as e:
                    continue
            
            print(f"\n{'='*70}")
            print(f"🎯 DNS Blocklist Labeling Complete:")
            print(f"  Ads labeled:     {labeled_count['ad']:,}")
            print(f"  Content labeled: {labeled_count['content']:,}")
            print(f"  Unlabeled:       {labeled_count['unlabeled']:,}")
            print(f"\n📈 Detection Method Breakdown:")
            print(f"  Blocklist matches: {self.stats['blocklist_ad_matches']:,}")
            print(f"  Pattern matches:   {self.stats['pattern_ad_matches']:,}")
            print(f"  Content matches:   {self.stats['content_matches']:,}")
            print(f"  Behavioral:        {self.stats['behavioral_labels']:,}")
            print(f"{'='*70}")
            
            total_samples = r.llen("ml_detector:training_data")
            print(f"\n💾 Total training samples in Redis: {total_samples:,}")
            
            if total_samples >= 100:
                print("✅ Ready for training! Run: python3 train_model.py")
            else:
                print(f"⏳ Need {100 - total_samples} more samples")
            
            return labeled_count
        
        except Exception as e:
            print(f"❌ Error in labeling: {e}")
            return labeled_count
    
    def continuous_labeling(self, interval=300):
        """Continuously label traffic every N seconds"""
        print("\n🔄 Starting continuous DNS blocklist labeling")
        print(f"⏱️  Running every {interval} seconds (Ctrl+C to stop)\n")
        
        while True:
            try:
                counts = self.label_slips_profiles()
                
                print(f"\n⏸️  Waiting {interval}s before next cycle...\n")
                time.sleep(interval)
            
            except KeyboardInterrupt:
                print("\n\n⏹️  Labeling stopped by user")
                break
            except Exception as e:
                print(f"❌ Error in continuous labeling: {e}")
                time.sleep(60)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='DNS Blocklist-based Traffic Labeling')
    parser.add_argument('--continuous', action='store_true', help='Run continuously')
    parser.add_argument('--interval', type=int, default=300, help='Interval in seconds (default: 300)')
    parser.add_argument('--db-path', default='/var/lib/karens-ips/blocklists.db', 
                       help='Path to blocklist SQLite database (default: /var/lib/karens-ips/blocklists.db)')
    
    args = parser.parse_args()
    
    labeler = DNSBlocklistLabeler(db_path=args.db_path)
    
    if args.continuous:
        labeler.continuous_labeling(interval=args.interval)
    else:
        labeler.label_slips_profiles()

if __name__ == "__main__":
    main()
