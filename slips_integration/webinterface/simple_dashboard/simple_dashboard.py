#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only

"""
Simple Ad Blocking Dashboard for Non-Technical Users
Shows easy-to-understand metrics about blocked ads and threats
"""

import json
import sqlite3
import subprocess
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify
from pathlib import Path
import redis
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

class SimpleDashboard:
    def __init__(self):
        self.db_path = "/var/lib/suricata/ips_filter.db"
        self.suricata_log = "/var/log/suricata/fast.log"
        try:
            self.redis_client = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
        except:
            self.redis_client = None
            logger.warning("Redis not available - using file-based stats")
    
    def get_protection_status(self):
        """Check if protection services are running"""
        services = {
            'suricata': False,
            'slips': False,
            'redis': False
        }
        
        try:
            # Check Suricata
            result = subprocess.run(['systemctl', 'is-active', 'suricata'], 
                                  capture_output=True, text=True)
            services['suricata'] = result.returncode == 0
            
            # Check SLIPS
            result = subprocess.run(['systemctl', 'is-active', 'slips'], 
                                  capture_output=True, text=True)
            services['slips'] = result.returncode == 0
            
            # Check Redis
            result = subprocess.run(['systemctl', 'is-active', 'redis-server'], 
                                  capture_output=True, text=True)
            services['redis'] = result.returncode == 0
            
        except Exception as e:
            logger.error(f"Error checking services: {e}")
        
        # Overall status
        all_running = all(services.values())
        status = "PROTECTED" if all_running else "PARTIAL" if any(services.values()) else "NOT PROTECTED"
        
        return {
            'status': status,
            'color': 'green' if all_running else 'yellow' if any(services.values()) else 'red',
            'services': services
        }
    
    def count_blocked_ads_today(self):
        """Count ads blocked today from Suricata logs"""
        try:
            today = datetime.now().strftime('%m/%d')
            
            # Count Karen's IPS blocked entries in Suricata fast.log
            if Path(self.suricata_log).exists():
                with open(self.suricata_log, 'r') as f:
                    count = 0
                    for line in f:
                        if today in line and 'KARENS-IPS' in line and 'Block' in line:
                            count += 1
                    return count
        except Exception as e:
            logger.error(f"Error counting blocked ads: {e}")
        
        return 0
    
    def count_blocked_ads_this_week(self):
        """Count ads blocked this week"""
        try:
            week_ago = datetime.now() - timedelta(days=7)
            count = 0
            
            if Path(self.suricata_log).exists():
                with open(self.suricata_log, 'r') as f:
                    for line in f:
                        if 'KARENS-IPS' in line and 'Block' in line:
                            count += 1
            
            return count
        except Exception as e:
            logger.error(f"Error counting weekly ads: {e}")
        
        return 0
    
    def get_blocked_device_types(self):
        """Get counts of blocked ads by device type"""
        device_counts = {
            'Samsung TV/Fridge': 0,
            'Netflix': 0, 
            'Android Devices': 0,
            'Amazon FireTV': 0,
            'Other Ads': 0
        }
        
        try:
            if Path(self.suricata_log).exists():
                with open(self.suricata_log, 'r') as f:
                    for line in f:
                        if 'KARENS-IPS' in line and 'Block' in line:
                            if 'samsung' in line.lower() or 'smarttv' in line.lower():
                                device_counts['Samsung TV/Fridge'] += 1
                            elif 'netflix' in line.lower():
                                device_counts['Netflix'] += 1
                            elif 'android' in line.lower():
                                device_counts['Android Devices'] += 1
                            elif 'firetv' in line.lower() or 'amazon' in line.lower():
                                device_counts['Amazon FireTV'] += 1
                            else:
                                device_counts['Other Ads'] += 1
        
        except Exception as e:
            logger.error(f"Error getting device stats: {e}")
        
        return device_counts
    
    def get_ml_threat_count(self):
        """Get ML-detected threats from SLIPS"""
        try:
            if self.redis_client:
                # Get SLIPS alerts from Redis
                alerts = self.redis_client.lrange('alerts', 0, -1)
                today = datetime.now().strftime('%Y-%m-%d')
                
                threat_count = 0
                for alert in alerts:
                    try:
                        alert_data = json.loads(alert)
                        if today in alert_data.get('timestamp', ''):
                            threat_count += 1
                    except:
                        continue
                
                return threat_count
        except Exception as e:
            logger.error(f"Error getting ML threats: {e}")
        
        return 0
    
    def get_top_blocked_domains(self, limit=5):
        """Get top blocked domains today"""
        domain_counts = {}
        
        try:
            today = datetime.now().strftime('%m/%d')
            
            if Path(self.suricata_log).exists():
                with open(self.suricata_log, 'r') as f:
                    for line in f:
                        if today in line and 'KARENS-IPS' in line and 'Block' in line:
                            # Extract domain from log line
                            parts = line.split()
                            for part in parts:
                                if '.' in part and not part.startswith('[') and not part.endswith(']'):
                                    domain = part.strip('()[]{}",')
                                    if len(domain.split('.')) >= 2:
                                        domain_counts[domain] = domain_counts.get(domain, 0) + 1
                                        break
        
        except Exception as e:
            logger.error(f"Error getting top domains: {e}")
        
        # Sort and return top domains
        top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{'domain': domain, 'count': count} for domain, count in top_domains]

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('simple_dashboard.html')

@app.route('/api/stats')
def api_stats():
    """API endpoint for dashboard stats"""
    dashboard = SimpleDashboard()
    
    stats = {
        'protection_status': dashboard.get_protection_status(),
        'ads_blocked_today': dashboard.count_blocked_ads_today(),
        'ads_blocked_week': dashboard.count_blocked_ads_this_week(),
        'device_types': dashboard.get_blocked_device_types(),
        'ml_threats': dashboard.get_ml_threat_count(),
        'top_domains': dashboard.get_top_blocked_domains(),
        'last_updated': datetime.now().strftime('%H:%M:%S')
    }
    
    return jsonify(stats)

if __name__ == '__main__':
    # Run on all interfaces, port 55001 (different from SLIPS main UI)
    app.run(host='0.0.0.0', port=55001, debug=False)