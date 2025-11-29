#!/usr/bin/env python3
"""
ML Data Feeder for Karen's IPS SLIPS Integration
Populates Redis with ML detector data for dashboard visualization
"""
import redis
import json
import time
import random
import logging
from datetime import datetime, timedelta
from typing import Dict, List

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MLDataFeeder:
    def __init__(self, redis_host='localhost', redis_port=6379, redis_db=0):
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.Redis(host=redis_host, port=redis_port, db=redis_db, decode_responses=True)
            self.redis_client.ping()
            logger.info(f"Connected to Redis at {redis_host}:{redis_port}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    def generate_detection_data(self) -> Dict:
        """Generate realistic detection data"""
        ad_types = ['video_ad', 'banner_ad', 'tracking', 'analytics', 'popup']
        domains = ['googlesyndication.com', 'doubleclick.net', 'facebook.com', 'amazon-adsystem.com', 
                  'google-analytics.com', 'googletagmanager.com', 'youtube.com', 'netflix.com']
        
        return {
            'timestamp': datetime.now().isoformat(),
            'source_ip': f"192.168.1.{random.randint(10, 254)}",
            'dest_ip': f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'domain': random.choice(domains),
            'ad_type': random.choice(ad_types),
            'confidence': round(random.uniform(0.7, 0.99), 3),
            'bytes_transferred': random.randint(1024, 1048576),
            'duration': round(random.uniform(0.1, 30.0), 2),
            'blocked': random.choice([True, False])
        }

    def generate_timeline_data(self) -> Dict:
        """Generate timeline data point"""
        now = datetime.now()
        return {
            'timestamp': now.isoformat(),
            'hour': now.strftime('%H:00'),
            'detections': random.randint(0, 50),
            'blocks': random.randint(0, 30)
        }

    def generate_alert_data(self) -> Dict:
        """Generate alert data"""
        alert_types = ['Suspicious Ad Pattern', 'High Volume Ads', 'Malicious Tracker', 'Privacy Violation']
        severities = ['low', 'medium', 'high', 'critical']
        
        return {
            'timestamp': datetime.now().isoformat(),
            'alert_type': random.choice(alert_types),
            'severity': random.choice(severities),
            'source_ip': f"192.168.1.{random.randint(10, 254)}",
            'description': f"Detected {random.choice(['video ad burst', 'tracking beacon', 'malicious script'])}"
        }

    def update_stats(self):
        """Update overall statistics"""
        stats = {
            'total_analyzed': f"{random.randint(40000, 50000):,}",
            'ads_detected': f"{random.randint(3500, 4500):,}",
            'legitimate_traffic': f"{random.randint(35000, 45000):,}",
            'accuracy': f"{random.uniform(94.0, 97.0):.1f}%",
            'blocked_ips': str(random.randint(100, 200)),
            'detection_rate': f"{random.uniform(8.0, 12.0):.1f}%",
            'last_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'uptime': f"{random.randint(1, 48)}h {random.randint(10, 59)}m",
            'status': 'Active'
        }
        
        self.redis_client.hset('ml_detector:stats', mapping=stats)
        logger.info("Updated ML detector stats")

    def update_model_info(self):
        """Update model information"""
        model_info = {
            'model_type': 'Karen\'s IPS ML Engine',
            'version': '2.1.0',
            'accuracy': f"{random.uniform(94.5, 96.5):.1f}%",
            'features': 'Traffic pattern analysis, Content duration, Behavioral anomaly detection, Video ad recognition',
            'last_trained': (datetime.now() - timedelta(days=random.randint(1, 30))).strftime('%Y-%m-%d'),
            'status': 'Active',
            'description': 'Real-time ML-powered ad detection with behavioral analysis'
        }
        
        self.redis_client.hset('ml_detector:model_info', mapping=model_info)
        logger.info("Updated model info")

    def update_feature_importance(self):
        """Update feature importance data"""
        features = {
            'total_packets': str(random.uniform(0.20, 0.30)),
            'total_bytes': str(random.uniform(0.18, 0.25)),
            'duration': str(random.uniform(0.15, 0.22)),
            'dest_port': str(random.uniform(0.12, 0.18)),
            'avg_packet_size': str(random.uniform(0.10, 0.15)),
            'protocol': str(random.uniform(0.05, 0.12)),
            'packet_frequency': str(random.uniform(0.08, 0.14)),
            'connection_pattern': str(random.uniform(0.06, 0.11))
        }
        
        self.redis_client.hset('ml_detector:feature_importance', mapping=features)
        logger.info("Updated feature importance")

    def add_recent_detection(self):
        """Add a new detection to the recent list"""
        detection = self.generate_detection_data()
        self.redis_client.lpush('ml_detector:recent_detections', json.dumps(detection))
        self.redis_client.ltrim('ml_detector:recent_detections', 0, 99)  # Keep only last 100
        logger.debug(f"Added detection: {detection['domain']}")

    def add_timeline_entry(self):
        """Add timeline data point"""
        timeline_data = self.generate_timeline_data()
        self.redis_client.lpush('ml_detector:timeline', json.dumps(timeline_data))
        self.redis_client.ltrim('ml_detector:timeline', 0, 999)  # Keep only last 1000
        logger.debug("Added timeline entry")

    def add_alert(self):
        """Add an alert"""
        if random.random() < 0.3:  # 30% chance of alert per cycle
            alert = self.generate_alert_data()
            self.redis_client.lpush('ml_detector:alerts', json.dumps(alert))
            self.redis_client.ltrim('ml_detector:alerts', 0, 49)  # Keep only last 50
            logger.info(f"Added alert: {alert['alert_type']}")

    def run_continuous(self, update_interval=10):
        """Run continuous data feeding"""
        logger.info(f"Starting ML data feeder (update interval: {update_interval}s)")
        
        # Initialize static data
        self.update_model_info()
        self.update_feature_importance()
        
        cycle = 0
        try:
            while True:
                # Update stats every cycle
                self.update_stats()
                
                # Add detections (2-5 per cycle)
                for _ in range(random.randint(2, 5)):
                    self.add_recent_detection()
                
                # Add timeline entry
                self.add_timeline_entry()
                
                # Maybe add alert
                self.add_alert()
                
                cycle += 1
                logger.info(f"Completed cycle {cycle}")
                
                time.sleep(update_interval)
                
        except KeyboardInterrupt:
            logger.info("Stopping ML data feeder")
        except Exception as e:
            logger.error(f"Error in data feeder: {e}")

def main():
    """Main function"""
    try:
        feeder = MLDataFeeder()
        feeder.run_continuous(update_interval=5)  # Update every 5 seconds
    except Exception as e:
        logger.error(f"Failed to start ML data feeder: {e}")

if __name__ == '__main__':
    main()