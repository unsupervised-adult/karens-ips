#!/usr/bin/env python3
"""
ML-based Ad Traffic Classifier
Recognizes universal video ad patterns: duration, skip timing, bitrate signatures
Works across YouTube, Twitch, Hulu, etc. - ads have consistent temporal patterns
"""
import redis
import json
import numpy as np
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pickle
import os
from collections import defaultdict
from time import time

class MLAdClassifier:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.model_path = '/opt/StratosphereLinuxIPS/webinterface/ml_detector/ad_classifier_model.pkl'
        self.scaler_path = '/opt/StratosphereLinuxIPS/webinterface/ml_detector/ad_classifier_scaler.pkl'
        
        self.ad_patterns = [
            'doubleclick', 'googlesyndication', 'googleadservices',
            'advertising', 'adservice', 'pagead', 'adnxs', 'adsrvr',
            'criteo', 'taboola', 'outbrain', 'amazon-adsystem',
            'googletagmanager', 'googletagservices', 'imasdk',
            'scorecardresearch', 'moatads', 'addthis', 'sharethis'
        ]
        
        # Universal video ad temporal patterns (platform-agnostic)
        self.universal_ad_signatures = {
            'bumper': {
                'duration': (1, 6),           # 6-second non-skippable
                'skip_time': None,
                'bitrate_range': (500, 2000),  # Lower quality
                'confidence': 0.95
            },
            'skippable_standard': {
                'duration': (15, 90),          # 15-90 seconds
                'skip_time': (5, 6),           # Skip after 5 seconds
                'bitrate_range': (800, 3000),
                'confidence': 0.90
            },
            'non_skippable_15': {
                'duration': (13, 17),          # 15-second forced
                'skip_time': None,
                'bitrate_range': (800, 3000),
                'confidence': 0.92
            },
            'non_skippable_20': {
                'duration': (18, 22),          # 20-second forced
                'skip_time': None,
                'bitrate_range': (800, 3000),
                'confidence': 0.92
            },
            'non_skippable_30': {
                'duration': (28, 32),          # 30-second forced
                'skip_time': None,
                'bitrate_range': (800, 3000),
                'confidence': 0.90
            },
            'mid_roll_short': {
                'duration': (10, 20),          # Mid-video interruption
                'skip_time': (5, 6),
                'bitrate_range': (800, 3000),
                'confidence': 0.85
            },
            'pre_roll_long': {
                'duration': (30, 180),         # Long pre-roll
                'skip_time': (5, 6),
                'bitrate_range': (1000, 4000),
                'confidence': 0.88
            },
            'double_ad_pod': {
                'duration': (55, 65),          # 2x30s consecutive ads
                'skip_time': None,
                'bitrate_range': (800, 3000),
                'confidence': 0.93
            },
            'triple_ad_pod': {
                'duration': (85, 95),          # 3x30s consecutive ads
                'skip_time': None,
                'bitrate_range': (800, 3000),
                'confidence': 0.93
            }
        }
        
        # Track recent ads per IP to detect ad pods
        self.recent_ads = defaultdict(list)  # {ip: [(timestamp, duration), ...]}
        
        if os.path.exists(self.model_path):
            self.load_model()
        else:
            self.train_initial_model()
    
    def detect_ad_pod_sequence(self, ip_addr, duration):
        """
        Track consecutive ads to detect ad pods (e.g., 2x30s YouTube ads)
        Returns: (is_pod, pod_type) or (False, None)
        """
        current_time = time()
        
        # Clean old entries (older than 5 minutes)
        self.recent_ads[ip_addr] = [
            (ts, dur) for ts, dur in self.recent_ads[ip_addr]
            if current_time - ts < 300
        ]
        
        # Add current ad
        self.recent_ads[ip_addr].append((current_time, duration))
        
        # Look for consecutive ads within 10 seconds of each other
        recent = self.recent_ads[ip_addr]
        if len(recent) >= 2:
            last_two = recent[-2:]
            time_gap = last_two[1][0] - last_two[0][0]
            total_duration = sum(dur for _, dur in last_two)
            
            # 2x30s ad pod (55-65 seconds total, within 10s gap)
            if time_gap < 10 and 55 <= total_duration <= 65:
                return True, 'double_ad_pod_detected'
            
            # Check for 3x30s if we have enough history
            if len(recent) >= 3:
                last_three = recent[-3:]
                if all(last_three[i+1][0] - last_three[i][0] < 10 for i in range(2)):
                    total_duration = sum(dur for _, dur in last_three)
                    if 85 <= total_duration <= 95:
                        return True, 'triple_ad_pod_detected'
        
        return False, None
    
    def detect_video_ad_pattern(self, duration, bytes_transferred, ip_addr=None, skip_detected=False):
        """
        Detect universal video ad patterns based on temporal signatures
        Returns: (is_ad, ad_type, confidence)
        """
        if duration <= 0:
            return False, None, 0.0
        
        # Calculate approximate bitrate (Kbps)
        bitrate = (bytes_transferred * 8) / (duration * 1000)
        
        # Check for ad pod sequences first (higher confidence)
        if ip_addr:
            is_pod, pod_type = self.detect_ad_pod_sequence(ip_addr, duration)
            if is_pod:
                return True, pod_type, 0.95
        
        best_match = None
        best_confidence = 0.0
        
        for ad_type, signature in self.universal_ad_signatures.items():
            min_dur, max_dur = signature['duration']
            min_br, max_br = signature['bitrate_range']
            
            # Check duration match
            if min_dur <= duration <= max_dur:
                confidence = signature['confidence']
                
                # Boost confidence if bitrate is in expected range
                if min_br <= bitrate <= max_br:
                    confidence += 0.05
                
                # Boost confidence if skip was detected at expected time
                if signature['skip_time'] and skip_detected:
                    confidence += 0.05
                
                # Non-skippable ads are more certain if no skip detected
                if signature['skip_time'] is None and not skip_detected:
                    confidence += 0.03
                
                if confidence > best_confidence:
                    best_confidence = min(1.0, confidence)
                    best_match = ad_type
        
        if best_match:
            return True, best_match, best_confidence
        
        # Check for suspicious patterns even without exact match
        # Short videos with low bitrate = likely ads
        if 5 <= duration <= 60 and bitrate < 2000:
            return True, 'unknown_short_ad', 0.70
        
        return False, None, 0.0
    
    def extract_flow_features(self, profile_data, dst_ip, dst_port):
        """Extract ML features from SLIPS flow data"""
        features = []
        
        try:
            packets = int(profile_data.get('packets', 0))
            bytes_sent = int(profile_data.get('bytes', 0))
            duration = float(profile_data.get('duration', 0.1))
            
            features.append(packets)
            features.append(bytes_sent)
            features.append(bytes_sent / max(packets, 1))
            features.append(packets / max(duration, 0.1))
            features.append(bytes_sent / max(duration, 0.1))
            features.append(1 if dst_port == 443 else 0)
            features.append(1 if dst_port == 80 else 0)
            features.append(len(dst_ip.split('.')))
            
        except:
            features = [0] * 8
        
        return np.array(features).reshape(1, -1)
    
    def train_initial_model(self):
        """Train initial model with synthetic ad/content patterns"""
        print("🎓 Training initial ML model...")
        
        ad_samples = []
        for _ in range(100):
            ad_samples.append([
                np.random.randint(1, 10),
                np.random.randint(100, 5000),
                np.random.randint(100, 500),
                np.random.randint(1, 20),
                np.random.randint(100, 2000),
                1,
                0,
                4
            ])
        
        content_samples = []
        for _ in range(100):
            content_samples.append([
                np.random.randint(50, 500),
                np.random.randint(50000, 5000000),
                np.random.randint(5000, 50000),
                np.random.randint(100, 1000),
                np.random.randint(50000, 500000),
                1,
                0,
                4
            ])
        
        X = np.array(ad_samples + content_samples)
        y = np.array([1] * len(ad_samples) + [0] * len(content_samples))
        
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        
        self.model = RandomForestClassifier(
            n_estimators=50,
            max_depth=10,
            min_samples_split=5,
            random_state=42,
            n_jobs=2
        )
        self.model.fit(X_scaled, y)
        
        self.save_model()
        print("✅ Initial model trained")
    
    def save_model(self):
        """Save model and scaler to disk"""
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            with open(self.scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
        except Exception as e:
            print(f"Warning: Could not save model: {e}")
    
    def load_model(self):
        """Load model and scaler from disk"""
        try:
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            with open(self.scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            print("✅ Loaded existing ML model")
        except Exception as e:
            print(f"Could not load model: {e}")
            self.train_initial_model()
    
    def is_ad_domain_pattern(self, domain):
        """Fast pattern matching first pass"""
        domain_lower = domain.lower()
        return any(pattern in domain_lower for pattern in self.ad_patterns)
    
    def classify_flow(self, domain, profile_data, dst_ip, dst_port):
        """
        Hybrid classification: pattern matching + ML
        Returns: (is_ad, confidence, method)
        """
        pattern_match = self.is_ad_domain_pattern(domain)
        
        if not pattern_match:
            return False, 0.0, "pattern_rejected"
        
        features = self.extract_flow_features(profile_data, dst_ip, dst_port)
        
        try:
            features_scaled = self.scaler.transform(features)
            ml_prediction = self.model.predict(features_scaled)[0]
            ml_confidence = self.model.predict_proba(features_scaled)[0]
            
            if ml_prediction == 1:
                confidence = max(ml_confidence[1], 0.70)
                return True, confidence, "hybrid_ml_pattern"
            else:
                return False, ml_confidence[0], "ml_rejected_pattern"
        except:
            return True, 0.85, "pattern_only"
    
    def retrain_on_feedback(self, new_samples_X, new_labels_y):
        """Incrementally retrain model with new labeled data"""
        if len(new_samples_X) < 10:
            return
        
        X_scaled = self.scaler.transform(new_samples_X)
        self.model.fit(X_scaled, new_labels_y)
        self.save_model()
        print(f"✅ Model retrained with {len(new_samples_X)} new samples")
    
    def classify_with_llm(self, domain, profile_data, dst_ip, dst_port, dns_history=None):
        """
        Hybrid ML + LLM classification for borderline cases
        Returns: (is_ad, confidence, method, llm_reasoning)
        """
        # First, get ML classification
        is_ad_ml, ml_confidence, ml_method = self.classify_flow(domain, profile_data, dst_ip, dst_port)
        
        # Only use LLM for borderline cases (confidence between 0.60 and 0.85)
        if ml_confidence < 0.60 or ml_confidence > 0.85:
            return is_ad_ml, ml_confidence, ml_method, None
        
        # Prepare data for LLM analysis
        try:
            import requests
            
            flow_data = {
                'daddr': dst_ip,
                'dport': dst_port,
                'packets': profile_data.get('packets', 0),
                'bytes': profile_data.get('bytes', 0),
                'duration': profile_data.get('duration', 0),
                'dns_history': dns_history or [],
                'ml_confidence': ml_confidence,
                'ml_classification': 'ad' if is_ad_ml else 'legitimate'
            }
            
            # Call LLM endpoint
            response = requests.post(
                'http://localhost:55000/ml_detector/analyze_flow_with_llm',
                json=flow_data,
                timeout=10
            )
            
            if response.status_code == 200:
                llm_result = response.json()
                
                if llm_result.get('success'):
                    llm_confidence = llm_result.get('confidence', 0.5)
                    llm_classification = llm_result.get('classification', 'uncertain')
                    llm_reasoning = llm_result.get('reasoning', '')
                    
                    # Combine ML and LLM confidence
                    combined_confidence = (ml_confidence + llm_confidence) / 2
                    
                    # Determine final classification
                    is_ad_final = (
                        llm_classification in ['video_ad', 'ad_telemetry'] or
                        (is_ad_ml and combined_confidence > 0.65)
                    )
                    
                    return is_ad_final, combined_confidence, 'hybrid_ml_llm', llm_reasoning
            
        except Exception as e:
            print(f"LLM analysis failed, falling back to ML only: {e}")
        
        # Fallback to ML-only decision
        return is_ad_ml, ml_confidence, ml_method, None

if __name__ == '__main__':
    classifier = MLAdClassifier()
    print(f"✅ ML Ad Classifier ready")
    print(f"   Pattern rules: {len(classifier.ad_patterns)} ad patterns")
    print(f"   ML Model: RandomForest with 50 estimators")
    print(f"   Features: 8 flow-based features")
    print(f"   LLM Enhancement: Available for borderline cases (0.60-0.85 confidence)")
