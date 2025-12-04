#!/usr/bin/env python3
"""
ML-based Ad Traffic Classifier
Combines pattern matching with machine learning to detect ad traffic
"""
import redis
import json
import numpy as np
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pickle
import os

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
        
        if os.path.exists(self.model_path):
            self.load_model()
        else:
            self.train_initial_model()
    
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

if __name__ == '__main__':
    classifier = MLAdClassifier()
    print(f"✅ ML Ad Classifier ready")
    print(f"   Pattern rules: {len(classifier.ad_patterns)} ad patterns")
    print(f"   ML Model: RandomForest with 50 estimators")
    print(f"   Features: 8 flow-based features")
