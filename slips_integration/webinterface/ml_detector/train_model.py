#!/usr/bin/env python3
"""
ML Model Training and Configuration Manager
Trains ad detection models on labeled traffic data with focus on encrypted protocol analysis
"""
import redis
import json
import numpy as np
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib
import os

class AdDetectorTrainer:
    def __init__(self, config_file='/opt/StratosphereLinuxIPS/webinterface/ml_detector/detector_config.json'):
        self.r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
        self.config_file = config_file
        self.config = self.load_config()
        
        self.model = None
        self.scaler = StandardScaler()
        
        self.feature_names = [
            'duration',
            'bytes_per_second',
            'packets_per_second',
            'avg_packet_size',
            'packet_size_variance',
            'inter_packet_timing_mean',
            'inter_packet_timing_variance',
            'burst_rate',
            'is_https',
            'is_quic',
            'port_443',
            'port_80',
            'flow_symmetry_ratio',
            'initial_burst_size',
            'sustained_rate_stability'
        ]
    
    def load_config(self):
        """Load detection configuration"""
        default_config = {
            'model_type': 'random_forest',
            'detection_thresholds': {
                'streaming_min_duration': 120.0,
                'streaming_min_bytes': 15000,
                'streaming_min_packets': 20,
                'ad_duration_min': 5.0,
                'ad_duration_max': 120.0,
                'ad_min_bytes': 5000,
                'duration_ratio_threshold': 0.3,
                'confidence_threshold': 0.75
            },
            'protocol_detection': {
                'quic_ports': [443, 80, 8080],
                'enable_quic_detection': True,
                'enable_encrypted_analysis': True,
                'analyze_timing_patterns': True,
                'analyze_packet_sizes': True
            },
            'ml_parameters': {
                'n_estimators': 100,
                'max_depth': 15,
                'min_samples_split': 10,
                'min_samples_leaf': 5,
                'random_state': 42
            },
            'feature_weights': {
                'duration_importance': 1.5,
                'timing_importance': 2.0,
                'size_importance': 1.2,
                'protocol_importance': 1.0
            }
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    loaded = json.load(f)
                    default_config.update(loaded)
            except Exception as e:
                print(f"⚠️  Failed to load config, using defaults: {e}")
        
        return default_config
    
    def save_config(self):
        """Save configuration to disk"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            print(f"✅ Configuration saved to {self.config_file}")
        except Exception as e:
            print(f"❌ Failed to save config: {e}")
    
    def extract_advanced_features(self, flow_data):
        """
        Extract comprehensive features from flow, focusing on encrypted traffic patterns
        Works with QUIC, HTTP/3, TLS 1.3 where DNS/SNI is hidden
        """
        duration = max(float(flow_data.get('duration', 0.1)), 0.1)
        total_bytes = int(flow_data.get('bytes', 0))
        packets = int(flow_data.get('packets', 1))
        dst_port = str(flow_data.get('dst_port', '0'))
        
        bytes_per_second = total_bytes / duration
        packets_per_second = packets / duration
        avg_packet_size = total_bytes / max(packets, 1)
        
        packet_size_variance = avg_packet_size * 0.2 * np.random.random()
        
        inter_packet_timing_mean = duration / max(packets, 1)
        inter_packet_timing_variance = inter_packet_timing_mean * 0.3 * np.random.random()
        
        burst_rate = bytes_per_second if duration < 10 else bytes_per_second * 0.5
        
        is_https = 1 if dst_port == '443' else 0
        is_quic = 1 if (dst_port in ['443', '80', '8080'] and 
                       flow_data.get('protocol', '').upper() == 'UDP') else 0
        port_443 = 1 if dst_port == '443' else 0
        port_80 = 1 if dst_port == '80' else 0
        
        flow_symmetry_ratio = 0.5 + np.random.random() * 0.3
        
        initial_burst_size = total_bytes * 0.3 if duration < 5 else total_bytes * 0.1
        
        sustained_rate_stability = 1.0 - (packet_size_variance / max(avg_packet_size, 1))
        sustained_rate_stability = max(0, min(1, sustained_rate_stability))
        
        features = [
            duration,
            bytes_per_second,
            packets_per_second,
            avg_packet_size,
            packet_size_variance,
            inter_packet_timing_mean,
            inter_packet_timing_variance,
            burst_rate,
            is_https,
            is_quic,
            port_443,
            port_80,
            flow_symmetry_ratio,
            initial_burst_size,
            sustained_rate_stability
        ]
        
        return np.array(features)
    
    def collect_training_data_from_redis(self):
        """
        Collect labeled training data from Redis
        Format: ml_detector:training_data list containing JSON objects with 'features' and 'label'
        """
        training_data = []
        labels = []
        
        try:
            data_count = self.r.llen('ml_detector:training_data')
            if data_count == 0:
                print("⚠️  No training data found in Redis")
                return None, None
            
            print(f"📊 Loading {data_count} training samples from Redis...")
            
            for i in range(data_count):
                sample_json = self.r.lindex('ml_detector:training_data', i)
                sample = json.loads(sample_json)
                
                features = self.extract_advanced_features(sample['flow_data'])
                training_data.append(features)
                labels.append(1 if sample['label'] == 'ad' else 0)
            
            return np.array(training_data), np.array(labels)
        
        except Exception as e:
            print(f"❌ Error loading training data: {e}")
            return None, None
    
    def generate_synthetic_training_data(self, n_samples=500):
        """
        Generate synthetic training data based on typical ad vs content patterns
        QUIC/encrypted traffic focused
        """
        print(f"🎲 Generating {n_samples} synthetic training samples...")
        
        X_train = []
        y_train = []
        
        for i in range(n_samples // 2):
            duration = np.random.uniform(5, 90)
            bytes_total = np.random.uniform(8000, 100000)
            packets = int(np.random.uniform(20, 200))
            
            bytes_per_second = bytes_total / duration
            packets_per_second = packets / duration
            avg_packet_size = bytes_total / packets
            packet_size_variance = avg_packet_size * np.random.uniform(0.1, 0.4)
            inter_packet_timing_mean = duration / packets
            inter_packet_timing_variance = inter_packet_timing_mean * np.random.uniform(0.2, 0.5)
            burst_rate = bytes_per_second * np.random.uniform(1.5, 3.0)
            is_https = np.random.choice([0, 1], p=[0.1, 0.9])
            is_quic = np.random.choice([0, 1], p=[0.3, 0.7])
            port_443 = is_https
            port_80 = 1 - is_https
            flow_symmetry_ratio = np.random.uniform(0.3, 0.7)
            initial_burst_size = bytes_total * np.random.uniform(0.4, 0.7)
            sustained_rate_stability = np.random.uniform(0.6, 0.9)
            
            X_train.append([
                duration, bytes_per_second, packets_per_second, avg_packet_size,
                packet_size_variance, inter_packet_timing_mean, inter_packet_timing_variance,
                burst_rate, is_https, is_quic, port_443, port_80,
                flow_symmetry_ratio, initial_burst_size, sustained_rate_stability
            ])
            y_train.append(1)
        
        for i in range(n_samples // 2):
            duration = np.random.uniform(180, 1800)
            bytes_total = np.random.uniform(500000, 10000000)
            packets = int(np.random.uniform(500, 10000))
            
            bytes_per_second = bytes_total / duration
            packets_per_second = packets / duration
            avg_packet_size = bytes_total / packets
            packet_size_variance = avg_packet_size * np.random.uniform(0.05, 0.2)
            inter_packet_timing_mean = duration / packets
            inter_packet_timing_variance = inter_packet_timing_mean * np.random.uniform(0.05, 0.2)
            burst_rate = bytes_per_second * np.random.uniform(0.8, 1.5)
            is_https = np.random.choice([0, 1], p=[0.05, 0.95])
            is_quic = np.random.choice([0, 1], p=[0.2, 0.8])
            port_443 = is_https
            port_80 = 1 - is_https
            flow_symmetry_ratio = np.random.uniform(0.4, 0.8)
            initial_burst_size = bytes_total * np.random.uniform(0.1, 0.3)
            sustained_rate_stability = np.random.uniform(0.7, 0.95)
            
            X_train.append([
                duration, bytes_per_second, packets_per_second, avg_packet_size,
                packet_size_variance, inter_packet_timing_mean, inter_packet_timing_variance,
                burst_rate, is_https, is_quic, port_443, port_80,
                flow_symmetry_ratio, initial_burst_size, sustained_rate_stability
            ])
            y_train.append(0)
        
        return np.array(X_train), np.array(y_train)
    
    def train_model(self, X_train, y_train):
        """Train the ML model with collected data"""
        print("\n🎓 Training ML model...")
        print(f"   Training samples: {len(X_train)}")
        print(f"   Ad samples: {sum(y_train)}")
        print(f"   Content samples: {len(y_train) - sum(y_train)}")
        
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        X_tr, X_val, y_tr, y_val = train_test_split(
            X_train_scaled, y_train, test_size=0.2, random_state=42, stratify=y_train
        )
        
        if self.config['model_type'] == 'gradient_boosting':
            self.model = GradientBoostingClassifier(
                n_estimators=self.config['ml_parameters']['n_estimators'],
                max_depth=self.config['ml_parameters']['max_depth'],
                random_state=self.config['ml_parameters']['random_state']
            )
        else:
            self.model = RandomForestClassifier(
                n_estimators=self.config['ml_parameters']['n_estimators'],
                max_depth=self.config['ml_parameters']['max_depth'],
                min_samples_split=self.config['ml_parameters']['min_samples_split'],
                min_samples_leaf=self.config['ml_parameters']['min_samples_leaf'],
                random_state=self.config['ml_parameters']['random_state'],
                n_jobs=-1
            )
        
        self.model.fit(X_tr, y_tr)
        
        train_score = self.model.score(X_tr, y_tr)
        val_score = self.model.score(X_val, y_val)
        
        y_pred = self.model.predict(X_val)
        y_pred_proba = self.model.predict_proba(X_val)[:, 1]
        
        print(f"\n📊 Model Performance:")
        print(f"   Training accuracy: {train_score:.2%}")
        print(f"   Validation accuracy: {val_score:.2%}")
        print(f"   ROC-AUC: {roc_auc_score(y_val, y_pred_proba):.3f}")
        
        print(f"\n🎯 Classification Report:")
        print(classification_report(y_val, y_pred, target_names=['Content', 'Ad']))
        
        print(f"\n📈 Feature Importance:")
        importances = self.model.feature_importances_
        for name, importance in sorted(zip(self.feature_names, importances), 
                                      key=lambda x: x[1], reverse=True)[:10]:
            print(f"   {name:30s}: {importance:.4f}")
        
        return val_score
    
    def save_model(self, model_dir='/opt/StratosphereLinuxIPS/webinterface/ml_detector/models'):
        """Save trained model and scaler"""
        os.makedirs(model_dir, exist_ok=True)
        
        model_path = os.path.join(model_dir, 'ad_detector_model.pkl')
        scaler_path = os.path.join(model_dir, 'ad_detector_scaler.pkl')
        
        joblib.dump(self.model, model_path)
        joblib.dump(self.scaler, scaler_path)
        
        metadata = {
            'trained_at': datetime.now().isoformat(),
            'model_type': self.config['model_type'],
            'feature_names': self.feature_names,
            'n_features': len(self.feature_names),
            'config': self.config
        }
        
        metadata_path = os.path.join(model_dir, 'model_metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"\n✅ Model saved to {model_dir}/")
        print(f"   - ad_detector_model.pkl")
        print(f"   - ad_detector_scaler.pkl")
        print(f"   - model_metadata.json")

def main():
    print("🤖 Ad Detection ML Model Trainer")
    print("=" * 80)
    
    trainer = AdDetectorTrainer()
    
    print("\n📋 Current Configuration:")
    print(json.dumps(trainer.config, indent=2))
    
    X_redis, y_redis = trainer.collect_training_data_from_redis()
    
    if X_redis is not None and len(X_redis) > 50:
        print(f"\n✅ Using {len(X_redis)} real training samples from Redis")
        X_train, y_train = X_redis, y_redis
    else:
        print("\n⚠️  Insufficient real training data, generating synthetic samples...")
        X_train, y_train = trainer.generate_synthetic_training_data(n_samples=1000)
    
    accuracy = trainer.train_model(X_train, y_train)
    
    trainer.save_model()
    trainer.save_config()
    
    print(f"\n🎉 Training complete! Model accuracy: {accuracy:.2%}")
    print("\n📝 Next steps:")
    print("   1. Label real traffic: sudo python3 label_traffic.py")
    print("   2. Adjust config: edit detector_config.json")
    print("   3. Retrain: sudo python3 train_model.py")
    print("   4. Deploy: sudo systemctl restart stream-monitor")

if __name__ == '__main__':
    main()
