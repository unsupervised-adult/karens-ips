"""
SLIPS ML Ad Detector Module

This module implements the SLIPS IModule interface for ML-based ad/telemetry detection.
Integrates with the SLIPS evidence system for coordinated threat response.
"""

import json
import time
import sqlite3
import threading
from datetime import datetime
from typing import Dict, Any, Optional, List
import logging
import ipaddress
from pathlib import Path

# SLIPS imports
from slips_files.common.abstracts.imodule import IModule
from slips_files.core.database.database_manager import DBManager

# Local imports
from .feature_extractor import AdTrafficFeatureExtractor
from .predictor import AdPredictor
from .utils import load_config, setup_logging, is_private_ip


class MLAdDetector(IModule):
    """
    Machine Learning Ad/Telemetry Detector for SLIPS.
    
    Analyzes network flows using ML to detect advertising and telemetry traffic.
    Sets evidence in SLIPS format for coordinated blocking decisions.
    """
    
    name = 'ML Ad Detector'
    description = 'Machine learning detection of ads and telemetry traffic'
    authors = ['Karen\'s IPS Project']
    
    def __init__(self, *args, **kwargs):
        """Initialize the ML Ad Detector module."""
        super().__init__(*args, **kwargs)
        
        # Module configuration
        self.config = None
        self.feature_extractor = None
        self.predictor = None
        self.db_manager = None
        
        # SQLite database for logging predictions
        self.predictions_db = None
        self.db_lock = threading.Lock()
        
        # Statistics tracking
        self.stats = {
            'total_flows_processed': 0,
            'predictions_made': 0,
            'ads_detected': 0,
            'evidence_set': 0,
            'false_positives': 0,
            'processing_time_total': 0
        }
        
        # Batch processing
        self.flow_batch = []
        self.batch_size = 32
        self.last_batch_time = time.time()
        
        self.logger = logging.getLogger(f'slips.{self.name}')
    
    def init(self) -> bool:
        """
        Initialize the module - load config, models, and connect to databases.
        
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            # Load configuration
            config_path = Path(__file__).parent.parent / 'config' / 'ml_detector.yaml'
            self.config = load_config(str(config_path))
            
            if not self.config:
                self.logger.error("Failed to load configuration")
                return False
            
            # Setup logging
            log_config = self.config.get('logging', {})
            setup_logging(
                log_config.get('level', 'INFO'),
                log_config.get('file', None)
            )
            
            # Initialize feature extractor
            redis_config = self.config.get('redis', {})
            self.feature_extractor = AdTrafficFeatureExtractor(
                redis_host=redis_config.get('host', 'localhost'),
                redis_ports={
                    'main': redis_config.get('ports', {}).get('main', 6379),
                    'cache': redis_config.get('ports', {}).get('cache', 6380)
                }
            )
            
            # Initialize predictor
            model_config = self.config.get('model', {})
            model_path = model_config.get('path', 'models/ad_detector_v1.tflite')
            scaler_path = model_config.get('scaler_path', 'models/scaler.pkl')
            
            # Check if model files exist
            if not Path(model_path).exists():
                self.logger.warning(f"Model file not found: {model_path}")
                self.logger.info("Module will run in data collection mode until model is trained")
                self.predictor = None
            else:
                self.predictor = AdPredictor(model_path, scaler_path)
                
                # Validate model
                if not self.predictor.validate_model():
                    self.logger.error("Model validation failed")
                    return False
            
            # Initialize SQLite database for predictions
            self._init_predictions_db()
            
            # Get SLIPS database manager
            self.db_manager = self.db
            
            self.logger.info("ML Ad Detector initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Initialization failed: {e}")
            return False
    
    def pre_main(self) -> None:
        """Set up subscriptions to SLIPS channels before main loop."""
        try:
            # Subscribe to new flow notifications
            self.db_manager.subscribe_to_new_flow()
            
            # Subscribe to evidence notifications for feedback
            self.db_manager.subscribe_to_evidence_added()
            
            self.logger.info("Subscribed to SLIPS channels")
            
        except Exception as e:
            self.logger.error(f"Failed to subscribe to channels: {e}")
    
    def main(self) -> None:
        """
        Main processing loop - analyze flows and set evidence.
        """
        try:
            while not self.should_stop():
                # Get new flows from SLIPS
                message = self.get_msg('new_flow')
                
                if message:
                    self._process_flow_message(message)
                
                # Process batched flows periodically
                current_time = time.time()
                if (len(self.flow_batch) >= self.batch_size or 
                    (self.flow_batch and current_time - self.last_batch_time > 5)):
                    self._process_flow_batch()
                
                # Update statistics periodically
                if current_time % 60 < 1:  # Every minute
                    self._update_statistics()
                
                time.sleep(0.1)  # Prevent CPU spinning
                
        except KeyboardInterrupt:
            self.logger.info("ML Ad Detector stopped by user")
        except Exception as e:
            self.logger.error(f"Main loop error: {e}")
    
    def _process_flow_message(self, message: str) -> None:
        """
        Process a new flow message from SLIPS.
        
        Args:
            message: JSON message with flow data
        """
        try:
            flow_info = json.loads(message)
            
            profileid = flow_info.get('profileid', '')
            twid = flow_info.get('twid', '') 
            flow_data = flow_info.get('flow', {})
            
            if not flow_data:
                return
            
            # Filter out private/local traffic
            dst_ip = flow_data.get('daddr', '')
            if is_private_ip(dst_ip):
                return
            
            # Add to batch for processing
            self.flow_batch.append({
                'profileid': profileid,
                'twid': twid,
                'flow_data': flow_data,
                'timestamp': time.time()
            })
            
            self.stats['total_flows_processed'] += 1
            
        except (json.JSONDecodeError, KeyError) as e:
            self.logger.debug(f"Error processing flow message: {e}")
    
    def _process_flow_batch(self) -> None:
        """Process batched flows for ML prediction."""
        if not self.flow_batch or not self.predictor:
            self.flow_batch.clear()
            self.last_batch_time = time.time()
            return
        
        start_time = time.time()
        
        try:
            # Extract features for each flow
            feature_list = []
            flow_contexts = []
            
            for flow_item in self.flow_batch:
                try:
                    # Extract time series features
                    dst_ip = flow_item['flow_data'].get('daddr', '')
                    features = self.feature_extractor.extract_time_series(dst_ip)
                    
                    feature_list.append(features)
                    flow_contexts.append(flow_item)
                    
                except Exception as e:
                    self.logger.debug(f"Feature extraction failed: {e}")
                    continue
            
            if not feature_list:
                self.flow_batch.clear()
                self.last_batch_time = time.time()
                return
            
            # Batch prediction
            predictions = self.predictor.predict_batch(feature_list)
            
            # Process predictions
            for context, prediction in zip(flow_contexts, predictions):
                self._handle_prediction(context, prediction)
            
            # Update statistics
            processing_time = time.time() - start_time
            self.stats['processing_time_total'] += processing_time
            self.stats['predictions_made'] += len(predictions)
            
            # Log batch performance
            if processing_time > 1.0:  # Log slow batches
                self.logger.warning(
                    f"Slow batch processing: {len(feature_list)} flows in {processing_time:.2f}s"
                )
            
        except Exception as e:
            self.logger.error(f"Batch processing failed: {e}")
        
        finally:
            self.flow_batch.clear()
            self.last_batch_time = time.time()
    
    def _handle_prediction(self, flow_context: Dict, prediction: float) -> None:
        """
        Handle ML prediction result and set evidence if needed.
        
        Args:
            flow_context: Flow context with profileid, twid, flow_data
            prediction: Prediction probability [0-1]
        """
        try:
            profileid = flow_context['profileid']
            twid = flow_context['twid'] 
            flow_data = flow_context['flow_data']
            dst_ip = flow_data.get('daddr', '')
            
            # Get confidence threshold from config
            confidence_threshold = self.config.get('detection', {}).get('confidence_threshold', 0.75)
            high_confidence_threshold = self.config.get('detection', {}).get('high_confidence_threshold', 0.90)
            
            # Log prediction to database
            self._log_prediction(dst_ip, prediction, flow_data)
            
            # Set evidence if prediction exceeds threshold
            if prediction >= confidence_threshold:
                threat_level = 'high' if prediction >= high_confidence_threshold else 'medium'
                
                self.set_evidence_ad_detected(
                    dst_ip=dst_ip,
                    confidence=prediction,
                    threat_level=threat_level,
                    profileid=profileid,
                    twid=twid,
                    flow_data=flow_data
                )
                
                self.stats['ads_detected'] += 1
                self.stats['evidence_set'] += 1
                
                self.logger.info(
                    f"Ad detected: {dst_ip} (confidence: {prediction:.3f}, level: {threat_level})"
                )
            
        except Exception as e:
            self.logger.error(f"Error handling prediction: {e}")
    
    def set_evidence_ad_detected(
        self, 
        dst_ip: str, 
        confidence: float, 
        threat_level: str,
        profileid: str, 
        twid: str, 
        flow_data: Dict
    ) -> None:
        """
        Set evidence in SLIPS format for ad/telemetry detection.
        
        Args:
            dst_ip: Destination IP address
            confidence: ML prediction confidence [0-1]
            threat_level: 'medium' or 'high'
            profileid: SLIPS profile ID
            twid: SLIPS time window ID  
            flow_data: Original flow data
        """
        try:
            # Create evidence in SLIPS format
            evidence = {
                'type': 'AdTelemetryDetected',
                'attacker': dst_ip,
                'threat_level': threat_level,
                'confidence': confidence,
                'description': f'ML detected ad/telemetry traffic (confidence: {confidence:.1%})',
                'profile': profileid,
                'timewindow': twid,
                'source': 'ml_ad_detector',
                'timestamp': datetime.now().isoformat(),
                'flow_info': {
                    'dst_port': flow_data.get('dport'),
                    'protocol': flow_data.get('proto'), 
                    'bytes_sent': flow_data.get('sbytes'),
                    'bytes_recv': flow_data.get('dbytes'),
                    'duration': flow_data.get('dur')
                }
            }
            
            # Set evidence in SLIPS database
            self.db_manager.set_evidence(
                profileid=profileid,
                twid=twid,
                evidence_type='AdTelemetryDetected',
                attacker_direction='dstip',
                attacker=dst_ip,
                threat_level=threat_level,
                confidence=confidence,
                description=evidence['description'],
                timestamp=datetime.now(),
                category='Malware',
                source_target_tag='src',
                conn_count=1,
                port=flow_data.get('dport', ''),
                proto=flow_data.get('proto', ''),
                evidence_data=evidence
            )
            
        except Exception as e:
            self.logger.error(f"Failed to set evidence: {e}")
    
    def _init_predictions_db(self) -> None:
        """Initialize SQLite database for logging predictions."""
        try:
            db_config = self.config.get('database', {})
            db_path = db_config.get('path', '/opt/ml-ad-detector/data/predictions.db')
            
            # Create directory if needed
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            
            self.predictions_db = sqlite3.connect(db_path, check_same_thread=False)
            
            # Create tables
            self.predictions_db.executescript("""
                CREATE TABLE IF NOT EXISTS ml_predictions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    dst_ip TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    prediction INTEGER NOT NULL,
                    flow_data TEXT,
                    actual INTEGER DEFAULT NULL,
                    feedback_timestamp REAL DEFAULT NULL
                );
                
                CREATE TABLE IF NOT EXISTS ml_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL UNIQUE,
                    predictions INTEGER DEFAULT 0,
                    blocks INTEGER DEFAULT 0,
                    false_positives INTEGER DEFAULT 0,
                    accuracy REAL DEFAULT NULL
                );
                
                CREATE INDEX IF NOT EXISTS idx_predictions_timestamp ON ml_predictions(timestamp);
                CREATE INDEX IF NOT EXISTS idx_predictions_dst_ip ON ml_predictions(dst_ip);
                CREATE INDEX IF NOT EXISTS idx_stats_date ON ml_stats(date);
            """)
            
            self.predictions_db.commit()
            self.logger.info(f"Predictions database initialized: {db_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize predictions database: {e}")
            self.predictions_db = None
    
    def _log_prediction(self, dst_ip: str, confidence: float, flow_data: Dict) -> None:
        """Log prediction to SQLite database."""
        if not self.predictions_db:
            return
        
        try:
            prediction = 1 if confidence >= 0.75 else 0
            
            with self.db_lock:
                self.predictions_db.execute("""
                    INSERT INTO ml_predictions 
                    (timestamp, dst_ip, confidence, prediction, flow_data)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    time.time(),
                    dst_ip,
                    confidence,
                    prediction,
                    json.dumps(flow_data)
                ))
                self.predictions_db.commit()
                
        except Exception as e:
            self.logger.debug(f"Failed to log prediction: {e}")
    
    def _update_statistics(self) -> None:
        """Update daily statistics in database."""
        if not self.predictions_db:
            return
        
        try:
            today = datetime.now().strftime('%Y-%m-%d')
            
            with self.db_lock:
                # Count today's predictions
                cursor = self.predictions_db.execute("""
                    SELECT COUNT(*), SUM(prediction) 
                    FROM ml_predictions 
                    WHERE DATE(timestamp, 'unixepoch') = ?
                """, (today,))
                
                row = cursor.fetchone()
                predictions_count = row[0] if row else 0
                blocks_count = row[1] if row and row[1] else 0
                
                # Update or insert statistics
                self.predictions_db.execute("""
                    INSERT OR REPLACE INTO ml_stats (date, predictions, blocks)
                    VALUES (?, ?, ?)
                """, (today, predictions_count, blocks_count))
                
                self.predictions_db.commit()
                
        except Exception as e:
            self.logger.debug(f"Failed to update statistics: {e}")
    
    def shutdown_gracefully(self) -> None:
        """Clean shutdown - save stats and close connections."""
        try:
            self.logger.info("ML Ad Detector shutting down...")
            
            # Process remaining batched flows
            if self.flow_batch:
                self._process_flow_batch()
            
            # Save final statistics
            self._update_statistics()
            
            # Close database
            if self.predictions_db:
                self.predictions_db.close()
            
            # Log final stats
            self.logger.info(f"Final statistics: {self.stats}")
            
            # Performance summary
            if self.predictor:
                perf_stats = self.predictor.get_performance_stats()
                self.logger.info(f"Performance: {perf_stats}")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")
    
    def get_statistics(self) -> Dict:
        """Get current module statistics."""
        stats = self.stats.copy()
        
        if self.predictor:
            stats['performance'] = self.predictor.get_performance_stats()
        
        return stats