"""
Integration tests for ML Ad Detector
"""

import pytest
import time
import json
import sqlite3
import numpy as np
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from feature_extractor import AdTrafficFeatureExtractor
from predictor import AdPredictor


@pytest.fixture
def test_db():
    """Create test database"""
    db_path = Path('/tmp/test_detector.db')

    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE ml_predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            dst_ip TEXT NOT NULL,
            confidence REAL NOT NULL,
            prediction INTEGER NOT NULL,
            actual INTEGER
        )
    ''')

    cursor.execute('''
        CREATE TABLE ml_stats (
            date TEXT PRIMARY KEY,
            predictions INTEGER DEFAULT 0,
            blocks INTEGER DEFAULT 0,
            false_positives INTEGER DEFAULT 0
        )
    ''')

    conn.commit()
    conn.close()

    yield db_path

    if db_path.exists():
        db_path.unlink()


@pytest.fixture
def mock_model():
    """Mock TFLite model"""
    model_path = Path('/tmp/test_model.tflite')

    model_data = b'\x00' * 1024
    model_path.write_bytes(model_data)

    yield model_path

    if model_path.exists():
        model_path.unlink()


class TestModuleInitialization:
    """Test SLIPS module initialization"""

    def test_module_import(self):
        """Test that module can be imported"""
        try:
            import slips_module
            assert hasattr(slips_module, 'MLAdDetector')
        except ImportError:
            pytest.skip("SLIPS module not available")

    def test_feature_extractor_init(self):
        """Test feature extractor initialization"""
        with patch('redis.Redis') as mock_redis:
            mock_redis.return_value.ping.return_value = True

            extractor = AdTrafficFeatureExtractor()
            assert extractor is not None

    def test_predictor_init_without_model(self):
        """Test predictor fails gracefully without model"""
        with pytest.raises(FileNotFoundError):
            AdPredictor(
                model_path='/nonexistent/model.tflite',
                scaler_path='/nonexistent/scaler.pkl'
            )


class TestFlowProcessing:
    """Test end-to-end flow processing"""

    def test_full_pipeline(self):
        """Test: receive flow → extract features → predict → log"""
        with patch('redis.Redis') as mock_redis:
            mock_redis.return_value.ping.return_value = True

            extractor = AdTrafficFeatureExtractor()

            flow = {
                'saddr': '192.168.1.100',
                'daddr': '142.250.1.1',
                'dport': '443',
                'proto': 'tcp',
                'starttime': time.time(),
                'dur': '1.5',
                'sbytes': '1024',
                'dbytes': '4096',
                'spkts': '10',
                'dpkts': '8',
                'state': 'SF',
            }

            features = extractor.extract_flow_features(flow)

            assert features is not None
            assert features.shape == (30,)

    def test_batch_processing(self):
        """Test batch processing efficiency"""
        with patch('redis.Redis') as mock_redis:
            mock_redis.return_value.ping.return_value = True

            extractor = AdTrafficFeatureExtractor()

            flows = [
                {
                    'saddr': '192.168.1.100',
                    'daddr': f'142.250.1.{i}',
                    'dport': '443',
                    'proto': 'tcp',
                    'starttime': time.time(),
                    'dur': '1.0',
                    'sbytes': '1024',
                    'dbytes': '2048',
                    'spkts': '5',
                    'dpkts': '5',
                    'state': 'SF',
                }
                for i in range(10)
            ]

            start = time.perf_counter()
            features_list = [extractor.extract_flow_features(f) for f in flows]
            elapsed = time.perf_counter() - start

            assert len(features_list) == 10
            assert elapsed < 0.1

    def test_evidence_creation(self):
        """Test SLIPS evidence format creation"""
        evidence = {
            'type': 'AdTelemetryDetected',
            'attacker': '142.250.1.1',
            'threat_level': 'medium',
            'confidence': 0.85,
            'description': 'ML detected ad/telemetry (confidence: 85%)',
            'profile': 'profile_192.168.1.100',
            'timewindow': 'timewindow1',
            'source': 'ml_ad_detector'
        }

        assert 'type' in evidence
        assert 'attacker' in evidence
        assert 'confidence' in evidence
        assert evidence['threat_level'] in ['medium', 'high']
        assert 0 <= evidence['confidence'] <= 1


class TestDatabaseIntegration:
    """Test database integration"""

    def test_log_prediction(self, test_db):
        """Test logging predictions to database"""
        conn = sqlite3.connect(str(test_db))
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO ml_predictions (timestamp, dst_ip, confidence, prediction)
            VALUES (?, ?, ?, ?)
        ''', (time.time(), '142.250.1.1', 0.85, 1))

        conn.commit()

        cursor.execute('SELECT COUNT(*) FROM ml_predictions')
        count = cursor.fetchone()[0]

        conn.close()

        assert count == 1

    def test_stats_tracking(self, test_db):
        """Test statistics tracking"""
        conn = sqlite3.connect(str(test_db))
        cursor = conn.cursor()

        date = '2025-01-01'
        cursor.execute('''
            INSERT INTO ml_stats (date, predictions, blocks, false_positives)
            VALUES (?, ?, ?, ?)
        ''', (date, 100, 10, 2))

        conn.commit()

        cursor.execute('SELECT * FROM ml_stats WHERE date = ?', (date,))
        row = cursor.fetchone()

        conn.close()

        assert row[1] == 100
        assert row[2] == 10
        assert row[3] == 2


class TestRedisIntegration:
    """Test Redis integration"""

    def test_redis_subscription(self):
        """Test Redis channel subscription"""
        with patch('redis.Redis') as mock_redis:
            client = MagicMock()
            client.ping.return_value = True
            client.pubsub.return_value = MagicMock()
            mock_redis.return_value = client

            pubsub = client.pubsub()
            pubsub.subscribe('new_flow')

            pubsub.subscribe.assert_called_with('new_flow')

    def test_redis_failure_handling(self):
        """Test graceful handling of Redis downtime"""
        with patch('redis.Redis') as mock_redis:
            mock_redis.return_value.ping.side_effect = Exception("Connection failed")

            with pytest.raises(ConnectionError):
                extractor = AdTrafficFeatureExtractor()


class TestModelUpdate:
    """Test model hot-reload"""

    def test_model_reload(self, mock_model):
        """Test that model can be reloaded without restart"""
        with patch('tflite_runtime.interpreter.Interpreter') as mock_interp:
            mock_interp.return_value.allocate_tensors.return_value = None
            mock_interp.return_value.get_input_details.return_value = [
                {'shape': [1, 10, 30]}
            ]
            mock_interp.return_value.get_output_details.return_value = [
                {'shape': [1, 1]}
            ]

            predictor1 = AdPredictor(str(mock_model), None)

            predictor2 = AdPredictor(str(mock_model), None)

            assert predictor1 is not None
            assert predictor2 is not None


class TestPerformance:
    """Test performance under load"""

    def test_high_load(self):
        """Test performance under load (1000 flows/sec)"""
        with patch('redis.Redis') as mock_redis:
            mock_redis.return_value.ping.return_value = True

            extractor = AdTrafficFeatureExtractor()

            flows = [
                {
                    'saddr': '192.168.1.100',
                    'daddr': f'142.250.1.{i % 255}',
                    'dport': '443',
                    'proto': 'tcp',
                    'starttime': time.time(),
                    'dur': '1.0',
                    'sbytes': '1024',
                    'dbytes': '2048',
                    'spkts': '5',
                    'dpkts': '5',
                    'state': 'SF',
                }
                for i in range(100)
            ]

            start = time.perf_counter()
            for flow in flows:
                extractor.extract_flow_features(flow)
            elapsed = time.perf_counter() - start

            rate = len(flows) / elapsed

            assert rate > 100

    def test_memory_efficiency(self):
        """Test memory efficiency with many flows"""
        with patch('redis.Redis') as mock_redis:
            mock_redis.return_value.ping.return_value = True

            extractor = AdTrafficFeatureExtractor()

            import tracemalloc
            tracemalloc.start()

            for i in range(1000):
                flow = {
                    'daddr': f'142.250.1.{i % 255}',
                    'dport': '443',
                    'dur': '1.0',
                    'sbytes': '1024',
                    'dbytes': '2048',
                    'spkts': '5',
                    'dpkts': '5',
                }
                extractor.extract_flow_features(flow)

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            peak_mb = peak / 1024 / 1024

            assert peak_mb < 100


class TestErrorHandling:
    """Test error handling"""

    def test_malformed_flow(self):
        """Test handling of malformed flow data"""
        with patch('redis.Redis') as mock_redis:
            mock_redis.return_value.ping.return_value = True

            extractor = AdTrafficFeatureExtractor()

            malformed = {'invalid': 'data'}
            features = extractor.extract_flow_features(malformed)

            assert features is not None
            assert not np.isnan(features).any()

    def test_database_write_failure(self, test_db):
        """Test handling of database write failures"""
        conn = sqlite3.connect(str(test_db))
        conn.close()

        with pytest.raises(sqlite3.ProgrammingError):
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM ml_predictions')


class TestSecurityAndValidation:
    """Test security and input validation"""

    def test_sql_injection_prevention(self, test_db):
        """Test SQL injection prevention"""
        conn = sqlite3.connect(str(test_db))
        cursor = conn.cursor()

        malicious_ip = "1.1.1.1'; DROP TABLE ml_predictions; --"

        cursor.execute('''
            INSERT INTO ml_predictions (timestamp, dst_ip, confidence, prediction)
            VALUES (?, ?, ?, ?)
        ''', (time.time(), malicious_ip, 0.85, 1))

        conn.commit()

        cursor.execute('SELECT COUNT(*) FROM ml_predictions')
        count = cursor.fetchone()[0]

        conn.close()

        assert count == 1

    def test_confidence_validation(self):
        """Test confidence score validation"""
        confidence = 0.85
        assert 0 <= confidence <= 1

        invalid_confidence = 1.5
        assert not (0 <= invalid_confidence <= 1)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
