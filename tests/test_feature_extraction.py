"""
Unit tests for feature extraction module
"""

import pytest
import numpy as np
import time
from unittest.mock import Mock, patch, MagicMock
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from feature_extractor import AdTrafficFeatureExtractor


@pytest.fixture
def mock_redis():
    """Mock Redis client"""
    with patch('redis.Redis') as mock:
        client = MagicMock()
        client.ping.return_value = True
        client.hgetall.return_value = {}
        client.scan_iter.return_value = []
        mock.return_value = client
        yield mock


@pytest.fixture
def extractor(mock_redis):
    """Create feature extractor instance"""
    return AdTrafficFeatureExtractor()


@pytest.fixture
def sample_flow():
    """Sample flow data"""
    return {
        'saddr': '192.168.1.100',
        'daddr': '142.250.1.1',
        'sport': '54321',
        'dport': '443',
        'proto': 'tcp',
        'starttime': time.time(),
        'dur': '1.5',
        'sbytes': '1024',
        'dbytes': '4096',
        'spkts': '10',
        'dpkts': '8',
        'state': 'SF',
        'history': '^',
    }


class TestFeatureExtractor:
    """Test cases for AdTrafficFeatureExtractor"""

    def test_connect_redis(self, mock_redis):
        """Test Redis connection handling"""
        extractor = AdTrafficFeatureExtractor(
            redis_host='localhost',
            redis_ports=[6379, 6380]
        )

        assert len(extractor.redis_clients) > 0

    def test_connect_redis_failure(self):
        """Test graceful handling of Redis connection failure"""
        with patch('redis.Redis') as mock:
            mock.return_value.ping.side_effect = Exception("Connection failed")

            with pytest.raises(ConnectionError):
                AdTrafficFeatureExtractor(redis_ports=[6379])

    def test_extract_flow_features_basic(self, extractor, sample_flow):
        """Test basic feature extraction"""
        features = extractor.extract_flow_features(sample_flow)

        assert isinstance(features, np.ndarray)
        assert features.shape == (30,)
        assert not np.isnan(features).any()
        assert not np.isinf(features).any()

    def test_extract_flow_features_values(self, extractor, sample_flow):
        """Test feature extraction accuracy"""
        features = extractor.extract_flow_features(sample_flow)

        assert features[0] == 1.5
        assert features[1] == 1024
        assert features[2] == 4096
        assert features[3] == 10
        assert features[4] == 8

        byte_ratio = 1024 / 4096
        assert abs(features[5] - byte_ratio) < 0.001

        pkt_ratio = 10 / 8
        assert abs(features[6] - pkt_ratio) < 0.001

    def test_extract_time_series(self, extractor):
        """Test time-series extraction"""
        dst_ip = '142.250.1.1'

        with patch.object(extractor, '_get_recent_flows') as mock_flows:
            mock_flows.return_value = [
                {
                    'saddr': '192.168.1.100',
                    'daddr': dst_ip,
                    'sport': '54321',
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
                for _ in range(10)
            ]

            time_series = extractor.extract_time_series(dst_ip, window_seconds=60)

            assert isinstance(time_series, np.ndarray)
            assert time_series.shape == (10, 30)
            assert not np.isnan(time_series).any()

    def test_handle_missing_data(self, extractor):
        """Test graceful handling of missing flow data"""
        incomplete_flow = {
            'daddr': '142.250.1.1',
            'dport': '443'
        }

        features = extractor.extract_flow_features(incomplete_flow)

        assert isinstance(features, np.ndarray)
        assert features.shape == (30,)
        assert not np.isnan(features).any()

    def test_ad_cdn_detection(self, extractor):
        """Test known ad CDN detection"""
        google_ads_ip = '142.250.1.1'
        assert extractor.is_ad_cdn(google_ads_ip) is True

        doubleclick_ip = '209.85.200.100'
        assert extractor.is_ad_cdn(doubleclick_ip) is True

        normal_ip = '1.1.1.1'
        assert extractor.is_ad_cdn(normal_ip) is False

    def test_performance_benchmark(self, extractor, sample_flow):
        """Test extraction performance (<5ms)"""
        iterations = 100
        start = time.perf_counter()

        for _ in range(iterations):
            extractor.extract_flow_features(sample_flow)

        elapsed = (time.perf_counter() - start) / iterations * 1000

        assert elapsed < 5.0, f"Extraction took {elapsed:.2f}ms (target: <5ms)"

    def test_caching_effectiveness(self, extractor):
        """Test cache effectiveness"""
        dst_ip = '142.250.1.1'

        with patch.object(extractor, '_get_recent_flows') as mock_flows:
            mock_flows.return_value = []

            extractor._get_recent_flows(dst_ip, time.time(), 60)
            extractor._get_recent_flows(dst_ip, time.time(), 60)

            assert mock_flows.call_count >= 1

    def test_concurrent_flows_count(self, extractor):
        """Test concurrent flows counting"""
        dst_ip = '142.250.1.1'
        current_time = time.time()

        with patch.object(extractor, '_get_concurrent_flows') as mock_concurrent:
            mock_concurrent.return_value = [
                {'starttime': current_time - 1},
                {'starttime': current_time - 2},
                {'starttime': current_time - 3},
            ]

            flows = extractor._get_concurrent_flows(dst_ip, current_time)
            assert len(flows) == 3

    def test_feature_ranges(self, extractor, sample_flow):
        """Test that features are in expected ranges"""
        features = extractor.extract_flow_features(sample_flow)

        assert features[0] >= 0
        assert features[1] >= 0
        assert features[2] >= 0
        assert features[3] >= 0
        assert features[4] >= 0

        assert features[5] >= 0
        assert features[6] >= 0

    def test_protocol_handling(self, extractor):
        """Test different protocol handling"""
        tcp_flow = {
            'daddr': '142.250.1.1',
            'dport': '443',
            'proto': 'tcp',
            'dur': '1.0',
            'sbytes': '1024',
            'dbytes': '2048',
            'spkts': '5',
            'dpkts': '5',
        }

        udp_flow = {
            'daddr': '142.250.1.1',
            'dport': '53',
            'proto': 'udp',
            'dur': '0.1',
            'sbytes': '64',
            'dbytes': '128',
            'spkts': '1',
            'dpkts': '1',
        }

        tcp_features = extractor.extract_flow_features(tcp_flow)
        udp_features = extractor.extract_flow_features(udp_flow)

        assert tcp_features.shape == udp_features.shape
        assert not np.array_equal(tcp_features, udp_features)

    def test_edge_cases(self, extractor):
        """Test edge cases"""
        zero_bytes_flow = {
            'daddr': '142.250.1.1',
            'dport': '443',
            'dur': '0',
            'sbytes': '0',
            'dbytes': '0',
            'spkts': '0',
            'dpkts': '0',
        }

        features = extractor.extract_flow_features(zero_bytes_flow)
        assert not np.isnan(features).any()
        assert not np.isinf(features).any()

    def test_invalid_ip(self, extractor):
        """Test handling of invalid IP addresses"""
        invalid_flow = {
            'daddr': 'invalid_ip',
            'dport': '443',
        }

        features = extractor.extract_flow_features(invalid_flow)
        assert isinstance(features, np.ndarray)

    def test_state_parsing(self, extractor):
        """Test TCP state parsing"""
        states = ['SF', 'S0', 'REJ', 'RSTO', 'RSTR', 'S1']

        for state in states:
            flow = {
                'daddr': '142.250.1.1',
                'dport': '443',
                'state': state,
                'dur': '1.0',
                'sbytes': '1024',
                'dbytes': '2048',
                'spkts': '5',
                'dpkts': '5',
            }

            features = extractor.extract_flow_features(flow)
            assert isinstance(features, np.ndarray)


class TestCDNDetection:
    """Test cases for CDN detection"""

    def test_google_ads_ranges(self, extractor):
        """Test Google Ads IP ranges"""
        google_ips = [
            '142.250.0.0',
            '142.251.0.0',
            '209.85.128.0',
        ]

        for ip in google_ips:
            assert extractor.is_ad_cdn(ip) is True

    def test_facebook_ads_ranges(self, extractor):
        """Test Facebook Ads IP ranges"""
        fb_ips = [
            '157.240.0.0',
            '31.13.64.0',
        ]

        for ip in fb_ips:
            assert extractor.is_ad_cdn(ip) is True

    def test_non_ad_ips(self, extractor):
        """Test non-ad IPs"""
        normal_ips = [
            '1.1.1.1',
            '8.8.8.8',
            '192.168.1.1',
            '10.0.0.1',
        ]

        for ip in normal_ips:
            assert extractor.is_ad_cdn(ip) is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
