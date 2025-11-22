"""
AdTrafficFeatureExtractor - Extract 30 features from SLIPS Redis data

This module extracts traffic features for ML-based ad/telemetry detection.
Connects to SLIPS Redis databases to analyze flow profiles and patterns.
"""

import redis
import numpy as np
import json
import time
import logging
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
import statistics
import ipaddress
from collections import defaultdict, deque


class AdTrafficFeatureExtractor:
    """
    Extract 30 features from SLIPS flow data for ad/telemetry classification.
    
    Features extracted:
    - Flow basics (7): duration, sbytes, dbytes, spkts, dpkts, byte_ratio, pkt_ratio  
    - Timing (6): inter-arrival, burst_score, time_since_last, request_freq, duration_std, flow_rate
    - Connection patterns (8): concurrent_count, avg_size, std_size, min_size, max_size, small_request_ratio, short_duration_ratio, connection_variance
    - CDN detection (5): is_ad_cdn, cdn_consistency, subnet_changes, endpoint_diversity, known_tracker
    - Behavior (4): user_agent_changes, cookie_tracking, redirect_chains, data_exfiltration_score
    """
    
    def __init__(self, redis_host: str = "localhost", redis_ports: Dict[str, int] = None):
        """
        Initialize feature extractor with Redis connections.
        
        Args:
            redis_host: Redis server hostname
            redis_ports: Dict with 'main' and 'cache' port numbers
        """
        self.redis_host = redis_host
        self.redis_ports = redis_ports or {"main": 6379, "cache": 6380}
        self.logger = logging.getLogger(__name__)
        
        # Initialize Redis connections
        self._init_redis_connections()
        
        # Feature cache for performance
        self._feature_cache = {}
        self._cache_ttl = 300  # 5 minutes
        
        # Known ad/tracking CDN IP ranges
        self._ad_cdn_ranges = self._load_ad_cdn_ranges()
        
        # Flow timing cache for inter-arrival calculations
        self._flow_times = defaultdict(deque)
        
        self.logger.info("AdTrafficFeatureExtractor initialized")
    
    def _init_redis_connections(self) -> None:
        """Initialize Redis database connections."""
        try:
            # SLIPS main database (flows, profiles)
            self.redis_main = redis.Redis(
                host=self.redis_host, 
                port=self.redis_ports["main"],
                db=1,  # SLIPS flows database
                decode_responses=True,
                socket_timeout=5
            )
            
            # SLIPS cache database
            self.redis_cache = redis.Redis(
                host=self.redis_host,
                port=self.redis_ports["cache"], 
                db=0,  # SLIPS cache
                decode_responses=True,
                socket_timeout=5
            )
            
            # Test connections
            self.redis_main.ping()
            self.redis_cache.ping()
            
            self.logger.info(f"Connected to Redis: {self.redis_host}:{self.redis_ports}")
            
        except redis.ConnectionError as e:
            self.logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    def _load_ad_cdn_ranges(self) -> List[ipaddress.IPv4Network]:
        """Load known advertising and tracking CDN IP ranges."""
        ad_cdn_ranges = [
            # Google Ads/DoubleClick
            "142.250.0.0/15",
            "172.217.0.0/16", 
            "216.58.192.0/19",
            
            # Facebook Ads
            "31.13.24.0/21",
            "31.13.64.0/18",
            "66.220.144.0/20",
            "69.63.176.0/20",
            "69.171.224.0/19",
            
            # Amazon advertising
            "52.84.0.0/15",
            "54.230.0.0/16",
            
            # Microsoft ads
            "13.107.42.0/24",
            "40.90.4.0/22",
            
            # Twitter ads
            "104.244.42.0/24",
            "199.16.156.0/22",
            
            # Common ad networks
            "23.235.32.0/20",  # Akamai CDN
            "184.51.0.0/16",   # Level3 CDN
        ]
        
        networks = []
        for cidr in ad_cdn_ranges:
            try:
                networks.append(ipaddress.IPv4Network(cidr))
            except ValueError:
                self.logger.warning(f"Invalid CIDR range: {cidr}")
        
        return networks
    
    def extract_flow_features(self, flow_data: Dict[str, Any]) -> np.ndarray:
        """
        Extract 30 features from a single flow record.
        
        Args:
            flow_data: Flow data dictionary from SLIPS Redis
            
        Returns:
            numpy array of shape (30,) containing extracted features
            
        Raises:
            ValueError: If flow_data is invalid or missing required fields
        """
        try:
            features = np.zeros(30, dtype=np.float32)
            
            # Basic flow information
            duration = float(flow_data.get('dur', 0))
            sbytes = float(flow_data.get('sbytes', 0))
            dbytes = float(flow_data.get('dbytes', 0))
            spkts = float(flow_data.get('spkts', 0))
            dpkts = float(flow_data.get('dpkts', 0))
            
            dst_ip = flow_data.get('daddr', '')
            src_ip = flow_data.get('saddr', '')
            dst_port = int(flow_data.get('dport', 0))
            
            # Flow basics (7 features)
            features[0] = duration
            features[1] = sbytes
            features[2] = dbytes
            features[3] = spkts
            features[4] = dpkts
            features[5] = sbytes / (dbytes + 1e-6)  # byte_ratio (avoid div by zero)
            features[6] = spkts / (dpkts + 1e-6)    # pkt_ratio
            
            # Get recent flows for timing and pattern analysis
            current_time = time.time()
            recent_flows = self._get_recent_flows(dst_ip, current_time, 60)
            concurrent_flows = self._get_concurrent_flows(dst_ip, current_time)
            
            # Timing features (6 features)
            features[7] = self._calculate_inter_arrival(dst_ip, current_time)
            features[8] = self._calculate_burst_score(recent_flows)
            features[9] = self._calculate_time_since_last(dst_ip, current_time)
            features[10] = len(recent_flows) / 60.0  # request_freq (flows per second)
            features[11] = self._calculate_duration_std(recent_flows)
            features[12] = (sbytes + dbytes) / (duration + 1e-6)  # flow_rate (bytes/sec)
            
            # Connection patterns (8 features)
            features[13] = len(concurrent_flows)  # concurrent_count
            sizes = [f.get('sbytes', 0) + f.get('dbytes', 0) for f in recent_flows if f]
            if sizes:
                features[14] = np.mean(sizes)     # avg_size
                features[15] = np.std(sizes)      # std_size  
                features[16] = np.min(sizes)      # min_size
                features[17] = np.max(sizes)      # max_size
                features[18] = sum(1 for s in sizes if s < 1024) / len(sizes)  # small_request_ratio
            else:
                features[14:19] = 0
                
            durations = [f.get('dur', 0) for f in recent_flows if f]
            if durations:
                features[19] = sum(1 for d in durations if d < 1.0) / len(durations)  # short_duration_ratio
                features[20] = np.var(durations)  # connection_variance
            else:
                features[19:21] = 0
            
            # CDN detection (5 features)  
            features[21] = float(self.is_ad_cdn(dst_ip))
            features[22] = self._calculate_cdn_consistency(dst_ip, recent_flows)
            features[23] = self._calculate_subnet_changes(recent_flows)
            features[24] = self._calculate_endpoint_diversity(recent_flows)
            features[25] = float(self._is_known_tracker(dst_ip))
            
            # Behavior patterns (4 features)
            features[26] = self._calculate_user_agent_changes(recent_flows)
            features[27] = self._calculate_cookie_tracking_score(recent_flows)
            features[28] = self._calculate_redirect_chains(recent_flows)
            features[29] = self._calculate_data_exfiltration_score(sbytes, dbytes, duration)
            
            # Update flow timing cache
            self._update_flow_timing_cache(dst_ip, current_time)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting features: {e}")
            # Return zero features on error to maintain array shape
            return np.zeros(30, dtype=np.float32)
    
    def extract_time_series(self, dst_ip: str, window_seconds: int = 60) -> np.ndarray:
        """
        Extract time series features for the last N flows to destination IP.
        
        Args:
            dst_ip: Destination IP address
            window_seconds: Time window to analyze
            
        Returns:
            numpy array of shape (10, 30) - features for last 10 flows
        """
        try:
            current_time = time.time()
            flows = self._get_recent_flows(dst_ip, current_time, window_seconds)
            
            # Get last 10 flows (pad with zeros if fewer)
            time_series = np.zeros((10, 30), dtype=np.float32)
            
            for i, flow in enumerate(flows[-10:]):
                if flow:
                    features = self.extract_flow_features(flow)
                    time_series[i] = features
            
            return time_series
            
        except Exception as e:
            self.logger.error(f"Error extracting time series for {dst_ip}: {e}")
            return np.zeros((10, 30), dtype=np.float32)
    
    def _get_recent_flows(self, dst_ip: str, current_time: float, window_seconds: int) -> List[Dict]:
        """Get flows to destination IP within time window."""
        try:
            # Query SLIPS Redis for profile keys
            profile_pattern = f"profile_*_timewindow_*"
            profile_keys = self.redis_main.keys(profile_pattern)
            
            recent_flows = []
            cutoff_time = current_time - window_seconds
            
            for key in profile_keys[-100:]:  # Limit to recent profiles for performance
                try:
                    profile_data = self.redis_main.hgetall(key)
                    if not profile_data:
                        continue
                        
                    # Parse flows in this profile
                    flows_data = profile_data.get('flows', '{}')
                    flows = json.loads(flows_data) if flows_data else {}
                    
                    for flow_key, flow_info in flows.items():
                        flow = json.loads(flow_info) if isinstance(flow_info, str) else flow_info
                        
                        # Check if flow matches destination IP and time window
                        if (flow.get('daddr') == dst_ip and 
                            flow.get('starttime', 0) >= cutoff_time):
                            recent_flows.append(flow)
                            
                except (json.JSONDecodeError, ValueError) as e:
                    self.logger.debug(f"Error parsing profile {key}: {e}")
                    continue
            
            # Sort by timestamp
            recent_flows.sort(key=lambda x: x.get('starttime', 0))
            return recent_flows
            
        except Exception as e:
            self.logger.error(f"Error getting recent flows: {e}")
            return []
    
    def _get_concurrent_flows(self, dst_ip: str, current_time: float) -> List[Dict]:
        """Get flows that were concurrent with current time."""
        try:
            flows = self._get_recent_flows(dst_ip, current_time, 300)  # 5 minute window
            
            concurrent = []
            for flow in flows:
                start_time = flow.get('starttime', 0)
                duration = flow.get('dur', 0)
                end_time = start_time + duration
                
                # Check if flow overlaps with current time
                if start_time <= current_time <= end_time:
                    concurrent.append(flow)
            
            return concurrent
            
        except Exception as e:
            self.logger.error(f"Error getting concurrent flows: {e}")
            return []
    
    def _calculate_inter_arrival(self, dst_ip: str, current_time: float) -> float:
        """Calculate inter-arrival time between flows."""
        times = self._flow_times[dst_ip]
        
        if len(times) < 2:
            return 0.0
        
        # Calculate average inter-arrival time
        intervals = [times[i] - times[i-1] for i in range(1, len(times))]
        return np.mean(intervals) if intervals else 0.0
    
    def _calculate_burst_score(self, flows: List[Dict]) -> float:
        """Calculate burst score based on flow timing patterns."""
        if len(flows) < 3:
            return 0.0
        
        # Get flow start times
        times = [f.get('starttime', 0) for f in flows]
        times.sort()
        
        # Calculate intervals
        intervals = [times[i] - times[i-1] for i in range(1, len(times))]
        
        if not intervals:
            return 0.0
        
        # Burst score: ratio of short intervals (< 1 second)
        short_intervals = sum(1 for interval in intervals if interval < 1.0)
        return short_intervals / len(intervals)
    
    def _calculate_time_since_last(self, dst_ip: str, current_time: float) -> float:
        """Calculate time since last flow to this destination."""
        times = self._flow_times[dst_ip]
        
        if not times:
            return 0.0
        
        return current_time - times[-1]
    
    def _calculate_duration_std(self, flows: List[Dict]) -> float:
        """Calculate standard deviation of flow durations."""
        durations = [f.get('dur', 0) for f in flows if f]
        
        if len(durations) < 2:
            return 0.0
        
        return np.std(durations)
    
    def _calculate_cdn_consistency(self, dst_ip: str, flows: List[Dict]) -> float:
        """Calculate CDN consistency score."""
        if not flows:
            return 0.0
        
        # Check if all flows go to same CDN network
        cdn_networks = set()
        for flow in flows:
            ip = flow.get('daddr', '')
            if self.is_ad_cdn(ip):
                # Find which CDN network
                for i, network in enumerate(self._ad_cdn_ranges):
                    try:
                        if ipaddress.IPv4Address(ip) in network:
                            cdn_networks.add(i)
                            break
                    except ipaddress.AddressValueError:
                        continue
        
        # Consistency score: fewer unique CDN networks = higher consistency
        return 1.0 - (len(cdn_networks) / max(len(self._ad_cdn_ranges), 1))
    
    def _calculate_subnet_changes(self, flows: List[Dict]) -> float:
        """Calculate frequency of subnet changes."""
        if len(flows) < 2:
            return 0.0
        
        subnets = set()
        for flow in flows:
            ip = flow.get('daddr', '')
            try:
                addr = ipaddress.IPv4Address(ip)
                # /24 subnet
                subnet = ipaddress.IPv4Network(f"{addr}/{24}", strict=False)
                subnets.add(subnet)
            except ipaddress.AddressValueError:
                continue
        
        return len(subnets) / len(flows)
    
    def _calculate_endpoint_diversity(self, flows: List[Dict]) -> float:
        """Calculate diversity of endpoints contacted."""
        if not flows:
            return 0.0
        
        unique_endpoints = set()
        for flow in flows:
            dst_ip = flow.get('daddr', '')
            dst_port = flow.get('dport', 0)
            unique_endpoints.add((dst_ip, dst_port))
        
        return len(unique_endpoints) / len(flows)
    
    def _is_known_tracker(self, ip: str) -> bool:
        """Check if IP belongs to known tracking service."""
        # Simple heuristic - check common tracking domains/IPs
        tracking_patterns = [
            'google-analytics',
            'googletagmanager', 
            'facebook.com',
            'doubleclick',
            'googlesyndication',
            'amazon-adsystem'
        ]
        
        # This would need reverse DNS lookup in practice
        # For now, return False as placeholder
        return False
    
    def _calculate_user_agent_changes(self, flows: List[Dict]) -> float:
        """Calculate user agent change frequency (placeholder)."""
        # SLIPS doesn't typically store HTTP headers in flow data
        # This would require HTTP log integration
        return 0.0
    
    def _calculate_cookie_tracking_score(self, flows: List[Dict]) -> float:
        """Calculate cookie-based tracking score (placeholder)."""
        # Would require HTTP header analysis
        return 0.0
    
    def _calculate_redirect_chains(self, flows: List[Dict]) -> float:
        """Calculate redirect chain complexity (placeholder)."""
        # Would require HTTP response code analysis
        return 0.0
    
    def _calculate_data_exfiltration_score(self, sbytes: float, dbytes: float, duration: float) -> float:
        """Calculate potential data exfiltration score."""
        if duration <= 0:
            return 0.0
        
        # High outbound data rate could indicate exfiltration
        outbound_rate = sbytes / duration
        inbound_rate = dbytes / duration
        
        # Score based on outbound/inbound ratio
        if inbound_rate == 0:
            return 1.0 if outbound_rate > 1024 else 0.0
        
        ratio = outbound_rate / inbound_rate
        # Normalize to 0-1 range
        return min(ratio / 10.0, 1.0)
    
    def _update_flow_timing_cache(self, dst_ip: str, timestamp: float) -> None:
        """Update flow timing cache for inter-arrival calculations."""
        times = self._flow_times[dst_ip]
        times.append(timestamp)
        
        # Keep only last 50 timestamps per IP
        if len(times) > 50:
            times.popleft()
    
    def is_ad_cdn(self, ip: str) -> bool:
        """
        Check if IP address belongs to known advertising CDN.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if IP belongs to advertising CDN, False otherwise
        """
        try:
            addr = ipaddress.IPv4Address(ip)
            
            for network in self._ad_cdn_ranges:
                if addr in network:
                    return True
            
            return False
            
        except ipaddress.AddressValueError:
            return False
    
    def clear_cache(self) -> None:
        """Clear feature cache."""
        self._feature_cache.clear()
        self._flow_times.clear()
        self.logger.info("Feature cache cleared")