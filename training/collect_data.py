#!/usr/bin/env python3
"""
Data collection script for ML Ad Detector
Extracts flows from SLIPS Redis for labeling
"""

import argparse
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any
import pandas as pd
import redis
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
from utils import is_private_ip, parse_redis_flow, setup_logging


class FlowCollector:
    """Collects flows from SLIPS Redis for training data"""

    def __init__(self, redis_host: str = 'localhost', redis_ports: List[int] = [6379, 6380]):
        """
        Initialize flow collector

        Args:
            redis_host: Redis server hostname
            redis_ports: List of Redis ports to query
        """
        self.logger = setup_logging('INFO')
        self.redis_clients = []

        for port in redis_ports:
            try:
                client = redis.Redis(
                    host=redis_host,
                    port=port,
                    db=0 if port == 6380 else 1,
                    decode_responses=True,
                    socket_connect_timeout=5
                )
                client.ping()
                self.redis_clients.append(client)
                self.logger.info(f"Connected to Redis at {redis_host}:{port}")
            except redis.ConnectionError as e:
                self.logger.warning(f"Failed to connect to Redis {redis_host}:{port}: {e}")

        if not self.redis_clients:
            raise ConnectionError("No Redis connections available")

    def get_profile_keys(self, hours_back: int = 24) -> List[str]:
        """
        Get profile keys from Redis within time window

        Args:
            hours_back: Hours to look back from now

        Returns:
            List of profile keys
        """
        cutoff_time = time.time() - (hours_back * 3600)
        all_keys = set()

        for client in self.redis_clients:
            try:
                for key in client.scan_iter(match='profile_*_timewindow*'):
                    all_keys.add(key)
            except redis.RedisError as e:
                self.logger.error(f"Error scanning Redis: {e}")

        self.logger.info(f"Found {len(all_keys)} profile keys")
        return sorted(all_keys)

    def extract_flows_from_profile(self, profile_key: str) -> List[Dict[str, Any]]:
        """
        Extract flows from a profile key

        Args:
            profile_key: Redis key for profile

        Returns:
            List of flow dictionaries
        """
        flows = []

        for client in self.redis_clients:
            try:
                flow_data = client.hgetall(profile_key)

                if not flow_data:
                    continue

                for flow_id, flow_json in flow_data.items():
                    if not flow_id.startswith('flow_'):
                        continue

                    try:
                        import json
                        flow = json.loads(flow_json) if isinstance(flow_json, str) else flow_json
                        parsed_flow = parse_redis_flow(flow)

                        if parsed_flow.get('dst_ip'):
                            flows.append(parsed_flow)

                    except (json.JSONDecodeError, ValueError) as e:
                        self.logger.debug(f"Failed to parse flow {flow_id}: {e}")
                        continue

            except redis.RedisError as e:
                self.logger.error(f"Error reading profile {profile_key}: {e}")

        return flows

    def collect_flows(
        self,
        hours_back: int = 24,
        output_dir: str = 'training/data/raw',
        ip_filter: str = None,
        port_filter: int = None
    ) -> pd.DataFrame:
        """
        Collect flows from SLIPS Redis

        Args:
            hours_back: Hours to look back
            output_dir: Output directory for CSV
            ip_filter: Optional IP address filter
            port_filter: Optional port filter

        Returns:
            DataFrame containing collected flows
        """
        self.logger.info(f"Collecting flows from last {hours_back} hours")

        profile_keys = self.get_profile_keys(hours_back)
        all_flows = []
        seen_flows = set()

        for profile_key in tqdm(profile_keys, desc="Processing profiles"):
            flows = self.extract_flows_from_profile(profile_key)

            for flow in flows:
                dst_ip = flow.get('dst_ip', '')
                src_ip = flow.get('src_ip', '')

                if is_private_ip(dst_ip):
                    continue

                if ip_filter and ip_filter not in [src_ip, dst_ip]:
                    continue

                if port_filter and flow.get('dst_port') != port_filter:
                    continue

                flow_sig = f"{src_ip}:{dst_ip}:{flow.get('dst_port')}:{flow.get('timestamp')}"
                if flow_sig in seen_flows:
                    continue

                seen_flows.add(flow_sig)
                flow['label'] = ''
                all_flows.append(flow)

        if not all_flows:
            self.logger.warning("No flows collected")
            return pd.DataFrame()

        df = pd.DataFrame(all_flows)

        df = df[[
            'timestamp', 'src_ip', 'dst_ip', 'dst_port', 'protocol',
            'duration', 'bytes_sent', 'bytes_recv', 'packets_sent', 'packets_recv',
            'state', 'label'
        ]]

        df = df.sort_values('timestamp').reset_index(drop=True)

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = output_path / f'flows_{timestamp}.csv'
        df.to_csv(output_file, index=False)

        self.logger.info(f"Collected {len(df)} flows")
        self.logger.info(f"Saved to {output_file}")

        return df


def main():
    parser = argparse.ArgumentParser(
        description='Collect flows from SLIPS Redis for ML training'
    )
    parser.add_argument(
        '--hours',
        type=int,
        default=24,
        help='Hours to look back (default: 24)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='training/data/raw',
        help='Output directory (default: training/data/raw)'
    )
    parser.add_argument(
        '--ip-filter',
        type=str,
        help='Filter by IP address'
    )
    parser.add_argument(
        '--port-filter',
        type=int,
        help='Filter by destination port'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        collector = FlowCollector()
        df = collector.collect_flows(
            hours_back=args.hours,
            output_dir=args.output,
            ip_filter=args.ip_filter,
            port_filter=args.port_filter
        )

        print(f"\n{'='*60}")
        print(f"Collection Summary:")
        print(f"{'='*60}")
        print(f"Total flows: {len(df)}")
        print(f"Unique destination IPs: {df['dst_ip'].nunique()}")
        print(f"Unique destination ports: {df['dst_port'].nunique()}")
        print(f"Time range: {df['timestamp'].min():.0f} - {df['timestamp'].max():.0f}")
        print(f"{'='*60}\n")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
