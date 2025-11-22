"""
Utility functions for ML Ad Detector
"""

import yaml
import logging
import json
import ipaddress
from typing import Dict, Any, Optional
from pathlib import Path


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load YAML configuration file

    Args:
        config_path: Path to YAML config file

    Returns:
        Dictionary containing configuration

    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config is invalid YAML
    """
    config_file = Path(config_path)

    if not config_file.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)

        if config is None:
            raise ValueError("Config file is empty")

        return config

    except yaml.YAMLError as e:
        raise yaml.YAMLError(f"Invalid YAML in config file: {e}")


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """
    Set up logging configuration

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path. If None, logs to console only

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger('ml_ad_detector')
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    if logger.handlers:
        logger.handlers.clear()

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is private/local

    Args:
        ip: IP address string

    Returns:
        True if IP is private, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False


def get_flow_key(profileid: str, twid: str) -> str:
    """
    Generate Redis key for flow profile

    Args:
        profileid: SLIPS profile ID (e.g., 'profile_192.168.1.100')
        twid: Time window ID (e.g., 'timewindow1')

    Returns:
        Redis key string
    """
    return f"{profileid}_{twid}"


def parse_redis_flow(flow_data: dict) -> Dict[str, Any]:
    """
    Parse and normalize flow data from SLIPS Redis format

    Args:
        flow_data: Raw flow data dictionary from Redis

    Returns:
        Normalized flow dictionary with standard fields
    """
    parsed = {
        'timestamp': flow_data.get('starttime', 0),
        'src_ip': flow_data.get('saddr', ''),
        'dst_ip': flow_data.get('daddr', ''),
        'src_port': int(flow_data.get('sport', 0)),
        'dst_port': int(flow_data.get('dport', 0)),
        'protocol': flow_data.get('proto', ''),
        'duration': float(flow_data.get('dur', 0)),
        'bytes_sent': int(flow_data.get('sbytes', 0)),
        'bytes_recv': int(flow_data.get('dbytes', 0)),
        'packets_sent': int(flow_data.get('spkts', 0)),
        'packets_recv': int(flow_data.get('dpkts', 0)),
        'state': flow_data.get('state', ''),
        'history': flow_data.get('history', ''),
    }

    for key in ['ttl', 'tcp_flags', 'syn_count', 'ack_count', 'fin_count', 'rst_count']:
        if key in flow_data:
            try:
                parsed[key] = int(flow_data[key])
            except (ValueError, TypeError):
                parsed[key] = 0

    return parsed


def save_stats(stats: Dict[str, Any], filepath: str) -> None:
    """
    Save statistics dictionary to JSON file

    Args:
        stats: Statistics dictionary
        filepath: Output file path

    Raises:
        IOError: If file cannot be written
    """
    stats_file = Path(filepath)
    stats_file.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
    except IOError as e:
        raise IOError(f"Failed to save stats to {filepath}: {e}")


def load_stats(filepath: str) -> Dict[str, Any]:
    """
    Load statistics dictionary from JSON file

    Args:
        filepath: Path to JSON stats file

    Returns:
        Statistics dictionary. Returns empty dict if file doesn't exist

    Raises:
        json.JSONDecodeError: If file contains invalid JSON
    """
    stats_file = Path(filepath)

    if not stats_file.exists():
        return {}

    try:
        with open(stats_file, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in stats file: {e}", e.doc, e.pos)
