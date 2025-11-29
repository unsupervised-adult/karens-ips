#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Karen's IPS ML Setup Diagnostics
# SPDX-License-Identifier: GPL-2.0-only

"""
Diagnostic script to troubleshoot ML detector and SLIPS integration issues
"""

import sys
import os
import subprocess
import json
import redis
import socket
import psutil
from pathlib import Path

def print_header(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_check(description, status, details=""):
    status_icon = "✅" if status else "❌"
    print(f"{status_icon} {description}")
    if details:
        print(f"   {details}")

def check_network_interfaces():
    print_header("Network Interface Configuration")
    
    try:
        # Get all interfaces
        interfaces = psutil.net_if_addrs()
        
        print("Available interfaces:")
        for name, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    print(f"  {name}: {addr.address}")
        
        # Check if br0 exists
        br0_exists = 'br0' in interfaces
        print_check("Bridge interface br0 exists", br0_exists)
        
        if br0_exists:
            # Check if br0 has traffic stats
            stats = psutil.net_if_stats().get('br0')
            if stats:
                print_check("br0 is UP", stats.isup)
                print(f"   Speed: {stats.speed} Mbps")
            
            # Check traffic counters
            counters = psutil.net_io_counters(pernic=True).get('br0')
            if counters:
                print(f"   Bytes sent: {counters.bytes_sent:,}")
                print(f"   Bytes received: {counters.bytes_recv:,}")
                print(f"   Packets sent: {counters.packets_sent:,}")
                print(f"   Packets received: {counters.packets_recv:,}")
                
                traffic_ok = counters.packets_recv > 0
                print_check("br0 has traffic", traffic_ok)
        
    except Exception as e:
        print_check("Network interface check", False, str(e))

def check_slips_service():
    print_header("SLIPS Service Status")
    
    try:
        # Check if SLIPS service is running
        result = subprocess.run(['systemctl', 'is-active', 'slips'], 
                              capture_output=True, text=True)
        slips_running = result.returncode == 0
        print_check("SLIPS service running", slips_running, result.stdout.strip())
        
        # Check SLIPS processes
        slips_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if 'slips' in proc.info['name'].lower() or \
                   any('slips' in arg.lower() for arg in proc.info['cmdline'] or []):
                    slips_processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        print_check(f"SLIPS processes running", len(slips_processes) > 0, 
                   f"{len(slips_processes)} processes found")
        
        for proc in slips_processes[:3]:  # Show first 3
            print(f"   PID {proc['pid']}: {' '.join(proc['cmdline'][:3])}...")
    
    except Exception as e:
        print_check("SLIPS service check", False, str(e))

def check_redis_connection():
    print_header("Redis Connection and Data")
    
    try:
        # Test Redis connection
        redis_client = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
        redis_client.ping()
        print_check("Redis connection", True, "Connected to localhost:6379")
        
        # Check Redis databases
        for db_num in [0, 1, 2]:
            try:
                db_client = redis.Redis(host='localhost', port=6379, db=db_num, decode_responses=True)
                db_size = db_client.dbsize()
                print(f"   Database {db_num}: {db_size} keys")
            except Exception:
                print(f"   Database {db_num}: Connection failed")
        
        # Check for SLIPS data in Redis
        slips_keys = redis_client.keys("profile_*")
        print_check("SLIPS profile data found", len(slips_keys) > 0, 
                   f"{len(slips_keys)} profiles")
        
        # Check for ML detector data
        ml_keys = [
            "ml_detector:stats",
            "ml_detector:recent_detections", 
            "ml_detector:alerts",
            "ml_detector:model_info"
        ]
        
        for key in ml_keys:
            exists = redis_client.exists(key)
            print_check(f"Redis key: {key}", exists)
    
    except Exception as e:
        print_check("Redis connection", False, str(e))

def check_slips_configuration():
    print_header("SLIPS Configuration")
    
    slips_config_paths = [
        "/opt/StratosphereLinuxIPS/config/slips.yaml",
        "/etc/slips/slips.yaml", 
        "/opt/StratosphereLinuxIPS/slips.yaml"
    ]
    
    config_found = False
    for path in slips_config_paths:
        if Path(path).exists():
            config_found = True
            print_check(f"SLIPS config found", True, path)
            
            try:
                with open(path, 'r') as f:
                    content = f.read()
                    
                    # Check for interface configuration
                    if 'br0' in content:
                        print_check("br0 configured in SLIPS", True)
                    else:
                        print_check("br0 configured in SLIPS", False, 
                                   "No br0 interface found in config")
                    
                    # Check for web interface config
                    if 'web_interface' in content or 'webinterface' in content:
                        print_check("Web interface configured", True)
                    
                    break
            except Exception as e:
                print_check(f"Reading config {path}", False, str(e))
    
    if not config_found:
        print_check("SLIPS config file", False, "No config file found")

def check_ml_detector_integration():
    print_header("ML Detector Integration")
    
    # Check if ML detector files exist
    ml_files = [
        "/opt/karens-ips/src/feature_extractor.py",
        "/opt/karens-ips/src/ml_auto_responder.py", 
        "/opt/karens-ips/slips_integration/webinterface/ml_detector/ml_detector.py"
    ]
    
    for file_path in ml_files:
        exists = Path(file_path).exists()
        print_check(f"ML file: {Path(file_path).name}", exists, file_path if exists else "Missing")
    
    # Check if ML auto responder service is running
    try:
        result = subprocess.run(['systemctl', 'is-active', 'ml-auto-responder'], 
                              capture_output=True, text=True)
        ml_running = result.returncode == 0
        print_check("ML auto responder service", ml_running, result.stdout.strip())
    except Exception:
        print_check("ML auto responder service", False, "Service check failed")

def check_web_interface():
    print_header("Web Interface Accessibility")
    
    try:
        # Check if web interface is listening
        import requests
        
        # Try different URLs
        urls = [
            "http://localhost:55000",
            "http://127.0.0.1:55000"
        ]
        
        for url in urls:
            try:
                response = requests.get(url, timeout=5)
                print_check(f"Web interface accessible", response.status_code == 200, 
                           f"{url} - Status: {response.status_code}")
                
                # Check if ML detector endpoint works
                ml_url = f"{url}/ml_detector/stats"
                ml_response = requests.get(ml_url, timeout=5)
                print_check(f"ML detector endpoint", ml_response.status_code == 200,
                           f"{ml_url} - Status: {ml_response.status_code}")
                
                if ml_response.status_code == 200:
                    data = ml_response.json()
                    print(f"   ML data: {data}")
                
                break
                
            except requests.exceptions.RequestException as e:
                print_check(f"Web interface at {url}", False, str(e))
    
    except ImportError:
        print_check("requests library", False, "pip install requests")

def check_nftables_setup():
    print_header("nftables Configuration")
    
    try:
        # Check if nftables is active
        result = subprocess.run(['systemctl', 'is-active', 'nftables'], 
                              capture_output=True, text=True)
        nft_running = result.returncode == 0
        print_check("nftables service", nft_running, result.stdout.strip())
        
        # Check if blocked4 set exists
        result = subprocess.run(['nft', 'list', 'set', 'inet', 'home', 'blocked4'], 
                              capture_output=True, text=True)
        blocked4_exists = result.returncode == 0
        print_check("blocked4 set exists", blocked4_exists)
        
        if blocked4_exists:
            # Count blocked IPs
            blocked_count = result.stdout.count('.')  # Rough count of IPs
            print(f"   Approximately {blocked_count} IPs currently blocked")
    
    except Exception as e:
        print_check("nftables check", False, str(e))

def main():
    print("Karen's IPS ML Setup Diagnostics")
    print("=" * 60)
    print("Checking system configuration and identifying issues...")
    
    # Run all checks
    check_network_interfaces()
    check_slips_service() 
    check_redis_connection()
    check_slips_configuration()
    check_ml_detector_integration()
    check_web_interface()
    check_nftables_setup()
    
    print_header("Summary and Recommendations")
    print("""
Common issues and fixes:

1. If br0 has no traffic:
   - Check if traffic is actually routing through the bridge
   - Verify br0 is properly configured with two interfaces
   - Check: ip link show br0

2. If SLIPS isn't monitoring br0:
   - Edit SLIPS config to specify interface: br0
   - Restart SLIPS: systemctl restart slips

3. If ML tab shows no data:
   - Wait a few minutes for data to accumulate
   - Check Redis for ml_detector keys
   - Verify ML auto responder is processing data

4. If web interface not accessible:
   - Check firewall: ufw allow 55000
   - Verify SLIPS web interface is bound to 0.0.0.0:55000

Run with sudo for complete diagnostics.
    """)

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("⚠️  Running without root privileges. Some checks may be limited.")
    
    main()