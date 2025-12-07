#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Karen's IPS Exception Management Tool
# SPDX-License-Identifier: GPL-2.0-only

"""
Simple exception management tool for Karen's IPS
Allows easy whitelist management for IPs, domains, and URLs
"""

import sys
import os

# Add parent directory to path to import from src
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from exception_manager import ExceptionManager
import argparse

def main():
    """Command-line interface for exception management"""
    
    parser = argparse.ArgumentParser(
        description="Karen's IPS Exception Management",
        epilog="""
Examples:
  %(prog)s --add-ip 8.8.8.8 --reason "Google DNS"
  %(prog)s --add-domain netflix.com --reason "Streaming service"  
  %(prog)s --add-url "https://github.com/*" --reason "GitHub access"
  %(prog)s --list
  %(prog)s --check-ip 1.1.1.1
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Add operations
    parser.add_argument('--add-ip', help='Add IP address to whitelist')
    parser.add_argument('--add-domain', help='Add domain to whitelist')
    parser.add_argument('--add-url', help='Add URL pattern to whitelist')
    parser.add_argument('--add-cidr', help='Add CIDR range to whitelist')
    
    # Remove operations
    parser.add_argument('--remove-ip', help='Remove IP from whitelist')
    parser.add_argument('--remove-domain', help='Remove domain from whitelist')
    
    # Check operations
    parser.add_argument('--check-ip', help='Check if IP is whitelisted')
    parser.add_argument('--check-domain', help='Check if domain is whitelisted')
    parser.add_argument('--check-url', help='Check if URL is whitelisted')
    
    # List and info
    parser.add_argument('--list', action='store_true', help='List all exceptions')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    
    # Options
    parser.add_argument('--reason', default='Manual addition', help='Reason for the exception')
    parser.add_argument('--temporary', type=int, metavar='HOURS', help='Make exception temporary (expires after N hours)')
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("❌ This tool must be run as root")
        print("Please run: sudo python3 manage-exceptions.py [options]")
        sys.exit(1)
    
    try:
        manager = ExceptionManager()
    except Exception as e:
        print(f"❌ Error initializing exception manager: {e}")
        sys.exit(1)
    
    # Handle operations
    if args.add_ip:
        permanent = args.temporary is None
        expires_hours = args.temporary
        
        if manager.add_ip_exception(args.add_ip, args.reason, "cli", permanent, expires_hours):
            duration = f"permanently" if permanent else f"for {expires_hours} hours"
            print(f"✅ Added IP exception {duration}: {args.add_ip}")
            print(f"   Reason: {args.reason}")
        else:
            print(f"❌ Failed to add IP exception: {args.add_ip}")
    
    elif args.add_domain:
        permanent = args.temporary is None
        expires_hours = args.temporary
        
        if manager.add_domain_exception(args.add_domain, args.reason, "cli", permanent, expires_hours):
            duration = f"permanently" if permanent else f"for {expires_hours} hours"
            print(f"✅ Added domain exception {duration}: {args.add_domain}")
            print(f"   Reason: {args.reason}")
        else:
            print(f"❌ Failed to add domain exception: {args.add_domain}")
    
    elif args.add_url:
        permanent = args.temporary is None
        expires_hours = args.temporary
        
        if manager.add_url_exception(args.add_url, args.reason, "cli", permanent, expires_hours):
            duration = f"permanently" if permanent else f"for {expires_hours} hours"
            print(f"✅ Added URL exception {duration}: {args.add_url}")
            print(f"   Reason: {args.reason}")
        else:
            print(f"❌ Failed to add URL exception: {args.add_url}")
    
    elif args.add_cidr:
        permanent = args.temporary is None
        expires_hours = args.temporary
        
        if manager.add_cidr_exception(args.add_cidr, args.reason, "cli", permanent, expires_hours):
            duration = f"permanently" if permanent else f"for {expires_hours} hours"
            print(f"✅ Added CIDR exception {duration}: {args.add_cidr}")
            print(f"   Reason: {args.reason}")
        else:
            print(f"❌ Failed to add CIDR exception: {args.add_cidr}")
    
    elif args.remove_ip:
        if manager.remove_ip_exception(args.remove_ip):
            print(f"✅ Removed IP exception: {args.remove_ip}")
        else:
            print(f"❌ Failed to remove IP exception: {args.remove_ip}")
    
    elif args.remove_domain:
        if manager.remove_domain_exception(args.remove_domain):
            print(f"✅ Removed domain exception: {args.remove_domain}")
        else:
            print(f"❌ Failed to remove domain exception: {args.remove_domain}")
    
    elif args.check_ip:
        excepted, reason = manager.is_ip_excepted(args.check_ip)
        if excepted:
            print(f"✅ IP {args.check_ip} is whitelisted")
            print(f"   Reason: {reason}")
        else:
            print(f"❌ IP {args.check_ip} is not whitelisted")
    
    elif args.check_domain:
        excepted, reason = manager.is_domain_excepted(args.check_domain)
        if excepted:
            print(f"✅ Domain {args.check_domain} is whitelisted")
            print(f"   Reason: {reason}")
        else:
            print(f"❌ Domain {args.check_domain} is not whitelisted")
    
    elif args.check_url:
        excepted, reason = manager.is_url_excepted(args.check_url)
        if excepted:
            print(f"✅ URL {args.check_url} is whitelisted")
            print(f"   Reason: {reason}")
        else:
            print(f"❌ URL {args.check_url} is not whitelisted")
    
    elif args.list:
        print("📋 Current Exceptions:")
        print("=" * 60)
        
        exceptions = manager.list_exceptions()
        
        if exceptions['ips']:
            print("\n🌐 IP Addresses:")
            for exc in exceptions['ips'][:10]:  # Limit display
                print(f"  {exc['ip']:<15} - {exc['reason']}")
            if len(exceptions['ips']) > 10:
                print(f"  ... and {len(exceptions['ips']) - 10} more")
        
        if exceptions['domains']:
            print("\n🌍 Domains:")
            for exc in exceptions['domains'][:10]:  # Limit display
                print(f"  {exc['domain']:<30} - {exc['reason']}")
            if len(exceptions['domains']) > 10:
                print(f"  ... and {len(exceptions['domains']) - 10} more")
        
        if exceptions['urls']:
            print("\n🔗 URL Patterns:")
            for exc in exceptions['urls'][:5]:  # Limit display
                print(f"  {exc['url'][:50]:<50} - {exc['reason']}")
            if len(exceptions['urls']) > 5:
                print(f"  ... and {len(exceptions['urls']) - 5} more")
        
        if exceptions['cidrs']:
            print("\n📡 CIDR Ranges:")
            for exc in exceptions['cidrs']:
                print(f"  {exc['cidr']:<18} - {exc['reason']}")
    
    elif args.stats:
        stats = manager.get_stats()
        print("📊 Exception Statistics:")
        print("=" * 30)
        print(f"🌐 IP addresses:  {stats['ip_count']}")
        print(f"🌍 Domains:       {stats['domain_count']}")
        print(f"🔗 URL patterns:  {stats['url_count']}")
        print(f"📡 CIDR ranges:   {stats['cidr_count']}")
        print(f"📋 Total:         {sum(stats.values())}")
    
    else:
        print("Karen's IPS Exception Management")
        print("=" * 40)
        print("\nQuick commands:")
        print("  --add-ip 8.8.8.8 --reason 'Google DNS'")
        print("  --add-domain netflix.com --reason 'Streaming'")
        print("  --add-url 'https://github.com/*' --reason 'GitHub'")
        print("  --list")
        print("  --stats")
        print("\nFor full help: --help")


if __name__ == '__main__':
    main()