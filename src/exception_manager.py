#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Karen's IPS Exception Manager
# SPDX-License-Identifier: GPL-2.0-only

"""
Exception Manager for Karen's IPS

Manages whitelist/exceptions for:
- IP addresses that should never be blocked
- Domains that should never be blocked  
- URLs that should always be allowed
- Critical services protection
"""

import json
import sqlite3
import ipaddress
import re
import logging
from typing import Set, List, Dict, Optional, Tuple
from pathlib import Path
import yaml
from datetime import datetime

class ExceptionManager:
    """Manage IP/URL/domain exceptions for blocking systems"""
    
    def __init__(self, 
                 db_path: str = "/var/lib/karens-ips/exceptions.db",
                 config_path: str = "/etc/karens-ips/exceptions.yaml"):
        """Initialize exception manager"""
        
        self.db_path = db_path
        self.config_path = config_path
        self.logger = logging.getLogger(__name__)
        
        # In-memory caches for fast lookups
        self.ip_exceptions: Set[str] = set()
        self.domain_exceptions: Set[str] = set()
        self.url_exceptions: Set[str] = set()
        self.ip_ranges: List[ipaddress.IPv4Network] = []
        
        # Initialize database and load config
        self._init_database()
        self._load_config()
        self._refresh_caches()
        
        self.logger.info("Exception Manager initialized")
    
    def _init_database(self):
        """Initialize SQLite database for exceptions"""
        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # IP exceptions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_exceptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL UNIQUE,
                    reason TEXT,
                    added_by TEXT DEFAULT 'system',
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    permanent INTEGER DEFAULT 1,
                    expires_at TIMESTAMP NULL
                )
            """)
            
            # Domain exceptions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS domain_exceptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    reason TEXT,
                    added_by TEXT DEFAULT 'system',
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    permanent INTEGER DEFAULT 1,
                    expires_at TIMESTAMP NULL
                )
            """)
            
            # URL exceptions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS url_exceptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url_pattern TEXT NOT NULL UNIQUE,
                    reason TEXT,
                    added_by TEXT DEFAULT 'system', 
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    permanent INTEGER DEFAULT 1,
                    expires_at TIMESTAMP NULL
                )
            """)
            
            # CIDR ranges table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cidr_exceptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cidr_range TEXT NOT NULL UNIQUE,
                    reason TEXT,
                    added_by TEXT DEFAULT 'system',
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    permanent INTEGER DEFAULT 1,
                    expires_at TIMESTAMP NULL
                )
            """)
            
            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_address ON ip_exceptions(ip_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain ON domain_exceptions(domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_url_pattern ON url_exceptions(url_pattern)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cidr_range ON cidr_exceptions(cidr_range)")
            
            conn.commit()
            conn.close()
            
            self.logger.info("Exception database initialized")
            
        except Exception as e:
            self.logger.error(f"Error initializing exception database: {e}")
            raise
    
    def _load_config(self):
        """Load exceptions from YAML config file"""
        try:
            if not Path(self.config_path).exists():
                self._create_default_config()
            
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f) or {}
            
            # Load default exceptions
            exceptions = config.get('exceptions', {})
            
            # Load IP exceptions
            for ip in exceptions.get('ips', []):
                self.add_ip_exception(ip, "Default config", "config", permanent=True)
            
            # Load domain exceptions  
            for domain in exceptions.get('domains', []):
                self.add_domain_exception(domain, "Default config", "config", permanent=True)
            
            # Load CIDR ranges
            for cidr in exceptions.get('ranges', []):
                self.add_cidr_exception(cidr, "Default range", "config", permanent=True)
            
            # Load URL patterns
            for url in exceptions.get('urls', []):
                self.add_url_exception(url, "Default URL", "config", permanent=True)
            
            self.logger.info(f"Loaded exceptions from {self.config_path}")
            
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
    
    def _create_default_config(self):
        """Create default exceptions config file"""
        default_config = {
            'exceptions': {
                'enabled': True,
                
                # Domain exceptions (never block these domains)
                'domains': [
                    'localhost',
                    'localhost.localdomain',
                    # Essential services
                    'github.com',
                    'githubusercontent.com',
                    'ubuntu.com',
                    'debian.org',
                    'kernel.org',
                    # DNS services
                    'cloudflare.com', 
                    '1.1.1.1',
                    'quad9.net',
                    'opendns.com',
                    # NTP
                    'pool.ntp.org',
                    'ntp.ubuntu.com',
                    # Package repos (critical)
                    'archive.ubuntu.com',
                    'security.ubuntu.com',
                    'deb.debian.org',
                    'download.docker.com',
                    # Emergency access
                    'ssh.com',
                    'putty.org'
                ],
                
                # IP exceptions (never block these IPs)
                'ips': [
                    '127.0.0.1',
                    '::1',
                    '8.8.8.8',      # Google DNS
                    '8.8.4.4', 
                    '1.1.1.1',      # Cloudflare DNS
                    '1.0.0.1',
                    '9.9.9.9',      # Quad9 DNS
                    '208.67.222.222', # OpenDNS
                    '208.67.220.220'
                ],
                
                # CIDR ranges (never block these ranges)
                'ranges': [
                    '127.0.0.0/8',    # Loopback
                    '10.0.0.0/8',     # Private A
                    '172.16.0.0/12',  # Private B  
                    '192.168.0.0/16', # Private C
                    '169.254.0.0/16', # Link-local
                    'fe80::/10',      # IPv6 link-local
                    '::1/128'         # IPv6 loopback
                ],
                
                # URL exceptions (never block these URL patterns)
                'urls': [
                    # System updates
                    'http://archive.ubuntu.com/*',
                    'https://security.ubuntu.com/*',
                    'http://deb.debian.org/*',
                    'https://download.docker.com/*',
                    # Package managers
                    'https://registry.npmjs.org/*',
                    'https://pypi.org/*',
                    'https://rubygems.org/*',
                    # Git repositories 
                    'https://github.com/*',
                    'https://gitlab.com/*',
                    'https://bitbucket.org/*'
                ]
            }
        }
        
        try:
            Path(self.config_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False, indent=2)
            
            self.logger.info(f"Created default config: {self.config_path}")
            
        except Exception as e:
            self.logger.error(f"Error creating default config: {e}")
    
    def _refresh_caches(self):
        """Refresh in-memory caches from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Load IP exceptions
            cursor.execute("SELECT ip_address FROM ip_exceptions WHERE permanent = 1 OR expires_at > ?", 
                          (datetime.now().isoformat(),))
            self.ip_exceptions = {row[0] for row in cursor.fetchall()}
            
            # Load domain exceptions
            cursor.execute("SELECT domain FROM domain_exceptions WHERE permanent = 1 OR expires_at > ?",
                          (datetime.now().isoformat(),))
            self.domain_exceptions = {row[0] for row in cursor.fetchall()}
            
            # Load URL exceptions
            cursor.execute("SELECT url_pattern FROM url_exceptions WHERE permanent = 1 OR expires_at > ?",
                          (datetime.now().isoformat(),))
            self.url_exceptions = {row[0] for row in cursor.fetchall()}
            
            # Load CIDR ranges
            cursor.execute("SELECT cidr_range FROM cidr_exceptions WHERE permanent = 1 OR expires_at > ?",
                          (datetime.now().isoformat(),))
            self.ip_ranges = []
            for row in cursor.fetchall():
                try:
                    self.ip_ranges.append(ipaddress.IPv4Network(row[0], strict=False))
                except ValueError:
                    self.logger.warning(f"Invalid CIDR range: {row[0]}")
            
            conn.close()
            
            self.logger.debug(f"Refreshed caches: {len(self.ip_exceptions)} IPs, "
                            f"{len(self.domain_exceptions)} domains, "
                            f"{len(self.url_exceptions)} URLs, "
                            f"{len(self.ip_ranges)} ranges")
            
        except Exception as e:
            self.logger.error(f"Error refreshing caches: {e}")
    
    def is_ip_excepted(self, ip: str) -> Tuple[bool, str]:
        """Check if IP should be excepted from blocking"""
        try:
            # Check direct IP exceptions
            if ip in self.ip_exceptions:
                return True, "Direct IP exception"
            
            # Check CIDR ranges
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                for network in self.ip_ranges:
                    if ip_obj in network:
                        return True, f"CIDR range exception: {network}"
            except ValueError:
                # Invalid IP format
                return False, "Invalid IP format"
            
            return False, ""
            
        except Exception as e:
            self.logger.error(f"Error checking IP exception for {ip}: {e}")
            return False, "Error during check"
    
    def is_domain_excepted(self, domain: str) -> Tuple[bool, str]:
        """Check if domain should be excepted from blocking"""
        try:
            domain = domain.lower().strip()
            
            # Direct domain match
            if domain in self.domain_exceptions:
                return True, "Direct domain exception"
            
            # Check parent domains
            parts = domain.split('.')
            for i in range(len(parts)):
                parent_domain = '.'.join(parts[i:])
                if parent_domain in self.domain_exceptions:
                    return True, f"Parent domain exception: {parent_domain}"
            
            return False, ""
            
        except Exception as e:
            self.logger.error(f"Error checking domain exception for {domain}: {e}")
            return False, "Error during check"
    
    def is_url_excepted(self, url: str) -> Tuple[bool, str]:
        """Check if URL should be excepted from blocking"""
        try:
            url = url.strip()
            
            # Check URL patterns
            for pattern in self.url_exceptions:
                if self._url_matches_pattern(url, pattern):
                    return True, f"URL pattern exception: {pattern}"
            
            return False, ""
            
        except Exception as e:
            self.logger.error(f"Error checking URL exception for {url}: {e}")
            return False, "Error during check"
    
    def _url_matches_pattern(self, url: str, pattern: str) -> bool:
        """Check if URL matches wildcard pattern"""
        try:
            # Convert wildcard pattern to regex
            regex_pattern = pattern.replace('*', '.*').replace('?', '.')
            regex_pattern = f"^{regex_pattern}$"
            
            return bool(re.match(regex_pattern, url, re.IGNORECASE))
            
        except Exception:
            return False
    
    def add_ip_exception(self, ip: str, reason: str = "", added_by: str = "user", 
                        permanent: bool = True, expires_hours: Optional[int] = None) -> bool:
        """Add IP to exceptions"""
        try:
            # Validate IP
            ipaddress.IPv4Address(ip)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            expires_at = None
            if not permanent and expires_hours:
                from datetime import datetime, timedelta
                expires_at = (datetime.now() + timedelta(hours=expires_hours)).isoformat()
            
            cursor.execute("""
                INSERT OR REPLACE INTO ip_exceptions 
                (ip_address, reason, added_by, permanent, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """, (ip, reason, added_by, 1 if permanent else 0, expires_at))
            
            conn.commit()
            conn.close()
            
            self._refresh_caches()
            self.logger.info(f"Added IP exception: {ip} ({reason})")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding IP exception {ip}: {e}")
            return False
    
    def add_domain_exception(self, domain: str, reason: str = "", added_by: str = "user",
                           permanent: bool = True, expires_hours: Optional[int] = None) -> bool:
        """Add domain to exceptions"""
        try:
            domain = domain.lower().strip()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            expires_at = None
            if not permanent and expires_hours:
                from datetime import datetime, timedelta
                expires_at = (datetime.now() + timedelta(hours=expires_hours)).isoformat()
            
            cursor.execute("""
                INSERT OR REPLACE INTO domain_exceptions
                (domain, reason, added_by, permanent, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """, (domain, reason, added_by, 1 if permanent else 0, expires_at))
            
            conn.commit()
            conn.close()
            
            self._refresh_caches()
            self.logger.info(f"Added domain exception: {domain} ({reason})")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding domain exception {domain}: {e}")
            return False
    
    def add_url_exception(self, url_pattern: str, reason: str = "", added_by: str = "user",
                         permanent: bool = True, expires_hours: Optional[int] = None) -> bool:
        """Add URL pattern to exceptions"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            expires_at = None
            if not permanent and expires_hours:
                from datetime import datetime, timedelta
                expires_at = (datetime.now() + timedelta(hours=expires_hours)).isoformat()
            
            cursor.execute("""
                INSERT OR REPLACE INTO url_exceptions
                (url_pattern, reason, added_by, permanent, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """, (url_pattern, reason, added_by, 1 if permanent else 0, expires_at))
            
            conn.commit()
            conn.close()
            
            self._refresh_caches()
            self.logger.info(f"Added URL exception: {url_pattern} ({reason})")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding URL exception {url_pattern}: {e}")
            return False
    
    def add_cidr_exception(self, cidr: str, reason: str = "", added_by: str = "user",
                          permanent: bool = True, expires_hours: Optional[int] = None) -> bool:
        """Add CIDR range to exceptions"""
        try:
            # Validate CIDR
            ipaddress.IPv4Network(cidr, strict=False)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            expires_at = None
            if not permanent and expires_hours:
                from datetime import datetime, timedelta  
                expires_at = (datetime.now() + timedelta(hours=expires_hours)).isoformat()
            
            cursor.execute("""
                INSERT OR REPLACE INTO cidr_exceptions
                (cidr_range, reason, added_by, permanent, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """, (cidr, reason, added_by, 1 if permanent else 0, expires_at))
            
            conn.commit()
            conn.close()
            
            self._refresh_caches()
            self.logger.info(f"Added CIDR exception: {cidr} ({reason})")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding CIDR exception {cidr}: {e}")
            return False
    
    def remove_ip_exception(self, ip: str) -> bool:
        """Remove IP from exceptions"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM ip_exceptions WHERE ip_address = ?", (ip,))
            conn.commit()
            conn.close()
            
            self._refresh_caches()
            self.logger.info(f"Removed IP exception: {ip}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error removing IP exception {ip}: {e}")
            return False
    
    def remove_domain_exception(self, domain: str) -> bool:
        """Remove domain from exceptions"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM domain_exceptions WHERE domain = ?", (domain.lower(),))
            conn.commit()
            conn.close()
            
            self._refresh_caches()
            self.logger.info(f"Removed domain exception: {domain}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error removing domain exception {domain}: {e}")
            return False
    
    def list_exceptions(self) -> Dict[str, List]:
        """List all current exceptions"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            result = {
                'ips': [],
                'domains': [],
                'urls': [],
                'cidrs': []
            }
            
            # Get IPs
            cursor.execute("SELECT ip_address, reason, added_by, added_at FROM ip_exceptions ORDER BY added_at DESC")
            result['ips'] = [{'ip': row[0], 'reason': row[1], 'added_by': row[2], 'added_at': row[3]} 
                            for row in cursor.fetchall()]
            
            # Get domains
            cursor.execute("SELECT domain, reason, added_by, added_at FROM domain_exceptions ORDER BY added_at DESC")
            result['domains'] = [{'domain': row[0], 'reason': row[1], 'added_by': row[2], 'added_at': row[3]}
                               for row in cursor.fetchall()]
            
            # Get URLs
            cursor.execute("SELECT url_pattern, reason, added_by, added_at FROM url_exceptions ORDER BY added_at DESC")
            result['urls'] = [{'url': row[0], 'reason': row[1], 'added_by': row[2], 'added_at': row[3]}
                            for row in cursor.fetchall()]
            
            # Get CIDRs
            cursor.execute("SELECT cidr_range, reason, added_by, added_at FROM cidr_exceptions ORDER BY added_at DESC")
            result['cidrs'] = [{'cidr': row[0], 'reason': row[1], 'added_by': row[2], 'added_at': row[3]}
                             for row in cursor.fetchall()]
            
            conn.close()
            return result
            
        except Exception as e:
            self.logger.error(f"Error listing exceptions: {e}")
            return {'ips': [], 'domains': [], 'urls': [], 'cidrs': []}
    
    def get_stats(self) -> Dict[str, int]:
        """Get exception statistics"""
        return {
            'ip_count': len(self.ip_exceptions),
            'domain_count': len(self.domain_exceptions),
            'url_count': len(self.url_exceptions),
            'cidr_count': len(self.ip_ranges)
        }


def main():
    """CLI interface for exception management"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Karen's IPS Exception Manager")
    parser.add_argument('--add-ip', help='Add IP exception')
    parser.add_argument('--add-domain', help='Add domain exception')
    parser.add_argument('--add-url', help='Add URL exception')
    parser.add_argument('--add-cidr', help='Add CIDR exception')
    parser.add_argument('--remove-ip', help='Remove IP exception')
    parser.add_argument('--remove-domain', help='Remove domain exception')
    parser.add_argument('--reason', default='Manual addition', help='Reason for exception')
    parser.add_argument('--list', action='store_true', help='List all exceptions')
    parser.add_argument('--check-ip', help='Check if IP is excepted')
    parser.add_argument('--check-domain', help='Check if domain is excepted')
    parser.add_argument('--check-url', help='Check if URL is excepted')
    parser.add_argument('--stats', action='store_true', help='Show exception statistics')
    
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    manager = ExceptionManager()
    
    if args.add_ip:
        if manager.add_ip_exception(args.add_ip, args.reason):
            print(f"✓ Added IP exception: {args.add_ip}")
        else:
            print(f"✗ Failed to add IP exception: {args.add_ip}")
    
    elif args.add_domain:
        if manager.add_domain_exception(args.add_domain, args.reason):
            print(f"✓ Added domain exception: {args.add_domain}")
        else:
            print(f"✗ Failed to add domain exception: {args.add_domain}")
    
    elif args.add_url:
        if manager.add_url_exception(args.add_url, args.reason):
            print(f"✓ Added URL exception: {args.add_url}")
        else:
            print(f"✗ Failed to add URL exception: {args.add_url}")
    
    elif args.add_cidr:
        if manager.add_cidr_exception(args.add_cidr, args.reason):
            print(f"✓ Added CIDR exception: {args.add_cidr}")
        else:
            print(f"✗ Failed to add CIDR exception: {args.add_cidr}")
    
    elif args.remove_ip:
        if manager.remove_ip_exception(args.remove_ip):
            print(f"✓ Removed IP exception: {args.remove_ip}")
        else:
            print(f"✗ Failed to remove IP exception: {args.remove_ip}")
    
    elif args.remove_domain:
        if manager.remove_domain_exception(args.remove_domain):
            print(f"✓ Removed domain exception: {args.remove_domain}")
        else:
            print(f"✗ Failed to remove domain exception: {args.remove_domain}")
    
    elif args.check_ip:
        excepted, reason = manager.is_ip_excepted(args.check_ip)
        if excepted:
            print(f"✓ IP {args.check_ip} is excepted: {reason}")
        else:
            print(f"✗ IP {args.check_ip} is not excepted")
    
    elif args.check_domain:
        excepted, reason = manager.is_domain_excepted(args.check_domain)
        if excepted:
            print(f"✓ Domain {args.check_domain} is excepted: {reason}")
        else:
            print(f"✗ Domain {args.check_domain} is not excepted")
    
    elif args.check_url:
        excepted, reason = manager.is_url_excepted(args.check_url)
        if excepted:
            print(f"✓ URL {args.check_url} is excepted: {reason}")
        else:
            print(f"✗ URL {args.check_url} is not excepted")
    
    elif args.list:
        exceptions = manager.list_exceptions()
        print("\n=== IP Exceptions ===")
        for exc in exceptions['ips']:
            print(f"{exc['ip']:<15} - {exc['reason']} (by {exc['added_by']})")
        
        print("\n=== Domain Exceptions ===")
        for exc in exceptions['domains']:
            print(f"{exc['domain']:<30} - {exc['reason']} (by {exc['added_by']})")
        
        print("\n=== URL Exceptions ===")
        for exc in exceptions['urls']:
            print(f"{exc['url']:<50} - {exc['reason']} (by {exc['added_by']})")
        
        print("\n=== CIDR Exceptions ===")
        for exc in exceptions['cidrs']:
            print(f"{exc['cidr']:<18} - {exc['reason']} (by {exc['added_by']})")
    
    elif args.stats:
        stats = manager.get_stats()
        print(f"Exception Statistics:")
        print(f"  IP addresses: {stats['ip_count']}")
        print(f"  Domains: {stats['domain_count']}")
        print(f"  URL patterns: {stats['url_count']}")
        print(f"  CIDR ranges: {stats['cidr_count']}")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()