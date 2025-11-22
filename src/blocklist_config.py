#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Karen's IPS ML Ad Detector
# SPDX-License-Identifier: GPL-2.0-only

"""
Blocklist Configuration Manager for Karen's IPS

Manages blocklist configuration, updates, and exceptions (whitelist).
"""

import yaml
import os
import subprocess
import logging
import ipaddress
from pathlib import Path
from typing import List, Dict, Optional, Set
from datetime import datetime

logger = logging.getLogger(__name__)


class BlocklistConfig:
    """Manages blocklist configuration from YAML file"""

    def __init__(self, config_path: str = "/etc/karens-ips/blocklists.yaml"):
        """
        Initialize configuration manager

        Args:
            config_path: Path to YAML configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self) -> Dict:
        """Load configuration from YAML file"""
        try:
            if not os.path.exists(self.config_path):
                logger.warning(f"Config file not found: {self.config_path}")
                return self._get_default_config()

            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)

            logger.info(f"Loaded configuration from {self.config_path}")
            return config

        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return self._get_default_config()

    def _get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            'repositories_dir': '/opt/karens-ips-blocklists',
            'auto_update': {'enabled': True, 'schedule': 'weekly'},
            'perflyst': {'enabled': True, 'lists': []},
            'hagezi': {'enabled': True, 'lists': []},
            'custom': {'enabled': False, 'lists': []},
            'exceptions': {'enabled': True, 'domains': [], 'ips': []},
            'database': {'path': '/var/lib/suricata/ips_filter.db'},
            'suricata': {'sync_after_import': True}
        }

    def get_enabled_lists(self, source: str = None) -> List[Dict]:
        """
        Get list of enabled blocklists

        Args:
            source: Filter by source (perflyst, hagezi, custom) or None for all

        Returns:
            List of enabled blocklist configurations
        """
        enabled = []

        sources = [source] if source else ['perflyst', 'hagezi', 'custom']

        for src in sources:
            if src not in self.config or not self.config[src].get('enabled'):
                continue

            for lst in self.config[src].get('lists', []):
                if lst.get('enabled', True):
                    lst['source'] = src
                    lst['repository'] = self.config[src].get('repository', '')
                    enabled.append(lst)

        return enabled

    def get_exception_domains(self) -> Set[str]:
        """Get set of excepted domains (whitelist)"""
        if not self.config.get('exceptions', {}).get('enabled'):
            return set()

        domains = self.config['exceptions'].get('domains', [])
        return set(d.lower().strip() for d in domains if d)

    def get_exception_ips(self) -> Set[str]:
        """Get set of excepted IPs and CIDR ranges"""
        if not self.config.get('exceptions', {}).get('enabled'):
            return set()

        ips = self.config['exceptions'].get('ips', [])
        ranges = self.config['exceptions'].get('ranges', [])

        return set(list(ips) + list(ranges))

    def is_domain_excepted(self, domain: str) -> bool:
        """
        Check if domain is in exception list

        Args:
            domain: Domain name to check

        Returns:
            True if domain should not be blocked
        """
        domain = domain.lower().strip()
        exceptions = self.get_exception_domains()

        # Direct match
        if domain in exceptions:
            return True

        # Check if subdomain of excepted domain
        for exc in exceptions:
            if domain.endswith('.' + exc):
                return True

        return False

    def is_ip_excepted(self, ip: str) -> bool:
        """
        Check if IP is in exception list

        Args:
            ip: IP address to check

        Returns:
            True if IP should not be blocked
        """
        try:
            ip_addr = ipaddress.ip_address(ip)
            exceptions = self.get_exception_ips()

            for exc in exceptions:
                try:
                    # Check if it's a network range
                    if '/' in exc:
                        network = ipaddress.ip_network(exc, strict=False)
                        if ip_addr in network:
                            return True
                    # Direct IP match
                    elif ip == exc:
                        return True
                except ValueError:
                    continue

            return False

        except ValueError:
            logger.warning(f"Invalid IP address: {ip}")
            return False

    def get_repositories_dir(self) -> str:
        """Get blocklists repository directory"""
        return self.config.get('repositories_dir', '/opt/karens-ips-blocklists')

    def get_database_path(self) -> str:
        """Get database path"""
        return self.config.get('database', {}).get('path', '/var/lib/suricata/ips_filter.db')

    def should_sync_suricata(self) -> bool:
        """Check if Suricata should be synced after import"""
        return self.config.get('suricata', {}).get('sync_after_import', True)


class BlocklistUpdater:
    """Manages blocklist repository updates"""

    def __init__(self, config: BlocklistConfig):
        """
        Initialize updater

        Args:
            config: BlocklistConfig instance
        """
        self.config = config
        self.repos_dir = Path(config.get_repositories_dir())

    def update_repository(self, name: str, url: str) -> bool:
        """
        Update or clone a git repository

        Args:
            name: Repository directory name
            url: Git repository URL

        Returns:
            True if successful
        """
        repo_path = self.repos_dir / name

        try:
            if repo_path.exists():
                logger.info(f"Updating {name}...")
                result = subprocess.run(
                    ['git', '-C', str(repo_path), 'pull', '--quiet'],
                    capture_output=True,
                    text=True,
                    timeout=300
                )

                if result.returncode == 0:
                    logger.info(f"✓ {name} updated successfully")
                    return True
                else:
                    logger.error(f"Failed to update {name}: {result.stderr}")
                    return False

            else:
                logger.info(f"Cloning {name}...")
                self.repos_dir.mkdir(parents=True, exist_ok=True)

                result = subprocess.run(
                    ['git', 'clone', '--depth', '1', url, str(repo_path)],
                    capture_output=True,
                    text=True,
                    timeout=600
                )

                if result.returncode == 0:
                    logger.info(f"✓ {name} cloned successfully")
                    return True
                else:
                    logger.error(f"Failed to clone {name}: {result.stderr}")
                    return False

        except subprocess.TimeoutExpired:
            logger.error(f"Timeout updating {name}")
            return False
        except Exception as e:
            logger.error(f"Error updating {name}: {e}")
            return False

    def update_all_repositories(self) -> Dict[str, bool]:
        """
        Update all configured repositories

        Returns:
            Dictionary of repository name -> success status
        """
        results = {}

        # Update Perflyst
        if self.config.config.get('perflyst', {}).get('enabled'):
            url = self.config.config['perflyst'].get('repository')
            if url:
                results['PiHoleBlocklist'] = self.update_repository('PiHoleBlocklist', url)

        # Update hagezi
        if self.config.config.get('hagezi', {}).get('enabled'):
            url = self.config.config['hagezi'].get('repository')
            if url:
                results['dns-blocklists'] = self.update_repository('dns-blocklists', url)

        return results

    def get_last_update_time(self, name: str) -> Optional[datetime]:
        """
        Get last update time for repository

        Args:
            name: Repository directory name

        Returns:
            Datetime of last update or None
        """
        repo_path = self.repos_dir / name / '.git'

        if not repo_path.exists():
            return None

        try:
            result = subprocess.run(
                ['git', '-C', str(repo_path.parent), 'log', '-1', '--format=%ct'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                timestamp = int(result.stdout.strip())
                return datetime.fromtimestamp(timestamp)

        except Exception as e:
            logger.warning(f"Could not get last update time for {name}: {e}")

        return None


class ExceptionManager:
    """Manages domain and IP exceptions (whitelist)"""

    def __init__(self, config: BlocklistConfig, db_path: str):
        """
        Initialize exception manager

        Args:
            config: BlocklistConfig instance
            db_path: Path to SQLite database
        """
        self.config = config
        self.db_path = db_path
        self._create_tables()

    def _create_tables(self):
        """Create exception tables in database"""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Domain exceptions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS exception_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    reason TEXT,
                    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    added_by TEXT
                )
            ''')

            # IP exceptions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS exception_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    reason TEXT,
                    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    added_by TEXT
                )
            ''')

            # Indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_exception_domains ON exception_domains(domain)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_exception_ips ON exception_ips(ip_address)')

            conn.commit()
            conn.close()

            logger.info("Exception tables created successfully")

        except Exception as e:
            logger.error(f"Failed to create exception tables: {e}")

    def add_domain_exception(self, domain: str, reason: str = "", added_by: str = "manual") -> bool:
        """Add domain to exception list"""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR IGNORE INTO exception_domains (domain, reason, added_by)
                VALUES (?, ?, ?)
            ''', (domain.lower().strip(), reason, added_by))

            rows = cursor.rowcount
            conn.commit()
            conn.close()

            if rows > 0:
                logger.info(f"Added domain exception: {domain}")
                return True
            else:
                logger.warning(f"Domain exception already exists: {domain}")
                return False

        except Exception as e:
            logger.error(f"Failed to add domain exception: {e}")
            return False

    def add_ip_exception(self, ip: str, reason: str = "", added_by: str = "manual") -> bool:
        """Add IP to exception list"""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR IGNORE INTO exception_ips (ip_address, reason, added_by)
                VALUES (?, ?, ?)
            ''', (ip.strip(), reason, added_by))

            rows = cursor.rowcount
            conn.commit()
            conn.close()

            if rows > 0:
                logger.info(f"Added IP exception: {ip}")
                return True
            else:
                logger.warning(f"IP exception already exists: {ip}")
                return False

        except Exception as e:
            logger.error(f"Failed to add IP exception: {e}")
            return False

    def remove_domain_exception(self, domain: str) -> bool:
        """Remove domain from exception list"""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('DELETE FROM exception_domains WHERE domain = ?', (domain.lower().strip(),))

            rows = cursor.rowcount
            conn.commit()
            conn.close()

            if rows > 0:
                logger.info(f"Removed domain exception: {domain}")
                return True
            else:
                logger.warning(f"Domain exception not found: {domain}")
                return False

        except Exception as e:
            logger.error(f"Failed to remove domain exception: {e}")
            return False

    def remove_ip_exception(self, ip: str) -> bool:
        """Remove IP from exception list"""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('DELETE FROM exception_ips WHERE ip_address = ?', (ip.strip(),))

            rows = cursor.rowcount
            conn.commit()
            conn.close()

            if rows > 0:
                logger.info(f"Removed IP exception: {ip}")
                return True
            else:
                logger.warning(f"IP exception not found: {ip}")
                return False

        except Exception as e:
            logger.error(f"Failed to remove IP exception: {e}")
            return False

    def list_domain_exceptions(self) -> List[Dict]:
        """List all domain exceptions"""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('SELECT * FROM exception_domains ORDER BY domain')
            rows = [dict(row) for row in cursor.fetchall()]

            conn.close()
            return rows

        except Exception as e:
            logger.error(f"Failed to list domain exceptions: {e}")
            return []

    def list_ip_exceptions(self) -> List[Dict]:
        """List all IP exceptions"""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('SELECT * FROM exception_ips ORDER BY ip_address')
            rows = [dict(row) for row in cursor.fetchall()]

            conn.close()
            return rows

        except Exception as e:
            logger.error(f"Failed to list IP exceptions: {e}")
            return []

    def is_domain_excepted(self, domain: str) -> bool:
        """Check if domain is in database exceptions"""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            domain = domain.lower().strip()

            # Check direct match
            cursor.execute('SELECT 1 FROM exception_domains WHERE domain = ? LIMIT 1', (domain,))
            if cursor.fetchone():
                conn.close()
                return True

            # Check if subdomain of excepted domain
            cursor.execute('SELECT domain FROM exception_domains')
            for (exc_domain,) in cursor.fetchall():
                if domain.endswith('.' + exc_domain):
                    conn.close()
                    return True

            conn.close()
            return False

        except Exception as e:
            logger.error(f"Failed to check domain exception: {e}")
            return False


def main():
    """CLI for configuration and exception management"""
    import argparse

    parser = argparse.ArgumentParser(description="Karen's IPS Blocklist Configuration Manager")

    parser.add_argument('--config', default='/etc/karens-ips/blocklists.yaml',
                        help='Path to configuration file')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Update command
    update_parser = subparsers.add_parser('update', help='Update blocklist repositories')
    update_parser.add_argument('--force', action='store_true', help='Force re-clone')

    # Exception commands
    exc_parser = subparsers.add_parser('exception', help='Manage exceptions')
    exc_subparsers = exc_parser.add_subparsers(dest='exc_command')

    # Add exception
    add_parser = exc_subparsers.add_parser('add', help='Add exception')
    add_parser.add_argument('type', choices=['domain', 'ip'], help='Exception type')
    add_parser.add_argument('value', help='Domain or IP to except')
    add_parser.add_argument('--reason', default='', help='Reason for exception')

    # Remove exception
    rm_parser = exc_subparsers.add_parser('remove', help='Remove exception')
    rm_parser.add_argument('type', choices=['domain', 'ip'], help='Exception type')
    rm_parser.add_argument('value', help='Domain or IP to remove')

    # List exceptions
    list_parser = exc_subparsers.add_parser('list', help='List exceptions')
    list_parser.add_argument('type', choices=['domain', 'ip', 'all'], help='Exception type')

    # Show config
    subparsers.add_parser('show-config', help='Show current configuration')

    args = parser.parse_args()

    # Load configuration
    config = BlocklistConfig(args.config)

    if args.command == 'update':
        updater = BlocklistUpdater(config)
        results = updater.update_all_repositories()

        print("\nUpdate Results:")
        for repo, success in results.items():
            status = "✓" if success else "✗"
            print(f"  {status} {repo}")

    elif args.command == 'exception':
        exc_mgr = ExceptionManager(config, config.get_database_path())

        if args.exc_command == 'add':
            if args.type == 'domain':
                exc_mgr.add_domain_exception(args.value, args.reason)
            else:
                exc_mgr.add_ip_exception(args.value, args.reason)

        elif args.exc_command == 'remove':
            if args.type == 'domain':
                exc_mgr.remove_domain_exception(args.value)
            else:
                exc_mgr.remove_ip_exception(args.value)

        elif args.exc_command == 'list':
            if args.type in ['domain', 'all']:
                domains = exc_mgr.list_domain_exceptions()
                print(f"\nDomain Exceptions ({len(domains)}):")
                for d in domains:
                    print(f"  {d['domain']:<50} {d.get('reason', '')}")

            if args.type in ['ip', 'all']:
                ips = exc_mgr.list_ip_exceptions()
                print(f"\nIP Exceptions ({len(ips)}):")
                for i in ips:
                    print(f"  {i['ip_address']:<20} {i.get('reason', '')}")

    elif args.command == 'show-config':
        print("\nCurrent Configuration:")
        print(f"  Repositories: {config.get_repositories_dir()}")
        print(f"  Database: {config.get_database_path()}")
        print(f"\nEnabled Lists ({len(config.get_enabled_lists())}):")
        for lst in config.get_enabled_lists():
            print(f"  • {lst['source']}/{lst['name']}: {lst.get('file', '')}")

    else:
        parser.print_help()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    main()
