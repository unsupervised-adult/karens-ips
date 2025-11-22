#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Karen's IPS ML Ad Detector
# SPDX-License-Identifier: GPL-2.0-only

"""
Blocklist Manager for Karen's IPS

This module manages ad/tracking blocklists from multiple sources:
- Perflyst/PiHoleBlocklist
- hagezi/dns-blocklists

It imports blocklists into a SQLite database and can generate Suricata rules
for IPS-level blocking as a fallback when DNS blocking fails.
"""

import sqlite3
import logging
import os
import re
import hashlib
from pathlib import Path
from typing import List, Set, Dict, Optional
from datetime import datetime
import argparse

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BlocklistDB:
    """SQLite database manager for blocklists"""

    def __init__(self, db_path: str = "/var/lib/karens-ips/blocklists.db"):
        """
        Initialize blocklist database

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._ensure_db_dir()
        self.conn = None
        self._connect()
        self._create_schema()

    def _ensure_db_dir(self):
        """Ensure database directory exists"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            logger.info(f"Created database directory: {db_dir}")

    def _connect(self):
        """Connect to SQLite database"""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            logger.info(f"Connected to database: {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    def _create_schema(self):
        """Create database schema"""
        try:
            cursor = self.conn.cursor()

            # Blocklist sources table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocklist_sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    url TEXT,
                    category TEXT,
                    enabled INTEGER DEFAULT 1,
                    last_updated TIMESTAMP,
                    entry_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Blocked domains table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    source_id INTEGER NOT NULL,
                    category TEXT,
                    confidence REAL DEFAULT 1.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (source_id) REFERENCES blocklist_sources(id),
                    UNIQUE(domain, source_id)
                )
            """)

            # Create indexes for performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_blocked_domains_domain
                ON blocked_domains(domain)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_blocked_domains_source
                ON blocked_domains(source_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_blocked_domains_category
                ON blocked_domains(category)
            """)

            # Blocklist metadata
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocklist_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            self.conn.commit()
            logger.info("Database schema created successfully")

        except sqlite3.Error as e:
            logger.error(f"Failed to create schema: {e}")
            raise

    def add_source(self, name: str, description: str = "", url: str = "",
                   category: str = "") -> int:
        """
        Add or update a blocklist source

        Args:
            name: Source name
            description: Source description
            url: Source URL
            category: Category (ads, tracking, malware, etc.)

        Returns:
            Source ID
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO blocklist_sources (name, description, url, category)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    description = excluded.description,
                    url = excluded.url,
                    category = excluded.category
            """, (name, description, url, category))

            self.conn.commit()

            # Get the source ID
            cursor.execute("SELECT id FROM blocklist_sources WHERE name = ?", (name,))
            row = cursor.fetchone()
            return row[0] if row else None

        except sqlite3.Error as e:
            logger.error(f"Failed to add source: {e}")
            raise

    def add_domains(self, source_id: int, domains: List[str],
                    category: str = "ads") -> int:
        """
        Add blocked domains to database

        Args:
            source_id: Blocklist source ID
            domains: List of domain names
            category: Domain category

        Returns:
            Number of domains added
        """
        added = 0
        try:
            cursor = self.conn.cursor()

            for domain in domains:
                domain = domain.strip().lower()
                if not domain or domain.startswith('#'):
                    continue

                try:
                    cursor.execute("""
                        INSERT OR IGNORE INTO blocked_domains
                        (domain, source_id, category)
                        VALUES (?, ?, ?)
                    """, (domain, source_id, category))

                    if cursor.rowcount > 0:
                        added += 1

                except sqlite3.Error as e:
                    logger.warning(f"Failed to add domain {domain}: {e}")
                    continue

            # Update source entry count
            cursor.execute("""
                UPDATE blocklist_sources
                SET entry_count = (
                    SELECT COUNT(*) FROM blocked_domains WHERE source_id = ?
                ),
                last_updated = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (source_id, source_id))

            self.conn.commit()
            logger.info(f"Added {added} domains from source {source_id}")
            return added

        except sqlite3.Error as e:
            logger.error(f"Failed to add domains: {e}")
            raise

    def get_all_domains(self, category: Optional[str] = None) -> List[str]:
        """
        Get all blocked domains

        Args:
            category: Filter by category (optional)

        Returns:
            List of domain names
        """
        try:
            cursor = self.conn.cursor()

            if category:
                cursor.execute("""
                    SELECT DISTINCT domain FROM blocked_domains
                    WHERE category = ?
                    ORDER BY domain
                """, (category,))
            else:
                cursor.execute("""
                    SELECT DISTINCT domain FROM blocked_domains
                    ORDER BY domain
                """)

            return [row[0] for row in cursor.fetchall()]

        except sqlite3.Error as e:
            logger.error(f"Failed to get domains: {e}")
            return []

    def get_stats(self) -> Dict[str, int]:
        """
        Get blocklist statistics

        Returns:
            Dictionary with statistics
        """
        try:
            cursor = self.conn.cursor()

            stats = {}

            # Total sources
            cursor.execute("SELECT COUNT(*) FROM blocklist_sources WHERE enabled = 1")
            stats['total_sources'] = cursor.fetchone()[0]

            # Total domains
            cursor.execute("SELECT COUNT(DISTINCT domain) FROM blocked_domains")
            stats['total_domains'] = cursor.fetchone()[0]

            # Domains by category
            cursor.execute("""
                SELECT category, COUNT(DISTINCT domain) as count
                FROM blocked_domains
                GROUP BY category
            """)
            stats['by_category'] = {row[0]: row[1] for row in cursor.fetchall()}

            return stats

        except sqlite3.Error as e:
            logger.error(f"Failed to get stats: {e}")
            return {}

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")


class BlocklistParser:
    """Parser for various blocklist formats"""

    @staticmethod
    def parse_domain_list(file_path: str) -> List[str]:
        """
        Parse a simple domain list file

        Format: One domain per line, # for comments

        Args:
            file_path: Path to blocklist file

        Returns:
            List of domain names
        """
        domains = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue

                    # Remove inline comments
                    if '#' in line:
                        line = line.split('#')[0].strip()

                    # Validate domain
                    if BlocklistParser._is_valid_domain(line):
                        domains.append(line.lower())

        except Exception as e:
            logger.error(f"Failed to parse {file_path}: {e}")

        return domains

    @staticmethod
    def parse_hosts_file(file_path: str) -> List[str]:
        """
        Parse hosts file format

        Format: 0.0.0.0 domain.com or 127.0.0.1 domain.com

        Args:
            file_path: Path to hosts file

        Returns:
            List of domain names
        """
        domains = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue

                    # Parse hosts format: IP domain
                    parts = line.split()
                    if len(parts) >= 2:
                        # Second part is the domain
                        domain = parts[1].lower()
                        if BlocklistParser._is_valid_domain(domain):
                            domains.append(domain)

        except Exception as e:
            logger.error(f"Failed to parse hosts file {file_path}: {e}")

        return domains

    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        """
        Validate domain name

        Args:
            domain: Domain name to validate

        Returns:
            True if valid domain
        """
        # Basic domain validation
        if not domain or len(domain) > 253:
            return False

        # Check for valid characters
        pattern = re.compile(
            r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*'
            r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$',
            re.IGNORECASE
        )

        return bool(pattern.match(domain))


class BlocklistImporter:
    """Import blocklists into database"""

    def __init__(self, db: BlocklistDB, repo_path: str):
        """
        Initialize importer

        Args:
            db: BlocklistDB instance
            repo_path: Path to blocklists repository
        """
        self.db = db
        self.repo_path = Path(repo_path)

    def import_perflyst_blocklists(self):
        """Import Perflyst PiHoleBlocklist repository"""
        logger.info("Importing Perflyst blocklists...")

        perflyst_path = self.repo_path / "PiHoleBlocklist"
        if not perflyst_path.exists():
            logger.warning(f"Perflyst repository not found at {perflyst_path}")
            return

        # Define blocklists to import
        blocklists = [
            ("SmartTV.txt", "Smart TV tracking and ads", "ads"),
            ("SmartTV-AGH.txt", "Smart TV (AdGuard Home format)", "ads"),
            ("AmazonFireTV.txt", "Amazon Fire TV tracking", "ads"),
            ("android-tracking.txt", "Android app tracking", "tracking"),
            ("SessionReplay.txt", "Session replay tracking", "tracking"),
        ]

        for filename, description, category in blocklists:
            file_path = perflyst_path / filename
            if not file_path.exists():
                logger.warning(f"Blocklist not found: {filename}")
                continue

            # Add source
            source_id = self.db.add_source(
                name=f"perflyst_{filename}",
                description=description,
                url=f"https://github.com/Perflyst/PiHoleBlocklist",
                category=category
            )

            # Parse and import domains
            domains = BlocklistParser.parse_domain_list(str(file_path))
            added = self.db.add_domains(source_id, domains, category)
            logger.info(f"Imported {added} domains from {filename}")

    def import_hagezi_blocklists(self):
        """Import hagezi dns-blocklists repository"""
        logger.info("Importing hagezi blocklists...")

        hagezi_path = self.repo_path / "dns-blocklists"
        if not hagezi_path.exists():
            logger.warning(f"Hagezi repository not found at {hagezi_path}")
            return

        # Use Pro version as recommended (balanced blocking)
        blocklists = [
            ("domains/pro.txt", "Hagezi Pro - Balanced blocking", "ads"),
            ("domains/native.txt", "Hagezi Native Tracker", "tracking"),
        ]

        for filename, description, category in blocklists:
            file_path = hagezi_path / filename
            if not file_path.exists():
                logger.warning(f"Blocklist not found: {filename}")
                continue

            # Add source
            source_name = f"hagezi_{Path(filename).stem}"
            source_id = self.db.add_source(
                name=source_name,
                description=description,
                url="https://github.com/hagezi/dns-blocklists",
                category=category
            )

            # Parse and import domains
            domains = BlocklistParser.parse_domain_list(str(file_path))
            added = self.db.add_domains(source_id, domains, category)
            logger.info(f"Imported {added} domains from {filename}")


class SuricataRuleGenerator:
    """Generate Suricata rules from blocklists"""

    def __init__(self, db: BlocklistDB):
        """
        Initialize rule generator

        Args:
            db: BlocklistDB instance
        """
        self.db = db

    def generate_rules(self, output_file: str, category: Optional[str] = None):
        """
        Generate Suricata rules file

        Args:
            output_file: Output file path
            category: Filter by category (optional)
        """
        logger.info(f"Generating Suricata rules to {output_file}")

        domains = self.db.get_all_domains(category)

        try:
            with open(output_file, 'w') as f:
                # File header
                f.write("# Karen's IPS Blocklist Rules\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write(f"# Total domains: {len(domains)}\n")
                if category:
                    f.write(f"# Category: {category}\n")
                f.write("\n")

                # Generate rules
                for idx, domain in enumerate(domains, start=1000000):
                    rule = self._generate_rule(idx, domain, category or "ads")
                    f.write(rule + "\n")

            logger.info(f"Generated {len(domains)} Suricata rules")

        except Exception as e:
            logger.error(f"Failed to generate rules: {e}")
            raise

    def _generate_rule(self, sid: int, domain: str, category: str) -> str:
        """
        Generate a single Suricata rule

        Args:
            sid: Signature ID
            domain: Domain name
            category: Category

        Returns:
            Suricata rule string
        """
        # HTTP rule
        rule = (
            f'alert http any any -> any any '
            f'(msg:"KARENS-IPS Blocked {category}: {domain}"; '
            f'flow:established,to_server; '
            f'http.host; content:"{domain}"; nocase; '
            f'classtype:policy-violation; '
            f'sid:{sid}; rev:1;)'
        )
        return rule


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Karen's IPS Blocklist Manager"
    )
    parser.add_argument(
        '--db-path',
        default='/var/lib/karens-ips/blocklists.db',
        help='SQLite database path'
    )
    parser.add_argument(
        '--repo-path',
        default='/opt/karens-ips-blocklists',
        help='Path to blocklists repositories'
    )
    parser.add_argument(
        '--import',
        action='store_true',
        dest='do_import',
        help='Import blocklists into database'
    )
    parser.add_argument(
        '--generate-rules',
        metavar='OUTPUT',
        help='Generate Suricata rules to file'
    )
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show blocklist statistics'
    )
    parser.add_argument(
        '--category',
        choices=['ads', 'tracking', 'malware', 'all'],
        default='all',
        help='Filter by category'
    )

    args = parser.parse_args()

    # Initialize database
    db = BlocklistDB(args.db_path)

    try:
        # Import blocklists
        if args.do_import:
            importer = BlocklistImporter(db, args.repo_path)
            importer.import_perflyst_blocklists()
            importer.import_hagezi_blocklists()

        # Generate Suricata rules
        if args.generate_rules:
            generator = SuricataRuleGenerator(db)
            category = None if args.category == 'all' else args.category
            generator.generate_rules(args.generate_rules, category)

        # Show statistics
        if args.stats:
            stats = db.get_stats()
            print("\n=== Blocklist Statistics ===")
            print(f"Total sources: {stats.get('total_sources', 0)}")
            print(f"Total domains: {stats.get('total_domains', 0)}")
            print("\nBy category:")
            for cat, count in stats.get('by_category', {}).items():
                print(f"  {cat}: {count}")
            print()

    finally:
        db.close()


if __name__ == '__main__':
    main()
