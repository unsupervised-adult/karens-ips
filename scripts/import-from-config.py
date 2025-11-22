#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only

"""
Configuration-based Blocklist Importer

Reads /etc/karens-ips/blocklists.yaml and imports only enabled lists.
"""

import yaml
import sys
import subprocess
import os
from pathlib import Path

# Configuration
CONFIG_FILE = "/etc/karens-ips/blocklists.yaml"
IPS_FILTER_DB = "/opt/ips-filter-db.py"


def load_config():
    """Load blocklist configuration"""
    if not os.path.exists(CONFIG_FILE):
        print(f"Error: Configuration file not found: {CONFIG_FILE}")
        sys.exit(1)

    with open(CONFIG_FILE, 'r') as f:
        return yaml.safe_load(f)


def import_list(repos_dir, source, list_config):
    """Import a single blocklist"""
    list_file = Path(repos_dir) / source / list_config['file']

    if not list_file.exists():
        print(f"  ⚠ List not found: {list_file}")
        return False

    print(f"  Importing {list_config['name']} ({list_config.get('category', 'ads')})...")

    source_name = f"{source.lower()}_{list_config['name'].lower().replace(' ', '_')}"

    cmd = [
        IPS_FILTER_DB,
        'import-list',
        '--list-file', str(list_file),
        '--category', list_config.get('category', 'ads'),
        '--source-name', source_name
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600
        )

        # Show import summary
        for line in result.stdout.split('\n'):
            if any(x in line for x in ['Imported:', 'Skipped:', 'Import Complete']):
                print(f"    {line}")

        return result.returncode == 0

    except subprocess.TimeoutExpired:
        print(f"    ✗ Timeout importing {list_config['name']}")
        return False
    except Exception as e:
        print(f"    ✗ Error: {e}")
        return False


def main():
    """Main import function"""
    print("=" * 60)
    print("Karen's IPS Configuration-Based Blocklist Importer")
    print("=" * 60)
    print()

    # Load configuration
    config = load_config()
    repos_dir = config.get('repositories_dir', '/opt/karens-ips-blocklists')

    if not os.path.exists(repos_dir):
        print(f"Error: Repositories directory not found: {repos_dir}")
        sys.exit(1)

    total_imported = 0
    total_failed = 0

    # Import Perflyst lists
    if config.get('perflyst', {}).get('enabled', False):
        print("Perflyst/PiHoleBlocklist:")
        print("-" * 60)

        for list_cfg in config['perflyst'].get('lists', []):
            if not list_cfg.get('enabled', True):
                print(f"  ⊘ Skipping {list_cfg['name']} (disabled in config)")
                continue

            if import_list(repos_dir, 'PiHoleBlocklist', list_cfg):
                total_imported += 1
            else:
                total_failed += 1

        print()

    # Import hagezi lists
    if config.get('hagezi', {}).get('enabled', False):
        print("hagezi/dns-blocklists:")
        print("-" * 60)

        for list_cfg in config['hagezi'].get('lists', []):
            if not list_cfg.get('enabled', True):
                print(f"  ⊘ Skipping {list_cfg['name']} (disabled in config)")
                continue

            if import_list(repos_dir, 'dns-blocklists', list_cfg):
                total_imported += 1
            else:
                total_failed += 1

        print()

    # Import custom lists
    if config.get('custom', {}).get('enabled', False):
        print("Custom blocklists:")
        print("-" * 60)

        for list_cfg in config['custom'].get('lists', []):
            if not list_cfg.get('enabled', True):
                print(f"  ⊘ Skipping {list_cfg['name']} (disabled in config)")
                continue

            # Custom lists use full path in 'file' field
            list_file = Path(list_cfg['file'])
            if not list_file.exists():
                print(f"  ⚠ Custom list not found: {list_file}")
                total_failed += 1
                continue

            print(f"  Importing {list_cfg['name']} ({list_cfg.get('category', 'custom')})...")

            cmd = [
                IPS_FILTER_DB,
                'import-list',
                '--list-file', str(list_file),
                '--category', list_cfg.get('category', 'custom'),
                '--source-name', f"custom_{list_cfg['name'].lower().replace(' ', '_')}"
            ]

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                for line in result.stdout.split('\n'):
                    if any(x in line for x in ['Imported:', 'Skipped:', 'Import Complete']):
                        print(f"    {line}")

                if result.returncode == 0:
                    total_imported += 1
                else:
                    total_failed += 1

            except Exception as e:
                print(f"    ✗ Error: {e}")
                total_failed += 1

        print()

    # Sync to Suricata if configured
    if config.get('suricata', {}).get('sync_after_import', True):
        print("Syncing to Suricata...")
        print("-" * 60)
        try:
            subprocess.run(
                [IPS_FILTER_DB, 'sync'],
                capture_output=False,
                timeout=600
            )
        except Exception as e:
            print(f"  ✗ Sync failed: {e}")

    # Summary
    print()
    print("=" * 60)
    print("Import Summary:")
    print(f"  ✓ Successfully imported: {total_imported} lists")
    if total_failed > 0:
        print(f"  ✗ Failed: {total_failed} lists")
    print("=" * 60)
    print()

    return 0 if total_failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
