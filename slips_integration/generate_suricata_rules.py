#!/usr/bin/env python3
"""
Generate Suricata drop rules from blocked domains database
Converts 344k+ blocked domains into TLS SNI drop rules for true IPS inline blocking
"""
import sqlite3
import sys
import os
from datetime import datetime

DB_PATH = '/var/lib/suricata/ips_filter.db'
RULES_FILE = '/var/lib/suricata/rules/ml-detector-blocking.rules'
BACKUP_DIR = '/var/lib/suricata/rules/backups'

# Starting SID for our rules (using high range to avoid conflicts)
STARTING_SID = 9000000

def generate_rules_from_database(db_path, output_file):
    """
    Generate Suricata drop rules from blocked domains database
    """
    print(f"[*] Connecting to database: {db_path}")

    if not os.path.exists(db_path):
        print(f"[ERROR] Database not found: {db_path}")
        return False

    # Create backup directory if it doesn't exist
    os.makedirs(BACKUP_DIR, exist_ok=True)

    # Backup existing rules file if it exists and is not empty
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        backup_file = os.path.join(
            BACKUP_DIR,
            f"ml-detector-blocking.rules.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        print(f"[*] Backing up existing rules to: {backup_file}")
        os.system(f"cp {output_file} {backup_file}")

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Get all blocked domains
        print("[*] Fetching blocked domains from database...")
        cursor.execute("SELECT domain, category FROM blocked_domains ORDER BY domain")
        domains = cursor.fetchall()

        total_domains = len(domains)
        print(f"[*] Found {total_domains} blocked domains")

        if total_domains == 0:
            print("[WARNING] No domains found in database")
            return False

        # Generate rules file
        print(f"[*] Generating Suricata rules: {output_file}")

        with open(output_file, 'w') as f:
            # Write header
            f.write("# Suricata TLS SNI Blocking Rules\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total domains: {total_domains}\n")
            f.write(f"# Source database: {db_path}\n")
            f.write("#\n")
            f.write("# These rules block TLS connections based on Server Name Indication (SNI)\n")
            f.write("# matching domains in the blocklist database\n")
            f.write("#\n\n")

            # Generate rules
            sid = STARTING_SID
            rules_written = 0

            for domain, category in domains:
                # Skip empty domains
                if not domain or domain.strip() == '':
                    continue

                category_str = category if category else "ads"

                # Escape special characters for Suricata content matching
                domain_escaped = domain.replace('"', '\\"')

                # Generate drop rule for this domain
                rule = (
                    f'drop tls any any -> any any '
                    f'(msg:"Blocked {category_str} domain: {domain_escaped}"; '
                    f'tls.sni; content:"{domain_escaped}"; nocase; '
                    f'classtype:policy-violation; '
                    f'sid:{sid}; rev:1;)\n'
                )

                f.write(rule)
                rules_written += 1
                sid += 1

                # Progress indicator
                if rules_written % 10000 == 0:
                    print(f"  Generated {rules_written}/{total_domains} rules...")

        print(f"[✓] Successfully generated {rules_written} Suricata drop rules")
        print(f"[✓] Rules written to: {output_file}")

        # Get file size
        file_size = os.path.getsize(output_file)
        size_mb = file_size / (1024 * 1024)
        print(f"[*] Rules file size: {size_mb:.2f} MB")

        conn.close()
        return True

    except sqlite3.Error as e:
        print(f"[ERROR] Database error: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        return False

def reload_suricata():
    """
    Reload Suricata to apply new rules
    """
    print("[*] Reloading Suricata to apply new rules...")

    # Try suricatasc reload-rules first (graceful reload)
    ret = os.system("suricatasc -c reload-rules 2>/dev/null")
    if ret == 0:
        print("[✓] Suricata rules reloaded successfully (suricatasc)")
        return True

    # Fallback to systemctl reload
    ret = os.system("systemctl reload suricata 2>/dev/null")
    if ret == 0:
        print("[✓] Suricata reloaded successfully (systemctl)")
        return True

    # Last resort: full restart
    print("[WARNING] Graceful reload failed, restarting Suricata...")
    ret = os.system("systemctl restart suricata")
    if ret == 0:
        print("[✓] Suricata restarted successfully")
        return True
    else:
        print("[ERROR] Failed to reload/restart Suricata")
        return False

def main():
    print("=" * 70)
    print("Suricata TLS SNI Blocking Rules Generator")
    print("=" * 70)
    print()

    # Check if running as root
    if os.geteuid() != 0:
        print("[ERROR] This script must be run as root (sudo)")
        sys.exit(1)

    # Generate rules
    success = generate_rules_from_database(DB_PATH, RULES_FILE)

    if not success:
        print("\n[ERROR] Failed to generate rules")
        sys.exit(1)

    # Reload Suricata
    print()
    if reload_suricata():
        print("\n" + "=" * 70)
        print("[✓] SUCCESS: TLS SNI blocking rules are now active!")
        print("=" * 70)
        print("\nSuricata will now drop packets matching these domains:")
        print(f"  - Total blocking rules: {len(open(RULES_FILE).readlines()) - 8}")  # Subtract header lines
        print(f"  - Rules file: {RULES_FILE}")
        print("\nMonitor blocked traffic:")
        print("  tail -f /var/log/suricata/fast.log")
        print("  journalctl -fu suricata")
        sys.exit(0)
    else:
        print("\n[ERROR] Rules generated but Suricata reload failed")
        print("Please manually reload Suricata:")
        print("  sudo systemctl reload suricata")
        sys.exit(1)

if __name__ == "__main__":
    main()
