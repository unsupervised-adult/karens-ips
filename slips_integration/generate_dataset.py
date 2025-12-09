#!/usr/bin/env python3
import sqlite3
import sys
import base64

DB_PATH = "/var/lib/suricata/ips_filter.db"
OUTPUT_FILE = "/var/lib/suricata/datasets/blocked-domains.lst"

def generate_dataset():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT DISTINCT domain FROM blocked_domains ORDER BY domain")
        domains = cursor.fetchall()
        conn.close()
        
        if not domains:
            print("No domains found in database", file=sys.stderr)
            return False
        
        with open(OUTPUT_FILE, 'w') as f:
            for domain, in domains:
                encoded = base64.b64encode(domain.encode('utf-8')).decode('ascii')
                f.write(f"{encoded}\n")
        
        print(f"Generated dataset with {len(domains)} domains in {OUTPUT_FILE}")
        return True
        
    except Exception as e:
        print(f"Error generating dataset: {e}", file=sys.stderr)
        return False

if __name__ == "__main__":
    sys.exit(0 if generate_dataset() else 1)
