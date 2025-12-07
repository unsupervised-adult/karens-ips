#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Installing aggressive logrotate configurations..."

cp "$REPO_ROOT/config/logrotate-suricata" /etc/logrotate.d/suricata
cp "$REPO_ROOT/config/logrotate-slips" /etc/logrotate.d/slips

chmod 644 /etc/logrotate.d/suricata /etc/logrotate.d/slips

if [ ! -f /etc/cron.hourly/logrotate ]; then
    echo "Creating hourly logrotate cron..."
    cat > /etc/cron.hourly/logrotate << 'EOF'
#!/bin/sh
/usr/sbin/logrotate /etc/logrotate.conf
EOF
    chmod 755 /etc/cron.hourly/logrotate
fi

echo "Testing logrotate configuration..."
logrotate -d /etc/logrotate.d/suricata
logrotate -d /etc/logrotate.d/slips

echo "Logrotate configured:"
echo "  - Suricata logs: Daily rotation, 7 days retention, 1GB max"
echo "  - EVE JSON: Hourly rotation, 2 days retention, 2GB max"
echo "  - SLIPS logs: Daily rotation, 7 days retention, 500MB max"
echo "  - SLIPS output: Daily rotation, 3 days retention, 200MB max"
echo "  - Hourly cron job: Runs logrotate every hour"
echo ""
echo "Force rotation now:"
echo "  logrotate -f /etc/logrotate.d/suricata"
echo "  logrotate -f /etc/logrotate.d/slips"
