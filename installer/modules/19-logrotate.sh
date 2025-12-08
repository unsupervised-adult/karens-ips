#!/usr/bin/env bash

module_19_logrotate() {
    log "Configuring aggressive log rotation policies..."

    cat > /etc/logrotate.d/suricata << 'EOF'
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    rotate 7
    maxage 7
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /bin/kill -HUP $(cat /var/run/suricata.pid 2>/dev/null) 2>/dev/null || true
    endscript
    maxsize 1G
    size 500M
}

/var/log/suricata/eve.json {
    hourly
    rotate 48
    maxage 2
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /bin/kill -HUP $(cat /var/run/suricata.pid 2>/dev/null) 2>/dev/null || true
    endscript
    maxsize 2G
    size 1G
}
EOF

    cat > /etc/logrotate.d/slips << 'EOF'
/var/log/slips/*.log {
    daily
    rotate 7
    maxage 7
    missingok
    notifempty
    compress
    delaycompress
    maxsize 500M
    size 250M
}

/opt/StratosphereLinuxIPS/output/*/*.log {
    daily
    rotate 3
    maxage 3
    missingok
    notifempty
    compress
    delaycompress
    maxsize 200M
    size 100M
}
EOF

    chmod 644 /etc/logrotate.d/suricata /etc/logrotate.d/slips

    if [ ! -f /etc/cron.hourly/logrotate ]; then
        log "Creating hourly logrotate cron job..."
        cat > /etc/cron.hourly/logrotate << 'EOF'
#!/bin/sh
/usr/sbin/logrotate /etc/logrotate.conf
EOF
        chmod 755 /etc/cron.hourly/logrotate
    fi

    log "Testing logrotate configuration..."
    logrotate -d /etc/logrotate.d/suricata > /dev/null 2>&1 || warn "Suricata logrotate test had warnings"
    logrotate -d /etc/logrotate.d/slips > /dev/null 2>&1 || warn "SLIPS logrotate test had warnings"

    success "Logrotate configured with aggressive policies"
    log "  - Suricata: Daily rotation, 7 days, 1GB max"
    log "  - EVE JSON: Hourly rotation, 2 days, 2GB max"
    log "  - SLIPS: Daily rotation, 7 days, 500MB max"
    log "  - Hourly cron job monitoring all logs"
}

module_19_logrotate_info() {
    cat << EOF
Module: Log Rotation
Purpose: Configure aggressive log rotation to manage disk space
Actions:
  - Install Suricata logrotate config (daily + hourly EVE JSON)
  - Install SLIPS logrotate config (daily with size limits)
  - Create hourly cron job for logrotate
  - Set strict size limits and retention periods
  - Enable compression with 1-day delay
EOF
}
