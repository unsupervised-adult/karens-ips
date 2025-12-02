#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: SystemD Services
# Phase: 14
# Description: Create SystemD service files for all IPS components

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ============================================================================
# SYSTEMD SERVICES CREATION
# ============================================================================

create_systemd_services() {
    log_subsection "SystemD Services Creation"

    # Check if SystemD services creation is enabled
    if [[ "${CREATE_SYSTEMD_SERVICES:-true}" != "true" ]]; then
        log "SystemD services creation disabled, skipping"
        return 0
    fi

    log "Creating SystemD services for IPS components..."

    # Create all service files
    create_suricata_service
    create_slips_service
    create_zeek_service
    create_slips_webui_service
    create_ips_filter_sync_service
    create_threat_blocker_service
    create_dataset_sync_service
    create_kalipso_launcher

    # Reload SystemD
    reload_systemd

    # Enable all services
    enable_services

    success "SystemD services created and enabled"
}

# ============================================================================
# SERVICE FILE CREATION
# ============================================================================

create_suricata_service() {
    log "Creating Suricata service..."

    cat > /etc/systemd/system/suricata.service << EOF
[Unit]
Description=Suricata IPS NFQUEUE Mode
Documentation=https://suricata.readthedocs.io/
After=network-online.target redis.service ips-interfaces.service nftables.service
Wants=network-online.target
Requires=ips-interfaces.service nftables.service

[Service]
Type=simple
User=root
Group=root
RuntimeDirectory=suricata
RuntimeDirectoryMode=0755
ExecStartPre=/usr/bin/suricata -c /etc/suricata/suricata.yaml -T
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -q 0 -v
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
Environment=HOME=/var/lib/suricata
WorkingDirectory=/var/lib/suricata

[Install]
WantedBy=multi-user.target
EOF

    log "Suricata service created"
}

create_slips_service() {
    log "Creating SLIPS service..."

    cat > /etc/systemd/system/slips.service << EOF
[Unit]
Description=SLIPS (Stratosphere Linux IPS) - ML Behavioral Analysis
Documentation=https://stratospherelinuxips.readthedocs.io/
After=network.target redis.service ips-interfaces.service
Wants=redis.service ips-interfaces.service
Requires=ips-interfaces.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${SLIPS_DIR}
ExecStartPre=/bin/mkdir -p /tmp/slips
ExecStartPre=/bin/chmod 1777 /tmp/slips
ExecStart=${SLIPS_DIR}/venv/bin/python ${SLIPS_DIR}/slips.py -c ${SLIPS_DIR}/config/slips.yaml -i br0
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
Environment=HOME=/root
Environment=PYTHONPATH=${SLIPS_DIR}
Environment=PATH=${SLIPS_DIR}/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
EOF

    log "SLIPS service created"
}

create_zeek_service() {
    log "Creating Zeek service..."

    cat > /etc/systemd/system/zeek.service << EOF
[Unit]
Description=Zeek Network Security Monitor
After=network.target ips-interfaces.service
Wants=ips-interfaces.service
Before=slips.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
Group=root
WorkingDirectory=/opt/zeek
Environment=PATH=/opt/zeek/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Use zeekctl for process management - it handles PID files internally
ExecStartPre=/opt/zeek/bin/zeekctl install
ExecStart=/opt/zeek/bin/zeekctl deploy
ExecReload=/opt/zeek/bin/zeekctl restart
ExecStop=/opt/zeek/bin/zeekctl stop
StandardOutput=journal
StandardError=journal
# Allow extra time for initial deployment and rule compilation
TimeoutStartSec=300
# Allow more time for stopping (zeek can be slow to shutdown cleanly)
TimeoutStopSec=90

# Resource limits
MemoryMax=1G
CPUQuota=100%

[Install]
WantedBy=multi-user.target
EOF

    log "Zeek service created"
}

create_slips_webui_service() {
    log "Creating SLIPS Web UI service..."

    # Detect management IP and interface
    local mgmt_ip="127.0.0.1"
    local mgmt_iface="${MGMT_IFACE:-lo}"
    if [[ -n "${MGMT_IFACE:-}" ]]; then
        mgmt_ip=$(ip addr show "$MGMT_IFACE" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || echo "127.0.0.1")
    fi

    cat > /etc/systemd/system/slips-webui.service << EOF
[Unit]
Description=SLIPS Web Interface
After=network.target redis.service ips-interfaces.service slips.service
Wants=redis.service ips-interfaces.service
# Web UI reads from Redis, so it should start after main SLIPS
Requires=slips.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${SLIPS_DIR}
# SLIPS requires /tmp/slips for SQLite lockfiles
ExecStartPre=/bin/mkdir -p /tmp/slips
ExecStartPre=/bin/chmod 1777 /tmp/slips
# Wait for Redis to be fully ready with databases
ExecStartPre=/bin/bash -c 'for i in {1..30}; do redis-cli ping > /dev/null 2>&1 && redis-cli DBSIZE > /dev/null 2>&1 && break || sleep 2; done'
# Run web-only interface via webinterface.sh script
# Connects to main SLIPS instance via Redis to display analysis
ExecStart=${SLIPS_DIR}/webinterface.sh
Restart=on-failure
RestartSec=30
StartLimitBurst=10
StartLimitIntervalSec=120
StandardOutput=journal
StandardError=journal
Environment=HOME=/root
Environment=PATH=${SLIPS_DIR}/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=SLIPS_WEB_HOST=${mgmt_ip}
Environment=SLIPS_WEB_PORT=55000
Environment=PYTHONUNBUFFERED=1

# Resource limits
MemoryMax=2G
CPUQuota=150%

[Install]
WantedBy=multi-user.target
EOF

    log "SLIPS Web UI service created"
}

create_ips_filter_sync_service() {
    log "Creating IPS Filter sync service and timer..."

    # Service file
    cat > /etc/systemd/system/ips-filter-sync.service << 'EOF'
[Unit]
Description=IPS Filter Database Sync
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/ips-filter-db.py --db-path /var/lib/suricata/ips_filter.db --sync
StandardOutput=journal
StandardError=journal
User=root

[Install]
WantedBy=multi-user.target
EOF

    # Timer file
    cat > /etc/systemd/system/ips-filter-sync.timer << 'EOF'
[Unit]
Description=IPS Filter Database Sync Timer
Requires=ips-filter-sync.service

[Timer]
OnBootSec=5min
OnUnitActiveSec=6h
Unit=ips-filter-sync.service

[Install]
WantedBy=timers.target
EOF

    log "IPS Filter sync service and timer created"
}

create_kalipso_launcher() {
    log "Creating Kalipso launcher script..."

    cat > /usr/bin/kalipso << 'KALIPSO_SCRIPT'
#!/bin/bash
# Kalipso Smart Launcher - Connect or Start Interactive Session
# Usage: sudo kalipso

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "Error: Kalipso must be run with sudo privileges"
    echo "Usage: sudo kalipso"
    exit 1
fi

KALIPSO_SESSION="kalipso"
KALIPSO_DIR="/opt/StratosphereLinuxIPS/modules/kalipso"
KALIPSO_CMD="/usr/bin/node /opt/StratosphereLinuxIPS/modules/kalipso/kalipso.js -p 6379"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}Kalipso Terminal UI Launcher${NC}"
echo -e "${BLUE}═══════════════════════════════════${NC}"

# Check if tmux session exists
if tmux has-session -t "$KALIPSO_SESSION" 2>/dev/null; then
    echo -e "${GREEN}Found existing Kalipso session, connecting...${NC}"
    echo -e "${YELLOW}Use Ctrl+B then D to detach and keep running${NC}"
    echo ""
    sleep 1
    exec tmux attach-session -t "$KALIPSO_SESSION"
else
    echo -e "${GREEN}Starting fresh Kalipso session...${NC}"
    echo -e "${YELLOW}Use Ctrl+B then D to detach and keep running${NC}"
    echo -e "${YELLOW}Use 'exit' or Ctrl+C to stop Kalipso completely${NC}"
    echo ""
    sleep 1

    # Check if Kalipso directory exists
    if [ ! -d "$KALIPSO_DIR" ]; then
        echo -e "${RED}Kalipso directory not found: $KALIPSO_DIR${NC}"
        exit 1
    fi

    # Start new tmux session with Kalipso
    cd "$KALIPSO_DIR"
    exec tmux new-session -s "$KALIPSO_SESSION" "$KALIPSO_CMD"
fi
KALIPSO_SCRIPT

    chmod +x /usr/bin/kalipso
    success "Kalipso launcher script created"
}

# ============================================================================
# SYSTEMD MANAGEMENT
# ============================================================================

reload_systemd() {
    log "Reloading SystemD daemon..."

    if systemctl daemon-reload; then
        success "SystemD daemon reloaded"
    else
        warn "Failed to reload SystemD daemon"
    fi
}

enable_services() {
    log "Enabling services to start on boot..."

    local services=(
        "ips-interfaces.service"
        "redis-server"
        "zeek.service"
        "suricata.service"
        "slips.service"
        "slips-webui.service"
        "threat-blocker.service"
        "ips-filter-sync.timer"
        "ips-dataset-sync.timer"
    )

    for service in "${services[@]}"; do
        if systemctl enable "$service" 2>/dev/null; then
            log "Enabled: $service"
        else
            warn "Failed to enable: $service"
        fi
    done

    success "Services enabled"
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_systemd_services() {
    log "Verifying SystemD services..."

    local errors=0
    local services=(
        "suricata.service"
        "slips.service"
        "zeek.service"
        "slips-webui.service"
        "ips-filter-sync.service"
        "ips-filter-sync.timer"
        "ips-interfaces.service"
    )

    for service in "${services[@]}"; do
        if [[ ! -f "/etc/systemd/system/$service" ]]; then
            warn "Service file not found: $service"
            ((errors++))
        fi
    done

    # Check if Kalipso launcher exists
    if [[ ! -f /usr/bin/kalipso ]]; then
        warn "Kalipso launcher not found"
        ((errors++))
    fi

    if [[ $errors -eq 0 ]]; then
        success "SystemD services verification passed"
        return 0
    else
        warn "SystemD services verification found $errors issues"
        return 1
    fi
}

# Export functions
create_threat_blocker_service() {
    log "Creating threat blocker service..."

    cat > /etc/systemd/system/threat-blocker.service << 'EOF'
[Unit]
Description=Redis Threat Blocker - Automatic IP Blocking
Documentation=https://github.com/unsupervised-adult/karens-ips
After=network.target redis.service slips.service
Wants=redis.service slips.service
Requires=redis.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/usr/local/bin
ExecStart=/usr/local/bin/redis-threat-blocker.py
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
Environment=HOME=/root
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Security
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log /var/run

[Install]
WantedBy=multi-user.target
EOF

    log "Threat blocker service created"
}

create_dataset_sync_service() {
    log "Creating comprehensive threat intelligence update service and timer..."

    # Service file - runs full chain: Repos → SQLite → Suricata
    cat > /etc/systemd/system/ips-dataset-sync.service << 'EOF'
[Unit]
Description=Threat Intelligence Update - Full chain (Repos → SQLite → Suricata)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update-threat-intelligence.sh
StandardOutput=journal
StandardError=journal
User=root
WorkingDirectory=/usr/local/bin
TimeoutStartSec=1800

[Install]
WantedBy=multi-user.target
EOF

    # Timer file - runs every 6 hours for complete update
    cat > /etc/systemd/system/ips-dataset-sync.timer << 'EOF'
[Unit]
Description=Threat Intelligence Update Timer - Complete repo/SQLite/dataset refresh
Requires=ips-dataset-sync.service

[Timer]
OnBootSec=10min
OnUnitActiveSec=6h
Persistent=true
AccuracySec=1m

[Install]
WantedBy=timers.target
EOF

    log "Comprehensive threat intelligence update service and timer created (6h interval)"
}

export -f create_systemd_services
export -f create_suricata_service
export -f create_slips_service
export -f create_zeek_service
export -f create_slips_webui_service
export -f create_ips_filter_sync_service
export -f create_threat_blocker_service
export -f create_dataset_sync_service
export -f create_kalipso_launcher
export -f reload_systemd
export -f enable_services
export -f verify_systemd_services
