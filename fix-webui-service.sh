#!/bin/bash

SLIPS_DIR="/opt/StratosphereLinuxIPS"

# Detect management IP and interface
mgmt_ip="127.0.0.1"
mgmt_iface=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
if [[ -n "$mgmt_iface" ]]; then
    mgmt_ip=$(ip addr show "$mgmt_iface" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || echo "127.0.0.1")
fi

echo "Creating fixed slips-webui.service..."

cat > /etc/systemd/system/slips-webui.service << EOF
[Unit]
Description=SLIPS Web Interface
After=network.target redis.service ips-interfaces.service slips.service
Wants=redis.service ips-interfaces.service
Requires=slips.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${SLIPS_DIR}
ExecStartPre=/bin/mkdir -p /tmp/slips
ExecStartPre=/bin/chmod 1777 /tmp/slips
ExecStart=${SLIPS_DIR}/webinterface.sh
Restart=on-failure
RestartSec=30
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

echo "Reloading systemd..."
systemctl daemon-reload

echo "Restarting slips-webui..."
systemctl restart slips-webui

echo "Checking status..."
systemctl status slips-webui --no-pager -l

echo ""
echo "Done! Web UI should be available at: http://${mgmt_ip}:55000"
