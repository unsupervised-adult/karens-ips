#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: ML Detector Service Installation
# Phase: 11
# Description: Install ML detector monitoring service for real-time ad detection

# Note: This module must be sourced by main.sh, not executed directly

# ============================================================================
# ML DETECTOR SERVICE INSTALLATION
# ============================================================================

install_ml_detector_service() {
    log_subsection "ML Detector Service Installation"

    # Check if ML Detector installation is enabled
    if [[ "${INSTALL_ML_DETECTOR:-true}" != "true" ]]; then
        log "ML Detector installation disabled, skipping"
        return 0
    fi

    log "Installing ML Detector monitoring service..."

    # Copy simple ML feeder script to SLIPS directory
    copy_ml_feeder_script

    # Install stream monitor service
    install_stream_monitor_service

    # Install stream ad blocker service
    install_stream_ad_blocker_service

    success "ML Detector service installed successfully"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

copy_ml_feeder_script() {
    log "Copying ML feeder script to SLIPS directory..."

    local source_script="$PROJECT_ROOT/slips_integration/simple_ml_feeder.py"
    local dest_script="$SLIPS_DIR/simple_ml_feeder.py"

    if [[ -f "$source_script" ]]; then
        cp "$source_script" "$dest_script"
        chmod +x "$dest_script"
        chown root:root "$dest_script"
        success "ML feeder script installed"
    else
        warn "ML feeder script not found at: $source_script"
    fi
}

install_stream_monitor_service() {
    log "Installing stream-monitor systemd service..."

    local service_source="$PROJECT_ROOT/slips_integration/webinterface/ml_detector/stream-monitor.service"
    local service_dest="/etc/systemd/system/stream-monitor.service"
    local script_source="$PROJECT_ROOT/slips_integration/webinterface/ml_detector/realtime_stream_monitor.py"
    local script_dest="$SLIPS_DIR/webinterface/ml_detector/realtime_stream_monitor.py"

    if [[ ! -f "$service_source" ]]; then
        warn "stream-monitor.service not found at: $service_source"
        return 1
    fi

    # Ensure destination directory exists
    mkdir -p "$(dirname "$script_dest")"

    # Ensure the Python script is installed
    if [[ -f "$script_source" ]] && [[ ! -f "$script_dest" ]]; then
        cp "$script_source" "$script_dest"
        chmod +x "$script_dest"
        chown root:root "$script_dest"
        log "realtime_stream_monitor.py installed"
    fi

    # Copy service file
    cp "$service_source" "$service_dest"
    chmod 644 "$service_dest"

    # Reload systemd
    systemctl daemon-reload

    # Enable and start service
    systemctl enable stream-monitor.service
    systemctl start stream-monitor.service

    # Check status
    if systemctl is-active --quiet stream-monitor.service; then
        success "stream-monitor service started successfully"
    else
        warn "stream-monitor service failed to start"
        log "Checking service status..."
        systemctl status stream-monitor.service --no-pager -l || true
    fi
}

install_stream_ad_blocker_service() {
    log "Installing stream-ad-blocker systemd service..."

    local service_source="$PROJECT_ROOT/slips_integration/webinterface/ml_detector/stream-ad-blocker.service"
    local service_dest="/etc/systemd/system/stream-ad-blocker.service"
    local script_source="$PROJECT_ROOT/slips_integration/webinterface/ml_detector/stream_ad_blocker.py"
    local script_dest="$SLIPS_DIR/webinterface/ml_detector/stream_ad_blocker.py"

    # Ensure destination directory exists
    mkdir -p "$(dirname "$script_dest")"

    # Copy Python script
    if [[ -f "$script_source" ]]; then
        cp "$script_source" "$script_dest"
        chmod +x "$script_dest"
        chown root:root "$script_dest"
        log "stream_ad_blocker.py installed"
    else
        warn "stream_ad_blocker.py not found at: $script_source"
        return 1
    fi

    # Copy service file
    if [[ ! -f "$service_source" ]]; then
        warn "stream-ad-blocker.service not found at: $service_source"
        return 1
    fi

    cp "$service_source" "$service_dest"
    chmod 644 "$service_dest"

    # Reload systemd
    systemctl daemon-reload

    # Enable but don't start yet (let user enable blocking via web UI)
    systemctl enable stream-ad-blocker.service

    log "stream-ad-blocker service enabled (start via web UI)"
    success "stream-ad-blocker service installed"
    
    # Install SLIPS ↔ Suricata dataset sync service
    log "Installing SLIPS ↔ Suricata dataset sync service..."
    local sync_service_source="$PROJECT_ROOT/deployment/systemd/slips-suricata-sync.service"
    local sync_service_dest="/etc/systemd/system/slips-suricata-sync.service"
    
    if [[ -f "$sync_service_source" ]]; then
        cp "$sync_service_source" "$sync_service_dest"
        systemctl daemon-reload
        systemctl enable slips-suricata-sync.service
        success "SLIPS ↔ Suricata dataset sync service installed"
    else
        warn "slips-suricata-sync.service not found at: $sync_service_source"
    fi
    
    # Prepopulate Redis with ML detector initial data
    prepopulate_ml_detector_redis
}

prepopulate_ml_detector_redis() {
    log "Prepopulating Redis with ML detector data..."
    
    local prepop_script="$SLIPS_DIR/webinterface/ml_detector/prepopulate_redis.py"
    
    if [[ -f "$prepop_script" ]]; then
        python3 "$prepop_script" 2>&1 | grep -v "^$" || warn "Failed to prepopulate Redis data"
        success "ML detector Redis data initialized"
    else
        warn "Prepopulation script not found at: $prepop_script"
        log "Dashboard may show 'Not Running' until services generate data"
    fi
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_ml_detector() {
    log "Verifying ML Detector installation..."

    local errors=0

    # Check if service file exists
    if [[ ! -f "/etc/systemd/system/stream-monitor.service" ]]; then
        warn "stream-monitor service file not found"
        ((errors++))
    fi

    # Check if service is running
    if ! systemctl is-active --quiet stream-monitor.service; then
        warn "stream-monitor service is not running"
        ((errors++))
    fi

    # Check Redis keys
    if command -v redis-cli >/dev/null 2>&1; then
        local stats_exist=$(redis-cli exists ml_detector:stats)
        if [[ "$stats_exist" != "1" ]]; then
            warn "ML detector stats not found in Redis (may take a minute to populate)"
        fi
    fi

    if [[ $errors -eq 0 ]]; then
        success "ML Detector verification passed"
        return 0
    else
        warn "ML Detector verification found $errors issues"
        return 1
    fi
}

# Export functions
export -f install_ml_detector_service
export -f copy_ml_feeder_script
export -f install_stream_monitor_service
export -f install_stream_ad_blocker_service
export -f prepopulate_ml_detector_redis
export -f verify_ml_detector
