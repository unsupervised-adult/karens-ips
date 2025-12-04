#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: ML Detector Dashboard
# Phase: 11
# Description: Install Karen's IPS ML Detector Dashboard integration for SLIPS Web UI

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ============================================================================
# ML DETECTOR DASHBOARD INSTALLATION
# ============================================================================

install_ml_detector_dashboard() {
    log_subsection "ML Detector Dashboard Installation"

    # Check if ML Detector installation is enabled
    if [[ "${INSTALL_ML_DETECTOR:-true}" != "true" ]]; then
        log "ML Detector dashboard installation disabled, skipping"
        return 0
    fi

    log "Installing Karen's IPS ML Detector Dashboard..."

    # Get the directory where Karen's IPS is installed
    local karens_ips_dir
    karens_ips_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

    # Check prerequisites
    check_slips_installed

    # Check if ML Detector files exist
    if ! check_ml_detector_files "$karens_ips_dir"; then
        warn "ML Detector dashboard files not found, skipping installation"
        return 0
    fi

    # Backup existing web interface
    backup_slips_webinterface

    # Install ML Detector blueprint
    install_ml_detector_blueprint "$karens_ips_dir"

    # Apply patches to SLIPS web interface
    install_app_py "$karens_ips_dir"
    install_app_html "$karens_ips_dir"

    # Set proper permissions
    set_ml_detector_permissions

    # Install additional dependencies
    install_ml_detector_dependencies "$karens_ips_dir"

    # Install DNS blocklist labeler and training system
    install_dns_labeler "$karens_ips_dir"
    install_auto_labeler "$karens_ips_dir"
    install_training_scripts "$karens_ips_dir"

    success "ML Detector Dashboard installed successfully!"
    log ""
    log "The ML Detector Dashboard will be available at:"
    log "  http://[SLIPS-IP]:55000 -> Click 'ML Detector' tab"
    log ""
    log "Training System:"
    log "  - DNS Labeler: sudo systemctl start dns-labeler"
    log "  - Auto Labeler: sudo systemctl start auto-labeler"
    log "  - Blocklist DB: /var/lib/karens-ips/blocklists.db"
    log ""
    log "Redis keys used by ML Detector:"
    log "  - ml_detector:stats"
    log "  - ml_detector:recent_detections"
    log "  - ml_detector:timeline"
    log "  - ml_detector:model_info"
    log "  - ml_detector:feature_importance"
    log "  - ml_detector:alerts"
    log "  - ml_detector:training_data"
    log ""
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

check_slips_installed() {
    if [ ! -d "$SLIPS_DIR" ]; then
        error_exit "SLIPS not found at $SLIPS_DIR. Install SLIPS first."
    fi
    log "SLIPS installation found"
}

check_ml_detector_files() {
    local karens_ips_dir="$1"

    if [ ! -d "$karens_ips_dir/slips_integration" ]; then
        return 1
    fi

    log "Found ML Detector integration files at $karens_ips_dir/slips_integration"
    return 0
}

backup_slips_webinterface() {
    cd "$SLIPS_DIR" || error_exit "Failed to change to SLIPS directory"

    local backup_dir="webinterface.backup.$(date +%Y%m%d)"

    if [ ! -d "$backup_dir" ]; then
        log "Creating backup of SLIPS webinterface..."
        cp -r webinterface "$backup_dir" || warn "Failed to create backup"
        success "Backup created: $backup_dir"
    else
        log "Backup already exists: $backup_dir"
    fi
}

install_ml_detector_blueprint() {
    local karens_ips_dir="$1"
    local ml_detector_dest="$SLIPS_DIR/webinterface/ml_detector"

    log "Installing ML Detector blueprint..."

    if [ -d "$ml_detector_dest" ]; then
        log "ML Detector already exists, updating..."
        rm -rf "$ml_detector_dest"
    fi

    cp -r "$karens_ips_dir/slips_integration/webinterface/ml_detector" "$ml_detector_dest" || error_exit "Failed to copy ML Detector blueprint"

    success "ML Detector blueprint installed"
    
    # Install SLIPS module to feed dashboard data
    log "Installing ML Dashboard Feeder SLIPS module..."
    local ml_module_dest="$SLIPS_DIR/modules/ml_dashboard_feeder"
    
    if [ -d "$ml_module_dest" ]; then
        log "ML Dashboard Feeder already exists, updating..."
        rm -rf "$ml_module_dest"
    fi
    
    cp -r "$karens_ips_dir/slips_integration/modules/ml_dashboard_feeder" "$ml_module_dest" || error_exit "Failed to copy ML Dashboard Feeder module"
    
    success "ML Dashboard Feeder module installed"
}
install_app_py() {
    local karens_ips_dir="$1"
    local source_file="$karens_ips_dir/slips_integration/webinterface/app.py"
    local dest_file="$SLIPS_DIR/webinterface/app.py"

    log "Installing webinterface/app.py..."

    if [ ! -f "$source_file" ]; then
        error_exit "Source app.py not found at $source_file"
    fi

    cp "$source_file" "$dest_file" || error_exit "Failed to install app.py"

    success "app.py installed"
}

install_app_html() {
    local karens_ips_dir="$1"
    local source_file="$karens_ips_dir/slips_integration/webinterface/templates/app.html"
    local dest_file="$SLIPS_DIR/webinterface/templates/app.html"

    log "Installing webinterface/templates/app.html..."

    if [ ! -f "$source_file" ]; then
        error_exit "Source app.html not found at $source_file"
    fi

    cp "$source_file" "$dest_file" || error_exit "Failed to install app.html"

    success "app.html installed"
}

set_ml_detector_permissions() {
    local ml_detector_dest="$SLIPS_DIR/webinterface/ml_detector"

    log "Setting permissions for ML Detector..."

    chown -R root:root "$ml_detector_dest"
    chmod 755 "$ml_detector_dest"

    find "$ml_detector_dest" -type f -name "*.py" -exec chmod 644 {} \;
    find "$ml_detector_dest" -type f -name "*.js" -exec chmod 644 {} \;
    find "$ml_detector_dest" -type f -name "*.css" -exec chmod 644 {} \;
    find "$ml_detector_dest" -type f -name "*.html" -exec chmod 644 {} \;

    success "Permissions set"
}

install_ml_detector_dependencies() {
    local karens_ips_dir="$1"

    if [ ! -f "$karens_ips_dir/requirements.txt" ]; then
        log "No additional requirements.txt found, skipping dependencies"
        return 0
    fi

    log "Installing additional Python dependencies..."

    cd "$SLIPS_DIR" || error_exit "Failed to change to SLIPS directory"

    source venv/bin/activate

    pip install --upgrade pip || true
    pip install -q flask markupsafe || true

    deactivate

    success "Dependencies installed"
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_ml_detector() {
    log "Verifying ML Detector installation..."

    local errors=0
    local ml_detector_dest="$SLIPS_DIR/webinterface/ml_detector"

    # Check if ML Detector directory exists
    if [[ ! -d "$ml_detector_dest" ]]; then
        warn "ML Detector directory not found at $ml_detector_dest"
        ((errors++))
    fi

    # Check if app.py has ML Detector integration
    if ! grep -q "from .ml_detector.ml_detector import ml_detector" "$SLIPS_DIR/webinterface/app.py" 2>/dev/null; then
        warn "app.py does not have ML Detector integration"
        ((errors++))
    fi

    # Check if ML Detector module files exist
    if [[ ! -f "$ml_detector_dest/ml_detector.py" ]]; then
        warn "ML Detector blueprint file not found"
        ((errors++))
    fi

    if [[ $errors -eq 0 ]]; then
        success "ML Detector verification passed"
        return 0
    else
        warn "ML Detector verification found $errors issues"
        return 1
    fi
}

install_dns_labeler() {
    local karens_ips_dir="$1"

    log "Installing DNS blocklist labeler..."

    # Create integration directory in SLIPS
    mkdir -p "$SLIPS_DIR/slips_integration"

    # Copy DNS labeler script
    if [ -f "$karens_ips_dir/slips_integration/dns_blocklist_labeler.py" ]; then
        cp "$karens_ips_dir/slips_integration/dns_blocklist_labeler.py" "$SLIPS_DIR/slips_integration/"
        chmod +x "$SLIPS_DIR/slips_integration/dns_blocklist_labeler.py"
        success "DNS labeler installed"
    else
        warn "DNS labeler not found, skipping"
        return 0
    fi

    # Install systemd service
    if [ -f "$karens_ips_dir/slips_integration/dns-labeler.service" ]; then
        cp "$karens_ips_dir/slips_integration/dns-labeler.service" /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable dns-labeler.service
        success "DNS labeler service installed and enabled"
    fi
}

install_auto_labeler() {
    local karens_ips_dir="$1"

    log "Installing behavioral auto-labeler..."

    # Copy auto-labeler script
    if [ -f "$karens_ips_dir/slips_integration/auto_label_traffic.py" ]; then
        cp "$karens_ips_dir/slips_integration/auto_label_traffic.py" "$SLIPS_DIR/slips_integration/"
        chmod +x "$SLIPS_DIR/slips_integration/auto_label_traffic.py"
        success "Auto-labeler installed"
    else
        warn "Auto-labeler not found, skipping"
        return 0
    fi

    # Install systemd service
    if [ -f "$karens_ips_dir/slips_integration/auto-labeler.service" ]; then
        cp "$karens_ips_dir/slips_integration/auto-labeler.service" /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable auto-labeler.service
        success "Auto-labeler service installed and enabled"
    fi
}

install_training_scripts() {
    local karens_ips_dir="$1"

    log "Installing ML training scripts..."

    # Copy training scripts to webinterface/ml_detector
    local ml_detector_dest="$SLIPS_DIR/webinterface/ml_detector"

    if [ -f "$karens_ips_dir/slips_integration/webinterface/ml_detector/train_model.py" ]; then
        # Already copied with blueprint
        success "Training scripts already installed with ML Detector blueprint"
    else
        warn "Training scripts not found"
    fi

    # Create models directory
    mkdir -p "$ml_detector_dest/models"
    chmod 755 "$ml_detector_dest/models"

    # Create detector config
    if [ -f "$karens_ips_dir/slips_integration/detector_config.json" ]; then
        cp "$karens_ips_dir/slips_integration/detector_config.json" "$ml_detector_dest/"
        success "Detector config installed"
    fi
}

# Export functions
export -f install_ml_detector_dashboard
export -f check_slips_installed
export -f check_ml_detector_files
export -f backup_slips_webinterface
export -f install_ml_detector_blueprint
export -f install_app_py
export -f install_app_html
export -f set_ml_detector_permissions
export -f install_ml_detector_dependencies
export -f install_dns_labeler
export -f install_auto_labeler
export -f install_training_scripts
export -f verify_ml_detector
