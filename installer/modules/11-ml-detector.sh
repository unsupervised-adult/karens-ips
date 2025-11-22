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
    apply_slips_patches "$karens_ips_dir"

    # Set proper permissions
    set_ml_detector_permissions

    # Install additional dependencies
    install_ml_detector_dependencies "$karens_ips_dir"

    success "ML Detector Dashboard installed successfully!"
    log ""
    log "The ML Detector Dashboard will be available at:"
    log "  http://[SLIPS-IP]:55000 -> Click 'ML Detector' tab"
    log ""
    log "Redis keys used by ML Detector:"
    log "  - ml_detector:stats"
    log "  - ml_detector:recent_detections"
    log "  - ml_detector:timeline"
    log "  - ml_detector:model_info"
    log "  - ml_detector:feature_importance"
    log "  - ml_detector:alerts"
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
}

apply_slips_patches() {
    local karens_ips_dir="$1"

    log "Applying patches to SLIPS web interface..."

    cd "$SLIPS_DIR" || error_exit "Failed to change to SLIPS directory"

    # Patch app.py
    patch_app_py "$karens_ips_dir"

    # Patch app.html
    patch_app_html "$karens_ips_dir"

    success "Patches applied"
}

patch_app_py() {
    local karens_ips_dir="$1"

    if grep -q "from .ml_detector.ml_detector import ml_detector" webinterface/app.py; then
        log "app.py already patched"
        return 0
    fi

    log "Patching webinterface/app.py..."

    # Try patch file first
    if [ -f "$karens_ips_dir/slips_integration/patches/app.py.patch" ]; then
        if patch -p1 --dry-run < "$karens_ips_dir/slips_integration/patches/app.py.patch" > /dev/null 2>&1; then
            patch -p1 < "$karens_ips_dir/slips_integration/patches/app.py.patch"
            success "app.py patched successfully"
            return 0
        fi
    fi

    # Manual patch fallback
    warn "Patch file failed, attempting manual integration..."
    sed -i '/from \.documentation\.documentation import documentation/a from .ml_detector.ml_detector import ml_detector' webinterface/app.py
    sed -i '/app.register_blueprint(documentation, url_prefix="\/documentation")/a \    app.register_blueprint(ml_detector, url_prefix="/ml_detector")' webinterface/app.py
    log "app.py manually patched"
}

patch_app_html() {
    local karens_ips_dir="$1"

    if grep -q "ml_detector.html" webinterface/templates/app.html; then
        log "app.html already patched"
        return 0
    fi

    log "Patching webinterface/templates/app.html..."

    # Try patch file first
    if [ -f "$karens_ips_dir/slips_integration/patches/app.html.patch" ]; then
        if patch -p1 --dry-run < "$karens_ips_dir/slips_integration/patches/app.html.patch" > /dev/null 2>&1; then
            patch -p1 < "$karens_ips_dir/slips_integration/patches/app.html.patch"
            success "app.html patched successfully"
            return 0
        fi
    fi

    # Manual patch failed
    warn "app.html patch failed - manual integration required"
    warn "Please follow instructions in $karens_ips_dir/slips_integration/README.md"
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

    # Check if app.py is patched
    if ! grep -q "from .ml_detector.ml_detector import ml_detector" "$SLIPS_DIR/webinterface/app.py" 2>/dev/null; then
        warn "app.py not patched for ML Detector"
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

# Export functions
export -f install_ml_detector_dashboard
export -f check_slips_installed
export -f check_ml_detector_files
export -f backup_slips_webinterface
export -f install_ml_detector_blueprint
export -f apply_slips_patches
export -f patch_app_py
export -f patch_app_html
export -f set_ml_detector_permissions
export -f install_ml_detector_dependencies
export -f verify_ml_detector
