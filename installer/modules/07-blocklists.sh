#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: Community Blocklists
# Phase: 6.5
# Description: Clone and import community blocklists (Perflyst + hagezi)

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ============================================================================
# COMMUNITY BLOCKLISTS INSTALLATION
# ============================================================================

import_community_blocklists() {
    log_subsection "Community Blocklists Import"

    # Check if blocklists are enabled
    if [[ "${INSTALL_BLOCKLISTS:-true}" != "true" ]]; then
        log "Blocklists installation disabled, skipping"
        return 0
    fi

    # Install blocklist manager script
    log "Installing blocklist management tools..."
    if [[ -f "$PROJECT_ROOT/src/blocklist_manager.py" ]]; then
        cp "$PROJECT_ROOT/src/blocklist_manager.py" /opt/ips-filter-db.py
        chmod 755 /opt/ips-filter-db.py
        success "Blocklist manager installed"
    else
        warn "Blocklist manager script not found in src/, stats will be unavailable"
    fi

    # Create blocklists directory
    create_dir "$BLOCKLISTS_DIR" "root:root" "755"
    cd "$BLOCKLISTS_DIR"

    log "Cloning blocklist repositories..."
    log "This may take several minutes due to repository size..."
    log ""

    # Clone Perflyst/PiHoleBlocklist
    clone_perflyst_repo

    # Clone hagezi/dns-blocklists
    clone_hagezi_repo

    log ""
    log "Importing blocklists into IPS database..."
    log "This will take several minutes for large lists..."
    log ""

    # Import Perflyst blocklists
    import_perflyst_lists

    # Import hagezi blocklists
    import_hagezi_lists

    log ""
    log "Syncing all imported domains to Suricata..."
    sync_to_suricata

    log ""
    log "Showing final statistics..."
    show_blocklist_stats

    log ""
    success "Blocklist import complete!"
    log "Database: /var/lib/suricata/ips_filter.db"
    log "Blocklists: $BLOCKLISTS_DIR"
    log ""
    log "To update blocklists in the future, run:"
    log "  ips-filter update-blocklists"
    log ""
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

clone_perflyst_repo() {
    if [[ ! -d "PiHoleBlocklist" ]]; then
        log "Cloning Perflyst/PiHoleBlocklist..."
        if git clone --depth 1 https://github.com/Perflyst/PiHoleBlocklist.git 2>&1 | grep -v "^remote:"; then
            success "Perflyst repository cloned"
        else
            warn "Failed to clone Perflyst repository"
            return 1
        fi
    else
        log "Perflyst/PiHoleBlocklist already exists, updating..."
        cd PiHoleBlocklist
        git pull --quiet 2>&1 | grep -v "^remote:" || true
        cd ..
        success "Perflyst repository updated"
    fi
}

clone_hagezi_repo() {
    if [[ ! -d "dns-blocklists" ]]; then
        log "Cloning hagezi/dns-blocklists (this is a large repository)..."
        if git clone --depth 1 https://github.com/hagezi/dns-blocklists.git 2>&1 | grep -v "^remote:"; then
            success "hagezi repository cloned"
        else
            warn "Failed to clone hagezi repository"
            return 1
        fi
    else
        log "hagezi/dns-blocklists already exists, updating..."
        cd dns-blocklists
        git pull --quiet 2>&1 | grep -v "^remote:" || true
        cd ..
        success "hagezi repository updated"
    fi
}

import_perflyst_lists() {
    local ips_filter_db="/opt/ips-filter-db.py"

    # SmartTV
    if [[ -f "$BLOCKLISTS_DIR/PiHoleBlocklist/SmartTV.txt" ]]; then
        log "Importing Perflyst SmartTV blocklist..."
        $ips_filter_db import-list \
            --list-file "$BLOCKLISTS_DIR/PiHoleBlocklist/SmartTV.txt" \
            --category "ads" \
            --source-name "perflyst_smarttv" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:)" || true
    fi

    # Android Tracking
    if [[ -f "$BLOCKLISTS_DIR/PiHoleBlocklist/android-tracking.txt" ]]; then
        log "Importing Perflyst Android tracking blocklist..."
        $ips_filter_db import-list \
            --list-file "$BLOCKLISTS_DIR/PiHoleBlocklist/android-tracking.txt" \
            --category "tracking" \
            --source-name "perflyst_android" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:)" || true
    fi

    # Amazon FireTV
    if [[ -f "$BLOCKLISTS_DIR/PiHoleBlocklist/AmazonFireTV.txt" ]]; then
        log "Importing Perflyst Amazon FireTV blocklist..."
        $ips_filter_db import-list \
            --list-file "$BLOCKLISTS_DIR/PiHoleBlocklist/AmazonFireTV.txt" \
            --category "ads" \
            --source-name "perflyst_firetv" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:)" || true
    fi

    # SessionReplay
    if [[ -f "$BLOCKLISTS_DIR/PiHoleBlocklist/SessionReplay.txt" ]]; then
        log "Importing Perflyst SessionReplay blocklist..."
        $ips_filter_db import-list \
            --list-file "$BLOCKLISTS_DIR/PiHoleBlocklist/SessionReplay.txt" \
            --category "tracking" \
            --source-name "perflyst_sessionreplay" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:)" || true
    fi
}

import_hagezi_lists() {
    local ips_filter_db="/opt/ips-filter-db.py"

    # Pro (recommended)
    if [[ -f "$BLOCKLISTS_DIR/dns-blocklists/domains/pro.txt" ]]; then
        log "Importing hagezi Pro blocklist (balanced - recommended)..."
        $ips_filter_db import-list \
            --list-file "$BLOCKLISTS_DIR/dns-blocklists/domains/pro.txt" \
            --category "ads" \
            --source-name "hagezi_pro" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:|Processing line)" || true
    else
        warn "hagezi Pro blocklist not found, skipping..."
    fi

    # Native Tracker
    if [[ -f "$BLOCKLISTS_DIR/dns-blocklists/domains/native.txt" ]]; then
        log "Importing hagezi Native Tracker blocklist..."
        $ips_filter_db import-list \
            --list-file "$BLOCKLISTS_DIR/dns-blocklists/domains/native.txt" \
            --category "tracking" \
            --source-name "hagezi_native" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:|Processing line)" || true
    else
        warn "hagezi Native Tracker blocklist not found, skipping..."
    fi
}

sync_to_suricata() {
    local ips_filter_db="/opt/ips-filter-db.py"
    if [[ -x "$ips_filter_db" ]]; then
        $ips_filter_db sync 2>&1 | grep -E "(Syncing|Successfully|Progress:|Warning:)" || true
    else
        warn "Blocklist manager not found, skipping Suricata sync"
    fi
}

show_blocklist_stats() {
    local ips_filter_db="/opt/ips-filter-db.py"
    if [[ -x "$ips_filter_db" ]]; then
        $ips_filter_db stats
    else
        warn "Blocklist manager not found, skipping stats display"
    fi
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_blocklists() {
    log "Verifying blocklist installation..."

    # Check database exists
    if [[ ! -f "/var/lib/suricata/ips_filter.db" ]]; then
        warn "Blocklist database not found"
        return 1
    fi

    # Check repositories exist
    if [[ ! -d "$BLOCKLISTS_DIR/PiHoleBlocklist" ]]; then
        warn "Perflyst repository not found"
        return 1
    fi

    if [[ ! -d "$BLOCKLISTS_DIR/dns-blocklists" ]]; then
        warn "hagezi repository not found"
        return 1
    fi

    success "Blocklists verified"
    return 0
}

# Export functions
export -f import_community_blocklists
export -f clone_perflyst_repo
export -f clone_hagezi_repo
export -f import_perflyst_lists
export -f import_hagezi_lists
export -f sync_to_suricata
export -f show_blocklist_stats
export -f verify_blocklists
