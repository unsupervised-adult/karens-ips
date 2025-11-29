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
# BLOCKLIST SELECTION
# ============================================================================

configure_blocklists() {
    if [[ "${NON_INTERACTIVE:-0}" == "1" ]]; then
        # Non-interactive: enable Perflyst lists and hagezi Pro (recommended)
        BLOCKLIST_PERFLYST_SMARTTV="${BLOCKLIST_PERFLYST_SMARTTV:-true}"
        BLOCKLIST_PERFLYST_ANDROID="${BLOCKLIST_PERFLYST_ANDROID:-true}"
        BLOCKLIST_PERFLYST_FIRETV="${BLOCKLIST_PERFLYST_FIRETV:-true}"
        BLOCKLIST_PERFLYST_SESSIONREPLAY="${BLOCKLIST_PERFLYST_SESSIONREPLAY:-true}"
        # Enable Pro by default (recommended balance)
        BLOCKLIST_HAGEZI_LIGHT="${BLOCKLIST_HAGEZI_LIGHT:-false}"
        BLOCKLIST_HAGEZI_NORMAL="${BLOCKLIST_HAGEZI_NORMAL:-false}"
        BLOCKLIST_HAGEZI_PRO="${BLOCKLIST_HAGEZI_PRO:-true}"
        BLOCKLIST_HAGEZI_PROPLUS="${BLOCKLIST_HAGEZI_PROPLUS:-false}"
        BLOCKLIST_HAGEZI_ULTIMATE="${BLOCKLIST_HAGEZI_ULTIMATE:-false}"
        BLOCKLIST_HAGEZI_NATIVE="${BLOCKLIST_HAGEZI_NATIVE:-true}"
        return
    fi

    log_subsection "Blocklist Selection"
    info "Select which blocklists to enable:"
    echo ""

    # Perflyst SmartTV
    if [[ -z "${BLOCKLIST_PERFLYST_SMARTTV}" ]]; then
        if ask_yes_no "Enable SmartTV tracking blocklist? (Samsung, LG, etc)" "y"; then
            BLOCKLIST_PERFLYST_SMARTTV="true"
        else
            BLOCKLIST_PERFLYST_SMARTTV="false"
        fi
    fi

    # Perflyst Android
    if [[ -z "${BLOCKLIST_PERFLYST_ANDROID}" ]]; then
        if ask_yes_no "Enable Android tracking blocklist?" "y"; then
            BLOCKLIST_PERFLYST_ANDROID="true"
        else
            BLOCKLIST_PERFLYST_ANDROID="false"
        fi
    fi

    # Perflyst FireTV
    if [[ -z "${BLOCKLIST_PERFLYST_FIRETV}" ]]; then
        if ask_yes_no "Enable Amazon FireTV tracking blocklist?" "y"; then
            BLOCKLIST_PERFLYST_FIRETV="true"
        else
            BLOCKLIST_PERFLYST_FIRETV="false"
        fi
    fi

    # Perflyst SessionReplay
    if [[ -z "${BLOCKLIST_PERFLYST_SESSIONREPLAY}" ]]; then
        if ask_yes_no "Enable SessionReplay tracking blocklist?" "y"; then
            BLOCKLIST_PERFLYST_SESSIONREPLAY="true"
        else
            BLOCKLIST_PERFLYST_SESSIONREPLAY="false"
        fi
    fi

    # hagezi blocklists - recommend choosing ONE version
    echo ""
    info "hagezi IP Blocklists (choose ONE version based on blocking level):"
    echo "  📗 Light      - Low blocking, minimal false positives"
    echo "  📘 Normal     - Medium blocking, relaxed/balanced"
    echo "  📒 Pro        - Balanced blocking (RECOMMENDED)"
    echo "  📙 Pro++      - Balanced/aggressive blocking"
    echo "  📕 Ultimate   - Most aggressive (may break sites)"
    echo ""

    # hagezi Light
    if [[ -z "${BLOCKLIST_HAGEZI_LIGHT}" ]]; then
        if ask_yes_no "Enable hagezi Light? (📗 low blocking)" "n"; then
            BLOCKLIST_HAGEZI_LIGHT="true"
            # Disable others if Light is selected
            BLOCKLIST_HAGEZI_NORMAL="false"
            BLOCKLIST_HAGEZI_PRO="false"
            BLOCKLIST_HAGEZI_PROPLUS="false"
            BLOCKLIST_HAGEZI_ULTIMATE="false"
        else
            BLOCKLIST_HAGEZI_LIGHT="false"
        fi
    fi

    # hagezi Normal
    if [[ -z "${BLOCKLIST_HAGEZI_NORMAL}" ]]; then
        if ask_yes_no "Enable hagezi Normal? (📘 medium blocking)" "n"; then
            BLOCKLIST_HAGEZI_NORMAL="true"
            # Disable others if Normal is selected
            BLOCKLIST_HAGEZI_LIGHT="false"
            BLOCKLIST_HAGEZI_PRO="false"
            BLOCKLIST_HAGEZI_PROPLUS="false"
            BLOCKLIST_HAGEZI_ULTIMATE="false"
        else
            BLOCKLIST_HAGEZI_NORMAL="false"
        fi
    fi

    # hagezi Pro
    if [[ -z "${BLOCKLIST_HAGEZI_PRO}" ]]; then
        if ask_yes_no "Enable hagezi Pro? (📒 balanced - RECOMMENDED)" "y"; then
            BLOCKLIST_HAGEZI_PRO="true"
            # Disable others if Pro is selected
            BLOCKLIST_HAGEZI_LIGHT="false"
            BLOCKLIST_HAGEZI_NORMAL="false"
            BLOCKLIST_HAGEZI_PROPLUS="false"
            BLOCKLIST_HAGEZI_ULTIMATE="false"
        else
            BLOCKLIST_HAGEZI_PRO="false"
        fi
    fi

    # hagezi Pro++
    if [[ -z "${BLOCKLIST_HAGEZI_PROPLUS}" ]]; then
        if ask_yes_no "Enable hagezi Pro++? (📙 aggressive)" "n"; then
            BLOCKLIST_HAGEZI_PROPLUS="true"
            # Disable others if Pro++ is selected
            BLOCKLIST_HAGEZI_LIGHT="false"
            BLOCKLIST_HAGEZI_NORMAL="false"
            BLOCKLIST_HAGEZI_PRO="false"
            BLOCKLIST_HAGEZI_ULTIMATE="false"
        else
            BLOCKLIST_HAGEZI_PROPLUS="false"
        fi
    fi

    # hagezi Ultimate
    if [[ -z "${BLOCKLIST_HAGEZI_ULTIMATE}" ]]; then
        if ask_yes_no "Enable hagezi Ultimate? (📕 most aggressive, may break sites)" "n"; then
            BLOCKLIST_HAGEZI_ULTIMATE="true"
            # Disable others if Ultimate is selected
            BLOCKLIST_HAGEZI_LIGHT="false"
            BLOCKLIST_HAGEZI_NORMAL="false"
            BLOCKLIST_HAGEZI_PRO="false"
            BLOCKLIST_HAGEZI_PROPLUS="false"
        else
            BLOCKLIST_HAGEZI_ULTIMATE="false"
        fi
    fi

    # hagezi Native (can be combined with any of the above)
    echo ""
    if [[ -z "${BLOCKLIST_HAGEZI_NATIVE}" ]]; then
        if ask_yes_no "Enable hagezi Native Tracker? (can combine with above)" "y"; then
            BLOCKLIST_HAGEZI_NATIVE="true"
        else
            BLOCKLIST_HAGEZI_NATIVE="false"
        fi
    fi

    echo ""
    success "Blocklist selection complete"
}

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

    # Configure which blocklists to use
    configure_blocklists

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

    # Clone Perflyst/PiHoleBlocklist (if any Perflyst lists enabled)
    if [[ "${BLOCKLIST_PERFLYST_SMARTTV}" == "true" ]] || \
       [[ "${BLOCKLIST_PERFLYST_ANDROID}" == "true" ]] || \
       [[ "${BLOCKLIST_PERFLYST_FIRETV}" == "true" ]] || \
       [[ "${BLOCKLIST_PERFLYST_SESSIONREPLAY}" == "true" ]]; then
        clone_perflyst_repo
    else
        log "No Perflyst blocklists selected, skipping repository clone"
    fi

    # Clone hagezi/dns-blocklists (if any hagezi lists enabled)
    if [[ "${BLOCKLIST_HAGEZI_LIGHT}" == "true" ]] || \
       [[ "${BLOCKLIST_HAGEZI_NORMAL}" == "true" ]] || \
       [[ "${BLOCKLIST_HAGEZI_PRO}" == "true" ]] || \
       [[ "${BLOCKLIST_HAGEZI_PROPLUS}" == "true" ]] || \
       [[ "${BLOCKLIST_HAGEZI_ULTIMATE}" == "true" ]] || \
       [[ "${BLOCKLIST_HAGEZI_NATIVE}" == "true" ]]; then
        clone_hagezi_repo
    else
        log "No hagezi blocklists selected, skipping repository clone"
    fi

    log ""
    log "Importing selected blocklists into IPS database..."
    log "This will take several minutes for large lists..."
    log ""

    # Import Perflyst blocklists (only selected ones)
    import_perflyst_lists

    # Import hagezi blocklists (only selected ones)
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
    local db_path="/var/lib/suricata/ips_filter.db"

    # SmartTV
    if [[ "${BLOCKLIST_PERFLYST_SMARTTV}" == "true" ]] && [[ -f "$BLOCKLISTS_DIR/PiHoleBlocklist/SmartTV.txt" ]]; then
        log "Importing Perflyst SmartTV blocklist..."
        $ips_filter_db --db-path "$db_path" --import-file "$BLOCKLISTS_DIR/PiHoleBlocklist/SmartTV.txt" \
            --source-name "perflyst_smarttv" \
            --source-description "Smart TV tracking and ads" \
            --category "ads" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:)" || true
    elif [[ "${BLOCKLIST_PERFLYST_SMARTTV}" == "false" ]]; then
        log "SmartTV blocklist disabled, skipping..."
    fi

    # Android Tracking
    if [[ "${BLOCKLIST_PERFLYST_ANDROID}" == "true" ]] && [[ -f "$BLOCKLISTS_DIR/PiHoleBlocklist/android-tracking.txt" ]]; then
        log "Importing Perflyst Android tracking blocklist..."
        $ips_filter_db --db-path "$db_path" --import-file "$BLOCKLISTS_DIR/PiHoleBlocklist/android-tracking.txt" \
            --source-name "perflyst_android" \
            --source-description "Android app tracking" \
            --category "tracking" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:)" || true
    elif [[ "${BLOCKLIST_PERFLYST_ANDROID}" == "false" ]]; then
        log "Android blocklist disabled, skipping..."
    fi

    # Amazon FireTV
    if [[ "${BLOCKLIST_PERFLYST_FIRETV}" == "true" ]] && [[ -f "$BLOCKLISTS_DIR/PiHoleBlocklist/AmazonFireTV.txt" ]]; then
        log "Importing Perflyst Amazon FireTV blocklist..."
        $ips_filter_db --db-path "$db_path" --import-file "$BLOCKLISTS_DIR/PiHoleBlocklist/AmazonFireTV.txt" \
            --source-name "perflyst_firetv" \
            --source-description "Amazon Fire TV tracking" \
            --category "ads" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:)" || true
    elif [[ "${BLOCKLIST_PERFLYST_FIRETV}" == "false" ]]; then
        log "FireTV blocklist disabled, skipping..."
    fi

    # SessionReplay
    if [[ "${BLOCKLIST_PERFLYST_SESSIONREPLAY}" == "true" ]] && [[ -f "$BLOCKLISTS_DIR/PiHoleBlocklist/SessionReplay.txt" ]]; then
        log "Importing Perflyst SessionReplay blocklist..."
        $ips_filter_db --db-path "$db_path" --import-file "$BLOCKLISTS_DIR/PiHoleBlocklist/SessionReplay.txt" \
            --source-name "perflyst_sessionreplay" \
            --source-description "Session replay tracking" \
            --category "tracking" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:)" || true
    elif [[ "${BLOCKLIST_PERFLYST_SESSIONREPLAY}" == "false" ]]; then
        log "SessionReplay blocklist disabled, skipping..."
    fi
}

import_hagezi_lists() {
    local ips_filter_db="/opt/ips-filter-db.py"
    local db_path="/var/lib/suricata/ips_filter.db"

    # Light (low blocking)
    if [[ "${BLOCKLIST_HAGEZI_LIGHT}" == "true" ]] && [[ -f "$BLOCKLISTS_DIR/dns-blocklists/domains/light.txt" ]]; then
        log "Importing hagezi Light blocklist (📗 low blocking, minimal false positives)..."
        $ips_filter_db --db-path "$db_path" --import-file "$BLOCKLISTS_DIR/dns-blocklists/domains/light.txt" \
            --source-name "hagezi_light" \
            --source-description "Hagezi Light - Low blocking" \
            --category "ads" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:|Processing line)" || true
    elif [[ "${BLOCKLIST_HAGEZI_LIGHT}" == "false" ]]; then
        log "hagezi Light blocklist disabled, skipping..."
    fi

    # Normal (medium blocking) - uses multi.txt
    if [[ "${BLOCKLIST_HAGEZI_NORMAL}" == "true" ]] && [[ -f "$BLOCKLISTS_DIR/dns-blocklists/domains/multi.txt" ]]; then
        log "Importing hagezi Normal blocklist (📘 medium blocking, relaxed/balanced)..."
        $ips_filter_db --db-path "$db_path" --import-file "$BLOCKLISTS_DIR/dns-blocklists/domains/multi.txt" \
            --source-name "hagezi_normal" \
            --source-description "Hagezi Normal - Medium blocking" \
            --category "ads" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:|Processing line)" || true
    elif [[ "${BLOCKLIST_HAGEZI_NORMAL}" == "false" ]]; then
        log "hagezi Normal blocklist disabled, skipping..."
    fi

    # Pro (balanced - recommended)
    if [[ "${BLOCKLIST_HAGEZI_PRO}" == "true" ]] && [[ -f "$BLOCKLISTS_DIR/dns-blocklists/domains/pro.txt" ]]; then
        log "Importing hagezi Pro blocklist (📒 balanced - recommended)..."
        $ips_filter_db --db-path "$db_path" --import-file "$BLOCKLISTS_DIR/dns-blocklists/domains/pro.txt" \
            --source-name "hagezi_pro" \
            --source-description "Hagezi Pro - Balanced blocking (recommended)" \
            --category "ads" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:|Processing line)" || true
    elif [[ "${BLOCKLIST_HAGEZI_PRO}" == "false" ]]; then
        log "hagezi Pro blocklist disabled, skipping..."
    fi

    # Pro++ (aggressive)
    if [[ "${BLOCKLIST_HAGEZI_PROPLUS}" == "true" ]] && [[ -f "$BLOCKLISTS_DIR/dns-blocklists/domains/pro.plus.txt" ]]; then
        log "Importing hagezi Pro++ blocklist (📙 balanced/aggressive)..."
        $ips_filter_db --db-path "$db_path" --import-file "$BLOCKLISTS_DIR/dns-blocklists/domains/pro.plus.txt" \
            --source-name "hagezi_proplus" \
            --source-description "Hagezi Pro++ - Aggressive blocking" \
            --category "ads" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:|Processing line)" || true
    elif [[ "${BLOCKLIST_HAGEZI_PROPLUS}" == "false" ]]; then
        log "hagezi Pro++ blocklist disabled, skipping..."
    fi

    # Ultimate (most aggressive)
    if [[ "${BLOCKLIST_HAGEZI_ULTIMATE}" == "true" ]] && [[ -f "$BLOCKLISTS_DIR/dns-blocklists/domains/ultimate.txt" ]]; then
        log "Importing hagezi Ultimate blocklist (📕 most aggressive, may break sites)..."
        $ips_filter_db --db-path "$db_path" --import-file "$BLOCKLISTS_DIR/dns-blocklists/domains/ultimate.txt" \
            --source-name "hagezi_ultimate" \
            --source-description "Hagezi Ultimate - Most aggressive" \
            --category "ads" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:|Processing line)" || true
    elif [[ "${BLOCKLIST_HAGEZI_ULTIMATE}" == "false" ]]; then
        log "hagezi Ultimate blocklist disabled, skipping..."
    fi

    # Native Tracker (can be combined with any version)
    # Import all platform-specific native tracker lists
    if [[ "${BLOCKLIST_HAGEZI_NATIVE}" == "true" ]]; then
        log "Importing hagezi Native Tracker blocklists (all platforms)..."

        # Import all native.*.txt files
        for native_file in "$BLOCKLISTS_DIR/dns-blocklists/domains"/native.*.txt; do
            if [[ -f "$native_file" ]]; then
                local platform=$(basename "$native_file" .txt | sed 's/native\.//')
                log "  - Importing native.$platform tracker..."
                $ips_filter_db --db-path "$db_path" --import-file "$native_file" \
                    --source-name "hagezi_native_$platform" \
                    --source-description "Hagezi Native Tracker - $platform" \
                    --category "tracking" 2>&1 | grep -E "(Importing|Import Complete|Imported:|Skipped:)" || true
            fi
        done
    elif [[ "${BLOCKLIST_HAGEZI_NATIVE}" == "false" ]]; then
        log "hagezi Native Tracker blocklist disabled, skipping..."
    fi
}

sync_to_suricata() {
    local ips_filter_db="/opt/ips-filter-db.py"
    local db_path="/var/lib/suricata/ips_filter.db"
    if [[ -x "$ips_filter_db" ]]; then
        $ips_filter_db --db-path "$db_path" --sync 2>&1 | grep -E "(Syncing|Successfully|Progress:|Warning:)" || true
    else
        warn "Blocklist manager not found, skipping Suricata sync"
    fi
}

show_blocklist_stats() {
    local ips_filter_db="/opt/ips-filter-db.py"
    local db_path="/var/lib/suricata/ips_filter.db"
    if [[ -x "$ips_filter_db" ]]; then
        $ips_filter_db --db-path "$db_path" --stats
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
export -f configure_blocklists
export -f import_perflyst_lists
export -f import_hagezi_lists
export -f sync_to_suricata
export -f show_blocklist_stats
export -f verify_blocklists
