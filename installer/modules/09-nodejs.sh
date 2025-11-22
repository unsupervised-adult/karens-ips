#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: Node.js Installation
# Phase: 9
# Description: Install Node.js for Kalipso web interface

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ============================================================================
# NODE.JS INSTALLATION
# ============================================================================

install_nodejs() {
    log_subsection "Node.js Installation for Kalipso"

    # Check if Node.js installation is enabled
    if [[ "${INSTALL_NODEJS:-true}" != "true" ]]; then
        log "Node.js installation disabled, skipping"
        return 0
    fi

    log "Installing Node.js for Kalipso web interface..."

    # Check if Node.js is already installed
    if command -v node >/dev/null 2>&1; then
        local node_version=$(node --version)
        log "Node.js already installed: $node_version"
        return 0
    fi

    # Install Node.js 22.x
    log "Adding Node.js 22.x repository..."
    if curl -fsSL https://deb.nodesource.com/setup_22.x | bash -; then
        success "Node.js repository added"
    else
        error_exit "Failed to add Node.js repository"
    fi

    log "Installing Node.js..."
    if apt-get install -y nodejs; then
        local node_version=$(node --version)
        success "Node.js installed: $node_version"
    else
        error_exit "Failed to install Node.js"
    fi
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_nodejs() {
    log "Verifying Node.js installation..."

    if command -v node >/dev/null 2>&1; then
        local node_version=$(node --version)
        log "Node.js version: $node_version"
        success "Node.js verification passed"
        return 0
    else
        warn "Node.js not found"
        return 1
    fi
}

# Export functions
export -f install_nodejs
export -f verify_nodejs
