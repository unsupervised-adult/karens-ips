#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Karen's IPS Installer Wrapper
# Maintains backwards compatibility while using modular installer

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Modular installer path
MODULAR_INSTALLER="$SCRIPT_DIR/installer/main.sh"

# Legacy installer fallback
LEGACY_INSTALLER="$SCRIPT_DIR/karens-ips-installer-legacy.sh"

# Check if modular installer exists
if [[ -f "$MODULAR_INSTALLER" ]]; then
    echo "========================================"
    echo "Karen's IPS Installation System"
    echo "Using: Modular Installer (v4.0)"
    echo "========================================"
    echo ""

    # Execute modular installer
    exec bash "$MODULAR_INSTALLER" "$@"
else
    echo "========================================"
    echo "Karen's IPS Installation System"
    echo "Using: Legacy Installer (Fallback)"
    echo "========================================"
    echo ""
    echo "Warning: Modular installer not found at: $MODULAR_INSTALLER"
    echo "Falling back to legacy monolithic installer..."
    echo ""

    # Fallback to legacy installer
    if [[ -f "$LEGACY_INSTALLER" ]]; then
        exec bash "$LEGACY_INSTALLER" "$@"
    else
        echo "Error: Neither modular nor legacy installer found!"
        echo "Please check installation integrity."
        exit 1
    fi
fi
