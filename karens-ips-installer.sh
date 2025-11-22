#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Karen's IPS Installer
# Main entry point for modular installer system

set -Eeuo pipefail

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Modular installer path
MODULAR_INSTALLER="$SCRIPT_DIR/installer/main.sh"

# Verify modular installer exists
if [[ ! -f "$MODULAR_INSTALLER" ]]; then
    echo "Error: Modular installer not found at: $MODULAR_INSTALLER"
    echo "Please ensure the installer/ directory is present."
    exit 1
fi

# Execute modular installer
exec bash "$MODULAR_INSTALLER" "$@"
