## Karen's IPS Installer Migration Guide

This guide explains how to complete the migration from the monolithic `karens-ips-installer.sh` to the modular installer architecture.

## Current Status

✅ **Completed:**
- Modular directory structure created
- Logging library (`lib/logging.sh`)
- Utilities library (`lib/utils.sh`)
- Configuration file (`config/installer.conf`)
- Main orchestrator (`main.sh`)
- Example module (`modules/07-blocklists.sh`)
- Documentation (`README.md`)

⏳ **In Progress:**
- Extracting remaining installation phases into modules

## Migration Strategy

The original `karens-ips-installer.sh` is 4800+ lines. We're splitting it into:
- **Libraries** (`lib/`): Shared functions
- **Modules** (`modules/`): Installation phases
- **Templates** (`templates/`): Configuration files
- **Main script** (`main.sh`): Orchestrator

## Step-by-Step Migration

### Step 1: Identify Functions to Extract

From `karens-ips-installer.sh`, these functions need to be extracted:

| Function | Target Module | Status |
|----------|---------------|--------|
| `install_base_system()` | `modules/01-base-system.sh` | ⏳ TODO |
| `install_zeek()` | `modules/01-base-system.sh` | ⏳ TODO |
| `setup_kernel_and_tuning()` | `modules/02-kernel-tuning.sh` | ⏳ TODO |
| `setup_nftables_blocking()` | `modules/03-nftables.sh` | ⏳ TODO |
| `install_suricata()` | `modules/04-suricata.sh` | ⏳ TODO |
| `configure_suricata_afpacket()` | `modules/05-suricata-config.sh` | ⏳ TODO |
| `update_suricata_rules()` | `modules/06-suricata-rules.sh` | ⏳ TODO |
| `import_community_blocklists()` | `modules/07-blocklists.sh` | ✅ DONE |
| `setup_blocklist_management()` | `modules/08-blocklist-mgmt.sh` | ⏳ TODO |
| `install_nodejs()` | `modules/09-nodejs.sh` | ⏳ TODO |
| `install_slips()` | `modules/10-slips.sh` | ⏳ TODO |
| `install_ml_detector_dashboard()` | `modules/11-ml-detector.sh` | ⏳ TODO |
| `setup_interfaces()` | `modules/12-interfaces.sh` | ⏳ TODO |
| `configure_redis()` | `modules/13-redis.sh` | ⏳ TODO |
| `create_systemd_services()` | `modules/14-systemd.sh` | ⏳ TODO |
| `start_services()` | `modules/15-services.sh` | ⏳ TODO |
| `create_motd()` | `modules/16-motd.sh` | ⏳ TODO |
| `verify_installation()` | `modules/17-verification.sh` | ⏳ TODO |

### Step 2: Module Template

Use this template for each new module:

```bash
#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: <Module Name>
# Phase: <Number>
# Description: <What this module does>

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    exit 1
fi

# ============================================================================
# MAIN FUNCTION
# ============================================================================

<function_name>() {
    log_subsection "<Phase Description>"

    # Implementation from karens-ips-installer.sh
    # ...

    success "Module completed successfully"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Any helper functions specific to this module
# ...

# ============================================================================
# VERIFICATION
# ============================================================================

verify_<module>() {
    log "Verifying installation..."

    # Verification checks
    # ...

    success "Verification passed"
    return 0
}

# Export functions
export -f <function_name>
export -f verify_<module>
```

### Step 3: Extraction Process

For each function in `karens-ips-installer.sh`:

1. **Find the function:**
   ```bash
   grep -n "^install_base_system()" karens-ips-installer.sh
   ```

2. **Copy the function to new module:**
   - Create the module file
   - Add module header (see template)
   - Paste function body
   - Remove any global variable assignments

3. **Replace hardcoded values with config variables:**
   ```bash
   # Before
   SLIPS_DIR="/opt/StratosphereLinuxIPS"

   # After (config variable from installer.conf)
   $SLIPS_DIR
   ```

4. **Update function calls:**
   ```bash
   # Before (in old installer)
   install_zeek

   # After (helper function in same module)
   install_zeek_helper
   ```

5. **Export functions:**
   ```bash
   export -f install_base_system
   export -f install_zeek_helper
   ```

### Step 4: Extract Large Embedded Scripts

Some functions contain large heredocs (e.g., Python scripts, systemd units). Extract these to templates:

**Example - Embedded Python Script:**

Before (in `karens-ips-installer.sh`):
```bash
cat > /opt/ips-filter-db.py << 'EOF'
#!/usr/bin/env python3
# ... 500 lines of Python ...
EOF
```

After:
1. Create `templates/scripts/ips-filter-db.py`
2. Move Python code there
3. In module, copy template:
   ```bash
   cp "$INSTALLER_DIR/templates/scripts/ips-filter-db.py" /opt/
   chmod +x /opt/ips-filter-db.py
   ```

**Example - Systemd Unit:**

Before:
```bash
cat > /etc/systemd/system/slips.service << 'EOF'
[Unit]
# ... systemd unit ...
EOF
```

After:
1. Create `templates/systemd/slips.service`
2. In module:
   ```bash
   cp "$INSTALLER_DIR/templates/systemd/slips.service" /etc/systemd/system/
   systemctl daemon-reload
   ```

### Step 5: Testing Each Module

Test each module independently:

```bash
# Load environment
source installer/lib/logging.sh
source installer/lib/utils.sh
source installer/config/installer.conf

# Load module
source installer/modules/01-base-system.sh

# Run function
install_base_system

# Verify
verify_base_system
```

### Step 6: Update Main Orchestrator

As you create modules, they're automatically loaded by `main.sh`:

```bash
# main.sh loads all modules in modules/*.sh
load_modules() {
    for module in "$INSTALLER_DIR/modules"/*.sh; do
        source "$module"
    done
}
```

No changes needed to `main.sh` unless adding new phases.

## Quick Reference: Creating a Module

```bash
# 1. Create module file
touch installer/modules/01-base-system.sh
chmod +x installer/modules/01-base-system.sh

# 2. Add header
cat > installer/modules/01-base-system.sh << 'EOF'
#!/bin/bash
# Module header...
EOF

# 3. Extract function from karens-ips-installer.sh
sed -n '/^install_base_system()/,/^}/p' karens-ips-installer.sh >> installer/modules/01-base-system.sh

# 4. Add source check and exports
# (edit file manually)

# 5. Test
source installer/lib/logging.sh
source installer/lib/utils.sh
source installer/config/installer.conf
source installer/modules/01-base-system.sh
install_base_system
```

## Priority Order

Suggested order for extracting modules (by importance/complexity):

1. ✅ `07-blocklists.sh` - Already done (example)
2. `01-base-system.sh` - Foundation (packages, Zeek)
3. `04-suricata.sh` - Core IPS
4. `05-suricata-config.sh` - Suricata setup
5. `10-slips.sh` - ML engine
6. `11-ml-detector.sh` - Dashboard
7. `12-interfaces.sh` - Networking
8. `14-systemd.sh` - Services
9. `15-services.sh` - Start everything
10. Remaining modules

## Common Patterns

### Pattern 1: Package Installation

```bash
install_packages() {
    local packages=(
        "package1"
        "package2"
    )

    log "Installing packages..."
    apt-get update
    apt-get install -y "${packages[@]}"

    success "Packages installed"
}
```

### Pattern 2: Configuration File Creation

```bash
create_config() {
    local config_file="/etc/app/config.conf"

    backup_file "$config_file"

    cp "$INSTALLER_DIR/templates/app/config.conf" "$config_file"

    # Or use cat/heredoc if not templated
    cat > "$config_file" << 'EOF'
# Configuration
key=value
EOF

    chown root:root "$config_file"
    chmod 644 "$config_file"

    success "Configuration created"
}
```

### Pattern 3: Service Management

```bash
setup_service() {
    local service="myservice"

    # Install systemd unit
    cp "$INSTALLER_DIR/templates/systemd/${service}.service" /etc/systemd/system/

    # Reload systemd
    systemctl daemon-reload

    # Enable service
    systemctl enable "$service"

    success "Service configured"
}
```

### Pattern 4: Git Repository Cloning

```bash
clone_repository() {
    local repo_url="$1"
    local target_dir="$2"

    if [[ -d "$target_dir" ]]; then
        log "Repository exists, updating..."
        git -C "$target_dir" pull
    else
        log "Cloning repository..."
        git clone "$repo_url" "$target_dir"
    fi

    success "Repository ready"
}
```

## Troubleshooting Migration

### Issue: Function not found

**Problem:** `bash: install_something: command not found`

**Solution:**
```bash
# Make sure function is exported in module
export -f install_something

# Verify module is loaded
source installer/modules/XX-module.sh

# Check if function exists
type install_something
```

### Issue: Variable not defined

**Problem:** `SLIPS_DIR: unbound variable`

**Solution:**
```bash
# Make sure config is loaded
source installer/config/installer.conf

# Or provide default
SLIPS_DIR="${SLIPS_DIR:-/opt/StratosphereLinuxIPS}"
```

### Issue: Module can't find libraries

**Problem:** `log: command not found`

**Solution:**
```bash
# In each module, at the top:
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/logging.sh"
source "$SCRIPT_DIR/../lib/utils.sh"

# Or rely on main.sh to source them first
```

## Benefits After Migration

Once complete, you'll have:

✅ **Maintainability**
- Each module is 100-300 lines (vs 4800)
- Easy to find and fix issues
- Clear separation of concerns

✅ **Testability**
- Test each phase independently
- Mock dependencies easily
- Faster development cycle

✅ **Flexibility**
- Skip phases with config flags
- Custom installation profiles
- Easy to add new features

✅ **Reusability**
- Modules usable in other contexts
- Shared libraries across projects
- Template-based configuration

✅ **Collaboration**
- Multiple developers can work on different modules
- Easier code reviews
- Better version control

## Next Steps

1. Choose highest priority module (e.g., `01-base-system.sh`)
2. Extract using template and process above
3. Test independently
4. Commit and move to next module
5. Update `MIGRATION_GUIDE.md` with progress

## Need Help?

- Check `installer/modules/07-blocklists.sh` for working example
- Review `installer/README.md` for architecture overview
- Test in VM before committing changes
- Keep `karens-ips-installer.sh` as backup during migration

## Completion Checklist

- [ ] All 17 modules created
- [ ] All templates extracted
- [ ] Main orchestrator tested
- [ ] Wrapper script updated
- [ ] Documentation complete
- [ ] Legacy installer marked deprecated
- [ ] Migration tested in clean VM
- [ ] Changes committed to git

---

Good luck with the migration! The modular architecture will make Karen's IPS much easier to maintain and extend. 🚀
