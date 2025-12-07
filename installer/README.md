# Karen's IPS Modular Installer

This directory contains the modular installer architecture for Karen's IPS.

## Directory Structure

```bash
installer/
├── main.sh                     # Main orchestrator script
├── config/
│   └── installer.conf          # Installation configuration
├── lib/
│   ├── logging.sh              # Logging functions
│   ├── utils.sh                # Utility functions
│   └── network.sh              # Network configuration helpers
├── modules/
│   ├── 01-base-system.sh       # Phase 1: Base system packages
│   ├── 02-kernel-tuning.sh     # Phase 2: Kernel optimization
│   ├── 03-nftables.sh          # Phase 3: nftables setup
│   ├── 04-suricata.sh          # Phase 4: Suricata installation
│   ├── 05-suricata-config.sh   # Phase 5: Suricata configuration
│   ├── 06-suricata-rules.sh    # Phase 6: Rule updates
│   ├── 07-blocklists.sh        # Phase 6.5: Community blocklists
│   ├── 08-blocklist-mgmt.sh    # Phase 6.6: Blocklist management
│   ├── 09-nodejs.sh            # Phase 7: Node.js
│   ├── 10-slips.sh             # Phase 8: SLIPS
│   ├── 11-ml-detector.sh       # Phase 8.5: ML Detector Dashboard
│   ├── 12-interfaces.sh        # Phase 9: Network interfaces
│   ├── 13-redis.sh             # Phase 10: Redis configuration
│   ├── 14-systemd.sh           # Phase 11: SystemD services
│   ├── 15-services.sh          # Phase 12: Start services
│   ├── 16-motd.sh              # Phase 13: MOTD
│   └── 17-verification.sh      # Phase 14: Verify installation
└── templates/
    ├── systemd/                # SystemD unit files
    ├── nftables/               # nftables configurations
    ├── suricata/               # Suricata configurations
    └── scripts/                # Helper scripts

```

## Benefits of Modular Architecture

### 1. **Maintainability**

- Each installation phase in its own file
- Easy to locate and update specific functionality
- Clear separation of concerns

### 2. **Testability**

- Individual modules can be tested independently
- Mock dependencies for unit testing
- Easier to debug specific phases

### 3. **Reusability**

- Modules can be used in different contexts
- Easy to create custom installation profiles
- Share common functionality via libraries

### 4. **Readability**

- Smaller files are easier to review
- Clear module naming shows purpose
- Better code organization

### 5. **Flexibility**

- Skip or customize specific phases
- Easy to add new installation phases
- Configuration-driven installation

## Usage

### Standard Installation

```bash
sudo ./installer/main.sh
```

### Custom Configuration

1. Copy and edit configuration:

```bash
cp installer/config/installer.conf installer/config/custom.conf
nano installer/config/custom.conf
```

2. Run with custom config:

```bash
sudo CONFIG_FILE=installer/config/custom.conf ./installer/main.sh
```

### Skip Specific Phases

```bash
# Skip blocklist installation
sudo SKIP_BLOCKLISTS=1 ./installer/main.sh

# Skip SLIPS Web UI
sudo INSTALL_WEBUI=false ./installer/main.sh
```

### Debug Mode

```bash
# Enable verbose output
sudo DEBUG=1 ./installer/main.sh
```

### Run Specific Module

```bash
# Source libraries first
source installer/lib/logging.sh
source installer/lib/utils.sh

# Load configuration
source installer/config/installer.conf

# Run specific module
bash installer/modules/07-blocklists.sh
```

## Module Development

### Module Template

Each module follows this structure:

```bash
#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: <Name>
# Phase: <Number>
# Description: <What this module does>

# Ensure script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script must be sourced, not executed"
    exit 1
fi

# Module function
install_<name>() {
    log_section "<Phase Name>"

    # Check prerequisites
    check_<prerequisite>() || error_exit "Prerequisite failed"

    # Installation steps
    log "Step 1: ..."
    # ... commands ...

    log "Step 2: ..."
    # ... commands ...

    # Verification
    verify_<name>() || error_exit "Verification failed"

    success "Module completed successfully"
}

# Verification function
verify_<name>() {
    # Check installation was successful
    command_exists <tool> || return 1
    service_running <service> || return 1
    return 0
}

# Export module function
export -f install_<name>
```

### Adding a New Module

1. Create module file:

```bash
touch installer/modules/18-my-module.sh
chmod +x installer/modules/18-my-module.sh
```

2. Implement using template above

3. Add to main.sh:

```bash
# In main.sh
if [[ "${INSTALL_MY_MODULE:-true}" == "true" ]]; then
    log "Phase 18: Installing My Module..."
    install_my_module
fi
```

4. Add configuration:

```bash
# In installer.conf
INSTALL_MY_MODULE=true
MY_MODULE_OPTION="value"
```

## Library Functions

### Logging (lib/logging.sh)

```bash
log "Info message"              # Green timestamped log
warn "Warning message"          # Yellow warning
error_exit "Error message"      # Red error and exit
info "Info without timestamp"   # Blue info
success "Success message"       # Green with checkmark
debug "Debug message"           # Only if DEBUG=1
log_section "Section Header"    # Section separator
```

### Utilities (lib/utils.sh)

```bash
# Prompts
ask_yes_no "Continue?" "y"      # Y/n prompt

# Checks
check_root                      # Verify running as root
check_os                        # Verify supported OS
check_internet                  # Verify connectivity
check_system_requirements       # RAM, CPU check

# Commands
command_exists "zeek"           # Check if command exists
package_installed "suricata"    # Check if package installed
service_running "redis"         # Check if service running

# Files
backup_file "/etc/config"       # Backup before modify
restore_file "/etc/config"      # Restore from backup
create_dir "/opt/app" "root" "755"

# Network
is_valid_ip "192.168.1.1"       # Validate IP
is_valid_cidr "10.0.0.0/24"     # Validate CIDR
interface_exists "eth0"         # Check if interface exists
get_interface_ip "eth0"         # Get IP of interface
```

## Configuration

All configurable options are in `installer/config/installer.conf`:

### Network Configuration

- Management interface
- Bridge interfaces
- Home network CIDR

### System Configuration

- Timezone
- Minimum requirements

### Feature Flags

- Enable/disable specific components
- Installation options

### Paths

- Installation directories
- Log locations
- Service names

## Migration from Monolithic Installer

The original `karens-ips-installer.sh` is now a wrapper that calls `installer/main.sh`:

```bash
#!/bin/bash
# Wrapper for backwards compatibility
exec "$(dirname "$0")/installer/main.sh" "$@"
```

This maintains backwards compatibility while providing the benefits of modular architecture.

## Testing

### Test Individual Modules

```bash
# Dry-run mode (if implemented)
sudo DRY_RUN=1 bash installer/modules/07-blocklists.sh

# Test with custom config
sudo bash -x installer/modules/07-blocklists.sh
```

### Test Full Installation

```bash
# In VM or container
sudo ./installer/main.sh

# With debug output
sudo DEBUG=1 ./installer/main.sh
```

## Troubleshooting

### Enable Debug Logging

```bash
export DEBUG=1
sudo ./installer/main.sh
```

### Check Logs

```bash
tail -f /var/log/ips-installer.log
```

### Run Specific Phase

```bash
# Load environment
source installer/lib/logging.sh
source installer/lib/utils.sh
source installer/config/installer.conf

# Run phase
source installer/modules/07-blocklists.sh
install_blocklists
```

### Common Issues

**Issue**: Module fails with "command not found"
**Solution**: Ensure all prerequisites are installed and libraries sourced

**Issue**: Permission denied
**Solution**: Run with sudo / as root

**Issue**: Configuration not loaded
**Solution**: Check CONFIG_FILE path and syntax

## Best Practices

1. **Always source libraries**
   - logging.sh for output
   - utils.sh for helpers

2. **Check prerequisites**
   - Verify dependencies before installation
   - Fail fast with clear error messages

3. **Idempotent operations**
   - Modules should be safe to run multiple times
   - Check if already installed before installing

4. **Error handling**
   - Use `set -e` to exit on errors
   - Provide helpful error messages
   - Clean up on failure when possible

5. **Logging**
   - Log all important operations
   - Use appropriate log levels
   - Include timestamps

6. **Configuration**
   - Use configuration file, not hardcoded values
   - Provide sensible defaults
   - Document all options

## Future Enhancements

- [ ] Uninstall modules
- [ ] Update/upgrade modules
- [ ] Configuration wizard
- [ ] Installation profiles (minimal, standard, full)
- [ ] Automated testing framework
- [ ] Rollback capability
- [ ] Progress indicator
- [ ] Installation report

## Contributing

When adding new modules:

1. Follow the module template
2. Document all configuration options
3. Add error handling
4. Include verification steps
5. Update this README

## License

GPL-2.0-only - See LICENSE file for details

## Security: Nginx Reverse Proxy

The installer automatically configures Nginx as a reverse proxy with multiple security layers:

### Features

- **HTTPS/TLS Encryption**: All traffic encrypted with TLS 1.2/1.3
- **HTTP Basic Authentication**: Username/password protection
- **Rate Limiting**:
  - General requests: 30 requests/minute
  - API endpoints: 5 requests/minute
  - Login attempts: 5 requests/minute
- **Security Headers**:
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options
  - X-Content-Type-Options
  - X-XSS-Protection
  - Referrer-Policy
- **Auto HTTP→HTTPS Redirect**: Forces secure connections

### Access

After installation:

```bash
# View credentials
sudo cat /root/.karens-ips-credentials

# Access web interface
https://YOUR_SERVER_IP
```

### Certificate Management

#### Self-Signed Certificate (Default)

The installer generates a self-signed certificate. Your browser will show a security warning - this is expected.

**To accept**:

1. Click "Advanced" or "Show Details"
2. Click "Proceed" or "Accept the Risk"

#### Let's Encrypt (Recommended for Production)

Replace the self-signed certificate with a free Let's Encrypt certificate:

```bash
# Install certbot
apt-get install certbot python3-certbot-nginx

# Obtain certificate (replace example.com with your domain)
certbot --nginx -d your-domain.com

# Auto-renewal is configured automatically
systemctl status certbot.timer
```

### Configuration Files

- **Nginx Config**: `/etc/nginx/sites-available/karens-ips`
- **SSL Certificate**: `/etc/nginx/ssl/karens-ips.crt`
- **SSL Key**: `/etc/nginx/ssl/karens-ips.key`
- **Credentials**: `/root/.karens-ips-credentials`
- **Auth File**: `/etc/nginx/.htpasswd`

### Adding Users

```bash
# Add a new user
sudo htpasswd /etc/nginx/.htpasswd username

# Remove a user
sudo htpasswd -D /etc/nginx/.htpasswd username

# Reload nginx
sudo systemctl reload nginx
```

### IP Whitelisting (Optional)

Restrict access to specific IPs:

```bash
# Edit nginx config
sudo nano /etc/nginx/sites-available/karens-ips

# Add inside the server block:
# allow 192.168.1.0/24;
# allow 10.0.0.0/8;
# deny all;

# Reload nginx
sudo systemctl reload nginx
```

### Disabling Authentication

If you want to disable authentication (not recommended):

```bash
# Edit nginx config
sudo nano /etc/nginx/sites-available/karens-ips

# Comment out these lines:
# auth_basic "Karen's IPS - Authentication Required";
# auth_basic_user_file /etc/nginx/.htpasswd;

# Reload nginx
sudo systemctl reload nginx
```

### Troubleshooting

```bash
# Check nginx status
sudo systemctl status nginx

# Test configuration
sudo nginx -t

# View error logs
sudo tail -f /var/log/nginx/karens-ips-error.log

# View access logs
sudo tail -f /var/log/nginx/karens-ips-access.log

# Restart nginx
sudo systemctl restart nginx
```
