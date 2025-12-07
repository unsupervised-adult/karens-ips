#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: Nginx Reverse Proxy
# Phase: 18
# Description: Configure Nginx reverse proxy with HTTPS and authentication

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ============================================================================
# NGINX CONFIGURATION
# ============================================================================

configure_nginx_proxy() {
    log_section "Nginx Reverse Proxy Setup"

    if [[ "${NON_INTERACTIVE:-0}" == "1" ]]; then
        ENABLE_NGINX="${ENABLE_NGINX:-true}"
        NGINX_HTTPS="${NGINX_HTTPS:-true}"
        NGINX_AUTH="${NGINX_AUTH:-true}"
        NGINX_PORT="${NGINX_PORT:-443}"
        NGINX_HTTP_PORT="${NGINX_HTTP_PORT:-80}"
    else
        if ! ask_yes_no "Enable Nginx reverse proxy with HTTPS and authentication?" "y"; then
            info "Skipping Nginx configuration"
            return 0
        fi
        ENABLE_NGINX="true"
        NGINX_HTTPS="true"
        NGINX_AUTH="true"
    fi

    if [[ "${ENABLE_NGINX}" != "true" ]]; then
        return 0
    fi

    install_nginx
    configure_ssl_certificate
    configure_authentication
    create_nginx_config
    enable_nginx_service
}

install_nginx() {
    log_subsection "Installing Nginx"

    if command -v nginx &>/dev/null; then
        info "Nginx already installed: $(nginx -v 2>&1 | head -1)"
        return 0
    fi

    log "Installing nginx and required packages..."
    apt-get install -y nginx apache2-utils || {
        error "Failed to install nginx"
        return 1
    }

    success "Nginx installed successfully"
}

configure_ssl_certificate() {
    log_subsection "SSL/TLS Certificate"

    local cert_dir="/etc/nginx/ssl"
    local cert_file="$cert_dir/karens-ips.crt"
    local key_file="$cert_dir/karens-ips.key"

    mkdir -p "$cert_dir"
    chmod 700 "$cert_dir"

    if [[ -f "$cert_file" ]] && [[ -f "$key_file" ]]; then
        info "SSL certificate already exists"
        return 0
    fi

    log "Generating self-signed SSL certificate..."
    log "You can replace this with a real certificate later (Let's Encrypt, etc.)"

    # Generate self-signed certificate valid for 10 years
    openssl req -x509 -nodes -days 3650 \
        -newkey rsa:4096 \
        -keyout "$key_file" \
        -out "$cert_file" \
        -subj "/C=US/ST=State/L=City/O=Karen's IPS/CN=${WEBUI_IP:-localhost}" \
        2>&1 | grep -v "^+" || {
        error "Failed to generate SSL certificate"
        return 1
    }

    chmod 600 "$key_file"
    chmod 644 "$cert_file"

    success "Self-signed SSL certificate generated"
    info "Certificate: $cert_file"
    info "Key: $key_file"
}

configure_authentication() {
    log_subsection "Authentication Setup"

    local htpasswd_file="/etc/nginx/.htpasswd"

    if [[ -f "$htpasswd_file" ]]; then
        info "Authentication file already exists"
        return 0
    fi

    local username="${NGINX_USERNAME:-admin}"
    local password="${NGINX_PASSWORD}"

    if [[ -z "$password" ]]; then
        if [[ "${NON_INTERACTIVE:-0}" == "1" ]]; then
            # Generate random password in non-interactive mode
            password=$(openssl rand -base64 16)
            info "Generated random password for user '$username'"
        else
            # Prompt for password in interactive mode
            while true; do
                read -sp "Enter password for user '$username': " password
                echo
                read -sp "Confirm password: " password2
                echo

                if [[ "$password" == "$password2" ]]; then
                    break
                else
                    warn "Passwords do not match. Please try again."
                fi
            done
        fi
    fi

    log "Creating authentication file..."
    htpasswd -bc "$htpasswd_file" "$username" "$password" || {
        error "Failed to create authentication file"
        return 1
    }

    chmod 600 "$htpasswd_file"

    success "Authentication configured"
    info "Username: $username"

    # Save credentials to file for reference
    cat > /root/.karens-ips-credentials << EOF
Karen's IPS Web Interface Credentials
======================================
URL: https://${WEBUI_IP:-localhost}
Username: $username
Password: $password

Note: Keep this file secure!
EOF
    chmod 600 /root/.karens-ips-credentials

    success "Credentials saved to /root/.karens-ips-credentials"
}

create_nginx_config() {
    log_subsection "Creating Nginx Configuration"

    local config_file="/etc/nginx/sites-available/karens-ips"
    local webui_port="${WEBUI_PORT:-55000}"
    local webui_ip="${WEBUI_IP:-127.0.0.1}"

    log "Creating reverse proxy configuration..."

    cat > "$config_file" << 'NGINX_CONFIG_EOF'
# Karen's IPS Web Interface - Nginx Reverse Proxy
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only

# Rate limiting zones
limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=general_limit:10m rate=30r/m;

# HTTP -> HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name _;

    # Allow Let's Encrypt challenges
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    # Redirect all other HTTP to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name _;

    # SSL Configuration
    ssl_certificate /etc/nginx/ssl/karens-ips.crt;
    ssl_certificate_key /etc/nginx/ssl/karens-ips.key;

    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # Authentication
    auth_basic "Karen's IPS - Authentication Required";
    auth_basic_user_file /etc/nginx/.htpasswd;

    # Logging
    access_log /var/log/nginx/karens-ips-access.log;
    error_log /var/log/nginx/karens-ips-error.log;

    # Proxy settings
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;

    # Root location - proxy to Flask app
    location / {
        limit_req zone=general_limit burst=10 nodelay;
        proxy_pass http://WEBUI_IP:WEBUI_PORT;
    }

    # WebSocket support for real-time updates
    location /ws {
        proxy_pass http://WEBUI_IP:WEBUI_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # API endpoints with stricter rate limiting
    location /api/ {
        limit_req zone=general_limit burst=5 nodelay;
        proxy_pass http://WEBUI_IP:WEBUI_PORT;
    }

    # Static files - cache for 1 hour
    location /static/ {
        proxy_pass http://WEBUI_IP:WEBUI_PORT;
        expires 1h;
        add_header Cache-Control "public, immutable";
    }
}
NGINX_CONFIG_EOF

    # Replace placeholders
    sed -i "s/WEBUI_IP/$webui_ip/g" "$config_file"
    sed -i "s/WEBUI_PORT/$webui_port/g" "$config_file"

    # Enable site
    ln -sf "$config_file" /etc/nginx/sites-enabled/karens-ips

    # Remove default site
    rm -f /etc/nginx/sites-enabled/default

    # Test configuration
    log "Testing Nginx configuration..."
    if nginx -t 2>&1 | grep -q "successful"; then
        success "Nginx configuration valid"
    else
        error "Nginx configuration test failed"
        nginx -t
        return 1
    fi
}

enable_nginx_service() {
    log_subsection "Enabling Nginx Service"

    log "Starting and enabling Nginx..."
    systemctl enable nginx || warn "Failed to enable nginx"
    systemctl restart nginx || {
        error "Failed to start nginx"
        systemctl status nginx --no-pager
        return 1
    }

    success "Nginx service started"

    # Show access information
    log ""
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    success "Nginx Reverse Proxy Configured Successfully!"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log ""
    log "  🌐 Access URL: https://${WEBUI_IP:-localhost}"
    log "  🔐 Credentials: See /root/.karens-ips-credentials"
    log ""
    log "  Features enabled:"
    log "    ✓ HTTPS/TLS encryption"
    log "    ✓ HTTP Basic Authentication"
    log "    ✓ Rate limiting (30 req/min general, 5 req/min API)"
    log "    ✓ Security headers"
    log "    ✓ Auto HTTP->HTTPS redirect"
    log ""
    log "  Notes:"
    log "    • Self-signed certificate will show browser warning"
    log "    • Replace with Let's Encrypt: certbot --nginx"
    log "    • Credentials file: /root/.karens-ips-credentials"
    log ""
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log ""
}

# ============================================================================
# MODULE EXECUTION
# ============================================================================

if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    # Script is being sourced - export functions
    export -f configure_nginx_proxy
    export -f install_nginx
    export -f configure_ssl_certificate
    export -f configure_authentication
    export -f create_nginx_config
    export -f enable_nginx_service
fi
