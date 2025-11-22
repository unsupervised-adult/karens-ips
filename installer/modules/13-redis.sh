#!/bin/bash
# SPDX-FileCopyrightText: 2025 Karen's IPS
# SPDX-License-Identifier: GPL-2.0-only
#
# Module: Redis Configuration
# Phase: 13
# Description: Configure Redis for SLIPS ML behavioral analysis

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This module must be sourced, not executed"
    echo "Usage: source $(basename "${BASH_SOURCE[0]}")"
    exit 1
fi

# ============================================================================
# REDIS CONFIGURATION
# ============================================================================

configure_redis() {
    log_subsection "Redis Configuration for SLIPS"

    # Check if Redis configuration is enabled
    if [[ "${CONFIGURE_REDIS:-true}" != "true" ]]; then
        log "Redis configuration disabled, skipping"
        return 0
    fi

    log "Configuring Redis for SLIPS..."

    # Check if Redis is installed
    check_redis_installed

    # Configure Redis settings
    configure_redis_settings

    # Restart and enable Redis
    restart_redis

    success "Redis configured and started"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

check_redis_installed() {
    if ! command -v redis-server >/dev/null 2>&1; then
        error_exit "Redis not installed. Please install redis-server first."
    fi

    if [[ ! -f /etc/redis/redis.conf ]]; then
        error_exit "Redis configuration file not found at /etc/redis/redis.conf"
    fi

    log "Redis installation found"
}

configure_redis_settings() {
    log "Updating Redis configuration..."

    local redis_conf="/etc/redis/redis.conf"

    # Backup original configuration
    if [[ ! -f "${redis_conf}.backup" ]]; then
        cp "$redis_conf" "${redis_conf}.backup"
        log "Backup created: ${redis_conf}.backup"
    fi

    # Configure bind address (localhost only for security)
    if grep -q "^bind 127.0.0.1 ::1" "$redis_conf"; then
        sed -i 's/^bind 127.0.0.1 ::1/bind 127.0.0.1/' "$redis_conf"
        log "Bind address configured for localhost only"
    elif grep -q "^# bind 127.0.0.1" "$redis_conf"; then
        sed -i 's/^# bind 127.0.0.1/bind 127.0.0.1/' "$redis_conf"
        log "Bind address configured for localhost only"
    fi

    # Configure maxmemory (2GB for SLIPS)
    if grep -q "^# maxmemory <bytes>" "$redis_conf"; then
        sed -i 's/^# maxmemory <bytes>/maxmemory 2gb/' "$redis_conf"
        log "Max memory set to 2GB"
    elif ! grep -q "^maxmemory" "$redis_conf"; then
        echo "maxmemory 2gb" >> "$redis_conf"
        log "Max memory set to 2GB"
    fi

    # Configure maxmemory-policy (LRU eviction)
    if grep -q "^# maxmemory-policy noeviction" "$redis_conf"; then
        sed -i 's/^# maxmemory-policy noeviction/maxmemory-policy allkeys-lru/' "$redis_conf"
        log "Memory eviction policy set to allkeys-lru"
    elif ! grep -q "^maxmemory-policy" "$redis_conf"; then
        echo "maxmemory-policy allkeys-lru" >> "$redis_conf"
        log "Memory eviction policy set to allkeys-lru"
    fi

    success "Redis configuration updated"
}

restart_redis() {
    log "Restarting Redis service..."

    if systemctl restart redis-server; then
        success "Redis restarted successfully"
    else
        error_exit "Failed to restart Redis"
    fi

    # Enable Redis to start on boot
    if systemctl enable redis-server; then
        log "Redis enabled to start on boot"
    else
        warn "Failed to enable Redis service"
    fi

    # Wait for Redis to be ready
    sleep 2

    # Test Redis connection
    if redis-cli ping >/dev/null 2>&1; then
        success "Redis is responding to connections"
    else
        warn "Redis may not be responding yet"
    fi
}

# ============================================================================
# VERIFICATION
# ============================================================================

verify_redis() {
    log "Verifying Redis configuration..."

    local errors=0

    # Check if Redis is running
    if ! systemctl is-active --quiet redis-server; then
        warn "Redis service is not running"
        ((errors++))
    fi

    # Check if Redis is enabled
    if ! systemctl is-enabled --quiet redis-server; then
        warn "Redis service is not enabled"
        ((errors++))
    fi

    # Test Redis connection
    if ! redis-cli ping >/dev/null 2>&1; then
        warn "Cannot connect to Redis"
        ((errors++))
    fi

    # Check configuration file
    if [[ ! -f /etc/redis/redis.conf ]]; then
        warn "Redis configuration file not found"
        ((errors++))
    fi

    # Verify maxmemory setting
    local maxmemory=$(redis-cli config get maxmemory 2>/dev/null | tail -1)
    if [[ -n "$maxmemory" && "$maxmemory" != "0" ]]; then
        log "Redis maxmemory: $maxmemory bytes"
    else
        warn "Redis maxmemory not configured"
    fi

    if [[ $errors -eq 0 ]]; then
        success "Redis verification passed"
        return 0
    else
        warn "Redis verification found $errors issues"
        return 1
    fi
}

# Export functions
export -f configure_redis
export -f check_redis_installed
export -f configure_redis_settings
export -f restart_redis
export -f verify_redis
