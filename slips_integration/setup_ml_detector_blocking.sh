#!/bin/bash
# Setup script for ML Detector Alerts & Actions functionality
# Configures firewall permissions and initializes Redis data

set -e

echo "========================================="
echo "ML Detector Alerts & Actions Setup"
echo "========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root (use sudo)"
    exit 1
fi

# Detect the web server user
WEB_USER=""
if id "www-data" &>/dev/null; then
    WEB_USER="www-data"
elif id "apache" &>/dev/null; then
    WEB_USER="apache"
elif id "nginx" &>/dev/null; then
    WEB_USER="nginx"
else
    echo "⚠️  Could not detect web server user. Common options:"
    echo "   - www-data (Debian/Ubuntu)"
    echo "   - apache (RedHat/CentOS)"
    echo "   - nginx"
    read -p "Enter web server username: " WEB_USER

    if ! id "$WEB_USER" &>/dev/null; then
        echo "❌ User $WEB_USER does not exist"
        exit 1
    fi
fi

echo "✅ Detected web server user: $WEB_USER"
echo ""

# Create sudoers configuration for iptables
SUDOERS_FILE="/etc/sudoers.d/ml_detector_iptables"

echo "📝 Creating sudoers configuration..."
cat > "$SUDOERS_FILE" <<EOF
# ML Detector - Allow web server to manage nftables for threat blocking
# Created: $(date)

# Allow nft commands for managing blacklist
$WEB_USER ALL=(ALL) NOPASSWD: /usr/sbin/nft add element inet filter ml_detector_blacklist *
$WEB_USER ALL=(ALL) NOPASSWD: /sbin/nft add element inet filter ml_detector_blacklist *
$WEB_USER ALL=(ALL) NOPASSWD: /usr/sbin/nft delete element inet filter ml_detector_blacklist *
$WEB_USER ALL=(ALL) NOPASSWD: /sbin/nft delete element inet filter ml_detector_blacklist *

# Allow listing and flushing the set
$WEB_USER ALL=(ALL) NOPASSWD: /usr/sbin/nft list set inet filter ml_detector_blacklist
$WEB_USER ALL=(ALL) NOPASSWD: /sbin/nft list set inet filter ml_detector_blacklist
$WEB_USER ALL=(ALL) NOPASSWD: /usr/sbin/nft flush set inet filter ml_detector_blacklist
$WEB_USER ALL=(ALL) NOPASSWD: /sbin/nft flush set inet filter ml_detector_blacklist

# Allow checking if table/set exists
$WEB_USER ALL=(ALL) NOPASSWD: /usr/sbin/nft list table inet filter
$WEB_USER ALL=(ALL) NOPASSWD: /sbin/nft list table inet filter
EOF

# Set correct permissions
chmod 0440 "$SUDOERS_FILE"

# Validate sudoers file
if visudo -c -f "$SUDOERS_FILE" &>/dev/null; then
    echo "✅ Sudoers configuration created and validated"
else
    echo "❌ Sudoers configuration is invalid! Removing..."
    rm -f "$SUDOERS_FILE"
    exit 1
fi

echo ""
echo "🔧 Setting up nftables configuration..."

# Create nftables table and set for ML detector
nft add table inet filter 2>/dev/null || true
nft add set inet filter ml_detector_blacklist '{ type ipv4_addr; flags interval; }' 2>/dev/null || true

# Add rule to drop packets from blacklisted IPs (if not exists)
if ! nft list chain inet filter input 2>/dev/null | grep -q "ml_detector_blacklist"; then
    # Check if input chain exists
    if ! nft list chain inet filter input 2>/dev/null; then
        nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }'
    fi
    # Add the blacklist rule at the beginning of the chain
    nft insert rule inet filter input ip saddr @ml_detector_blacklist drop
    echo "✅ Added nftables rule to drop blacklisted IPs"
else
    echo "✅ nftables blacklist rule already exists"
fi

# Make nftables rules persistent
if [ -d "/etc/nftables.d" ]; then
    cat > /etc/nftables.d/ml_detector.nft <<'NFTEOF'
# ML Detector blacklist table and set
table inet filter {
    set ml_detector_blacklist {
        type ipv4_addr
        flags interval
    }

    chain input {
        type filter hook input priority 0; policy accept;
        ip saddr @ml_detector_blacklist drop
    }
}
NFTEOF
    echo "✅ Created persistent nftables configuration"
elif [ -f "/etc/nftables.conf" ]; then
    # Append to main config if not already there
    if ! grep -q "ml_detector_blacklist" /etc/nftables.conf 2>/dev/null; then
        cat >> /etc/nftables.conf <<'NFTEOF'

# ML Detector blacklist
add table inet filter
add set inet filter ml_detector_blacklist { type ipv4_addr; flags interval; }
add chain inet filter input { type filter hook input priority 0; policy accept; }
add rule inet filter input ip saddr @ml_detector_blacklist drop
NFTEOF
        echo "✅ Added ML detector rules to nftables.conf"
    fi
fi

echo ""
echo "🔧 Initializing Redis data..."

# Initialize blocking status (disabled by default)
redis-cli SET ml_detector:blocking_enabled 0 >/dev/null 2>&1 || true

# Initialize empty whitelist and blacklist
redis-cli DEL ml_detector:whitelist >/dev/null 2>&1 || true
redis-cli DEL ml_detector:blacklist >/dev/null 2>&1 || true

# Add default whitelisted IPs (localhost and common private ranges)
redis-cli SADD ml_detector:whitelist "127.0.0.1" >/dev/null 2>&1 || true
redis-cli SADD ml_detector:whitelist "::1" >/dev/null 2>&1 || true

# Initialize model info with features_used field
redis-cli HSET ml_detector:model_info features_used "Flow patterns, Connection duration, Data transfer volume, Domain analysis, Protocol behavior, Timing patterns, Packet sizes, Geographic patterns" >/dev/null 2>&1 || true

echo "✅ Redis initialization complete"
echo ""

# Test nftables permissions
echo "🧪 Testing nftables permissions..."
TEST_IP="192.0.2.1"  # TEST-NET-1 (reserved, safe to test)

# Try to add IP to blacklist set
if sudo -u "$WEB_USER" sudo nft add element inet filter ml_detector_blacklist "{ $TEST_IP }" 2>/dev/null; then
    echo "   ✅ Add permission works"

    # Try to delete IP from blacklist set
    if sudo -u "$WEB_USER" sudo nft delete element inet filter ml_detector_blacklist "{ $TEST_IP }" 2>/dev/null; then
        echo "   ✅ Delete permission works"
    else
        echo "   ⚠️  Delete permission failed (cleaning up manually)"
        nft delete element inet filter ml_detector_blacklist "{ $TEST_IP }" 2>/dev/null || true
    fi
else
    echo "   ❌ Add permission failed"
    echo "   Please check sudoers configuration"
    exit 1
fi

# Test list permission
if sudo -u "$WEB_USER" sudo nft list set inet filter ml_detector_blacklist >/dev/null 2>&1; then
    echo "   ✅ List permission works"
else
    echo "   ⚠️  List permission failed"
fi

echo ""
echo "========================================="
echo "✅ Setup Complete!"
echo "========================================="
echo ""
echo "Configuration Summary:"
echo "  • Web server user: $WEB_USER"
echo "  • Sudoers file: $SUDOERS_FILE"
echo "  • Live blocking: DISABLED (default)"
echo "  • Whitelisted IPs: 127.0.0.1, ::1"
echo ""
echo "Next steps:"
echo "  1. Restart your web server:"
echo "     systemctl restart apache2  # or nginx/httpd"
echo ""
echo "  2. Access the ML Detector dashboard:"
echo "     http://your-server/ml_detector/"
echo ""
echo "  3. Go to 'Alerts & Actions' tab to:"
echo "     - Enable live blocking"
echo "     - Manage whitelist/blacklist"
echo "     - Provide detection feedback"
echo ""
echo "⚠️  IMPORTANT:"
echo "  - Live blocking is DISABLED by default for safety"
echo "  - Test thoroughly before enabling in production"
echo "  - Whitelist your own IP before enabling blocking!"
echo ""
