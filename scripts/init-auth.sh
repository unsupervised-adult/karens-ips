#!/bin/bash

set -e

PASSWORD_FILE="/etc/karens-ips/.password"
DEFAULT_PASSWORD="admin"

echo "Setting up Karen's IPS web authentication..."

sudo mkdir -p /etc/karens-ips

if [ -f "$PASSWORD_FILE" ]; then
    echo "Password file already exists at $PASSWORD_FILE"
    echo "Skipping initialization."
else
    echo "Creating default password (admin)..."
    python3 -c "import bcrypt; print(bcrypt.hashpw(b'$DEFAULT_PASSWORD', bcrypt.gensalt()).decode())" | sudo tee "$PASSWORD_FILE" > /dev/null
    sudo chmod 600 "$PASSWORD_FILE"
    echo "Default password set successfully!"
    echo ""
    echo "⚠️  IMPORTANT: Change the default password immediately after first login!"
    echo "   Navigate to: https://your-server/auth/change-password"
fi

echo ""
echo "Setup complete!"
