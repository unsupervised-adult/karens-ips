# Web Authentication Setup

Secure the Karen's IPS web interface with password authentication and HTTPS.

## Architecture

- **Flask**: Runs on `127.0.0.1:55000` (localhost only, not exposed)
- **Nginx**: Listens on `0.0.0.0:443` (HTTPS, publicly accessible)
- **Authentication**: Session-based with bcrypt password hashing
- **SSL**: Self-signed certificate (365-day validity)

## Quick Setup

```bash
cd /path/to/karens-ips

# 1. Initialize authentication (sets default password: admin)
sudo ./scripts/init-auth.sh

# 2. Generate SSL certificate
sudo ./scripts/generate-ssl-cert.sh

# 3. Install Nginx configuration
sudo cp deployment/nginx-karens-ips.conf /etc/nginx/sites-available/karens-ips
sudo ln -s /etc/nginx/sites-available/karens-ips /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# 4. Restart web interface (Flask now binds to localhost only)
sudo systemctl restart slips-webui
```

## Access

- **HTTPS**: `https://your-server-ip/` (Nginx → Flask proxy)
- **Login**: Username not required, password only
- **Default Password**: `admin` (change immediately!)

## First Login

1. Navigate to `https://your-server-ip/`
2. Accept self-signed certificate warning
3. Enter password: `admin`
4. **Immediately** go to `https://your-server-ip/auth/change-password`
5. Change default password

## Change Password

Navigate to: `https://your-server-ip/auth/change-password`

Requirements:
- Current password
- New password (minimum 8 characters)
- Passwords must match

## Session Management

- **Session Duration**: 1 hour (auto-logout after inactivity)
- **Logout**: `https://your-server-ip/auth/logout`
- **Session Storage**: Secure Flask sessions (encrypted cookie)

## Security Features

- Flask binds to `127.0.0.1` only (not exposed to network)
- Nginx handles all external traffic on port 443
- bcrypt password hashing (cost factor: 12)
- Session cookies with httponly flag
- TLS 1.2/1.3 only
- HTTPS redirect from port 80
- Password file permissions: 600 (root only)

## File Locations

```
/etc/karens-ips/.password           # bcrypt password hash
/etc/karens-ips/ssl/cert.pem        # SSL certificate
/etc/karens-ips/ssl/key.pem         # SSL private key
/etc/nginx/sites-enabled/karens-ips # Nginx config symlink
/var/log/nginx/karens-ips-*.log     # Access/error logs
```

## Troubleshooting

### Can't access web interface

Check Flask is running on localhost:
```bash
sudo systemctl status slips-webui
curl http://127.0.0.1:55000/
```

Check Nginx is running:
```bash
sudo systemctl status nginx
sudo nginx -t
```

### Login fails with correct password

Verify password file exists:
```bash
sudo ls -l /etc/karens-ips/.password
```

Reinitialize authentication:
```bash
sudo rm /etc/karens-ips/.password
sudo ./scripts/init-auth.sh
```

### SSL certificate warnings

Self-signed certificates trigger browser warnings. Options:

1. **Accept warning** (recommended for internal use)
2. **Use Let's Encrypt** for valid certificate:
   ```bash
   sudo apt install certbot python3-certbot-nginx
   sudo certbot --nginx -d your-domain.com
   ```

### Session expires too quickly

Edit `slips_integration/webinterface/app.py`:
```python
app.config["PERMANENT_SESSION_LIFETIME"] = 7200  # 2 hours
```

## Production Recommendations

1. **Use real certificate**: Let's Encrypt or commercial CA
2. **Strong password**: >12 characters, mixed case, numbers, symbols
3. **Firewall**: Block port 55000 externally (Flask should only be localhost)
4. **Nginx logs**: Monitor for brute-force attempts
5. **Rate limiting**: Add Nginx fail2ban integration

## Nginx Configuration Details

```nginx
# HTTPS listener (port 443)
server {
    listen 443 ssl http2;
    
    # Proxy to Flask on localhost
    location / {
        proxy_pass http://127.0.0.1:55000;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}

# HTTP → HTTPS redirect (port 80)
server {
    listen 80;
    return 301 https://$host$request_uri;
}
```

## Manual Password Reset

If you forget the password:

```bash
# Generate new bcrypt hash for password "newpassword"
python3 -c "import bcrypt; print(bcrypt.hashpw(b'newpassword', bcrypt.gensalt()).decode())" | sudo tee /etc/karens-ips/.password
```

## Uninstall Authentication

To remove authentication and revert to open access:

```bash
# Remove password file
sudo rm /etc/karens-ips/.password

# Remove Nginx config
sudo rm /etc/nginx/sites-enabled/karens-ips
sudo systemctl reload nginx

# Revert Flask to bind 0.0.0.0
# Edit slips_integration/webinterface/app.py:
#   app.run(host="0.0.0.0", port=55000)
sudo systemctl restart slips-webui
```
