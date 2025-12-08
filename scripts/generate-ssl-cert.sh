#!/bin/bash

set -e

SSL_DIR="/etc/karens-ips/ssl"
CERT_FILE="$SSL_DIR/cert.pem"
KEY_FILE="$SSL_DIR/key.pem"

echo "Generating self-signed SSL certificate for Karen's IPS..."

sudo mkdir -p "$SSL_DIR"

sudo openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/C=US/ST=State/L=City/O=Karen's IPS/OU=Security/CN=karens-ips" \
    -addext "subjectAltName=DNS:karens-ips,DNS:localhost,IP:127.0.0.1"

sudo chmod 600 "$KEY_FILE"
sudo chmod 644 "$CERT_FILE"

echo "SSL certificate generated successfully!"
echo "Certificate: $CERT_FILE"
echo "Private Key: $KEY_FILE"
echo ""
echo "Valid for 365 days"
