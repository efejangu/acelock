#!/bin/bash

# Script to check for and generate SSL certificates for the TCP server
# This script checks if the ssl_deets directory exists and contains the required certificates
# If not, it creates the directory and generates self-signed certificates

# Check if openssl is installed
if ! command -v openssl &> /dev/null; then
    echo "Error: openssl is not installed or not in PATH"
    echo "Please install openssl before running this script"
    exit 1
fi

# Set variables
SSL_DIR="ssl_deets"
CERT_FILE="$SSL_DIR/server.crt"
KEY_FILE="$SSL_DIR/server.key"

# Function to generate certificates
generate_certificates() {
    echo "Generating self-signed SSL certificates..."

    # Create directory if it doesn't exist
    mkdir -p "$SSL_DIR"

    # Generate private key and self-signed certificate
    openssl req -x509 -newkey rsa:4096 -nodes -out "$CERT_FILE" -keyout "$KEY_FILE" -days 365 \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=localhost" \
        -addext "subjectAltName = DNS:localhost,IP:127.0.0.1"

    # Check if generation was successful
    if [ $? -eq 0 ]; then
        echo "Certificate generation successful!"
        echo "Certificate: $CERT_FILE"
        echo "Private key: $KEY_FILE"
        chmod 600 "$KEY_FILE"  # Secure the private key
    else
        echo "Certificate generation failed!"
        exit 1
    fi
}

# Main script logic
echo "Checking for SSL certificates..."

# Check if directory exists
if [ ! -d "$SSL_DIR" ]; then
    echo "SSL directory not found. Creating $SSL_DIR directory."
    generate_certificates
else
    echo "SSL directory exists. Checking for certificates..."

    # Check if both certificate and key exist
    if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
        echo "Certificates found:"
        echo "Certificate: $CERT_FILE"
        echo "Private key: $KEY_FILE"
    else
        echo "Certificates not found or incomplete."
        generate_certificates
    fi
fi

echo "SSL certificate check complete."