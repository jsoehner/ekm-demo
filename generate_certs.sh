#!/bin/bash
set -e

# Create certs directory if it doesn't exist
mkdir -p certs

echo "[*] Verifying certificates and private keys..."

# 1. Generate CA key and cert if not existing
if [ ! -f certs/ca.key ] || [ ! -f certs/ca.crt ]; then
    echo "[*] Generating Root CA..."
    openssl req -x509 -newkey rsa:4096 -keyout certs/ca.key -out certs/ca.crt -days 365 -nodes -subj '/CN=DemoRootCA' 2>/dev/null
else
    echo "[+] CA key and certificate already exist."
fi

# 2. Generate Vault key, CSR, and cert if not existing
if [ ! -f certs/vault.key ] || [ ! -f certs/vault.crt ]; then
    echo "[*] Generating Vault server certificate..."
    openssl req -newkey rsa:2048 -keyout certs/vault.key -out certs/vault.csr -nodes -subj '/CN=vault' -addext 'subjectAltName = DNS:vault,DNS:localhost,IP:127.0.0.1' 2>/dev/null
    openssl x509 -req -in certs/vault.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/vault.crt -days 365 -copy_extensions copy 2>/dev/null
else
    echo "[+] Vault key and certificate already exist."
fi

# 3. Generate Proxy key, CSR, and cert if not existing
if [ ! -f certs/proxy.key ] || [ ! -f certs/proxy.crt ]; then
    echo "[*] Generating Proxy client certificate (mTLS)..."
    openssl req -newkey rsa:2048 -keyout certs/proxy.key -out certs/proxy.csr -nodes -subj '/CN=ekm-proxy' 2>/dev/null
    openssl x509 -req -in certs/proxy.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/proxy.crt -days 365 2>/dev/null
else
    echo "[+] Proxy key and certificate already exist."
fi

echo "[*] Certificate verification complete."
