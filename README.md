# External Key Manager (EKM) Demo

A reference implementation and demonstration of an **External Key Manager (EKM)** pattern combining identity-based authorization (Keycloak OIDC JWT), transport-level mutual TLS (mTLS), and centralized cryptographic services (HashiCorp Vault Transit Secrets Engine).

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker Compose](https://img.shields.io/badge/Docker%20Compose-v2-blue.svg)](docker-compose.yml)
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](app/proxy.py)

---

## About

Cloud applications often require fine-grained governance over encryption keys, particularly when sensitive data is stored across multi-tenant or third-party environments. The **External Key Management (EKM)** pattern ensures that data decryption keys (DEKs) cannot be unwrapped without strictly validating both **who** is asking (Application-level JWT identity) and **what system** is making the request (Transport-level mTLS authentication).

This repository provides an automated, end-to-end sandbox demonstrating:
1. **Application Security (Layer 7)**: Verifying client identity and permissions via OpenID Connect (OIDC) JSON Web Key Sets (JWKS) provided by Keycloak.
2. **Transport Security (Layer 4)**: Authenticating the proxy service to HashiCorp Vault using x509 client certificates (mTLS).
3. **Cryptographic Isolation (Layer 1)**: Delegating envelope encryption and Key Encryption Key (KEK) management to Vault's Transit Secrets Engine.

---

## Architecture

```
                                  +---------------------------------------+
                                  |            Keycloak (OIDC)            |
                                  |    (Realm: ekm-demo, JWKS Endpoint)   |
                                  +-------------------+-------------------+
                                                      ^
                                                      | 1. Validate JWT via JWKS
                                                      |
+---------------------+     POST /unwrap-key          v     POST /v1/transit/decrypt    +------------------------+
|    Client / App     | ------------------------> [ EKM-PROXY ] ----------------------> |    HashiCorp Vault     |
| (Bearer JWT + DEK)  | <------------------------ [   Flask   ] <---------------------- | (Transit KEK Engine)   |
+---------------------+    Plaintext DEK (JSON)       +     mTLS (Cert Auth + TLS)      +------------------------+
                                                      |
                                             Security Controls:
                                             - Rate Limiting (In-memory)
                                             - Response Security Headers
                                             - Plaintext Log Masking
```

---

## Features

- **Automated Lifecycle & Demo Runner**: Execute full setup, provisioning, and interactive verification with a single script (`demo_builder-v1.py`).
- **Cryptographic Separation of Duties**: The proxy performs translation and policy enforcement; root keys never leave Vault.
- **PKI & Certificate Automation**: Built-in Root CA and server/client x509 certificate generation with SAN extensions.
- **Comprehensive Defense-in-Depth**:
  - In-memory client rate limiting.
  - Hardened HTTP security headers (`CSP`, `HSTS`, `X-Frame-Options`, `Permissions-Policy`).
  - Sensitive token/key masking in application logs.
  - Health and statistics monitoring endpoints.

---

## Prerequisites

Ensure you have the following installed on your host system:
- **Docker** and **Docker Compose** (v2+)
- **Python 3.9+**
- **OpenSSL**
- Python `requests` library (for running the demo script):
  ```bash
  pip install requests urllib3
  ```

---

## Quick Start

### 1. Run the Automated Demo

The fastest way to experience the EKM workflow is via the demo builder script:

```bash
python3 demo_builder-v1.py
```

This script automatically:
1. Generates local PKI certificates (`ca.crt`, `vault.crt`, `proxy.crt`).
2. Starts Docker containers for **Keycloak**, **HashiCorp Vault**, and **EKM-Proxy**.
3. Configures Keycloak realm (`ekm-demo`), clients, and users (`alice`).
4. Configures Vault Transit engine, master KEK (`my-master-kek`), and cert authentication.
5. Encrypts a sample DEK and requests an identity token from Keycloak.
6. Calls `POST /unwrap-key` on the EKM proxy to demonstrate successful unwrapping.
7. Demonstrates negative security tests (tampered tokens, invalid certificates, expired claims).

---

## Manual Installation & Deployment

If you prefer to start services independently:

### 1. Generate Certificates
```bash
./generate_certs.sh
```

### 2. Launch Services
```bash
docker compose up -d
```

### 3. Verify Health
Check that all services are operational:
```bash
# EKM Proxy Health
curl -s http://localhost:5050/health | jq .

# Keycloak OpenID Configuration
curl -s http://localhost:8080/realms/ekm-demo/.well-known/openid-configuration | jq .

# Vault Status
curl -k -s https://localhost:8250/v1/sys/health | jq .
```

---

## API Reference

### Unwrap Key
Decrypts an encrypted Data Encryption Key (DEK).

- **URL**: `/unwrap-key`
- **Method**: `POST`
- **Headers**:
  - `Authorization: Bearer <Keycloak_JWT_Token>`
  - `Content-Type: application/json`
- **Body**:
  ```json
  {
    "ciphertext": "vault:v1:..."
  }
  ```
- **Success Response (200 OK)**:
  ```json
  {
    "plaintext_dek": "base64-encoded-plaintext-key"
  }
  ```
- **Error Responses**:
  - `401 Unauthorized`: Missing or invalid Bearer token / signature verification failure.
  - `403 Forbidden`: Token expired or missing required scopes.
  - `429 Too Many Requests`: Rate limit exceeded.
  - `503 Service Unavailable`: Vault connection or mTLS handshake failed.

### Health Check
- **URL**: `/health`
- **Method**: `GET`
- **Response (200 OK)**:
  ```json
  {
    "status": "healthy",
    "timestamp": "2026-08-27T04:40:00.000000",
    "vault_connection": "OK"
  }
  ```

### Server Stats
- **URL**: `/stats`
- **Method**: `GET`

---

## Project Structure

```
.
├── app/
│   └── proxy.py              # Flask EKM Proxy server (JWT verification, mTLS client, DEK unwrap)
├── config/
│   └── vault.hcl             # Vault server configuration (TLS, file storage)
├── docs/
│   └── adr/                  # Architectural Decision Records
├── certs/                    # Local PKI assets (generated during setup)
├── demo_builder-v1.py        # Automated test harness and demo runner
├── docker-compose.yml        # Multi-container orchestration (Keycloak, Vault, Proxy)
├── generate_certs.sh         # Shell script for self-signed x509 cert generation
└── README.md
```

---

## Security Governance & Audits

This repository includes security audit results and compliance reports:
- [Security Governance Report](security_governance_report.md)
- [Hardening & Remediation Report](security_hardening_report.md)
- [SAST Security Report](sast_security_report.md)
- [Software Bill of Materials (SBOM)](sbom.json)

---

## Contributing

Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/amazing-feature`).
3. Commit your changes (`git commit -m 'feat: add amazing feature'`).
4. Push to the branch (`git push origin feature/amazing-feature`).
5. Open a Pull Request.

---

## License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.
