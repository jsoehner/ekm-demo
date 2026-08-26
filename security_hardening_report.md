# OKF Decision
Type: Policy / Architecture Standard
Title: Phase 1 Security Assessment & STRIDE Threat Model
Date: 2026-08-26
Status: Baseline Established

## 1. Security Baseline & Vulnerability Scan Analysis
A code review of `app/proxy.py`, `docker-compose.yml`, and `config/vault.hcl` reveals several security risks:

1. **Credential/Sensitive Data Leakage in Logs (High):**
   - The Authorization header (containing the Bearer JWT token) is logged verbatim: `logger.info(f"Request Headers: {dict(request.headers)}")`.
   - The decrypted plaintext DEK is logged directly: `logger.info(f"RESPONSE - {json.dumps(response_body, indent=2)}")`.
2. **Identity Verification Weakness (Medium):**
   - The JWT validation explicitly disables audience verification: `options=options or {"verify_aud": False}`.
3. **Transport Security (Medium):**
   - Insecure requests warning suppression: `urllib3.disable_warnings(...)` is active, which can hide TLS misconfigurations.
4. **Lack of Rate Limiting / DDoS Protections (Medium):**
   - The `/unwrap-key` endpoint does not have rate-limiting controls, leaving Vault Transit and Keycloak JWKS vulnerable to resource exhaustion.
5. **Hardcoded Admin Credentials in Docker Compose (Low):**
   - Keycloak admin credentials default to `admin`/`admin`.

---

## 2. STRIDE Threat Model

| Threat Category | Threat Description | Mitigation Strategy | Priority |
| :--- | :--- | :--- | :--- |
| **Spoofing Identity** | Attacker presents a token for a different audience or client. | Enable strict JWT signature, issuer, and audience validation in `JWKSClient`. | **High** |
| **Tampering with Data** | Attacker sends malicious `ciphertext` payload to crash or fuzz Vault. | Validate `ciphertext` format (e.g. Base64 and prefix validation) before forwarding. | **Medium** |
| **Repudiation** | Actions are not logged securely or logs leak secrets. | Remove sensitive values (JWTs, plaintext DEKs) from log lines. Log metadata/subjects only. | **High** |
| **Information Disclosure** | Hardcoded configs or logs expose secrets. | Use environment variables for secrets/configs. Suppress sensitive field prints. | **High** |
| **Denial of Service** | DoS on `/unwrap-key` or JWKS endpoint. | Add Flask rate-limiting / connection timeout limits. | **Medium** |
| **Elevation of Privilege** | Reused expired JWT or compromised client cert. | Ensure mTLS certificate verification is strict and JWT validation checks expiration securely. | **High** |

---

## 3. Zero-Trust Security Architecture Review
- **Layer 7 (Application):** Enforce identity validation with strict signature verification using the JWKS endpoint from Keycloak. Verify the `aud` (Audience) and `iss` (Issuer).
- **Layer 4 (Transport):** Enforce strict mTLS between the EKM proxy and Vault, utilizing `/certs/ca.crt` to verify the peer identity.
- **Layer 1 (Data):** Plaintext keys must never be logged or persisted anywhere outside the transient memory space of the application.
