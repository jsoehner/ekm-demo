# OKF Decision
Type: Policy / Architecture Standard
Title: ADR-001: Implementing Security Hardening & Zero-Trust Egress Safeguards
Date: 2026-08-26
Status: Accepted

## Context and Problem Statement
The EKM Proxy Server (`proxy.py`) handles critical cryptographic translation services (decrypting DEKs). However, the initial baseline evaluation revealed several architectural vulnerabilities:
1. **Information Disclosure:** Decrypted plaintext DEKs and client JWT authentication headers were being logged verbatim in application logs.
2. **Denial of Service (DoS):** No rate limiting was enforced on `/unwrap-key`, leaving downstream Vault Transit and Keycloak JWKS interfaces vulnerable to exhaustion.
3. **Weak Identity Verification:** JWT signature verification had audience check validation disabled by default.
4. **Weak Transport Controls:** Missing standard browser security headers (CSP, HSTS, X-Frame-Options) and disabled SSL cert warnings.
5. **Supply Chain Vulnerabilities:** Core packages (`urllib3`, `requests`, `idna`, `pip`) had 11 known vulnerabilities.

---

## Decision Drivers
- **Data Protection:** Plaintext encryption keys and user auth tokens must never leak into logging backends (SIEM / audit pipelines).
- **Service Availability:** The proxy must withstand high-volume endpoint abuse.
- **Identity & Transport Quality Attributes:** Zero-Trust principles require strict validation of token audience/issuer and transport integrity.

---

## Considered Options
1. **Option A (Do Nothing):** Retain baseline codebase; rely strictly on perimeter firewalls. (Rejected: Violates defense-in-depth principles).
2. **Option B (Implement Hardened Layer Controls):** Introduce active logging filters, in-memory rate limiting, strict JWT options, security headers, and upgrade packages. (Accepted).

---

## Decision Outcome
Accepted **Option B**. The following implementations are now formalized policies:

### 1. Logging Sanitization Policy
- Every log message must be inspected to ensure it does not dump the `Authorization` header or decrypted plaintext payloads. All keys returned from Vault must be masked before debugging output.

### 2. Egress Transport Header Policy
- All HTTP responses must include defensive security headers:
  - `Content-Security-Policy: default-src 'self'`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Strict-Transport-Security` (HSTS) with a max age of 1 year.

### 3. Rate-Limiting Policy
- Apply IP-based rate limiting on sensitive API endpoints. Default limits are 100 requests per 60-second window.

### 4. Explicit Configuration Over Hardcoding
- Interface binds, port selections, and JWT validation parameters (`JWT_AUDIENCE`, `JWT_ISSUER`) must be retrieved dynamically from environment configurations rather than hardcoded in source.

---

## Consequences
- **Positive:** Safe logging complies with regulatory standards (SOC2, GDPR). The proxy is hardened against brute-force attacks and token replay attempts.
- **Negative:** Slightly increased operational configuration complexity (deployments must define key JWT environments).
