# OKF Decision
Type: Policy / Architecture Standard
Title: ADR Discovery: Security Hardening & Dependency Upgrades
Date: 2026-08-26
Status: Decided (ADR Recommended)

## 1. Context & Architectural Significance Inputs
The recent security enhancements applied to the EKM Proxy Server (`proxy.py`) introduced several key modifications to the application's runtime characteristics, configurations, and boundaries:
- Upgraded core networking dependencies (`urllib3`, `requests`) and environment components (`pip`, `idna`).
- Masked sensitive data (JWT signatures and decrypted plaintext DEKs) in application logging.
- Introduced in-memory client rate limiting.
- Configured configurable Layer-7 identity checks (verification options for Issuer and Audience).
- Added global security headers middleware.

---

## 2. Evaluation Against ASR Indicators

- **Quality Attributes (Non-Functional Requirements) [Significant]:**
  - **Security:** Logging sanitization and rate limiting directly harden the proxy against leakage and abuse.
  - **Reliability:** Rate limiting prevents Vault/Keycloak resource starvation under load.
- **Constraints [Significant]:**
  - Introduces new environment variables (`JWT_AUDIENCE`, `JWT_ISSUER`, `HOST`, `PORT`, `RATE_LIMIT_MAX_REQUESTS`) required for runtime configuration.
- **Scope & Boundaries [Significant]:**
  - The `@app.after_request` middleware modifies every single egress communication boundary by appending headers.
- **Reversibility Cost [Medium]:**
  - Undoing the sanitization or rate limiting involves changing key blocks in `proxy.py` and could expose the proxy to regulatory or operational risk.

---

## 3. Recommendation & Next Steps

* **Decision:** **ADR Required.**
* **Proposed ADR Title:** `ADR-001: Implementing Security Hardening & Zero-Trust Egress Safeguards`
* **Suggested Action:** Proceed with writing `ADR-001` using standard MADR or generic ADR format to formalize these policies and prevent regression during future development.
