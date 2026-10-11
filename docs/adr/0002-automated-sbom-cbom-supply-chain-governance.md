# ADR 0002: Automated SBOM and CBOM Supply Chain Governance

* **Status:** Accepted
* **Deciders:** EKM Demo Engineering Team, DevSecOps & Security Automation
* **Date:** 2026-10-11

---

## 1. Context & Problem Statement

Modern software supply chain risks (such as vulnerable third-party dependencies, unsigned cryptographic libraries, and post-quantum migration challenges) require continuous automated inventory and verification. The External Key Manager (`ekm-demo`) handles critical cryptographic operations—orchestrating Keycloak OIDC JWT authentication, mutual TLS (mTLS) transport validation, and HashiCorp Vault Transit envelope encryption for Data Encryption Keys (DEKs).

Prior to this decision:
1. No automated Software Bill of Materials (SBOM) was generated or published to track container dependencies or open-source components across standard formats (CycloneDX, SPDX).
2. No Cryptographic Bill of Materials (CBOM) existed to catalog cryptographic algorithms, cipher suites, key lengths, curves, and post-quantum cryptography (PQC) readiness across Vault Transit and application layers.
3. Static security tooling lacked semantic Abstract Syntax Tree (AST) scanning to detect cryptographic call sites and reconcile them against declared software bills.

We need an automated, reproducible CI pipeline and local developer tooling to generate, reconcile, verify, and document both SBOM and CBOM assets continuously.

---

## 2. Alternatives Considered

| Alternative | Pros | Cons |
| :--- | :--- | :--- |
| **Manual Audits / Periodic Point-in-Time Scans** | Low pipeline setup complexity. | Out-of-date quickly; does not enforce compliance per pull request or commit. |
| **SBOM Only (e.g. Syft standalone)** | Identifies vulnerable third-party packages. | Lacks visibility into cryptographic algorithms, key strengths, and PQC migration risks. |
| **Dual-Engine Automated SBOM & CBOM with AST Crypto Scans (Selected)** | Comprehensive supply chain and cryptographic visibility; automated CI verification harness; dual-format (CycloneDX & SPDX) support; PQC migration roadmap. | Adds minor CI pipeline execution overhead and local tooling footprint. |

---

## 3. Decision Outcome

Chosen Strategy: **Adopt an automated dual-engine SBOM and CBOM generation and verification workflow integrating Anchore/Syft, cbomkit, semantic AST cryptographic discovery, and automated CI test harnesses.**

### Key Architectural Actions

1. **Dual SBOM Generation**: Utilize Anchore/Syft (`anchore/sbom-action`) to generate both CycloneDX JSON (`oss/sbom.cyclonedx.json`) and SPDX JSON (`oss/sbom.spdx.json`) in CI and local environments.
2. **CBOM Generation**: Integrate `cbomkit-action` to discover cryptographic components and export standard CBOM artifacts (`oss/cbom.json`).
3. **AST Cryptographic Scanning & Reconciliation**: Deploy `scripts/scan_crypto_ast.py` to perform semantic AST analysis of repository source code, identifying cryptographic call sites and reconciling them with CBOM catalogs.
4. **Automated Verification Harness**: Introduce `scripts/test_boms.sh` to validate schema conformance, verify non-empty component inventories, and enforce minimum cryptographic quality gates.
5. **Post-Quantum Cryptography (PQC) Readiness Assessment**: Integrate `scripts/analyze_cbom.py` to evaluate classical vs. post-quantum algorithm posture and generate markdown summaries (`docs/security/CRYPTOGRAPHIC_AUDIT.md` and GitHub Actions Step Summaries).
6. **Continuous Workflow Execution**: Standardize on `.github/workflows/sbom-cbom.yml` running on Node 24 standard actions on pushes, pull requests, and manual triggers.

---

## 4. Consequences & Trade-offs

### Positive Consequences
- **Complete Supply Chain Transparency**: Immediate visibility into application dependencies, licenses, and vulnerabilities.
- **Cryptographic Asset Inventory**: Clear mapping of all cryptographic primitives across envelope encryption, mTLS, and JWT verification, facilitating proactive migration to Post-Quantum Cryptography (PQC) standards.
- **Shift-Left Security Gate**: Developers can run `scripts/generate_boms.sh` and `scripts/test_boms.sh` locally prior to opening PRs.
- **Regulatory & Compliance Alignment**: Conforms with modern executive orders and industry standards for software supply chain transparency (EO 14028, NIST IR 8547 / SP 800-218).

### Negative Consequences / Trade-offs
- **CI Build Duration**: Adds an additional workflow job (~1-2 minutes) to pull-request and push pipelines.
- **Maintenance Overhead**: Script and tooling maintenance in `scripts/` (`analyze_cbom.py`, `scan_crypto_ast.py`, `generate_boms.sh`, `test_boms.sh`).

---

## 5. Related Records

- [ADR-001: Implementing Security Hardening & Zero-Trust Egress Safeguards](0001-security-hardening.md)
