# OKF Decision
Type: Policy / Architecture Standard
Title: Dependency Security Scan & Remediation Roadmap (Remediated)
Date: 2026-08-26
Status: Completed & Verified

## Executive Summary
A follow-up security verification scan was performed after updating the recommended dependencies. **Zero vulnerabilities** are now present in the virtual environment.

---

## 1. Remediation Action History

The following packages were successfully upgraded:

| Package | Original Version | Upgraded Version | Vulnerability ID(s) Resolved | Remediation Status |
| :--- | :--- | :--- | :--- | :--- |
| **idna** | `3.11` | `3.19` | `PYSEC-2026-215` | **Fixed & Verified** |
| **pip** | `26.0` | `26.2.1` | `PYSEC-2026-196`, `PYSEC-2026-2875`, `PYSEC-2026-2876`, `PYSEC-2026-3721` | **Fixed & Verified** |
| **requests** | `2.32.5` | `2.34.2` | `PYSEC-2026-2275` | **Fixed & Verified** |
| **urllib3** | `2.6.3` | `2.7.0` | `PYSEC-2026-141`, `PYSEC-2026-142` | **Fixed & Verified** |

---

## 2. Verification Status

1. **`pip-audit` Verification:**
   - Command run: `./venv/bin/pip-audit`
   - Output: `No known vulnerabilities found` (Exit Code `0`)
2. **SBOM & Clean Reports:**
   - Updated CycloneDX SBOM: [sbom.json](file:///Users/jsoehner/ekm-demo/sbom.json)
   - Updated Markdown Report: [audit-report.md](file:///Users/jsoehner/ekm-demo/audit-report.md)
