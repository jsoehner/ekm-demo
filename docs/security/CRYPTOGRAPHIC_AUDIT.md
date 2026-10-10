## 🛡️ Cryptographic Bill of Materials (CBOM) & PQC Migration Assessment

**Format**: CycloneDX (v1.6) | **Total Components**: 1 | **Crypto Assets**: 1

### 📊 Post-Quantum Migration Scorecard

| Metric | Count | Migration Status |
|---|---|---|
| **Post-Quantum Ready (PQC)** | **0** | 🟢 Quantum-Resistant (NIST FIPS 203/204/205) |
| **Quantum-Vulnerable (Backlog)** | **1** | 🔴 At Risk of 'Harvest Now, Decrypt Later' |
| **Classical Symmetric / Hashing** | **0** | 🟡 Classical Security (Requires AES-256 / SHA-256+) |
| **Asymmetric PQC Migration Progress** | **0.0%** | (0 of 1 asymmetric primitives migrated) |

### ✅ Post-Quantum Cryptography Migrated Assets

> ⚠️ **No Post-Quantum Ready assets detected.** Immediate migration planning recommended for asymmetric key exchanges and digital signatures.

### ⚠️ Quantum-Vulnerable Assets & Remediation Plan

| Component / Algorithm | Type / Primitive | Key Length / Curve | Recommended Target | Source Location(s) & Code Context |
|---|---|---|---|---|
| **`RSA-2048`**<br><sub>RSA-2048</sub> | algorithm / signature | 2048 | **ML-KEM-768 / Kyber (FIPS 203)** | `demo_builder-v1.py:50`<br><sub><code>subprocess.run("openssl req -x509 -newkey rsa:4096 -keyout certs/ca.key -out certs/ca.crt -days 365 -nodes -subj '/CN=De</code></sub><br><br>`demo_builder-v1.py:51`<br><sub><code>subprocess.run("openssl req -newkey rsa:2048 -keyout certs/vault.key -out certs/vault.csr -nodes -subj '/CN=vault' -adde</code></sub><br><br>`demo_builder-v1.py:53`<br><sub><code>subprocess.run("openssl req -newkey rsa:2048 -keyout certs/proxy.key -out certs/proxy.csr -nodes -subj '/CN=ekm-proxy'",</code></sub> |

### 🔒 Classical Symmetric & Digest Assets
