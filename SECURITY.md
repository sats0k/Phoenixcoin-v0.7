# Security Policy

## Overview

This project implements a **hybrid digital signature system** combining:

- ECDSA (secp256k1)
- ML-DSA-65 (post-quantum, Dilithium)

It also supports **password-encrypted private key serialization** using
AES-256-GCM with PBKDF2 key derivation.

This document describes the security assumptions, guarantees, and
responsible disclosure process.

---

## Cryptographic Design

### Signature Algorithms

| Algorithm       | Purpose                                     |
|-----------------|---------------------------------------------|
| ECDSA secp256k1 | Classical security, ecosystem compatibility |
| ML-DSA-65       | Post-quantum security                       |

Hybrid verification **requires exactly one valid signature per algorithm**.
Missing, duplicate, or malformed signatures cause verification failure.

---

### Message Construction

All signatures operate over a domain-separated message:

`"BIT-HYBRID-SIG-v1"`

- ECDSA signs the **hash** of the hybrid message
- ML-DSA signs the **raw hybrid message**

This asymmetry is intentional and consensus-critical.

---

### Private Key Encryption

Encrypted private keys use:

- PBKDF2-HMAC-SHA256 (200,000 iterations)
- Random 128-bit salt
- AES-256-GCM
- Random 96-bit nonce
- Authenticated header (magic + version)

Any modification to ciphertext, header, salt, nonce, or tag
causes decryption failure.

---

## Threat Model

### Defended Against

- Offline brute-force attacks on encrypted private keys
- Signature malleability (low-S normalization)
- Algorithm substitution attacks
- Parsing ambiguities / length overflows
- Timing attacks in key comparisons
- Post-quantum cryptanalytic attacks (via ML-DSA)

---

### Not Defended Against

- Compromised endpoints
- Malicious OpenSSL builds
- Side-channel attacks on hardware (e.g. cache attacks)
- Weak user-chosen passwords

---

## Determinism & Test Vectors

- Test vectors are generated once and committed
- No runtime RNG dependence in tests
- ML-DSA key generation uses OpenSSL DRBG
- Regenerating vectors is forbidden

---

## Fuzzing & Hardening

- All serialized inputs are length-checked
- Trailing data is rejected
- Constant-time comparisons are used for key material
- Verify-only secp256k1 context is enforced

---

## Reporting Security Issues

**Please do not open public GitHub issues for security bugs.**

Instead, report vulnerabilities to: gsats0k@gmail.com

Include:
- Description of the issue
- Impact analysis
- Proof-of-concept if available

---

## Supported Versions

Only the **latest released version** is supported with security updates.

---

## License & Disclaimer

This software is provided "as is" without warranty.
Use at your own risk in accordance with applicable laws.
