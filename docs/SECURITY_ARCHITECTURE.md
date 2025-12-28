# Security Architecture

This document provides a comprehensive overview of the security architecture and cryptographic algorithms used throughout QSafeVault.

## Table of Contents
- [Overview](#overview)
- [Cryptographic Algorithms by Area](#cryptographic-algorithms-by-area)
- [Key Hierarchy](#key-hierarchy)
- [Platform Security Layers](#platform-security-layers)
- [Data Protection](#data-protection)
- [Authentication & Authorization](#authentication--authorization)
- [Threat Model](#threat-model)
- [Security Testing](#security-testing)

## Overview

QSafeVault implements a defense-in-depth security architecture with multiple layers:

1. **Encryption Layer** - All sensitive data encrypted at rest
2. **Key Derivation Layer** - Password-based and deterministic key derivation
3. **Secure Storage Layer** - Platform-specific hardware-backed key storage
4. **Transport Layer** - End-to-end encrypted sync
5. **Memory Protection** - Secure zeroization of sensitive data

## Cryptographic Algorithms by Area

### Vault Encryption

| Component | Algorithm | Key Size | Purpose |
|-----------|-----------|----------|---------|
| Vault Data | AES-256-GCM | 256-bit | Authenticated encryption of password entries |
| Master Key | Argon2id | 256-bit output | Password-based key derivation |
| Integrity | HMAC-SHA3-256 | 256-bit | Data integrity verification |

**Why AES-256-GCM?**
- NIST approved for sensitive data
- Provides both confidentiality and authenticity
- Hardware acceleration on modern CPUs
- 128-bit authentication tag prevents tampering

### Password Hashing

| Component | Algorithm | Parameters | Purpose |
|-----------|-----------|------------|---------|
| Master Password | Argon2id | m=64MB, t=3, p=4 | Memory-hard password hashing |
| Fast Unlock | Argon2id | m=16MB, t=1, p=1 | Quick re-authentication |
| Transfer Key | Argon2id | Derived from PIN | Sync encryption key |

**Why Argon2id?**
- Winner of Password Hashing Competition
- Resistant to GPU/ASIC attacks
- Side-channel resistant (id variant)
- Configurable memory/time tradeoffs

### Key Exchange (Post-Quantum)

| Component | Algorithm | Key Size | Purpose |
|-----------|-----------|----------|---------|
| PQC KEM | ML-KEM-768 (Kyber) | 2400-bit secret | Quantum-resistant key encapsulation |
| Classical | X25519 | 256-bit | Elliptic curve Diffie-Hellman |
| Hybrid | HKDF-SHA3-256 | 256-bit output | Combined key derivation |

**Why Hybrid (ML-KEM + X25519)?**
- Quantum-resistant via Kyber (NIST standard)
- Classical security from X25519
- Defense-in-depth: secure even if one is broken
- Combined via HKDF for single shared secret

### Digital Signatures

| Component | Algorithm | Key Size | Purpose |
|-----------|-----------|----------|---------|
| Device Identity | Ed25519 | 256-bit | Device authentication |
| Sync Auth | Ed25519 | 256-bit | Peer verification |

### Platform Secure Storage

| Platform | Technology | Hardware-Backed | Purpose |
|----------|------------|-----------------|---------|
| Linux | TPM 2.0 | Yes | Sealed key storage |
| Linux | SoftHSM2 (PKCS#11) | No | Software HSM fallback |
| Windows | TPM via CNG | Yes | Windows key protection |
| macOS | Secure Enclave | Yes | Hardware key isolation |
| iOS | Secure Enclave | Yes | Hardware key isolation |
| Android | StrongBox Keystore | Yes | Hardware-backed keys |

## Key Hierarchy

```
User Master Password
        │
        ▼ [Argon2id: m=64MB, t=3, p=4]
┌───────────────────────────────────┐
│      Master Key (256-bit)         │
└───────────────────────────────────┘
        │
        ├──▶ [AES-256-GCM] ──▶ Encrypted Vault
        │
        ├──▶ [HMAC-SHA3-256] ──▶ Integrity Verifier
        │
        └──▶ [Hybrid KEM] ──▶ Key Exchange for Sync
                │
                ▼
        ┌───────────────────┐
        │ Hybrid Keypair    │
        │ • ML-KEM-768 (PQC)│
        │ • X25519 (Classical)
        └───────────────────┘
                │
                ▼ [Platform Keystore Sealed]
        ┌───────────────────────────────┐
        │ Sealed Private Key Blob       │
        │ (TPM/Secure Enclave/SoftHSM)  │
        └───────────────────────────────┘
```

## Platform Security Layers

### Linux

```
                    ┌──────────────────────┐
Application ───────▶│   Rust Crypto Engine │
                    └──────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
       ┌───────────┐   ┌───────────┐   ┌───────────┐
       │ TPM 2.0   │   │ SoftHSM2  │   │ Software  │
       │ (tss2)    │   │ (PKCS#11) │   │ Fallback  │
       └───────────┘   └───────────┘   └───────────┘
       Priority: 1      Priority: 2     Priority: 3
```

### Windows

```
                    ┌──────────────────────┐
Application ───────▶│   Rust Crypto Engine │
                    └──────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
       ┌───────────┐   ┌───────────┐   ┌───────────┐
       │ TPM 2.0   │   │ SoftHSM2  │   │ Software  │
       │ (CNG)     │   │ (PKCS#11) │   │ Fallback  │
       └───────────┘   └───────────┘   └───────────┘
```

### macOS / iOS

```
                    ┌──────────────────────┐
Application ───────▶│   Rust Crypto Engine │
                    └──────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
       ┌───────────────────┐         ┌───────────────┐
       │ Secure Enclave    │         │ Software      │
       │ (Security.framework)        │ Fallback      │
       └───────────────────┘         └───────────────┘
```

## Data Protection

### Data at Rest

| Data Type | Protection Method | Location |
|-----------|-------------------|----------|
| Vault entries | AES-256-GCM | Local filesystem |
| Private keys | Platform keystore | TPM/Secure Enclave/SoftHSM |
| Settings | Encrypted JSON | App directory |
| Backups | AES-256-GCM | User-specified |

### Data in Transit

| Channel | Protection | Purpose |
|---------|------------|---------|
| Sync (P2P) | WebRTC DTLS/SRTP | Device sync |
| Sync (Relay) | TLS 1.3 + E2E AES-GCM | Fallback sync |
| API calls | TLS 1.3 | Signaling server |

### Data in Memory

| Protection | Mechanism |
|------------|-----------|
| Zeroization | `zeroize` crate for Rust types |
| No Dart exposure | Keys only in Rust memory |
| Handle-based API | Opaque handles in Flutter |

## Authentication & Authorization

### Master Password Authentication

```
User Input ──▶ [Argon2id] ──▶ Master Key ──▶ [Decrypt Vault]
                                   │
                                   ▼
                            [Verify HMAC] ──▶ Success/Fail
```

### Fast Unlock (Biometric/PIN)

```
Biometric/PIN ──▶ [Platform Keychain] ──▶ Wrapped Key
                                              │
                                              ▼
                                   [Unwrap with Device Key]
                                              │
                                              ▼
                                       Master Key ──▶ Unlock
```

### Peer Authentication (Sync)

```
Device A                           Device B
   │                                  │
   ├──── Ed25519 Public Key ────────▶│
   │◀──── Ed25519 Public Key ────────┤
   │                                  │
   ├──── Signed Challenge ──────────▶│
   │◀──── Signed Response ───────────┤
   │                                  │
   └────── Verified Session ─────────┘
```

## Threat Model

### Threats Addressed

| Threat | Mitigation |
|--------|------------|
| Password guessing | Argon2id with high memory cost |
| Quantum computer attacks | ML-KEM-768 hybrid KEM |
| Memory forensics | Secure zeroization |
| Offline attacks | Hardware-backed key storage |
| Man-in-the-middle | E2E encryption + peer verification |
| Unauthorized access | Master password + optional biometric |
| Data tampering | AEAD (AES-GCM) + HMAC verification |

### Assumptions

- User protects master password
- Device is not rooted/jailbroken
- Operating system is not compromised
- Hardware security modules are trustworthy

### Out of Scope

- Side-channel attacks on user input
- Social engineering attacks
- Physical device theft with unlock
- Malicious Flutter plugins

## Security Testing

### Test Categories

#### Vulnerability Testing
- Static analysis with Clippy and Rust Analyzer
- CodeQL security scanning
- Dependency vulnerability scanning (cargo-audit)

#### Penetration Testing
- FFI boundary testing
- Input validation bypass attempts
- Buffer overflow testing
- Memory leak detection

#### Authentication Testing
- Password strength enforcement
- Brute-force protection
- Session management
- Biometric bypass attempts

#### Data Protection Testing
- Encryption verification
- Key derivation correctness
- Zeroization effectiveness
- Platform keystore integration

### Running Security Tests

```bash
# Rust security tests
cd crypto_engine
cargo test --release

# Static analysis
cargo clippy -- -D warnings

# Dependency audit
cargo audit

# Memory safety with Miri
cargo +nightly miri test
```

## Best Practices for Users

1. **Use a strong master password** - 16+ characters recommended
2. **Enable biometric unlock** - Faster and still secure
3. **Keep devices updated** - Security patches are critical
4. **Verify sync peers** - Check Ed25519 fingerprints
5. **Regular backups** - Encrypted backups to secure storage
6. **Don't share passwords** - Each device should have its own vault

## Future Security Enhancements

- [ ] Hardware-bound key generation (not just storage)
- [ ] Key rotation support
- [ ] Forward secrecy for all sync operations
- [ ] Third-party security audit
- [ ] Bug bounty program
