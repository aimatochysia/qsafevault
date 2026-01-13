# Software Requirements Specification (SRS)

## QSafeVault - Post-Quantum Secure Password Manager

**Version**: 1.0  
**Last Updated**: January 2026  
**Classification**: Technical Documentation

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Overview](#2-system-overview)
3. [Architecture](#3-architecture)
4. [Cryptographic Engine](#4-cryptographic-engine)
5. [Security Model](#5-security-model)
6. [Edition System](#6-edition-system)
7. [Platform Support](#7-platform-support)
8. [Data Storage](#8-data-storage)
9. [Synchronization](#9-synchronization)
10. [API Reference](#10-api-reference)
11. [Dependencies](#11-dependencies)
12. [Testing](#12-testing)
13. [Security Considerations](#13-security-considerations)

---

## 1. Introduction

### 1.1 Purpose

This document specifies the software requirements and technical architecture for QSafeVault, a post-quantum secure password manager.

### 1.2 Scope

QSafeVault is a cross-platform password manager that:

- Stores credentials encrypted locally
- Provides post-quantum cryptographic protection
- Supports peer-to-peer synchronization
- Offers hardware-backed key storage

### 1.3 Definitions

| Term | Definition |
|------|------------|
| PQC | Post-Quantum Cryptography |
| KEM | Key Encapsulation Mechanism |
| AEAD | Authenticated Encryption with Associated Data |
| HSM | Hardware Security Module |
| TPM | Trusted Platform Module |
| FFI | Foreign Function Interface |

---

## 2. System Overview

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Flutter UI Layer                        │
│    (Dart: Pages, Services, State Management, Platform I/O)   │
└─────────────────────┬───────────────────────────────────────┘
                      │ FFI Boundary
┌─────────────────────▼───────────────────────────────────────┐
│                  Rust Cryptographic Engine                   │
│  (PQC: ML-KEM, Dilithium | Symmetric: AES-GCM | Keystore)   │
└─────────────────────┬───────────────────────────────────────┘
                      │ Platform APIs
┌─────────────────────▼───────────────────────────────────────┐
│                   Platform Keystores                         │
│  (TPM2 | Secure Enclave | StrongBox | SoftHSM | Fallback)   │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Component Summary

| Component | Technology | Responsibility |
|-----------|------------|----------------|
| UI Layer | Flutter/Dart | User interface, state, platform I/O |
| Crypto Engine | Rust | All cryptographic operations |
| Keystore | Platform-specific | Secure key storage |
| Sync Server | Node.js | Stateless relay for P2P sync |

---

## 3. Architecture

### 3.1 Flutter Application Layer

```
lib/
├── main.dart                 # Application entry point
├── config/
│   ├── edition_config.dart   # Edition system configuration
│   └── sync_config.dart      # Sync server configuration
├── ffi/
│   ├── crypto_bindings.dart  # Rust FFI bindings
│   └── rust_crypto_service.dart  # High-level crypto API
├── pages/
│   ├── landing_page.dart     # Main vault view
│   ├── entry_page.dart       # Password entry editor
│   └── sync_page.dart        # Synchronization UI
├── services/
│   ├── crypto_service.dart   # Crypto operations wrapper
│   ├── storage_service.dart  # Vault persistence
│   ├── sync_service.dart     # P2P synchronization
│   └── crypto_backend_notifier.dart  # Backend status UI
└── models/
    ├── vault.dart            # Vault data model
    └── entry.dart            # Password entry model
```

### 3.2 Rust Cryptographic Engine

```
crypto_engine/
├── Cargo.toml               # Rust dependencies
├── src/
│   ├── lib.rs               # Library entry point
│   ├── ffi.rs               # C ABI exports
│   ├── edition.rs           # Edition policy enforcement
│   ├── key_provider.rs      # Key management
│   ├── pqc_kem.rs           # ML-KEM 768 (Kyber)
│   ├── pqc_signature.rs     # Dilithium3 signatures
│   ├── classical_kem.rs     # X25519 ECDH
│   ├── hybrid_kem.rs        # PQC + Classical hybrid
│   ├── symmetric.rs         # AES-256-GCM
│   ├── sealed_storage.rs    # Versioned blob format
│   └── platform_keystore/
│       ├── mod.rs           # Keystore abstraction
│       ├── windows_tpm.rs   # Windows TPM2/CNG
│       ├── linux_tpm.rs     # Linux TPM2/tss-esapi
│       ├── ios_secure_enclave.rs
│       ├── macos_secure_enclave.rs
│       ├── android_strongbox.rs
│       ├── softhsm_pkcs11.rs
│       └── fallback_software.rs
└── qsafevault_crypto.h      # C header for FFI
```

### 3.3 Backend Server

```
qsafevault-server/
├── server.js                # Express server entry
├── editionConfig.js         # Edition system
├── sessionManager.js        # Session handling
├── api/
│   ├── relay.js             # Legacy relay endpoint
│   └── v1/
│       ├── sessions/        # Session management
│       └── devices/         # Device registry
├── package.json
└── vercel.json              # Vercel deployment config
```

---

## 4. Cryptographic Engine

### 4.1 Algorithm Summary

| Function | Consumer Edition | Enterprise Edition |
|----------|-----------------|-------------------|
| Key Encapsulation | ML-KEM 768 + X25519 (Hybrid) | AES-256 Key Wrap |
| Digital Signatures | Dilithium3 | ECDSA-P256 |
| Symmetric Encryption | AES-256-GCM | AES-256-GCM |
| Key Derivation | HKDF-SHA3-256 | HKDF-SHA256 |
| Password KDF | Argon2id | PBKDF2-SHA256 |

### 4.2 ML-KEM 768 (Kyber)

NIST FIPS 203 standardized post-quantum Key Encapsulation Mechanism.

| Parameter | Value |
|-----------|-------|
| Security Level | NIST Level 3 |
| Public Key Size | 1184 bytes |
| Secret Key Size | 2400 bytes |
| Ciphertext Size | 1088 bytes |
| Shared Secret | 32 bytes |

### 4.3 Dilithium3

NIST FIPS 204 standardized post-quantum Digital Signature Algorithm.

| Parameter | Value |
|-----------|-------|
| Security Level | NIST Level 3 |
| Public Key Size | 1952 bytes |
| Secret Key Size | 4016 bytes |
| Signature Size | 3293 bytes |

### 4.4 Hybrid Key Encapsulation

Consumer edition combines PQC and classical algorithms for defense-in-depth:

```
┌──────────────────┐     ┌──────────────────┐
│    ML-KEM 768    │     │     X25519       │
│   (Post-Quantum) │     │   (Classical)    │
└────────┬─────────┘     └────────┬─────────┘
         │                        │
         ▼                        ▼
    shared_secret_pq         shared_secret_classical
         │                        │
         └──────────┬─────────────┘
                    │
                    ▼
            HKDF-SHA3-256
                    │
                    ▼
            final_shared_secret (32 bytes)
```

### 4.5 Sealed Blob Format

```
┌──────────────────────────────────────────────────────────┐
│ Version (2 bytes) │ Algorithm ID (2 bytes) │ Timestamp   │
├──────────────────────────────────────────────────────────┤
│ Key ID (32 bytes)                                        │
├──────────────────────────────────────────────────────────┤
│ Nonce (12 bytes for AES-GCM)                             │
├──────────────────────────────────────────────────────────┤
│ Ciphertext (variable)                                    │
├──────────────────────────────────────────────────────────┤
│ Auth Tag (16 bytes for AES-GCM)                          │
└──────────────────────────────────────────────────────────┘
```

---

## 5. Security Model

### 5.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| Quantum computer attacks | ML-KEM 768, Dilithium3 |
| Classical cryptanalysis | X25519 hybrid, AES-256 |
| Memory dumps | Zeroization on drop |
| Key extraction | Hardware keystores (TPM, Secure Enclave) |
| Data tampering | AEAD 128-bit authentication tags |
| Replay attacks | Unique nonces per encryption |
| Man-in-the-middle | End-to-end encryption, device pinning |

### 5.2 Security Boundaries

```
┌─────────────────────────────────────────────────────────┐
│                    Flutter (Dart)                        │
│                 ❌ NOT a security boundary               │
│     - Handles UI only                                    │
│     - Never sees plaintext keys                          │
│     - Only receives opaque handles                       │
└─────────────────────────┬───────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                  Rust FFI Layer                          │
│                 ✅ Security Boundary                     │
│     - All crypto operations here                         │
│     - Edition policy enforcement                         │
│     - Key material never leaves Rust                     │
│     - Automatic zeroization                              │
└─────────────────────────┬───────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                  Platform Keystores                      │
│                 ✅ Hardware-backed when available        │
│     - TPM2, Secure Enclave, StrongBox                   │
│     - Keys bound to device hardware                      │
│     - Non-extractable storage                            │
└─────────────────────────────────────────────────────────┘
```

### 5.3 Key Hierarchy

```
Master Password (user input)
         │
         ▼ Argon2id (m=64MB, t=3, p=4)
         │
    Master Key (32 bytes)
         │
         ├──▶ Vault Encryption (AES-256-GCM)
         │
         ├──▶ Wrapped in Platform Keystore (for fast unlock)
         │
         └──▶ Wrapped via Hybrid KEM (for sync)
                    │
                    ▼
              Sealed Blob (for transmission)
```

### 5.4 Zero-Trust Server Design

The relay server is designed with zero-knowledge principles:

- **No account database**: Server has no user records
- **No key storage**: All keys derived client-side
- **No plaintext access**: Only encrypted blobs handled
- **No persistent storage**: 60-second TTL, memory only
- **No decryption capability**: Missing key material

---

## 6. Edition System

### 6.1 Edition Definitions

| Edition | Crypto Policy | Key Provider | Target |
|---------|--------------|--------------|--------|
| Consumer | PQ + Classical | Local/TPM/SoftHSM | Personal use |
| Enterprise | FIPS-only | External HSM | Regulated environments |

### 6.2 Policy Enforcement

Policy enforcement occurs **only in Rust**, not in Dart/Flutter:

```rust
pub fn is_algorithm_allowed(edition: Edition, algorithm: Algorithm) -> bool {
    match edition {
        Edition::Consumer => true, // All algorithms allowed
        Edition::Enterprise => matches!(
            algorithm,
            Algorithm::Aes256Gcm |
            Algorithm::Sha256 |
            Algorithm::HkdfSha256 |
            Algorithm::Pbkdf2Sha256
        ),
    }
}
```

### 6.3 Configuration

**Flutter (build-time)**:
```bash
flutter run --dart-define=QSAFEVAULT_EDITION=enterprise
```

**Rust FFI (runtime)**:
```rust
pqcrypto_initialize_edition(1); // 0=Consumer, 1=Enterprise
```

**Server (environment)**:
```bash
export QSAFEVAULT_EDITION=enterprise
export QSAFEVAULT_ENTERPRISE_ACKNOWLEDGED=true
```

---

## 7. Platform Support

### 7.1 Platform Matrix

| Platform | Status | Keystore | Notes |
|----------|--------|----------|-------|
| Windows | ✅ Stable | TPM2/CNG | Windows 10+ |
| Linux | ✅ Stable | TPM2/tss-esapi | Ubuntu 20.04+ |
| Android | ✅ Stable | StrongBox | API 26+ |
| macOS | ⚠️ Beta | Secure Enclave | macOS 11+ |
| iOS | ⚠️ Beta | Secure Enclave | iOS 14+ |
| Web | ⚠️ Limited | None | Reduced functionality |

### 7.2 Keystore Priority

Auto-detection selects the best available keystore:

1. **Dual-Sealing** (TPM2 + SoftHSM): Maximum security
2. **TPM2 only**: Hardware-backed
3. **SoftHSM only**: PKCS#11 simulation
4. **Platform Native**: Secure Enclave, StrongBox
5. **Software Fallback**: Encrypted filesystem

---

## 8. Data Storage

### 8.1 Vault Format

```json
{
  "version": 2,
  "created": "2026-01-13T00:00:00Z",
  "modified": "2026-01-13T00:00:00Z",
  "entries": [
    {
      "id": "uuid-v4",
      "title": "Example",
      "username": "user@example.com",
      "password": "encrypted-blob",
      "url": "https://example.com",
      "notes": "encrypted-blob",
      "created": "2026-01-13T00:00:00Z",
      "modified": "2026-01-13T00:00:00Z"
    }
  ]
}
```

### 8.2 Storage Locations

| Platform | Location |
|----------|----------|
| Windows | `%APPDATA%\qsafevault\` |
| Linux | `~/.local/share/qsafevault/` |
| macOS | `~/Library/Application Support/qsafevault/` |
| Android | Internal app storage |
| iOS | App container (Keychain for keys) |

### 8.3 File Structure

```
qsafevault/
├── vault.json.enc          # Encrypted vault data
├── vault.json.enc.backup   # Backup of previous vault
├── config.json             # Non-sensitive settings
├── device_identity.pub     # Dilithium3 public key
└── logs/                   # Debug logs (no secrets)
```

---

## 9. Synchronization

### 9.1 Protocol Overview

```
┌─────────┐                    ┌─────────┐                    ┌─────────┐
│ Sender  │                    │ Relay   │                    │Receiver │
└────┬────┘                    └────┬────┘                    └────┬────┘
     │                              │                              │
     │  POST /api/send              │                              │
     │  {pin, passwordHash, chunk}  │                              │
     │─────────────────────────────▶│                              │
     │                              │                              │
     │                              │      GET /api/receive        │
     │                              │◀─────────────────────────────│
     │                              │                              │
     │                              │      {status, chunk}         │
     │                              │─────────────────────────────▶│
     │                              │                              │
     │  (chunks deleted after TTL)  │                              │
```

### 9.2 Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/relay` | POST | Legacy relay endpoint |
| `/api/v1/sessions` | POST | Create sync session |
| `/api/v1/sessions/:id/offer` | POST/GET | Exchange SDP offer |
| `/api/v1/sessions/:id/answer` | POST/GET | Exchange SDP answer |
| `/api/v1/edition` | GET | Server edition info |

### 9.3 Security Properties

- **End-to-end encryption**: Vault encrypted before transmission
- **Transfer key derivation**: Argon2id(PIN + password + salt)
- **60-second TTL**: Chunks auto-expire
- **Stateless relay**: No persistent storage
- **Forward secrecy**: Ephemeral keys per session

---

## 10. API Reference

### 10.1 FFI Functions

#### Key Generation

```c
// Generate hybrid keypair (PQC + Classical)
int pqcrypto_generate_hybrid_keypair(
    uint64_t* out_handle,
    uint8_t** out_pqc_public_key,
    size_t* out_pqc_public_key_len,
    uint8_t** out_classical_public_key,
    size_t* out_classical_public_key_len
);

// Generate signing keypair (Dilithium3)
int pqcrypto_generate_signing_keypair(
    uint64_t* out_handle,
    uint8_t** out_public_key,
    size_t* out_public_key_len
);
```

#### Encryption/Decryption

```c
// Encrypt master key with hybrid KEM
int pqcrypto_hybrid_encrypt_master_key(
    const uint8_t* pqc_public_key,
    size_t pqc_public_key_len,
    const uint8_t* classical_public_key,
    size_t classical_public_key_len,
    const uint8_t* master_key,
    size_t master_key_len,
    uint8_t** out_sealed_blob,
    size_t* out_sealed_blob_len
);

// Decrypt master key with hybrid KEM
int pqcrypto_hybrid_decrypt_master_key(
    uint64_t keypair_handle,
    const uint8_t* sealed_blob,
    size_t sealed_blob_len,
    uint8_t** out_master_key,
    size_t* out_master_key_len
);
```

#### Vault Operations

```c
// Encrypt vault data
int pqcrypto_encrypt_vault(
    const uint8_t* master_key,
    size_t master_key_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t** out_sealed,
    size_t* out_sealed_len
);

// Decrypt vault data
int pqcrypto_decrypt_vault(
    const uint8_t* master_key,
    size_t master_key_len,
    const uint8_t* sealed,
    size_t sealed_len,
    uint8_t** out_plaintext,
    size_t* out_plaintext_len
);
```

### 10.2 Status Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| -1 | General error |
| -2 | Invalid parameter |
| -3 | Not found |
| -10 | Edition not initialized |
| -11 | Edition already initialized |
| -20 | FIPS violation |
| -21 | PQ disabled (Enterprise) |
| -22 | HSM required (Enterprise) |
| -23 | SoftHSM prohibited (Enterprise) |
| -30 | Server edition mismatch |

---

## 11. Dependencies

### 11.1 Rust Crates

| Crate | Version | Purpose |
|-------|---------|---------|
| pqcrypto-mlkem | 0.8+ | ML-KEM 768 (Kyber) |
| pqcrypto-dilithium | 0.5+ | Dilithium3 signatures |
| x25519-dalek | 2.0+ | X25519 ECDH |
| aes-gcm | 0.10+ | AES-256-GCM |
| hkdf | 0.12+ | HKDF key derivation |
| sha3 | 0.10+ | SHA3-256 |
| zeroize | 1.6+ | Secure memory clearing |

### 11.2 Flutter Packages

| Package | Version | Purpose |
|---------|---------|---------|
| ffi | 2.0+ | Dart FFI support |
| path_provider | 2.0+ | Platform directories |
| flutter_secure_storage | 9.0+ | Secure storage |
| cryptography | 2.5+ | Fallback crypto (legacy) |

### 11.3 Server Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| express | 4.18+ | HTTP server |
| uuid | 9.0+ | UUID generation |

---

## 12. Testing

### 12.1 Test Categories

| Category | Location | Coverage |
|----------|----------|----------|
| Rust Unit Tests | `crypto_engine/src/*.rs` | Crypto algorithms |
| Dart Unit Tests | `test/` | Services, models |
| Integration Tests | `test/integration/` | FFI boundary |
| E2E Tests | `test/e2e/` | Full workflows |

### 12.2 Running Tests

```bash
# Rust tests
cd crypto_engine
cargo test

# Flutter tests
flutter test

# Integration tests
flutter test integration_test/
```

### 12.3 Security Tests

Located in `crypto_engine/src/security_tests.rs`:

- Key zeroization verification
- Nonce uniqueness tests
- Algorithm policy enforcement
- Handle-based API validation

---

## 13. Security Considerations

### 13.1 Immediate Security Benefits

- **Post-Quantum Security**: Protection against future quantum attacks
- **Memory Safety**: Rust prevents memory bugs
- **Zeroization**: Automatic clearing of sensitive data
- **Hardware Integration**: Platform keystores when available

### 13.2 Known Limitations

1. **Platform Keystores**: Vary by platform; some use fallback
2. **Cross-Compilation**: Manual setup for mobile targets
3. **Web Platform**: Limited crypto functionality
4. **Enterprise HSM**: Placeholder implementation

### 13.3 Security Audit Status

| Component | Status |
|-----------|--------|
| Crypto algorithms | ✅ Uses audited libraries |
| FFI boundary | 🔄 Internal review |
| Key management | 🔄 Internal review |
| Side-channel analysis | ❌ Not yet performed |
| Penetration testing | ❌ Not yet performed |

### 13.4 Recommended Before Production

- [ ] Professional cryptographic review
- [ ] Security audit of FFI boundary
- [ ] Side-channel analysis
- [ ] Penetration testing
- [ ] Fuzzing campaigns

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| AEAD | Authenticated Encryption with Associated Data |
| CNG | Cryptography Next Generation (Windows API) |
| FIPS | Federal Information Processing Standards |
| HSM | Hardware Security Module |
| KEM | Key Encapsulation Mechanism |
| ML-KEM | Module-Lattice Key Encapsulation Mechanism (Kyber) |
| PKCS#11 | Cryptographic Token Interface Standard |
| PQC | Post-Quantum Cryptography |
| TPM | Trusted Platform Module |

---

## Appendix B: References

- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/publications/detail/fips/203/final)
- [NIST FIPS 204: ML-DSA (Dilithium)](https://csrc.nist.gov/publications/detail/fips/204/final)
- [RFC 9106: Argon2](https://www.rfc-editor.org/rfc/rfc9106)
- [NIST SP 800-56C: Key Derivation](https://csrc.nist.gov/publications/detail/sp/800-56c/rev-2/final)

---

*Document Version: 1.0 | Last Updated: January 2026*
