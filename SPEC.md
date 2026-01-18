# QSafeVault Software Specification

**Version**: 2.0  
**Last Updated**: January 2026  
**Classification**: Technical Specification

---

## 1. Overview

QSafeVault is a post-quantum secure password manager implementing **FIPS 203/204/205 certified** cryptographic algorithms. All cryptographic operations use NIST-standardized, FIPS-certified algorithms only.

### 1.1 Core Principles

- **FIPS-only cryptography**: All algorithms are FIPS-approved
- **Post-quantum security**: FIPS 203/204/205 certified algorithms
- **Zero-knowledge architecture**: Server never stores plaintext or keys
- **Local-first storage**: All vault data stored locally on user devices
- **Open source**: All components are open source

---

## 2. Cryptographic Algorithms

### 2.1 FIPS-Certified Post-Quantum Algorithms

| Function | Algorithm | Standard | Security Level |
|----------|-----------|----------|----------------|
| Key Encapsulation | **ML-KEM-1024** | NIST FIPS 203 | Level 5 (highest) |
| Digital Signatures | **ML-DSA-65** | NIST FIPS 204 | Level 3 |
| Hash-Based Signatures | **SLH-DSA-SHA2-128s** | NIST FIPS 205 | Level 1 |

### 2.2 FIPS-Certified Classical Algorithms

| Function | Algorithm | Standard |
|----------|-----------|----------|
| Symmetric Encryption | AES-256-GCM | FIPS 197 |
| Key Derivation | HKDF-SHA256 | NIST SP 800-56C |
| Password KDF | PBKDF2-HMAC-SHA256 | NIST SP 800-132 |
| Hash Function | SHA-256/384 | FIPS 180-4 |

### 2.3 Algorithm Enforcement

All algorithms in the system are FIPS-approved. Both Consumer and Enterprise editions use the same FIPS-certified algorithms:

| Algorithm | Consumer | Enterprise |
|-----------|----------|------------|
| ML-KEM-1024 (FIPS 203) | ✅ Enabled | ✅ Enabled |
| ML-DSA-65 (FIPS 204) | ✅ Enabled | ✅ Enabled |
| SLH-DSA (FIPS 205) | ✅ Enabled | ✅ Enabled |
| AES-256-GCM | ✅ Enabled | ✅ Enabled |
| HKDF-SHA256 | ✅ Enabled | ✅ Enabled |
| PBKDF2-HMAC-SHA256 | ✅ Enabled | ✅ Enabled |

---

## 3. Architecture

### 3.1 System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      Flutter UI Layer                        │
│    (Dart: Pages, Services, State Management, Platform I/O)   │
└─────────────────────┬───────────────────────────────────────┘
                      │ FFI Boundary
┌─────────────────────▼───────────────────────────────────────┐
│                  Rust Cryptographic Engine                   │
│  (FIPS 203/204/205: ML-KEM, ML-DSA, SLH-DSA | AES-GCM)      │
└─────────────────────┬───────────────────────────────────────┘
                      │ Platform APIs
┌─────────────────────▼───────────────────────────────────────┐
│                   Platform Keystores                         │
│  (TPM2 | Secure Enclave | StrongBox | External HSM)         │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Security Boundary

The Rust FFI layer is the sole security enforcement point:

- All algorithm selection happens in Rust
- All key generation and storage happens in Rust
- All policy enforcement happens in Rust
- Flutter treats Rust errors as FATAL

### 3.3 Component Summary

| Component | Technology | Responsibility |
|-----------|------------|----------------|
| UI Layer | Flutter/Dart | User interface, state, platform I/O |
| Crypto Engine | Rust | All cryptographic operations (FIPS-only) |
| Keystore | Platform-specific | Secure key storage |
| Sync Server | Node.js | Stateless relay for P2P sync |

---

## 4. Edition System

### 4.1 Edition Definitions

| Edition | Crypto Policy | Key Provider | HSM Requirement |
|---------|--------------|--------------|-----------------|
| Consumer | FipsApproved | Local/TPM/SoftHSM | Optional |
| Enterprise | FipsApproved | External HSM | Required |

### 4.2 Consumer Edition

- **Algorithms**: FIPS 203/204/205 post-quantum + classical FIPS
- **Key providers**: Local software, TPM, Secure Enclave, SoftHSM (all allowed)
- **Deployment**: Public or self-hosted allowed

### 4.3 Enterprise Edition

- **Algorithms**: FIPS 203/204/205 post-quantum + classical FIPS
- **Key providers**: External HSM REQUIRED, SoftHSM PROHIBITED
- **Deployment**: Self-hosted ONLY

---

## 5. Key Management

### 5.1 Key Hierarchy

1. **Master Key**: 256-bit symmetric key, protected by ML-KEM-1024
2. **Vault Key**: Derived from master key using HKDF-SHA256
3. **Entry Keys**: Per-entry keys derived from vault key

### 5.2 Key Storage

| Platform | Backend | Security Level |
|----------|---------|----------------|
| Windows | TPM 2.0 | Hardware-backed |
| Linux | TPM 2.0 / SoftHSM | Hardware/Software |
| macOS | Secure Enclave | Hardware-backed |
| iOS | Secure Enclave | Hardware-backed |
| Android | StrongBox | Hardware-backed |

---

## 6. Data Storage

### 6.1 Vault Format

Vaults are stored locally using the SealedBlob format:

```
SealedBlob {
    metadata: BlobMetadata {
        version: BlobVersion::V2,
        algorithm: AlgorithmId::MlKem1024,
        created_at: u64,
        key_id: Option<String>,
        backend: BackendType,
    },
    ciphertext: Vec<u8>,
}
```

### 6.2 Algorithm IDs

| ID | Algorithm |
|----|-----------|
| MlKem1024 | FIPS 203: ML-KEM-1024 |
| MlDsa65 | FIPS 204: ML-DSA-65 |
| SlhDsaSha2128s | FIPS 205: SLH-DSA |
| Aes256Gcm | FIPS: AES-256-GCM |

---

## 7. Synchronization

### 7.1 Protocol

- Peer-to-peer synchronization with end-to-end encryption
- Server acts as stateless relay only
- All data encrypted with ML-KEM-1024 before transmission

### 7.2 Server Requirements

| Edition | Server |
|---------|--------|
| Consumer | Public relay or self-hosted |
| Enterprise | Self-hosted ONLY |

---

## 8. FFI API

### 8.1 Status Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | STATUS_OK | Success |
| -1 | STATUS_ERROR | General error |
| -2 | STATUS_INVALID_PARAM | Invalid parameter |
| -10 | STATUS_EDITION_NOT_INITIALIZED | Edition not initialized |
| -11 | STATUS_EDITION_ALREADY_INITIALIZED | Edition already set |
| -22 | STATUS_HSM_REQUIRED | External HSM required |
| -23 | STATUS_SOFTHSM_PROHIBITED | SoftHSM not allowed |
| -30 | STATUS_SERVER_EDITION_MISMATCH | Edition mismatch |

### 8.2 Core Functions

```c
// Edition
int pqcrypto_initialize_edition(int edition, char** error);
int pqcrypto_get_edition(int* edition, char** error);
int pqcrypto_is_edition_initialized();

// Key Generation (ML-KEM-1024, FIPS 203)
int pqcrypto_generate_keypair(uint64_t* handle, uint8_t** pk, size_t* pk_len, char** error);
int pqcrypto_encrypt_master_key(uint8_t* pk, size_t pk_len, uint8_t* mk, uint8_t** blob, size_t* blob_len, char** error);
int pqcrypto_decrypt_master_key(uint64_t handle, uint8_t* blob, size_t blob_len, uint8_t* mk, char** error);

// Signing (ML-DSA-65, FIPS 204)
int pqcrypto_generate_signing_keypair(uint64_t* handle, uint8_t** pk, size_t* pk_len, char** error);
int pqcrypto_sign_message(uint64_t handle, uint8_t* msg, size_t msg_len, uint8_t** sig, size_t* sig_len, char** error);
int pqcrypto_verify_signature(uint8_t* pk, size_t pk_len, uint8_t* msg, size_t msg_len, uint8_t* sig, size_t sig_len, int* valid, char** error);

// Symmetric Encryption (AES-256-GCM)
int pqcrypto_encrypt_vault(uint8_t* mk, uint8_t* data, size_t len, uint8_t** blob, size_t* blob_len, char** error);
int pqcrypto_decrypt_vault(uint8_t* mk, uint8_t* blob, size_t blob_len, uint8_t** data, size_t* len, char** error);

// Key Derivation (HKDF-SHA256)
int pqcrypto_derive_key_hkdf(uint8_t* ikm, size_t ikm_len, uint8_t* salt, size_t salt_len, uint8_t* info, size_t info_len, size_t okm_len, uint8_t** okm, char** error);
```

---

## 9. Platform Support

### 9.1 Desktop

| Platform | Minimum Requirements |
|----------|---------------------|
| Windows | Windows 10/11, 64-bit |
| Linux | Ubuntu 20.04+ or equivalent |
| macOS | macOS 11+ (Big Sur) |

### 9.2 Mobile

| Platform | Minimum Requirements |
|----------|---------------------|
| Android | Android 8.0+ (API 26) |
| iOS | iOS 14+ |

---

## 10. Testing

### 10.1 Test Categories

1. **Unit Tests**: Cryptographic operation validation
2. **Security Tests**: Vulnerability, penetration, authentication tests
3. **Integration Tests**: Cross-platform functionality
4. **Live Tests**: Server connectivity and sync tests

### 10.2 Running Tests

```bash
# Crypto engine tests
cd crypto_engine && cargo test

# Server tests
cd qsafevault-server && npm test
```

---

## 11. Version Information

Query version and algorithm information:

```json
{
  "version": "0.1.0",
  "algorithms": {
    "kem": "ML-KEM-1024 (FIPS 203)",
    "signature": "ML-DSA-65 (FIPS 204)",
    "hash_signature": "SLH-DSA-SHA2-128s (FIPS 205)",
    "kdf": "HKDF-SHA256",
    "cipher": "AES-256-GCM",
    "hash": "SHA-256"
  },
  "fips_203": true,
  "fips_204": true,
  "fips_205": true,
  "fips_only": true,
  "post_quantum": true
}
```
