# QSafeVault Cryptographic Backend Architecture

## Overview
This document describes the hybrid post-quantum + classical cryptographic backend implemented in Rust for the QSafeVault password manager.

## Architecture

### 1. Rust Cryptographic Core

The Rust backend (`crypto_engine/`) provides all cryptographic operations through a C FFI interface.

#### Core Modules

**pqc_kem.rs** - Post-Quantum Cryptography
- Implements Kyber ML-KEM 768 (NIST standardized post-quantum KEM)
- Key generation, encapsulation, and decapsulation
- Provides quantum-resistant key establishment

**classical_kem.rs** - Classical Cryptography
- Implements X25519 Elliptic Curve Diffie-Hellman
- Provides classical ECDH key agreement
- Complements PQC for defense-in-depth

**hybrid_kem.rs** - Hybrid Key Establishment
- Combines PQC (Kyber) + Classical (X25519) using HKDF-SHA3
- Derives a single shared secret from both key establishment mechanisms
- Ensures security even if one mechanism is broken

**symmetric.rs** - Symmetric Encryption
- AES-256-GCM authenticated encryption
- Random nonce generation per encryption
- Authenticated encryption with associated data (AEAD)

**sealed_storage.rs** - Versioned Sealed Blobs
- Deterministic blob format with version, algorithm ID, timestamp, and key ID
- Supports multiple algorithm identifiers
- Forward-compatible versioning for crypto agility

**platform_keystore/** - Platform-Specific Secure Storage
- **ios_secure_enclave.rs**: iOS Keychain with Secure Enclave integration
- **macos_secure_enclave.rs**: macOS Keychain with T2/Secure Enclave support
- **android_strongbox.rs**: Android StrongBox Keystore (requires JNI - stub for now)
- **windows_tpm.rs**: Windows TPM2 via CNG/KSP (requires Windows APIs - stub for now)
- **linux_tpm.rs**: Linux TPM2 via tpm2-tss (requires system libraries - stub for now)
- **fallback_software.rs**: Software fallback with filesystem-based storage

**ffi.rs** - Foreign Function Interface
- C ABI exports for Flutter FFI integration
- Handle-based API (no direct key material exposure)
- Error handling with status codes and error messages

### 2. Flutter Integration Layer

#### Dart FFI Wrapper (`lib/ffi/`)

**crypto_bindings.dart**
- Defines native function signatures
- Platform-specific library loading
- Status code constants

**rust_crypto_service.dart**
- High-level Dart API wrapping Rust FFI
- Memory management (allocation/deallocation)
- Type conversions between Dart and C types
- Error handling

### 3. API Functions

All cryptographic operations are accessed through these FFI functions:

1. **pqcrypto_generate_hybrid_keypair()**
   - Generates PQC + Classical keypair
   - Returns handle and public keys
   - Private keys stored in Rust memory

2. **pqcrypto_hybrid_encrypt_master_key()**
   - Encapsulates to recipient's public keys
   - Derives shared secret via hybrid KEM
   - Encrypts master key with AES-256-GCM

3. **pqcrypto_hybrid_decrypt_master_key()**
   - Decapsulates ciphertext with private keys
   - Derives same shared secret
   - Decrypts master key

4. **pqcrypto_seal_private_key_with_platform_keystore()**
   - Serializes private keys
   - Stores in platform-specific secure storage
   - Attempts hardware-backed storage first, falls back to software

5. **pqcrypto_unseal_private_key_from_platform_keystore()**
   - Retrieves sealed private keys
   - Reconstructs keypair with public keys
   - Returns handle for use

6. **pqcrypto_encrypt_vault()**
   - Encrypts vault data with AES-256-GCM
   - Uses master key (32 bytes)
   - Returns sealed blob with metadata

7. **pqcrypto_decrypt_vault()**
   - Decrypts sealed blob
   - Verifies authentication tag
   - Returns plaintext

8. **pqcrypto_free_handle()**
   - Frees keypair/key handle
   - Zeroizes sensitive data

### 4. Security Properties

#### Key Management
- **No Key Material in Flutter**: All keys exist only in Rust memory
- **Handle-Based API**: Flutter only receives opaque handles
- **Automatic Zeroization**: Sensitive data cleared on drop
- **Secure Memory**: Rust types use zeroize crate

#### Cryptographic Strength
- **Post-Quantum Secure**: Kyber ML-KEM protects against quantum attacks
- **Classical Fallback**: X25519 provides present-day security
- **Hybrid Construction**: Combined security from both mechanisms
- **Authenticated Encryption**: AES-GCM prevents tampering

#### Platform Security
- **Hardware-Backed Storage**: Uses Secure Enclave, StrongBox, TPM when available
- **Software Fallback**: File-based storage with restricted permissions
- **Graceful Degradation**: Attempts best available security

### 5. Key Hierarchy

```
Master Password (user input)
    ↓ (Argon2id KDF - existing Flutter logic)
Master Key (32 bytes, symmetric)
    ↓ (Rust: AES-256-GCM encryption)
Vault Data (password entries, encrypted at rest)

For key exchange/backup:
Hybrid Keypair (PQC + Classical, generated in Rust)
    ↓ (Rust: Hybrid KEM with HKDF-SHA3)
Shared Secret (32 bytes)
    ↓ (Rust: AES-256-GCM key wrapping)
Wrapped Master Key (sealed blob)
```

### 6. Build Process

#### Rust Library
```bash
cd crypto_engine
cargo build --release
```

Produces:
- Linux: `libcrypto_engine.so`
- macOS: `libcrypto_engine.dylib`
- Windows: `crypto_engine.dll`
- iOS: Static library or XCFramework
- Android: JNI `.so` for multiple architectures

#### Flutter Integration
The `lib/ffi/rust_crypto_service.dart` loads the appropriate library per platform.

### 7. Migration Path

To migrate from existing Dart crypto to Rust backend:

1. **Keep Existing Logic**: Current password-based vault unlock continues to work
2. **Add Hybrid Keypair**: Generate PQC+Classical keypair for future features
3. **Seal Private Keys**: Store in platform keystore
4. **Enable Key Exchange**: Support encrypted vault sharing via hybrid KEM
5. **Deprecate Dart Crypto**: Phase out Dart cryptographic code over time

### 8. Future Enhancements

#### Platform Keystore Integration
- Full Android StrongBox implementation via JNI
- Full Windows TPM2 integration via CNG
- Full Linux TPM2 integration via tss-esapi
- Hardware key generation (not just storage)

#### Additional Features
- Key rotation support
- Multiple device keypairs
- Backup and recovery mechanisms
- Forward secrecy for vault sharing

#### Security Audits
- Professional cryptographic review
- Side-channel analysis
- Fuzzing and penetration testing

### 9. Testing

#### Rust Unit Tests
```bash
cd crypto_engine
cargo test
```

Tests cover:
- PQC key generation and encapsulation
- Classical ECDH key agreement
- Hybrid KEM derivation
- AES-GCM encryption/decryption
- Sealed blob serialization

#### Integration Tests
- FFI boundary testing
- Memory leak detection
- Error handling verification

### 10. Dependencies

**Rust Crates:**
- `pqcrypto-mlkem`: Kyber ML-KEM implementation
- `x25519-dalek`: X25519 ECDH
- `aes-gcm`: AES-256-GCM
- `hkdf` + `sha3`: Key derivation
- `zeroize`: Secure memory clearing
- `serde` + `bincode`: Serialization
- `security-framework` (iOS/macOS): Keychain access
- Platform-specific crates for TPM, etc.

**Flutter Packages:**
- `ffi`: Dart FFI support

### 11. Security Considerations

#### Threat Model
- Protects against quantum computer attacks (via PQC)
- Protects against classical cryptanalytic attacks (via X25519)
- Protects against memory dumps (via zeroization)
- Protects against unauthorized access (via platform keystores)

#### Limitations
- Platform keystore stubs require full implementation
- Software fallback is less secure than hardware storage
- Flutter UI still handles encrypted blobs (not raw keys)

#### Best Practices
- Never log sensitive data
- Always validate input lengths
- Check all FFI return codes
- Free all allocated memory
- Zeroize before freeing

## Conclusion

This architecture provides a production-grade cryptographic backend with hybrid post-quantum security, platform-specific secure storage, and clean separation between UI (Flutter) and cryptography (Rust). The FFI boundary ensures no key material leaks to the Dart layer, and all sensitive operations are handled in Rust's memory-safe environment.
