# QSafeVault Cryptographic Backend Architecture

## Overview
This document describes the **fully post-quantum** cryptographic backend implemented in Rust for the QSafeVault password manager. **All cryptographic operations are post-quantum safe**, with no classical-only algorithms remaining in security-critical paths.

## Post-Quantum Algorithm Summary

| Function | Algorithm | Standard | Security Level |
|----------|-----------|----------|----------------|
| Key Encapsulation | ML-KEM 768 (Kyber) | NIST FIPS 203 | Level 3 |
| Digital Signatures | Dilithium3 | NIST FIPS 204 | Level 3 |
| Symmetric Encryption | AES-256-GCM | NIST | 256-bit |
| Key Derivation | HKDF-SHA3-256 | NIST SP 800-56C | 256-bit |
| Password KDF | Argon2id | RFC 9106 | Memory-hard |

## Architecture

### 1. Rust Cryptographic Core

The Rust backend (`crypto_engine/`) provides all cryptographic operations through a C FFI interface.

#### Core Modules

**pqc_kem.rs** - Post-Quantum Key Encapsulation
- Implements Kyber ML-KEM 768 (NIST standardized post-quantum KEM)
- Key generation, encapsulation, and decapsulation
- Provides quantum-resistant key establishment
- 2400-byte public keys, 3168-byte ciphertexts

**pqc_signature.rs** - Post-Quantum Digital Signatures
- Implements Dilithium3 (NIST standardized post-quantum signatures)
- Key generation, signing, and verification
- Device identity and sync authentication
- 1952-byte public keys, 3293-byte signatures

**classical_kem.rs** - Classical Cryptography (Hybrid Mode)
- Implements X25519 Elliptic Curve Diffie-Hellman
- Used in hybrid mode combined with PQC for defense-in-depth
- Provides classical ECDH key agreement as backup

**hybrid_kem.rs** - Hybrid Key Establishment
- Combines PQC (Kyber) + Classical (X25519) using HKDF-SHA3
- Derives a single shared secret from both key establishment mechanisms
- Ensures security even if one mechanism is broken (belt-and-suspenders)

**symmetric.rs** - Symmetric Encryption
- AES-256-GCM authenticated encryption
- Random 96-bit nonce generation per encryption (unique nonces guaranteed)
- 128-bit authentication tag for integrity
- Authenticated encryption with associated data (AEAD)

**sealed_storage.rs** - Versioned Sealed Blobs
- Deterministic blob format with version, algorithm ID, timestamp, and key ID
- Supports multiple algorithm identifiers
- Forward-compatible versioning for crypto agility

**platform_keystore/** - Platform-Specific Secure Storage
- **ios_secure_enclave.rs**: iOS Keychain with Secure Enclave integration
- **macos_secure_enclave.rs**: macOS Keychain with T2/Secure Enclave support
- **android_strongbox.rs**: Android StrongBox Keystore
- **windows_tpm.rs**: Windows TPM2 via CNG/KSP
- **linux_tpm.rs**: Linux TPM2 via tpm2-tss
- **softhsm_pkcs11.rs**: SoftHSM PKCS#11 support
- **fallback_software.rs**: Software fallback with filesystem-based storage

**ffi.rs** - Foreign Function Interface
- C ABI exports for Flutter FFI integration
- Handle-based API (no direct key material exposure)
- Error handling with status codes and error messages
- Exports for: keypair generation, encryption, decryption, signing, verification

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

#### Key Encapsulation (KEM)

1. **pqcrypto_generate_hybrid_keypair()**
   - Generates PQC (Kyber) + Classical (X25519) keypair
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

#### Digital Signatures (Dilithium3)

4. **pqcrypto_generate_signing_keypair()**
   - Generates Dilithium3 signing keypair
   - Returns handle and public key
   - Private key stored in Rust memory

5. **pqcrypto_sign_message()**
   - Signs message with Dilithium3 private key
   - Returns detached signature bytes
   - Constant-time operations

6. **pqcrypto_verify_signature()**
   - Verifies Dilithium3 signature against public key
   - Returns validity status
   - Rejects tampered messages

7. **pqcrypto_get_signing_public_key()**
   - Retrieves public key from signing keypair handle

#### Platform Keystore

8. **pqcrypto_seal_private_key_with_platform_keystore()**
   - Serializes private keys
   - Stores in platform-specific secure storage
   - Attempts hardware-backed storage first, falls back to software

9. **pqcrypto_unseal_private_key_from_platform_keystore()**
   - Retrieves sealed private keys
   - Reconstructs keypair with public keys
   - Returns handle for use

#### Vault Encryption

10. **pqcrypto_encrypt_vault()**
    - Encrypts vault data with AES-256-GCM
    - Uses master key (32 bytes)
    - Returns sealed blob with metadata

11. **pqcrypto_decrypt_vault()**
    - Decrypts sealed blob
    - Verifies 128-bit authentication tag
    - Returns plaintext

#### Key Derivation & Utilities

12. **pqcrypto_derive_key_hkdf()**
    - Derives keys using HKDF-SHA3-256
    - Used for key derivation from PQ KEM output

13. **pqcrypto_generate_random_bytes()**
    - Generates cryptographically secure random bytes
    - Uses OS CSPRNG

14. **pqcrypto_get_version()**
    - Returns crypto engine version and algorithm info

15. **pqcrypto_get_backend_info()**
    - Returns platform keystore backend status

#### Memory Management

16. **pqcrypto_free_handle()**
    - Frees keypair/key handle
    - Zeroizes sensitive data

17. **pqcrypto_free_signing_keypair()**
    - Frees signing keypair handle
    - Zeroizes secret key material

18. **pqcrypto_free_memory() / pqcrypto_free_string()**
    - Frees memory allocated by Rust

### 4. Security Properties

#### Key Management
- **No Key Material in Flutter**: All keys exist only in Rust memory
- **Handle-Based API**: Flutter only receives opaque handles
- **Automatic Zeroization**: Sensitive data cleared on drop
- **Secure Memory**: Rust types use zeroize crate

#### Cryptographic Strength
- **Post-Quantum KEM**: Kyber ML-KEM 768 protects against quantum attacks
- **Post-Quantum Signatures**: Dilithium3 provides quantum-resistant authentication
- **Hybrid Construction**: Combined PQ+Classical security for defense-in-depth
- **Authenticated Encryption**: AES-256-GCM with 128-bit tags prevents tampering
- **Unique Nonces**: Random 96-bit nonces per encryption (never reused)

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
- Dilithium3 signing and verification
- Sealed blob serialization

#### Integration Tests
- FFI boundary testing
- Memory leak detection
- Error handling verification

### 10. Dependencies

**Rust Crates:**
- `pqcrypto-mlkem`: Kyber ML-KEM 768 (post-quantum KEM)
- `pqcrypto-dilithium`: Dilithium3 (post-quantum signatures)
- `pqcrypto-traits`: Common PQC traits
- `x25519-dalek`: X25519 ECDH (hybrid mode)
- `aes-gcm`: AES-256-GCM authenticated encryption
- `hkdf` + `sha3`: HKDF-SHA3-256 key derivation
- `zeroize`: Secure memory clearing
- `serde` + `bincode`: Serialization
- `security-framework` (iOS/macOS): Keychain access
- `windows` (Windows): CNG/TPM access
- `pkcs11` (Linux/macOS): SoftHSM support

**Flutter Packages:**
- `ffi`: Dart FFI support

### 11. Security Considerations

#### Threat Model
- Protects against quantum computer attacks (via Kyber ML-KEM and Dilithium3)
- Protects against classical cryptanalytic attacks (via hybrid mode with X25519)
- Protects against memory dumps (via zeroization)
- Protects against unauthorized access (via platform keystores)
- Protects against tampering (via 128-bit authentication tags)
- Protects against replay attacks (via unique nonces)

#### Limitations
- Platform keystore implementations vary by platform
- Software fallback is less secure than hardware storage
- Flutter UI still handles encrypted blobs (not raw keys)

#### Best Practices
- Never log sensitive data
- Always validate input lengths
- Check all FFI return codes
- Free all allocated memory
- Zeroize before freeing
- Use constant-time operations for security-critical comparisons

## Conclusion

This architecture provides a **fully post-quantum secure** cryptographic backend with:

- **Post-quantum KEM**: Kyber ML-KEM 768 (NIST FIPS 203)
- **Post-quantum signatures**: Dilithium3 (NIST FIPS 204)
- **Platform-specific secure storage**: TPM2, Secure Enclave, StrongBox, SoftHSM
- **Clean separation**: UI (Flutter) and cryptography (Rust)

The FFI boundary ensures no key material leaks to the Dart layer, and all sensitive operations are handled in Rust's memory-safe environment. **No classical-only algorithms remain in security-critical paths** - the vault is protected against both current and future quantum computer attacks.
