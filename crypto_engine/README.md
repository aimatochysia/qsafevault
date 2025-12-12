# QSafeVault Crypto Engine

Production-grade cryptographic backend for QSafeVault password manager, implementing hybrid post-quantum + classical cryptography.

## Features

- **Hybrid Post-Quantum Cryptography**: Combines Kyber ML-KEM (NIST standardized PQC) with X25519 ECDH
- **AES-256-GCM Encryption**: Authenticated encryption for vault data
- **Platform Secure Storage**: Integration with Secure Enclave (iOS/macOS), StrongBox (Android), TPM2 (Windows/Linux)
- **FFI Interface**: Clean C ABI for Flutter integration
- **Memory Safety**: Automatic zeroization of sensitive data
- **Handle-Based API**: No raw key material exposed to Flutter layer

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Flutter UI Layer                    │
│  (No cryptographic operations, only FFI calls)   │
└─────────────────────────────────────────────────┘
                     ↓ FFI
┌─────────────────────────────────────────────────┐
│         Rust Crypto Engine (this crate)          │
├─────────────────────────────────────────────────┤
│ • PQC KEM (Kyber ML-KEM 768)                    │
│ • Classical KEM (X25519)                         │
│ • Hybrid KEM (PQC + Classical + HKDF-SHA3)       │
│ • Symmetric (AES-256-GCM)                        │
│ • Sealed Storage (versioned blobs)               │
│ • Platform Keystore (Secure Enclave, etc.)       │
└─────────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────┐
│         Platform Secure Storage                  │
│  • iOS: Secure Enclave + Keychain               │
│  • macOS: Keychain (T2/Secure Enclave)          │
│  • Android: StrongBox Keystore                   │
│  • Windows: TPM2 via CNG                         │
│  • Linux: TPM2 via tpm2-tss                      │
│  • Fallback: Filesystem (restricted perms)       │
└─────────────────────────────────────────────────┘
```

## Building

### Prerequisites

- Rust 1.70+ (`rustup` recommended)
- Cargo

### Build Commands

**Debug build:**
```bash
cargo build
```

**Release build:**
```bash
cargo build --release
```

**Run tests:**
```bash
cargo test
```

**From project root (using build script):**
```bash
# Linux/macOS
./build_crypto.sh release

# Windows
build_crypto.bat release
```

### Build Artifacts

The build produces a dynamic library for your platform:
- **Linux**: `target/[debug|release]/libcrypto_engine.so`
- **macOS**: `target/[debug|release]/libcrypto_engine.dylib`
- **Windows**: `target/[debug|release]/crypto_engine.dll`

## API Overview

All functions use a C ABI and return status codes. See `qsafevault_crypto.h` for full API.

### Core Functions

1. **pqcrypto_generate_hybrid_keypair()** - Generate PQC + Classical keypair
2. **pqcrypto_hybrid_encrypt_master_key()** - Encrypt a master key using hybrid KEM
3. **pqcrypto_hybrid_decrypt_master_key()** - Decrypt a master key
4. **pqcrypto_seal_private_key_with_platform_keystore()** - Store private key in platform secure storage
5. **pqcrypto_unseal_private_key_from_platform_keystore()** - Retrieve private key from secure storage
6. **pqcrypto_encrypt_vault()** - Encrypt vault data with AES-256-GCM
7. **pqcrypto_decrypt_vault()** - Decrypt vault data
8. **pqcrypto_free_handle()** - Free keypair/key handle

## Usage Example

See `example/crypto_usage_example.dart` for a complete Flutter/Dart example.

```dart
import 'package:qsafevault/ffi/rust_crypto_service.dart';

void main() {
  final crypto = RustCryptoService();
  
  // Generate keypair
  final keypair = crypto.generateHybridKeypair();
  
  // Encrypt master key
  final masterKey = Uint8List(32); // Your 32-byte master key
  final encrypted = crypto.hybridEncryptMasterKey(
    keypair.pqcPublicKey,
    keypair.classicalPublicKey,
    masterKey,
  );
  
  // Decrypt master key
  final decrypted = crypto.hybridDecryptMasterKey(
    keypair.handle,
    encrypted,
  );
  
  // Encrypt vault data
  final vaultData = utf8.encode('secret data');
  final encryptedVault = crypto.encryptVault(masterKey, vaultData);
  
  // Decrypt vault data
  final decryptedVault = crypto.decryptVault(masterKey, encryptedVault);
  
  // Cleanup
  crypto.freeHandle(keypair.handle);
}
```

## Security

### Cryptographic Algorithms

- **Post-Quantum KEM**: Kyber ML-KEM 768 (NIST FIPS 203)
- **Classical KEM**: X25519 Elliptic Curve Diffie-Hellman
- **KDF**: HKDF with SHA3-256
- **Symmetric**: AES-256-GCM (AEAD)
- **Password Hashing**: Argon2id (in Flutter layer)

### Security Properties

- **Quantum Resistance**: Kyber protects against Shor's algorithm
- **Classical Security**: X25519 provides 128-bit security today
- **Hybrid Security**: Combined security from both mechanisms
- **Authenticated Encryption**: GCM mode prevents tampering
- **Memory Safety**: Rust's ownership + zeroization on drop
- **No Key Exposure**: Handle-based API, keys never leave Rust

### Threat Model

**Protects Against:**
- Quantum computer attacks (via Kyber)
- Classical cryptanalysis (via X25519)
- Memory dumps (via zeroization)
- Unauthorized access (via platform keystores)
- MITM attacks (authenticated encryption)

**Does Not Protect Against:**
- Compromised platform keystore (relies on OS security)
- Side-channel attacks (implementation-dependent)
- Physical device access (out of scope)

## Dependencies

### Core Dependencies

- `pqcrypto-mlkem` - Kyber ML-KEM implementation
- `x25519-dalek` - X25519 ECDH
- `aes-gcm` - AES-256-GCM encryption
- `hkdf` + `sha3` - Key derivation
- `zeroize` - Secure memory clearing
- `serde` + `bincode` - Serialization

### Platform-Specific Dependencies

- **iOS/macOS**: `security-framework` (Keychain access)
- **Windows**: `windows` crate (CNG/KSP APIs) - stub for now
- **Android**: JNI bindings - stub for now
- **Linux**: `tss-esapi` (TPM2 access) - commented out, stub for now

## Platform Support

| Platform | Status | Secure Storage |
|----------|--------|----------------|
| Linux    | ✅ Working | Software fallback (TPM2 stub) |
| macOS    | ✅ Working | Keychain (Secure Enclave capable) |
| Windows  | ⚠️ Partial | Software fallback (TPM2 stub) |
| iOS      | ⚠️ Untested | Keychain + Secure Enclave |
| Android  | ⚠️ Stub | Software fallback (StrongBox stub) |

**Note**: Platform-specific secure storage implementations require additional work:
- Android StrongBox requires JNI integration
- Windows TPM2 requires full CNG/KSP implementation
- Linux TPM2 requires tss-esapi integration

## Testing

Run unit tests:
```bash
cargo test
```

Run with output:
```bash
cargo test -- --nocapture
```

Run specific test:
```bash
cargo test test_hybrid_kem_roundtrip
```

## Performance

Approximate timings on modern hardware (debug build):

| Operation | Time |
|-----------|------|
| Keypair generation | ~1ms |
| Hybrid encapsulation | ~0.5ms |
| Hybrid decapsulation | ~0.5ms |
| AES-256-GCM encrypt (1KB) | ~50μs |
| AES-256-GCM decrypt (1KB) | ~50μs |

Release builds are significantly faster.

## License

Same as parent project (CC BY-NC 4.0).

## Contributing

Security-critical code. All contributions must:
- Follow Rust best practices
- Include tests
- Pass `cargo clippy` and `cargo fmt`
- Not introduce unsafe code without justification
- Document all public APIs

## Roadmap

### Short Term
- [ ] Full Android StrongBox integration via JNI
- [ ] Full Windows TPM2 integration via CNG
- [ ] Full Linux TPM2 integration via tss-esapi
- [ ] iOS/macOS Secure Enclave key generation (not just storage)
- [ ] Cross-platform build automation

### Long Term
- [ ] Hardware key generation (not just storage)
- [ ] Key rotation support
- [ ] Forward secrecy for vault sharing
- [ ] Professional security audit
- [ ] Side-channel analysis
- [ ] Fuzzing infrastructure
- [ ] Benchmarking suite

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Kyber ML-KEM Specification](https://pq-crystals.org/kyber/)
- [X25519 RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748)
- [AES-GCM RFC 5116](https://datatracker.ietf.org/doc/html/rfc5116)
- [HKDF RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)
