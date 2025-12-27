# QSafeVault Crypto Engine

The QSafeVault Crypto Engine is a Rust-based FFI library providing high-performance cryptographic primitives for secure password management.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Getting Started](#getting-started)
- [Building](#building)
- [Platform Support](#platform-support)
- [API Reference](#api-reference)
- [Security](#security)
- [Testing](#testing)

## Overview

The crypto_engine provides:
- **AES-256-GCM** - Authenticated encryption/decryption
- **Argon2id** - Password-based key derivation (memory-hard)
- **HKDF-SHA3-256** - Key derivation function
- **HMAC-SHA3-256** - Message authentication
- **X25519** - Elliptic curve Diffie-Hellman key exchange
- **ML-KEM-768** - Post-quantum key encapsulation (Kyber)
- **Hybrid KEM** - Quantum-resistant key exchange (X25519 + ML-KEM)
- **SoftHSM2** - Hardware Security Module support via PKCS#11

## Features

### Core Cryptography
| Feature | Algorithm | Key Size | Status |
|---------|-----------|----------|--------|
| Encryption | AES-256-GCM | 256-bit | ✅ |
| Password KDF | Argon2id | Configurable | ✅ |
| Key Derivation | HKDF-SHA3-256 | Variable | ✅ |
| MAC | HMAC-SHA3-256 | 256-bit | ✅ |
| Key Exchange | X25519 | 256-bit | ✅ |
| Post-Quantum KEM | ML-KEM-768 | 256-bit shared | ✅ |
| Hybrid KEM | X25519 + ML-KEM | 256-bit shared | ✅ |

### HSM Support (Desktop Only)
| Feature | Algorithm | Status |
|---------|-----------|--------|
| Key Storage | AES-256 | ✅ |
| RSA Keys | 2048/4096-bit | ✅ |
| ECDSA Keys | P-256/P-384 | ✅ |
| HSM Encryption | AES-GCM | ✅ |
| Digital Signatures | RSA/ECDSA | ✅ |
| Hardware RNG | PKCS#11 | ✅ |

## Getting Started

### Prerequisites

1. **Rust toolchain** (1.70+)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Platform-specific dependencies**
   - Linux: `apt-get install build-essential`
   - macOS: Xcode Command Line Tools
   - Windows: Visual Studio with C++ workload

3. **SoftHSM2** (optional, for HSM features)
   - See [SoftHSM Installation Guide](SOFTHSM_INSTALLATION.md)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/aimatochysia/qsafevault.git
cd qsafevault/crypto_engine

# Build the library
cargo build --release

# Run tests
cargo test --release

# The library will be in:
# - Linux: target/release/libcrypto_engine.so
# - macOS: target/release/libcrypto_engine.dylib
# - Windows: target/release/crypto_engine.dll
```

## Building

### Debug Build
```bash
cargo build
```

### Release Build
```bash
cargo build --release
```

### Cross-Compilation

#### Android
```bash
# Install Android NDK and cargo-ndk
cargo install cargo-ndk

# Build for Android targets
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 build --release
```

#### iOS
```bash
# Add iOS targets
rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim

# Build
cargo build --release --target aarch64-apple-ios
```

#### WebAssembly
```bash
# Install wasm-pack
cargo install wasm-pack

# Build
wasm-pack build --release
```

## Platform Support

| Platform | Core Crypto | SoftHSM2 | Build Status |
|----------|-------------|----------|--------------|
| Linux x86_64 | ✅ | ✅ | Tested |
| Linux ARM64 | ✅ | ✅ | Tested |
| macOS x86_64 | ✅ | ✅ | Tested |
| macOS ARM64 | ✅ | ✅ | Tested |
| Windows x86_64 | ✅ | ✅ | Tested |
| Android arm64-v8a | ✅ | ❌ | Tested |
| Android armeabi-v7a | ✅ | ❌ | Tested |
| Android x86_64 | ✅ | ❌ | Tested |
| iOS arm64 | ✅ | ❌ | Tested |
| iOS Simulator | ✅ | ❌ | Tested |
| WebAssembly | ✅ | ❌ | Experimental |

## API Reference

### Error Codes

```c
#define CRYPTO_SUCCESS                    0
#define CRYPTO_ERROR_NULL_POINTER        -1
#define CRYPTO_ERROR_INVALID_LENGTH      -2
#define CRYPTO_ERROR_ENCRYPTION_FAILED   -3
#define CRYPTO_ERROR_DECRYPTION_FAILED   -4
#define CRYPTO_ERROR_KEY_DERIVATION_FAILED -5
#define CRYPTO_ERROR_KEY_EXCHANGE_FAILED -6
#define CRYPTO_ERROR_KEM_FAILED          -7
#define CRYPTO_ERROR_BUFFER_TOO_SMALL    -8
```

### Core Functions

#### Random Bytes
```c
int32_t crypto_random_bytes(uint8_t* dest, size_t len);
```

#### Secure Zeroization
```c
int32_t crypto_secure_zero(uint8_t* buffer, size_t len);
```

#### AES-256-GCM Encryption
```c
int32_t crypto_aes_gcm_encrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* output, size_t output_capacity,
    size_t* output_len
);

int32_t crypto_aes_gcm_decrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    uint8_t* output, size_t output_capacity,
    size_t* output_len
);
```

#### Argon2id Key Derivation
```c
int32_t crypto_argon2id_derive(
    const uint8_t* password, size_t password_len,
    const uint8_t* salt, size_t salt_len,
    uint32_t memory_kib,
    uint32_t iterations,
    uint32_t parallelism,
    uint8_t* output_key, size_t output_key_len
);
```

#### X25519 Key Exchange
```c
int32_t crypto_x25519_keypair(
    uint8_t* public_key,  // 32 bytes
    uint8_t* secret_key   // 32 bytes
);

int32_t crypto_x25519_exchange(
    const uint8_t* my_secret_key,
    const uint8_t* their_public_key,
    uint8_t* shared_secret  // 32 bytes
);
```

#### ML-KEM-768 (Post-Quantum)
```c
int32_t crypto_mlkem_keypair(
    uint8_t* public_key,  // 1184 bytes
    uint8_t* secret_key   // 2400 bytes
);

int32_t crypto_mlkem_encapsulate(
    const uint8_t* public_key,
    uint8_t* ciphertext,    // 1088 bytes
    uint8_t* shared_secret  // 32 bytes
);

int32_t crypto_mlkem_decapsulate(
    const uint8_t* secret_key,
    const uint8_t* ciphertext,
    uint8_t* shared_secret  // 32 bytes
);
```

#### Hybrid KEM (X25519 + ML-KEM)
```c
int32_t crypto_hybrid_keypair(
    uint8_t* public_key,  // 1216 bytes
    uint8_t* secret_key   // 2432 bytes
);

int32_t crypto_hybrid_encapsulate(
    const uint8_t* their_public_key,
    uint8_t* ciphertext,    // 1120 bytes
    uint8_t* shared_secret  // 32 bytes
);

int32_t crypto_hybrid_decapsulate(
    const uint8_t* my_secret_key,
    const uint8_t* ciphertext,
    uint8_t* shared_secret  // 32 bytes
);
```

### HSM Functions (Desktop Only)

See [SoftHSM Installation Guide](SOFTHSM_INSTALLATION.md) for setup.

```c
// Initialization
int32_t hsm_initialize(const char* library_path, size_t library_path_len);
int32_t hsm_finalize(void);
int32_t hsm_is_available(void);

// Session Management
int32_t hsm_open_session(uint32_t slot_index, const uint8_t* user_pin, size_t user_pin_len);
int32_t hsm_close_session(void);

// Key Generation
int32_t hsm_generate_aes_key(
    const uint8_t* key_label, size_t key_label_len,
    const uint8_t* key_id, size_t key_id_len,
    bool extractable,
    uint64_t* key_handle
);

int32_t hsm_generate_rsa_keypair(
    uint32_t key_bits,  // 2048 or 4096
    const uint8_t* key_label, size_t key_label_len,
    const uint8_t* key_id, size_t key_id_len,
    uint64_t* public_key_handle,
    uint64_t* private_key_handle
);

// Cryptographic Operations
int32_t hsm_aes_gcm_encrypt(
    uint64_t key_handle,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* output, size_t output_capacity,
    size_t* output_len
);

int32_t hsm_rsa_sign_sha256(
    uint64_t private_key_handle,
    const uint8_t* data, size_t data_len,
    uint8_t* signature, size_t signature_capacity,
    size_t* signature_len
);
```

## Security

### Threat Model
- **Memory Safety**: Rust prevents buffer overflows and use-after-free
- **Constant-Time**: Critical operations use constant-time algorithms
- **Secure Zeroization**: Sensitive data is securely cleared from memory
- **Authenticated Encryption**: All encryption includes integrity verification

### Best Practices
1. Always check return codes
2. Use `crypto_secure_zero()` to clear sensitive buffers
3. Use strong passwords with Argon2id (min 16384 KiB memory)
4. Prefer hybrid KEM for quantum resistance
5. Store HSM PINs securely

### Auditing
- [ ] Third-party security audit (planned)
- [x] Static analysis with Clippy
- [x] CodeQL security scanning
- [x] Fuzzing tests (planned)

## Testing

### Run All Tests
```bash
cargo test --release
```

### Run Specific Test
```bash
cargo test test_aes_gcm_encrypt_decrypt --release
```

### Test Coverage
```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

### Current Test Coverage
- Core crypto functions: 14 tests
- SoftHSM2 functions: 2 tests (basic availability and error messages)
- Edge cases: Null pointers, invalid lengths, tampered data

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| aes-gcm | 0.10 | AES-256-GCM encryption |
| argon2 | 0.5 | Password hashing |
| hkdf | 0.12 | Key derivation |
| hmac | 0.12 | Message authentication |
| sha3 | 0.10 | SHA-3 hash functions |
| x25519-dalek | 2.0 | ECDH key exchange |
| pqcrypto-mlkem | 0.1 | Post-quantum KEM |
| zeroize | 1.0 | Secure memory clearing |
| cryptoki | 0.7 | PKCS#11 interface |
| rand | 0.8 | Random number generation |

## License

See [LICENSE](../LICENSE) for details.

## Related Documentation

- [SoftHSM Installation Guide](SOFTHSM_INSTALLATION.md)
- [Sync Guide](../SYNC_GUIDE.md)
- [Main README](../README.md)
