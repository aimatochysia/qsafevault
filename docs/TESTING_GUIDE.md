# QSafeVault Testing Guide

This guide covers how to run all tests for QSafeVault, including Rust crypto engine tests, Flutter/Dart tests, and security tests.

## Quick Start

```bash
# Run all Rust tests
cd crypto_engine && cargo test

# Run Flutter tests
flutter test

# Run specific test file
flutter test test/vault_test.dart
```

## Rust Crypto Engine Tests

The Rust crypto engine contains comprehensive tests for all cryptographic operations.

### Running Rust Tests

```bash
# Navigate to crypto engine directory
cd crypto_engine

# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test module
cargo test security_tests

# Run tests in release mode (faster)
cargo test --release

# Run tests with verbose output
cargo test -- --test-threads=1 --nocapture
```

### Test Categories

#### Unit Tests (37 tests)

| Module | Tests | Description |
|--------|-------|-------------|
| `pqc_kem` | 2 | Post-quantum key encapsulation |
| `classical_kem` | 2 | X25519 ECDH key exchange |
| `hybrid_kem` | 2 | Hybrid PQC + Classical KEM |
| `symmetric` | 3 | AES-256-GCM encryption |
| `sealed_storage` | 4 | Blob serialization and validation |
| `security_tests` | 21 | Security and penetration tests |
| `platform_keystore` | 2 | Software keystore and SoftHSM |
| `integration` | 1 | End-to-end integration |

#### Security Tests

The `security_tests` module contains comprehensive security validation:

**Vulnerability Testing:**
- `test_null_input_handling` - Null pointer and invalid input handling
- `test_large_data_handling` - 1MB+ data encryption/decryption
- `test_max_size_handling` - 10MB data stress test

**Penetration Testing:**
- `test_wrong_key_decryption_fails` - Wrong key detection
- `test_tampered_ciphertext_detection` - Ciphertext integrity
- `test_tampered_nonce_detection` - Nonce integrity
- `test_tampered_tag_detection` - Authentication tag integrity
- `test_replay_attack_detection` - Replay attack prevention

**Authentication Testing:**
- `test_keypair_uniqueness` - Unique keypair generation
- `test_shared_secret_correctness` - Shared secret derivation
- `test_key_isolation` - Key isolation between operations
- `test_wrong_private_key_decapsulation_produces_different_secret` - Key mismatch detection

**Data Protection Testing:**
- `test_aad_protection` - Additional authenticated data
- `test_aad_required_consistency` - AAD consistency
- `test_sealed_blob_integrity` - Blob integrity verification
- `test_nonce_never_reused` - Nonce uniqueness
- `test_key_derivation_determinism` - Deterministic key derivation

### Running Tests with Coverage

```bash
# Install coverage tools
cargo install cargo-tarpaulin

# Run with coverage
cargo tarpaulin --out Html

# View coverage report
open tarpaulin-report.html
```

## Flutter/Dart Tests

### Running Flutter Tests

```bash
# Run all tests
flutter test

# Run with coverage
flutter test --coverage

# Run specific test file
flutter test test/vault_test.dart

# Run tests matching a pattern
flutter test --name "encryption"

# Run tests with verbose output
flutter test --reporter expanded
```

### Test Files

| File | Description |
|------|-------------|
| `test/vault_test.dart` | Vault encryption and storage |
| `test/sync_test.dart` | Device synchronization |
| `test/crypto_test.dart` | Cryptographic operations |
| `test/widget_test.dart` | UI widget tests |

### Integration Tests

```bash
# Run integration tests
flutter test integration_test/

# Run on specific device
flutter test integration_test/ -d <device_id>
```

## Platform-Specific Testing

### Linux

```bash
# Build and test
./build_crypto.sh
cd crypto_engine && cargo test
flutter test
```

### macOS

```bash
# Build and test
./build_crypto.sh
cd crypto_engine && cargo test
flutter test
```

### Windows

```powershell
# Build and test
.\build_crypto.bat
cd crypto_engine
cargo test
flutter test
```

### Android

```bash
# Build Rust library for Android
./build_crypto_android.sh

# Run Flutter tests
flutter test

# Run on connected device
flutter test -d <device_id>
```

### iOS

```bash
# Build Rust library for iOS
./build_crypto_ios.sh

# Run Flutter tests
flutter test

# Run on simulator
flutter test -d <simulator_id>
```

## CI/CD Testing

Tests are automatically run in GitHub Actions:

- **Linux**: Full test suite with SoftHSM
- **Windows**: Full test suite
- **macOS**: Full test suite with SoftHSM
- **Android**: Build verification
- **iOS**: Build verification

### Viewing CI Results

1. Go to the [Actions tab](../../actions)
2. Select the workflow run
3. View test results in the job logs

## Testing SoftHSM Integration

To test SoftHSM functionality:

```bash
# Install SoftHSM (see docs/SOFTHSM_INSTALLATION.md)
sudo apt-get install softhsm2  # Linux
brew install softhsm           # macOS

# Verify installation
which softhsm2-util  # Should return path to softhsm2-util

# Initialize token
softhsm2-util --init-token --slot 0 --label "QSafeVault" --pin 1234 --so-pin 1234

# Verify token was created
softhsm2-util --show-slots

# Run SoftHSM-specific tests
cd crypto_engine
cargo test softhsm
```

## Testing TPM Integration

TPM tests require hardware TPM or TPM simulator:

```bash
# Check TPM availability
ls -l /dev/tpm0 /dev/tpmrm0  # Linux
Get-Tpm                       # Windows PowerShell

# Run TPM-specific tests (requires tpm feature)
cd crypto_engine
cargo test --features tpm
```

## Benchmarking

```bash
# Run benchmarks
cd crypto_engine
cargo bench

# Quick performance test
cargo test --release -- --nocapture test_large_data
```

## Troubleshooting

### Tests fail with "library not found"

Ensure the Rust library is built:
```bash
cd crypto_engine
cargo build --release
```

### SoftHSM tests fail

Verify SoftHSM installation:
```bash
softhsm2-util --show-slots
```

### FFI tests hang

Check for deadlocks in FFI calls. Run with single thread:
```bash
cargo test -- --test-threads=1
```

### Permission denied on TPM

Add user to tss group:
```bash
sudo usermod -a -G tss $USER
# Log out and back in
```

## Writing New Tests

### Rust Test Example

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_feature() {
        // Arrange
        let input = b"test data";
        
        // Act
        let result = my_function(input);
        
        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }
}
```

### Flutter Test Example

```dart
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('Feature tests', () {
    test('should do something', () {
      // Arrange
      final input = 'test';
      
      // Act
      final result = myFunction(input);
      
      // Assert
      expect(result, equals(expected));
    });
  });
}
```

## Security Testing Checklist

Before release, verify:

- [ ] All 37 Rust tests pass
- [ ] All Flutter tests pass
- [ ] SoftHSM integration tested
- [ ] TPM integration tested (if available)
- [ ] Large data handling tested (1MB+)
- [ ] Error handling verified
- [ ] Memory leak check passed
- [ ] No compiler warnings

## Related Documentation

- [Security Architecture](SECURITY_ARCHITECTURE.md) - Security design
- [Crypto Engine](CRYPTO_ENGINE.md) - FFI documentation
- [Implementation Summary](IMPLEMENTATION_SUMMARY.md) - Implementation details
