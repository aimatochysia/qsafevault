# QSafeVault Documentation

This directory contains detailed documentation for QSafeVault components.

## Contents

| Document | Description |
|----------|-------------|
| [Getting Started](GETTING_STARTED.md) | App onboarding and setup guide |
| [Security Architecture](SECURITY_ARCHITECTURE.md) | Algorithms, threat model, and security design |
| [Crypto Engine](CRYPTO_ENGINE.md) | Rust FFI library for cryptographic operations |
| [Crypto Architecture](CRYPTO_ARCHITECTURE.md) | Technical architecture details |
| [SoftHSM2 Installation](SOFTHSM_INSTALLATION.md) | Hardware Security Module setup for all platforms |
| [Sync Guide](SYNC_GUIDE.md) | Device-to-device synchronization |
| [Implementation Summary](IMPLEMENTATION_SUMMARY.md) | Implementation details |
| [Testing Guide](TESTING_GUIDE.md) | How to run all tests |

## Quick Links

### For Users
- [Getting Started](GETTING_STARTED.md) - Installation and first-time setup
- [Sync Guide](SYNC_GUIDE.md) - Device-to-device synchronization
- [Main README](../README.md) - Overview and quick start

### For Developers
- [Crypto Engine API](CRYPTO_ENGINE.md#api-reference) - FFI function reference
- [Crypto Architecture](CRYPTO_ARCHITECTURE.md) - Technical architecture details
- [Building from Source](CRYPTO_ENGINE.md#building) - Compilation instructions
- [Platform Support](CRYPTO_ENGINE.md#platform-support) - Supported platforms matrix
- [Testing Guide](TESTING_GUIDE.md) - Running tests

### Security
- [Security Architecture](SECURITY_ARCHITECTURE.md) - Complete security documentation
- [Algorithm Usage](SECURITY_ARCHITECTURE.md#cryptographic-algorithms-by-area) - Which algorithms are used where
- [Threat Model](SECURITY_ARCHITECTURE.md#threat-model) - Security assumptions and mitigations
- [Security Testing](SECURITY_ARCHITECTURE.md#security-testing) - Testing methodology

## Wiki Integration

These documents are designed to be easily migrated to a GitHub Wiki:

1. Copy the markdown files to your wiki repository
2. Update internal links to use wiki syntax
3. The table of contents and cross-references should work automatically

## Document Map

```
docs/
├── README.md                  # This index file
├── GETTING_STARTED.md         # User onboarding guide
├── SECURITY_ARCHITECTURE.md   # Security design document
├── CRYPTO_ENGINE.md           # Rust FFI documentation
├── CRYPTO_ARCHITECTURE.md     # Technical architecture
├── SOFTHSM_INSTALLATION.md    # HSM setup guide
├── SYNC_GUIDE.md              # Sync documentation
├── IMPLEMENTATION_SUMMARY.md  # Implementation details
└── TESTING_GUIDE.md           # Testing instructions

Root/
└── README.md                  # Main project readme
```

## Contributing

Documentation improvements are welcome! Please follow these guidelines:

- Use clear, concise language
- Include code examples where applicable
- Keep platform-specific instructions up to date
- Test all commands before documenting them

## License

This documentation is part of QSafeVault and is licensed under CC BY-NC 4.0.
