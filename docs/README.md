# QSafeVault Documentation

This directory contains detailed documentation for QSafeVault components.

## Contents

| Document | Description |
|----------|-------------|
| [Crypto Engine](CRYPTO_ENGINE.md) | Rust FFI library for cryptographic operations |
| [SoftHSM2 Installation](SOFTHSM_INSTALLATION.md) | Hardware Security Module setup for all platforms |

## Quick Links

### Getting Started
- [Main README](../README.md) - Overview and quick start
- [Sync Guide](../SYNC_GUIDE.md) - Device-to-device synchronization

### Developer Resources
- [Crypto Engine API](CRYPTO_ENGINE.md#api-reference) - FFI function reference
- [Building from Source](CRYPTO_ENGINE.md#building) - Compilation instructions
- [Platform Support](CRYPTO_ENGINE.md#platform-support) - Supported platforms matrix

### Security
- [Security Model](../README.md#security-model) - Threat model and design
- [SoftHSM2 Security](SOFTHSM_INSTALLATION.md#security-considerations) - HSM security notes

## Wiki Integration

These documents are designed to be easily migrated to a GitHub Wiki:

1. Copy the markdown files to your wiki repository
2. Update internal links to use wiki syntax
3. The table of contents and cross-references should work automatically

## Contributing

Documentation improvements are welcome! Please follow these guidelines:

- Use clear, concise language
- Include code examples where applicable
- Keep platform-specific instructions up to date
- Test all commands before documenting them

## License

This documentation is part of QSafeVault and is licensed under CC BY-NC 4.0.
