# SoftHSM2 Installation Guide

SoftHSM2 is a software implementation of a Hardware Security Module (HSM) that provides PKCS#11 interface for secure key storage and cryptographic operations.

## Table of Contents
- [Overview](#overview)
- [Platform Support](#platform-support)
- [Linux Installation](#linux-installation)
- [macOS Installation](#macos-installation)
- [Windows Installation](#windows-installation)
- [Configuration](#configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## Overview

QSafeVault's crypto_engine uses SoftHSM2 for secure key management. The HSM provides:
- Secure key storage with PIN protection
- AES-256, RSA, and ECDSA key generation
- Hardware-grade cryptographic operations
- PKCS#11 compliant interface

## Platform Support

| Platform | Support | Installation Method |
|----------|---------|---------------------|
| Linux (x86_64, ARM64) | ✅ Full | Package manager |
| macOS (x86_64, ARM64) | ✅ Full | Homebrew |
| Windows (x86_64) | ✅ Full | Installer |
| Android | ❌ None | PKCS#11 not available |
| iOS | ❌ None | PKCS#11 not available |
| WebAssembly | ❌ None | Native library not supported |

## Linux Installation

### Ubuntu / Debian

```bash
# Update package list
sudo apt-get update

# Install SoftHSM2
sudo apt-get install -y softhsm2

# Verify installation
softhsm2-util --version
```

### Fedora / RHEL / CentOS

```bash
# Install SoftHSM2
sudo dnf install -y softhsm

# Or on older systems with yum
sudo yum install -y softhsm

# Verify installation
softhsm2-util --version
```

### Arch Linux

```bash
# Install SoftHSM2
sudo pacman -S softhsm

# Verify installation
softhsm2-util --version
```

### openSUSE

```bash
# Install SoftHSM2
sudo zypper install softhsm

# Verify installation
softhsm2-util --version
```

### Library Locations (Linux)

The crypto_engine auto-detects these paths:
- `/usr/lib/softhsm/libsofthsm2.so`
- `/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`
- `/usr/lib64/softhsm/libsofthsm2.so`
- `/usr/local/lib/softhsm/libsofthsm2.so`

## macOS Installation

### Using Homebrew (Recommended)

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install SoftHSM2
brew install softhsm

# Verify installation
softhsm2-util --version
```

### Using MacPorts

```bash
# Install SoftHSM2
sudo port install softhsm

# Verify installation
softhsm2-util --version
```

### Library Locations (macOS)

The crypto_engine auto-detects these paths:
- `/usr/local/lib/softhsm/libsofthsm2.so` (Intel)
- `/opt/homebrew/lib/softhsm/libsofthsm2.so` (Apple Silicon)

## Windows Installation

### Option 1: Pre-built Installer (Recommended)

1. Download the latest SoftHSM2 installer from:
   - [SoftHSM2 Windows Releases](https://github.com/disig/SoftHSM2-for-Windows/releases)

2. Run the installer and follow the prompts

3. Default installation path: `C:\SoftHSM2\`

### Option 2: Build from Source

```powershell
# Install Visual Studio with C++ workload
# Clone and build SoftHSM2
git clone https://github.com/opendnssec/SoftHSMv2.git
cd SoftHSMv2
# Follow build instructions in the repository
```

### Library Locations (Windows)

The crypto_engine auto-detects these paths:
- `C:\SoftHSM2\lib\softhsm2.dll`
- `C:\Program Files\SoftHSM2\lib\softhsm2.dll`
- `C:\Program Files (x86)\SoftHSM2\lib\softhsm2.dll`

### Environment Variables (Windows)

Add to system PATH if needed:
```powershell
$env:PATH += ";C:\SoftHSM2\bin"
```

## Configuration

### Initialize a Token

After installation, create a token for key storage:

```bash
# Create token directory (if needed)
mkdir -p ~/.softhsm/tokens

# Initialize a token
softhsm2-util --init-token --slot 0 --label "QSafeVault" --pin 1234 --so-pin 12345678
```

### Configuration File

The configuration file is typically located at:
- Linux: `/etc/softhsm2.conf` or `~/.config/softhsm2/softhsm2.conf`
- macOS: `/usr/local/etc/softhsm2.conf` or `~/.config/softhsm2/softhsm2.conf`
- Windows: `C:\SoftHSM2\etc\softhsm2.conf`

Example configuration:
```conf
# SoftHSM v2 configuration file
directories.tokendir = /path/to/tokens
objectstore.backend = file
log.level = INFO
```

## Verification

### Check Installation

```bash
# List available slots
softhsm2-util --show-slots

# Expected output:
# Slot 0
#     Slot info:
#         Description:      SoftHSM slot ID 0x0
#         Manufacturer ID:  SoftHSM project
#         ...
```

### Test with pkcs11-tool

```bash
# Install OpenSC for pkcs11-tool
# Ubuntu: sudo apt-get install opensc
# macOS: brew install opensc

# Test PKCS#11 module
pkcs11-tool --module /path/to/libsofthsm2.so -L
```

### Test with QSafeVault Crypto Engine

The crypto_engine provides an availability check:

```rust
// In Rust code
use crypto_engine::softhsm::hsm_is_available;

let available = hsm_is_available();
// Returns 1 if SoftHSM2 is installed, 0 otherwise
```

## Troubleshooting

### Common Issues

#### "Library not found" Error

**Problem**: The crypto_engine cannot find the SoftHSM2 library.

**Solution**:
1. Verify SoftHSM2 is installed: `softhsm2-util --version`
2. Check library path: `find /usr -name "libsofthsm2*" 2>/dev/null`
3. If in non-standard location, set environment variable:
   ```bash
   export SOFTHSM2_LIB=/path/to/libsofthsm2.so
   ```

#### "No slot available" Error

**Problem**: No tokens have been initialized.

**Solution**:
```bash
# Initialize a new token
softhsm2-util --init-token --slot 0 --label "QSafeVault" --pin 1234 --so-pin 12345678
```

#### "Token not present" Error

**Problem**: The token directory is missing or inaccessible.

**Solution**:
1. Check token directory exists:
   ```bash
   ls -la ~/.softhsm/tokens
   ```
2. Create if missing:
   ```bash
   mkdir -p ~/.softhsm/tokens
   ```
3. Check permissions:
   ```bash
   chmod 700 ~/.softhsm/tokens
   ```

#### "PIN incorrect" Error

**Problem**: Wrong PIN provided.

**Solution**:
1. Use the correct PIN set during token initialization
2. If forgotten, re-initialize the token (this will delete all keys):
   ```bash
   softhsm2-util --delete-token --token "QSafeVault"
   softhsm2-util --init-token --slot 0 --label "QSafeVault" --pin 1234 --so-pin 12345678
   ```

### Debug Logging

Enable debug output:
```bash
# Set log level in softhsm2.conf
log.level = DEBUG
```

### Getting Help

- [SoftHSM2 GitHub Repository](https://github.com/opendnssec/SoftHSMv2)
- [PKCS#11 Specification](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)
- [QSafeVault Issues](https://github.com/aimatochysia/qsafevault/issues)

## Security Considerations

1. **PIN Protection**: Always use strong PINs for token access
2. **Token Storage**: Secure the token directory with appropriate permissions
3. **Key Material**: Keys stored in SoftHSM2 are encrypted but software-based
4. **Production Use**: For high-security environments, consider hardware HSMs

## Next Steps

- [Crypto Engine Getting Started](CRYPTO_ENGINE.md)
- [API Reference](CRYPTO_ENGINE_API.md)
- [Main Documentation](../README.md)
