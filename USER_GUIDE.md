# QSafeVault User Guide

Complete guide for installing, configuring, and using QSafeVault - the post-quantum secure password manager.

---

## Table of Contents

- [Introduction](#introduction)
- [System Requirements](#system-requirements)
- [Installation](#installation)
  - [Pre-built Binaries](#pre-built-binaries)
  - [Building from Source](#building-from-source)
  - [Mobile Builds](#mobile-builds)
- [Configuration](#configuration)
  - [Edition Selection](#edition-selection)
  - [Server Configuration](#server-configuration)
  - [Environment Variables](#environment-variables)
- [Self-Hosting the Backend](#self-hosting-the-backend)
  - [Consumer Self-Hosting](#consumer-self-hosting)
  - [Enterprise Deployment](#enterprise-deployment)
- [Using QSafeVault](#using-qsafevault)
  - [Creating a Vault](#creating-a-vault)
  - [Managing Passwords](#managing-passwords)
  - [Device Synchronization](#device-synchronization)
- [Hardware Security Setup](#hardware-security-setup)
  - [TPM2 Configuration](#tpm2-configuration)
  - [SoftHSM Setup](#softhsm-setup)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

---

## Introduction

QSafeVault is a secure, local-first password manager featuring **FIPS 203/204/205 certified post-quantum cryptography**. Your vault data is:

- **Encrypted at rest** with AES-256-GCM (FIPS-approved)
- **Protected by FIPS-certified post-quantum algorithms** (ML-KEM-1024, ML-DSA-65, SLH-DSA)
- **Stored locally only** - no cloud storage
- **Synchronized peer-to-peer** with end-to-end encryption

### FIPS-Certified Algorithms

| Function | Algorithm | Standard |
|----------|-----------|----------|
| Key Encapsulation | ML-KEM-1024 | FIPS 203 |
| Digital Signatures | ML-DSA-65 | FIPS 204 |
| Hash-Based Signatures | SLH-DSA-SHA2-128s | FIPS 205 |
| Symmetric Encryption | AES-256-GCM | FIPS 197 |
| Key Derivation | HKDF-SHA256 | NIST SP 800-56C |

### Editions

| Feature | Consumer | Enterprise |
|---------|----------|------------|
| Post-quantum crypto | ✅ FIPS 203/204/205 | ✅ FIPS 203/204/205 |
| Default server | Public relay | Self-hosted required |
| HSM requirement | Optional | Required |

---

## System Requirements

### Desktop

| Platform | Minimum Requirements |
|----------|---------------------|
| Windows | Windows 10/11, 64-bit |
| Linux | Ubuntu 20.04+ or equivalent, 64-bit |
| macOS | macOS 11+ (Big Sur), Intel or Apple Silicon |

### Mobile

| Platform | Minimum Requirements |
|----------|---------------------|
| Android | Android 8.0+ (API 26), ARM64 or x86_64 |
| iOS | iOS 14+ |

### Development (Building from Source)

- Flutter SDK 3.0+ (stable channel)
- Rust toolchain (for crypto engine)
- Platform-specific toolchains (see Building from Source)

---

## Installation

### Pre-built Binaries

Download the latest release for your platform from the [Releases](https://github.com/aimatochysia/qsafevault/releases) page.

#### Windows

1. Download `qsafevault-consumer-windows.exe` or `qsafevault-enterprise-windows.exe`
2. Run the installer
3. Follow the installation wizard
4. Launch QSafeVault from Start Menu or Desktop

#### Linux

```bash
# Debian/Ubuntu
sudo dpkg -i qsafevault-consumer-linux.deb

# Or extract and run manually
tar -xzf qsafevault-linux.tar.gz
./qsafevault
```

#### Android

1. Download `qsafevault-consumer-android.apk`
2. Enable "Install from unknown sources" in Settings
3. Open the APK to install
4. Launch QSafeVault from app drawer

#### macOS

1. Download `qsafevault-consumer-macos.dmg`
2. Open the DMG file
3. Drag QSafeVault to Applications
4. Right-click and select "Open" (first time only, for Gatekeeper)

### Building from Source

#### Prerequisites

```bash
# Install Flutter
# See https://docs.flutter.dev/get-started/install

# Verify Flutter installation
flutter doctor

# Clone repository
git clone https://github.com/aimatochysia/qsafevault.git
cd qsafevault
```

#### Desktop Builds

```bash
# Install dependencies
flutter pub get

# Build for your platform
flutter build windows --release  # Windows
flutter build linux --release    # Linux
flutter build macos --release    # macOS
```

#### With Edition and Server Configuration

```bash
# Consumer mode (default)
flutter build windows --release

# Consumer with custom server
flutter build windows --release \
  --dart-define=QSV_SYNC_BASEURL=https://your-server.com

# Enterprise mode (requires custom server)
flutter build windows --release \
  --dart-define=QSAFEVAULT_EDITION=enterprise \
  --dart-define=QSV_SYNC_BASEURL=https://internal.company.com
```

### Mobile Builds

#### Android

```bash
# Prerequisites: Android SDK, NDK

# Build Rust crypto library for Android
./build_crypto_android.sh

# Build APK
flutter build apk --release \
  --dart-define=QSV_SYNC_BASEURL=https://your-server.com

# Or build App Bundle for Play Store
flutter build appbundle --release \
  --dart-define=QSV_SYNC_BASEURL=https://your-server.com
```

#### iOS

```bash
# Prerequisites: macOS, Xcode, CocoaPods

# Build Rust crypto library for iOS
./build_crypto_ios.sh

# Build iOS app
flutter build ios --release \
  --dart-define=QSV_SYNC_BASEURL=https://your-server.com

# For App Store submission
flutter build ipa --release \
  --dart-define=QSV_SYNC_BASEURL=https://your-server.com
```

---

## Configuration

### Edition Selection

QSafeVault supports two editions:

#### Consumer Edition (Default)

- Post-quantum cryptography enabled (ML-KEM 768, Dilithium3)
- Uses public relay server by default
- Flexible key providers (TPM, SoftHSM, software)

```bash
flutter run  # Consumer is default
```

#### Enterprise Edition

- FIPS-only cryptography (AES-256-GCM, SHA-256)
- Post-quantum disabled until FIPS-approved
- Self-hosted server required
- External HSM required

```bash
flutter run --dart-define=QSAFEVAULT_EDITION=enterprise \
  --dart-define=QSV_SYNC_BASEURL=https://internal.company.com
```

### Server Configuration

| Edition | Default Server | Custom Server |
|---------|---------------|---------------|
| Consumer | `qsafevault-server.vercel.app` | Optional |
| Enterprise | None (disabled) | **Required** |

```bash
# Consumer with public relay (default)
flutter run

# Consumer with custom server
flutter run --dart-define=QSV_SYNC_BASEURL=https://your-server.com

# Enterprise (server required)
flutter run \
  --dart-define=QSAFEVAULT_EDITION=enterprise \
  --dart-define=QSV_SYNC_BASEURL=https://internal.company.com
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `QSAFEVAULT_EDITION` | `consumer` or `enterprise` | `consumer` |
| `QSV_SYNC_BASEURL` | Backend server URL | Public relay (consumer) |
| `QSV_TRANSPORT` | Transport mode (`tor` or `webrtc`) | `tor` |
| `QSV_TURN_URLS` | TURN server URLs (comma-separated) | None |
| `QSV_TURN_USERNAME` | TURN authentication username | None |
| `QSV_TURN_CREDENTIAL` | TURN authentication credential | None |
| `QSV_TURN_FORCE_RELAY` | Force TURN relay mode | `false` |

---

## Self-Hosting the Backend

### Consumer Self-Hosting

For users who want to host their own relay server instead of using the public relay.

#### Option 1: Vercel (Recommended)

```bash
# Clone repository
git clone https://github.com/aimatochysia/qsafevault.git
cd qsafevault/qsafevault-server

# Install Vercel CLI
npm install -g vercel

# Deploy
vercel

# Use your deployment URL
flutter run --dart-define=QSV_SYNC_BASEURL=https://your-project.vercel.app
```

#### Option 2: VPS with Node.js

```bash
# On your server
cd /opt
git clone https://github.com/aimatochysia/qsafevault.git
cd qsafevault/qsafevault-server

# Install dependencies
npm install --production

# Run with PM2
npm install -g pm2
pm2 start server.js --name qsafevault-relay
pm2 save
pm2 startup
```

#### Option 3: Docker

```bash
# Build and run
docker build -t qsafevault-relay ./qsafevault-server
docker run -d -p 3000:3000 --name relay qsafevault-relay
```

### Enterprise Deployment

For regulated environments requiring FIPS-only mode.

#### Prerequisites

- Internal network access
- HTTPS certificate (internal CA acceptable)
- Node.js 18+

#### Deployment Steps

```bash
# 1. Clone repository
git clone https://github.com/aimatochysia/qsafevault.git
cd qsafevault/qsafevault-server

# 2. Install dependencies
npm install --production

# 3. Configure environment
export QSAFEVAULT_EDITION=enterprise
export QSAFEVAULT_ENTERPRISE_ACKNOWLEDGED=true
export PORT=3000

# 4. Start server
node server.js
```

#### Production with PM2

```bash
# Create ecosystem file
cat > ecosystem.config.js << 'EOF'
module.exports = {
  apps: [{
    name: 'qsafevault-relay',
    script: 'server.js',
    env: {
      NODE_ENV: 'production',
      QSAFEVAULT_EDITION: 'enterprise',
      QSAFEVAULT_ENTERPRISE_ACKNOWLEDGED: 'true',
      PORT: 3000
    }
  }]
};
EOF

# Start with PM2
pm2 start ecosystem.config.js
pm2 save
pm2 startup
```

#### Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name relay.internal.company.com;
    
    ssl_certificate /etc/ssl/certs/relay.crt;
    ssl_certificate_key /etc/ssl/private/relay.key;
    
    # Restrict to internal IPs
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    allow 192.168.0.0/16;
    deny all;
    
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

#### Enterprise Security Checklist

- [ ] Server on internal network only
- [ ] HTTPS with valid certificates
- [ ] Firewall restricting to corporate IPs
- [ ] `QSAFEVAULT_ENTERPRISE_ACKNOWLEDGED=true` set
- [ ] Stateless relay (no data persistence)
- [ ] PM2/systemd for process management
- [ ] Log rotation configured

---

## Using QSafeVault

### Creating a Vault

1. **Launch QSafeVault** on your device
2. **Choose a master password** - this will encrypt your vault
   - Use a strong, unique password
   - Minimum 12 characters recommended
   - This password is never transmitted anywhere
3. **Confirm your password**
4. Your vault is now created and encrypted locally

### Managing Passwords

#### Adding a Password

1. Click **"+"** or **"Add Entry"**
2. Fill in the details:
   - **Title**: Name for the entry (e.g., "Gmail")
   - **Username**: Your login username/email
   - **Password**: Click generate or enter manually
   - **URL**: Optional website URL
   - **Notes**: Optional additional information
3. Click **Save**

#### Generating Passwords

QSafeVault includes a secure password generator:

- Customizable length (8-128 characters)
- Include/exclude: uppercase, lowercase, numbers, symbols
- No patterns or dictionary words
- Cryptographically secure randomness

#### Editing Entries

1. Click on an entry to view details
2. Click **Edit**
3. Make changes
4. Click **Save**

#### Deleting Entries

1. Click on an entry
2. Click **Delete**
3. Confirm deletion

### Device Synchronization

Sync your vault between devices using encrypted peer-to-peer transfer.

#### Prerequisites

- Both devices have QSafeVault installed
- Both devices connected to the internet
- Agree on a 6-digit PIN and transfer password

#### Sending Vault

1. Open **Sync** → **Send**
2. Choose a **6-digit PIN** (share with receiver)
3. Enter a **transfer password** (share with receiver)
4. Click **Start Transfer**
5. Wait for receiver to connect

#### Receiving Vault

1. Open **Sync** → **Receive**
2. Enter the **6-digit PIN** from sender
3. Enter the **transfer password** from sender
4. Click **Connect**
5. Wait for transfer to complete

#### Security

- Vault is encrypted end-to-end before transmission
- Server never sees plaintext data
- Transfer password is never transmitted
- PIN expires after 60 seconds

---

## Hardware Security Setup

### TPM2 Configuration

QSafeVault can use TPM2 for hardware-backed key storage.

#### Windows TPM2

Modern Windows systems have built-in TPM 2.0.

```powershell
# Verify TPM
Get-Tpm
# Should show: TpmPresent: True, TpmReady: True
```

QSafeVault automatically detects and uses TPM2 via Windows CNG.

#### Linux TPM2

```bash
# Check TPM availability
ls -l /dev/tpm0 /dev/tpmrm0

# Install tools (optional)
sudo apt-get install tpm2-tools

# Verify
sudo tpm2_getcap properties-fixed

# Grant access to your user
sudo usermod -a -G tss $USER
# Log out and back in
```

### SoftHSM Setup

SoftHSM provides PKCS#11 HSM simulation for development/testing.

#### Linux

```bash
# Install
sudo apt-get install softhsm2

# Initialize token
softhsm2-util --init-token --slot 0 --label "QSafeVault" --pin 1234 --so-pin 1234

# Verify
softhsm2-util --show-slots
```

#### macOS

```bash
# Install via Homebrew
brew install softhsm

# Initialize token
softhsm2-util --init-token --slot 0 --label "QSafeVault" --pin 1234 --so-pin 1234
```

#### Windows

```powershell
# Download from https://github.com/opendnssec/SoftHSMv2/releases
# Install and add to PATH

softhsm2-util --init-token --slot 0 --label "QSafeVault" --pin 1234 --so-pin 1234
```

---

## Troubleshooting

### Sync Issues

**"Waiting" status persists**
- Sender not yet uploading
- PIN or password mismatch
- Check network connectivity

**"Expired" status**
- 60-second TTL elapsed
- Restart with new PIN/password

**Decryption failure**
- PIN or password mismatch
- Ensure exact match between sender and receiver

### Build Issues

**Flutter build fails**
```bash
flutter clean
flutter pub get
flutter build <platform> --release
```

**Rust library not found**
```bash
# Rebuild crypto engine
./build_crypto.sh release  # Unix
build_crypto.bat release   # Windows
```

### Hardware Security Issues

**TPM not detected (Linux)**
```bash
# Check kernel module
lsmod | grep tpm

# Load module
sudo modprobe tpm_tis
```

**Permission denied (Linux TPM)**
```bash
sudo usermod -a -G tss $USER
# Log out and back in
```

**SoftHSM not detected**
```bash
# Verify library exists
ls /usr/lib/softhsm/libsofthsm2.so

# Check configuration
echo $SOFTHSM2_CONF
```

---

## FAQ

### Is my data sent to the cloud?

**No.** Your vault is stored locally on your device. The only data transmitted is during sync:
- Encrypted vault chunks sent through relay
- Relay only stores opaque encrypted blobs
- 60-second TTL, then deleted
- Server cannot decrypt your data

### What happens if I forget my master password?

**Your vault cannot be recovered.** There is no password reset or recovery mechanism. This is by design for security. We recommend:
- Use a memorable but strong password
- Consider writing it down and storing securely
- Test your password periodically

### Is QSafeVault post-quantum secure?

**Yes** (Consumer edition). QSafeVault uses:
- ML-KEM 768 (Kyber) for key encapsulation
- Dilithium3 for digital signatures
- These are NIST-standardized post-quantum algorithms

Enterprise edition uses FIPS-only algorithms until PQC is FIPS-approved.

### Can I use QSafeVault offline?

**Yes.** QSafeVault works completely offline. Sync features require internet connection, but vault creation, password management, and encryption all work offline.

### How do I backup my vault?

The vault is stored at:
- **Windows**: `%APPDATA%\qsafevault\`
- **Linux**: `~/.local/share/qsafevault/`
- **macOS**: `~/Library/Application Support/qsafevault/`
- **Android**: Internal app storage

To backup, copy the entire folder to a secure location.

### Is QSafeVault open source?

**Yes.** QSafeVault is released under CC BY-NC 4.0 license. Source code is available at:
https://github.com/aimatochysia/qsafevault

---

## Support

- **Issues**: https://github.com/aimatochysia/qsafevault/issues
- **Security Issues**: Report privately via GitHub Security Advisories
- **Documentation**: See [SRS.md](SRS.md) for technical architecture

---

*Last updated: January 2026*
