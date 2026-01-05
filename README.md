# Q‑Safe Vault

A secure, local‑first password manager built with Flutter featuring **post-quantum cryptography**. Vault data is encrypted at rest with AES‑256‑GCM using keys derived via post-quantum Kyber ML-KEM 768, with Argon2id for password‑based key derivation and optional fast‑unlock keys wrapped in platform secure storage. Device‑to‑device sync uses encrypted relay channels, authenticated by Dilithium3 post-quantum digital signatures.

> 📚 **For detailed documentation, see:**
> - [USER_GUIDE.md](USER_GUIDE.md) - Complete installation, setup, and usage guide
> - [SRS.md](SRS.md) - Software Requirements Specification (architecture, engine, APIs)
> - [CRYPTO_ARCHITECTURE.md](CRYPTO_ARCHITECTURE.md) - Cryptographic backend details

## 🔐 Post-Quantum Security

This vault is **fully post-quantum secure**, protecting against both classical and quantum computer attacks:

| Cryptographic Function | Algorithm | Security Level |
|------------------------|-----------|----------------|
| Key Encapsulation | ML-KEM 768 (Kyber) | NIST Level 3 (PQ-safe) |
| Digital Signatures | Dilithium3 | NIST Level 3 (PQ-safe) |
| Symmetric Encryption | AES-256-GCM | 256-bit (PQ-safe) |
| Key Derivation | HKDF-SHA3-256 | 256-bit (PQ-safe) |
| Password KDF | Argon2id | Memory-hard |

**No classical-only cryptography remains** in the security-critical paths.

## 📦 Product Editions

QSafeVault supports two product modes: **Consumer Grade** and **Enterprise Grade**.

| Feature | Consumer | Enterprise |
|---------|----------|------------|
| Post-quantum crypto | ✅ Enabled | ❌ Disabled (until FIPS-approved) |
| FIPS-only mode | ❌ | ✅ Required |
| Key providers | Local/TPM/SoftHSM | External HSM required |
| Deployment | Any | Self-hosted only |
| Open source | ✅ | ✅ |
| Account database | ❌ None | ❌ None |
| Vault storage | Local only | Local only |

## 🚀 Quick Start

### Consumer (Personal Use)

```bash
# Clone and run
git clone https://github.com/aimatochysia/qsafevault.git
cd qsafevault
flutter pub get
flutter run
```

Uses public relay by default. For self-hosting, see [USER_GUIDE.md](USER_GUIDE.md#self-hosting-the-backend).

### Enterprise (Regulated Environments)

```bash
# 1. Start your backend server
cd qsafevault-server
npm install
export QSAFEVAULT_EDITION=enterprise
export QSAFEVAULT_ENTERPRISE_ACKNOWLEDGED=true
node server.js

# 2. Run the app (separate terminal)
cd ..
flutter run --dart-define=QSAFEVAULT_EDITION=enterprise \
  --dart-define=QSV_SYNC_BASEURL=http://localhost:3000
```

Enterprise mode requires self-hosted backend. See [USER_GUIDE.md](USER_GUIDE.md#enterprise-deployment) for production setup.

## 🔨 GitHub Actions Build

Use the **Manual Build** workflow for custom builds:

1. Go to **Actions** → **Manual Build with Options**
2. Select **edition** (consumer/enterprise)
3. Choose platforms (Android, Linux, Windows, macOS, iOS, Web)
4. Optionally specify **server URL** (required for Enterprise)
5. Click **Run workflow**

See [`.github/workflows/manual_build.yml`](.github/workflows/manual_build.yml) for details.

## 📋 Documentation Index

| Document | Description |
|----------|-------------|
| [USER_GUIDE.md](USER_GUIDE.md) | Installation, setup, configuration, usage |
| [SRS.md](SRS.md) | Architecture, crypto engine, APIs, security model |
| [CRYPTO_ARCHITECTURE.md](CRYPTO_ARCHITECTURE.md) | Cryptographic backend details |
| [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) | What's implemented, what's planned |
| [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) | Developer getting started guide |
| [docs/SYNC_GUIDE.md](docs/SYNC_GUIDE.md) | Device synchronization details |
| [docs/TESTING_GUIDE.md](docs/TESTING_GUIDE.md) | Testing instructions |

## ✨ Key Features

- **Local-only vault** - No cloud storage
- **Post-quantum encryption** - Kyber ML-KEM + AES-256-GCM
- **Post-quantum signatures** - Dilithium3 for device identity
- **Hardware security** - TPM2, Secure Enclave, StrongBox support
- **Cross-platform** - Windows, Linux, Android (macOS/iOS in development)
- **P2P sync** - End-to-end encrypted, stateless relay
- **No telemetry** - Zero tracking, zero analytics

## 🖥️ Supported Platforms

| Platform | Status | Hardware Security |
|----------|--------|-------------------|
| Windows | ✅ Stable | TPM2/CNG |
| Linux | ✅ Stable | TPM2/SoftHSM |
| Android | ✅ Stable | StrongBox Keystore |
| macOS | 🔄 In Development | Secure Enclave |
| iOS | 🔄 In Development | Secure Enclave |
| Web | ⚠️ Limited | Software only |

## 📄 License

Creative Commons Attribution‑NonCommercial 4.0 International (CC BY‑NC 4.0). See [LICENSE](LICENSE).

## 🙏 Acknowledgements

- pqcrypto-mlkem, pqcrypto-dilithium, aes-gcm, hkdf, sha3, zeroize
- Flutter and Rust ecosystems

---

*For detailed documentation, see [USER_GUIDE.md](USER_GUIDE.md) and [SRS.md](SRS.md).*
