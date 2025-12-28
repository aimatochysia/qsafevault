# Q‑Safe Vault

A secure, local‑first password manager built with Flutter featuring **post-quantum cryptography**. Vault data is encrypted at rest with AES‑256‑GCM using keys derived via post-quantum Kyber ML-KEM 768, with Argon2id for password‑based key derivation and optional fast‑unlock keys wrapped in platform secure storage. Device‑to‑device sync uses encrypted relay channels, authenticated by Dilithium3 post-quantum digital signatures.

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

Key highlights
- Local‑only vault; no cloud storage
- **Post-quantum encryption**: Kyber ML-KEM + AES‑256‑GCM
- **Post-quantum signatures**: Dilithium3 for device identity
- Argon2id password KDF (m=64MB, t=3, p=4 for full unlock)
- Fast unlock via OS secure storage (optional)
- Cross‑platform app (Windows, Linux, Android; macOS/iOS planned)
- Peer‑to‑peer sync with end-to-end PQ encryption
- No telemetry

Supported platforms
- Windows (desktop) - TPM2/CNG support
- Linux (desktop) - TPM2/SoftHSM support
- Android (mobile) - StrongBox Keystore support
- macOS/iOS (on dev) - Secure Enclave support

License
- Creative Commons Attribution‑NonCommercial 4.0 International (CC BY‑NC 4.0)

---

## Table of contents
- Overview and architecture
- Security model
- Requirements
- Install and run
- Build from source
- Configuration (rendezvous server, environment)
- Device synchronization (PIN pairing)
- Troubleshooting
- Contributing
- Roadmap
- License and acknowledgements

---

## Overview and architecture

Components
- App: Flutter UI and services (vault storage, crypto, sync).
- Crypto Engine: Rust FFI providing all post-quantum cryptographic operations.
- Storage: AES‑256‑GCM encrypted vault (keys from PQ KEM); atomic writes; backups; optional wrapped key in secure storage.
- Device identity: Dilithium3 key pair generated per device for post-quantum authentication.
- Sync: Stateless, PIN + password‑protected encrypted relay over HTTPS. The app encrypts the payload end‑to‑end using PQ-derived keys and sends it in short‑lived chunks via a serverless relay; the relay stores only opaque chunks with a 30–60s TTL and never sees plaintext.

Data flow
1) Unlock vault with password (Argon2id -> master key -> decrypt vault)
2) Optionally store a wrapped fast‑unlock key in platform secure storage
3) Sync (relay):
   - Sender chooses a 6‑digit PIN and a transfer password
   - App derives a transfer key deterministically from PIN + password and encrypts the vault
   - Encrypted bytes are chunked and POSTed to /api/send with { pin, passwordHash, chunkIndex, totalChunks, data }
   - Receiver polls GET /api/receive?pin=...&passwordHash=...; chunks are dequeued and assembled
   - Receiver decrypts with the same transfer key and applies the vault

---

## Security model

- **Encryption at rest**: AES‑256‑GCM with keys derived from PQ KEM (Kyber)
- **Key Exchange**: ML-KEM 768 (Kyber) - NIST standardized post-quantum KEM
- **Digital Signatures**: Dilithium3 - NIST standardized post-quantum signatures
- **Password KDF**: Argon2id (calibrated: m=64MB, t=3, p=4 for full unlock; m=16MB, t=1, p=1 for fast unlock)
- **Key Derivation**: HKDF-SHA3-256 for deriving encryption and MAC keys from PQ KEM output
- **Integrity**: AEAD 128-bit authentication tags; HMAC‑SHA3 for tamper detection
- **Device trust**: Dilithium3 public key pinning; sync will warn on untrusted peers
- **Signaling privacy**: Offer/Answer sealed with AES‑GCM using a key derived from PIN via Argon2id (server stores only sealed envelopes)
- **Transport**: End-to-end encryption with forward secrecy (ephemeral PQ keys)

### Zero-Trust Architecture
- Server stores only opaque encrypted blobs; cannot decrypt vault data
- All keys derived locally; no key material transmitted to server
- Multi-device key sharing uses secure PQ-encrypted channels
- Rate limiting for login and sync operations
- Logging contains no secret data, only metadata (timestamps, device IDs)

Operator guidance
- Share only public keys; verify and add peers to trusted list before syncing
- Use a new PIN for each pairing; PINs expire automatically
- Clipboard handling exposes secrets to OS/global clipboard

---

## Requirements

- Flutter SDK (stable); Dart as included with Flutter
- Platform toolchains:
  - Windows: Visual Studio with Desktop C++ workload
  - Linux: gtk3/clang toolchain as required by Flutter
  - Android: Android Studio/SDK and a device/emulator
- Optional: a rendezvous server for PIN pairing (HTTPS)

---

## Install and run

Prebuilt binaries
- See Releases for Windows installer, Linux .deb, Android APK/AAB.
- Android: allow installing from unknown sources to sideload APK.

Run from source (quick)
- Windows: flutter run -d windows
- Linux: flutter run -d linux
- Android: flutter run -d android

Web is not a primary target, but can be tried via: flutter run -d chrome

---

## Build from source

Install deps
- flutter pub get

Build release
- Windows: flutter build windows
- Linux: flutter build linux
- Android (APK): flutter build apk --release
- Android (AAB): flutter build appbundle --release

### Building Rust Crypto Library for Mobile

The desktop platforms (Windows, Linux, macOS) use the Rust crypto library from `crypto_engine/target/release/` automatically. For mobile platforms, you need to build and bundle the Rust library separately:

#### Android

**Prerequisites:**
- Rust toolchain installed (`https://rustup.rs/`)
- Android NDK (automatically installed with Android Studio)
- Set `ANDROID_NDK_HOME` or `NDK_HOME` environment variable

**Build:**
```bash
./build_crypto_android.sh
```

This script:
- Builds the Rust library for all Android ABIs (arm64-v8a, armeabi-v7a, x86_64, x86)
- Places libraries in `android/app/src/main/jniLibs/<abi>/libcrypto_engine.so`
- The Flutter app will automatically find and load them

**Then build your Flutter app normally:**
```bash
flutter build apk --release
# or
flutter build appbundle --release
```

#### iOS

**Prerequisites:**
- Rust toolchain installed (`https://rustup.rs/`)
- macOS with Xcode installed
- iOS targets added to Rust

**Build:**
```bash
./build_crypto_ios.sh
```

This script:
- Builds the Rust library for iOS devices and simulators
- Creates an XCFramework at `ios/Frameworks/CryptoEngine.xcframework`
- You may need to link this in Xcode (open `ios/Runner.xcworkspace`)

**Then build your Flutter app normally:**
```bash
flutter build ios --release
# or
flutter build ipa --release
```

**Note:** Backend status notifications (TPM2/SoftHSM detection popup) only appear when the Rust library is successfully built and bundled. On mobile without the Rust library, the app uses the existing Dart cryptography implementation and notifications are silently skipped.

CI/CD
- See .github/workflows/flutter_build.yml for multi‑platform builds and release packaging.

---

## Configuration

Runtime configuration is via --dart-define.

- QSV_SYNC_BASEURL: Base URL for the relay server
  - Example: --dart-define=QSV_SYNC_BASEURL=https://your-relay.vercel.app
  - For local development: --dart-define=QSV_SYNC_BASEURL=http://localhost:3000

Notes
- All HTTP/HTTPS calls are short‑lived; the relay retains chunks for 60s only.
- Poll settings: httpTimeout≈8s, pollInterval≈800ms, pollMaxWait≈180s.

---

## Device synchronization (PIN relay)

Prerequisites
- Sender and Receiver agree on a 6‑digit PIN and a temporary transfer password (not stored).
- Both devices open the Sync dialog (relay mode).

Relay endpoints (stateless)
- POST /api/send → { status }
- GET  /api/receive?pin=...&passwordHash=... → { status, chunk? }
  - status ∈ waiting | chunkAvailable | done | expired
  - chunk: { chunkIndex, totalChunks, data } (opaque, encrypted; base64)

How to sync
- Sender:
  - Choose PIN + transfer password
  - The app encrypts and uploads chunks to /api/send (TTL 60s)
- Receiver:
  - Enter the same PIN + transfer password
  - The app polls /api/receive, assembles chunks, decrypts, and applies the vault
  - Sends acknowledgment to notify sender the transfer is complete

Bidirectional sync
- After the initial transfer, roles reverse automatically
- The original receiver becomes the sender for the return transfer
- Uses the same PIN and password for seamless bidirectional sync
- Acknowledgment keys persist for 60s to ensure reliable completion

Security
- End‑to‑end encryption: Vault is encrypted with AES‑GCM using a key derived (Argon2id) from PIN + transfer password with deterministic salt; relay cannot read payloads.
- Stateless relay: Chunks are stored in memory only with a TTL (60s) and deleted upon delivery.
- Acknowledgment key: The receiver sends an acknowledgment after receiving all chunks. This ack key persists for 60s to support reliable bidirectional sync, even after the session is marked completed.
- No persistent storage, databases, or logs on the relay.

---

## Troubleshooting

- waiting status persists
  - Sender not yet uploading or PIN/password mismatch.
- expired
  - 60s TTL elapsed before transfer finished. Restart with a new PIN/password.
- Decryption failure
  - PIN or transfer password mismatch; retry.
- Very large vault stalls
  - Keep both apps foreground; avoid device sleep during transfer.

---

## Logging and diagnostics
- Sync relay HTTP logs use prefix [relay]
- Events: DataSentEvent / DataReceivedEvent counts, HandshakeCompleteEvent (receive finished)
- No chunks retained after delivery or TTL; replay not possible.

---

## Contributing

- Issues and PRs are welcome for bug reports, documentation, and non‑commercial improvements.
- Security issues: please report privately (see Responsible disclosure).

---

## Enterprise Setup: Hardware Security Backends (TPM2 & SoftHSM)

For enterprise deployments requiring hardware-backed key storage, QSafeVault supports automatic detection and use of TPM2 and SoftHSM backends. **Regular users do not need to configure anything** – the app works immediately with secure defaults on all platforms.

### Auto-Detection System

QSafeVault automatically detects and uses the best available secure storage:

**Priority Order:**
1. **Dual-Sealing** (TPM2 + SoftHSM): Maximum security – keys sealed with both backends
2. **TPM2 only**: Hardware-backed security (Windows/Linux)
3. **SoftHSM only**: PKCS#11 HSM simulation
4. **Platform Native**: Secure Enclave (iOS/macOS), StrongBox (Android)
5. **Software Fallback**: Encrypted filesystem storage (always available)

### Default Behavior (No Setup Required)

- **iOS/macOS**: Uses Secure Enclave + Keychain automatically
- **Android**: Uses StrongBox Keystore if available
- **Windows/Linux**: Uses software fallback (secure, but not hardware-backed)

### Enterprise TPM2 Setup (Windows & Linux)

#### Windows TPM2

Modern Windows systems (8+) have built-in TPM 2.0. No installation required.

**Verify TPM availability:**
```powershell
Get-Tpm
# Should show: TpmPresent: True, TpmReady: True
```

**Enable TPM in BIOS/UEFI:**
1. Restart → Enter BIOS/UEFI setup
2. Navigate to Security settings
3. Enable TPM/Intel PTT/AMD fTPM
4. Save and reboot

QSafeVault will automatically detect and use TPM2 via Windows CNG.

#### Linux TPM2

**1. Check TPM availability:**
```bash
ls -l /dev/tpm0 /dev/tpmrm0
# Should show device nodes if TPM exists
```

**2. Install TPM2 tools (optional, for verification):**
```bash
# Debian/Ubuntu
sudo apt-get install tpm2-tools

# Fedora/RHEL
sudo dnf install tpm2-tools

# Arch
sudo pacman -S tpm2-tools
```

**3. Verify TPM is functional:**
```bash
sudo tpm2_getcap properties-fixed
# Should display TPM manufacturer and capabilities
```

**4. Ensure proper permissions:**
```bash
# Add user to tss group (TPM access)
sudo usermod -a -G tss $USER
# Log out and back in for group changes to take effect
```

QSafeVault will automatically detect TPM2 via `/dev/tpm0` or `/dev/tpmrm0`.

### Enterprise SoftHSM Setup (Development & Testing)

SoftHSM provides PKCS#11 HSM simulation without hardware. Useful for:
- Development environments
- CI/CD pipelines
- Testing HSM integration
- Systems without TPM hardware

#### Linux SoftHSM

```bash
# Install SoftHSM
sudo apt-get install softhsm2  # Debian/Ubuntu
sudo dnf install softhsm       # Fedora/RHEL
sudo pacman -S softhsm         # Arch

# Initialize token
softhsm2-util --init-token --slot 0 --label "QSafeVault" --pin 1234 --so-pin 1234

# Verify installation
softhsm2-util --show-slots
```

#### macOS SoftHSM

```bash
# Install via Homebrew
brew install softhsm

# Initialize token
softhsm2-util --init-token --slot 0 --label "QSafeVault" --pin 1234 --so-pin 1234

# Verify
softhsm2-util --show-slots
```

#### Windows SoftHSM

```powershell
# Download from https://github.com/opendnssec/SoftHSMv2/releases
# Install to C:\SoftHSM2 (or custom path)

# Add to system PATH
$env:Path += ";C:\SoftHSM2\bin"
[Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)

# Initialize token
softhsm2-util --init-token --slot 0 --label "QSafeVault" --pin 1234 --so-pin 1234

# Verify
softhsm2-util --show-slots
```

### Verifying Backend Detection

QSafeVault displays detected backends on startup as a fleeting notification:

**Example notifications:**
- `🔐 Security: Secure Enclave + Keychain | Kyber ML-KEM 768 + X25519`
- `🔐 Security: TPM2 + SoftHSM (dual-seal) | Hybrid PQC active`
- `🔐 Security: TPM2 | Post-quantum encryption enabled`
- `🔐 Security: Software fallback | All data encrypted`

**Manual verification via logs:**
```bash
# Check app logs for backend detection
# Location varies by platform:
# Linux: ~/.local/share/qsafevault/logs/
# Windows: %APPDATA%\qsafevault\logs\
# macOS: ~/Library/Application Support/qsafevault/logs/

# Look for lines like:
# INFO  Backend detection: TPM2: YES, SoftHSM: YES
# INFO  Using BOTH TPM2 + SoftHSM (dual-sealing)
```

### Security Guarantees

**TPM2 (Hardware-backed):**
- ✅ Keys never leave TPM chip
- ✅ Tamper-resistant
- ✅ Bound to specific device
- ✅ Survives OS reinstall attacks
- ❌ Not portable between devices

**SoftHSM (Software simulation):**
- ✅ PKCS#11 standard compliance
- ✅ Useful for testing/development
- ❌ Keys stored on filesystem
- ❌ Not hardware-backed
- ❌ Vulnerable to memory dumps

**Dual-Sealing (TPM2 + SoftHSM):**
- ✅ Keys wrapped with both backends
- ✅ Either backend can decrypt independently
- ✅ Protection against single backend compromise
- ✅ Maximum defense-in-depth

**Platform Native (iOS/macOS/Android):**
- ✅ Hardware-backed on supported devices
- ✅ OS-integrated security
- ✅ No additional setup required
- ✅ Works out-of-the-box

**Software Fallback:**
- ✅ Always available
- ✅ No dependencies
- ✅ Encrypted with AES-256-GCM
- ❌ Keys on filesystem (restricted permissions)

### Troubleshooting

**TPM not detected on Linux:**
```bash
# Check kernel module loaded
lsmod | grep tpm
# Should show: tpm_tis, tpm_crb, or similar

# If missing, load module
sudo modprobe tpm_tis
```

**Permission denied accessing TPM:**
```bash
# Check device permissions
ls -l /dev/tpm0
# Should show: crw-rw---- 1 tss tss

# Add user to tss group
sudo usermod -a -G tss $USER
# Log out and back in
```

**SoftHSM not detected:**
```bash
# Verify SoftHSM library exists
ls /usr/lib/softhsm/libsofthsm2.so  # Linux
ls /usr/local/lib/softhsm/libsofthsm2.so  # macOS
dir C:\SoftHSM2\lib\softhsm2.dll  # Windows

# Check environment variable
echo $SOFTHSM2_CONF  # Should point to softhsm2.conf
```

**No backend detected (using fallback):**
- This is normal and safe – the app works correctly with software fallback
- All data remains encrypted with production-grade algorithms
- Enterprise users should follow setup guides above for hardware security

### For System Administrators

**Group Policy / Automated Deployment:**

**Linux (Ansible/Puppet/Salt):**
```yaml
# Install TPM tools
- name: Install TPM2 support
  package:
    name: tpm2-tools
    state: present

# Add users to tss group
- name: Grant TPM access
  user:
    name: "{{ username }}"
    groups: tss
    append: yes
```

**Windows (GPO/SCCM):**
```powershell
# Verify TPM via Group Policy script
$tpm = Get-Tpm
if ($tpm.TpmPresent -and $tpm.TpmReady) {
    Write-Host "TPM2 ready for QSafeVault"
} else {
    Write-Warning "TPM2 not available - software fallback will be used"
}
```

**Docker/Container Environments:**
```dockerfile
# For containerized deployments requiring SoftHSM
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y softhsm2
RUN softhsm2-util --init-token --slot 0 --label "QSafeVault" --pin 1234 --so-pin 1234 --free
# Note: TPM2 not available in containers - use SoftHSM or host TPM passthrough
```

---

## Roadmap

- [Done] Core vault and desktop/mobile UI
- [Done] AES‑256‑GCM + Argon2id (calibrated)
- [Done] Fast unlock via secure storage (optional)
- [Done] Atomic writes, backups, multi‑part storage
- [Done] WebRTC sync with PIN rendezvous and device trust
- [Done] Post-quantum KEM (Kyber ML-KEM 768) - NIST standardized
- [Done] Post-quantum signatures (Dilithium3) - NIST standardized
- [Done] Platform secure storage auto-detection (TPM2, SoftHSM, Secure Enclave)
- [Done] Rust FFI crypto engine for all platforms
- [Planned] macOS/iOS support (in progress)
- [Planned] Third‑party security audit
- [Planned] Full TPM2/SoftHSM sealing implementation

---

## License and acknowledgements

License
- Creative Commons Attribution‑NonCommercial 4.0 International (CC BY‑NC 4.0). See LICENSE.

Acknowledgements
- pqcrypto-mlkem, pqcrypto-dilithium, aes-gcm, hkdf, sha3, zeroize, and the Flutter/Rust ecosystems.

---
