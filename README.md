# Q‑Safe Vault

A secure, local‑first password manager built with Flutter. Vault data is encrypted at rest with AES‑256‑GCM, using Argon2id for password‑based key derivation and optional fast‑unlock keys wrapped in platform secure storage. Device‑to‑device sync uses WebRTC data channels, authenticated by Ed25519 device identities, and a short‑lived PIN rendezvous.

Key highlights
- Local‑only vault; no cloud storage
- AES‑256‑GCM encryption; Argon2id KDF
- Fast unlock via OS secure storage (optional)
- Cross‑platform app (Windows, Linux, Android; macOS/iOS planned)
- Peer‑to‑peer sync over WebRTC with PIN rendezvous
- No telemetry

Supported platforms
- Windows (desktop)
- Linux (desktop)
- Android (mobile)
- macOS/iOS (on dev)

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
- Storage: AES‑256‑GCM encrypted vault; atomic writes; backups; optional wrapped key in secure storage.
- Device identity: Ed25519 key pair generated per device (for local features).
- Sync: Stateless, PIN + password‑protected encrypted relay over HTTPS. The app encrypts the payload end‑to‑end and sends it in short‑lived chunks via a serverless relay; the relay stores only opaque chunks with a 30–60s TTL and never sees plaintext.

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

- Encryption at rest: AES‑256‑GCM
- Password KDF: Argon2id (calibrated); fast‑unlock also Argon2id with separate parameters
- Integrity: AEAD tags; HMAC‑SHA3‑512 for verifier and tamper detection of fast‑params
- Device trust: Ed25519 public key pinning; sync will warn on untrusted peers
- Signaling privacy: Offer/Answer sealed with AES‑GCM using a key derived from PIN via Argon2id (server stores only sealed envelopes)
- Transport: WebRTC DTLS/SRTP

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

CI/CD
- See .github/workflows/flutter_build.yml for multi‑platform builds and release packaging.

---

## Configuration

Runtime configuration is via --dart-define.

- QSV_SYNC_BASEURL: Base URL for the relay server
  - Example: --dart-define=QSV_SYNC_BASEURL=https://your-relay.vercel.app
  - For local development: --dart-define=QSV_SYNC_BASEURL=http://localhost:3000

Notes
- All HTTP/HTTPS calls are short‑lived; the relay retains chunks for 30–60s only.
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
  - The app encrypts and uploads chunks to /api/send (TTL 30–60s)
- Receiver:
  - Enter the same PIN + transfer password
  - The app polls /api/receive, assembles chunks, decrypts, and applies the vault

Security
- End‑to‑end encryption with AES‑GCM using a key derived (Argon2id) from PIN + transfer password (deterministic salt).
- Relay stores only opaque chunk strings and deletes them immediately after delivery or TTL expiry.

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

## Roadmap

- [Done] Core vault and desktop/mobile UI
- [Done] AES‑256‑GCM + Argon2id (calibrated)
- [Done] Fast unlock via secure storage (optional)
- [Done] Atomic writes, backups, multi‑part storage
- [Done] WebRTC sync with PIN rendezvous and device trust
- [Planned] macOS/iOS support
- [Planned] Third‑party security audit
- [Planned] PQ/hybrid crypto options

---

## License and acknowledgements

License
- Creative Commons Attribution‑NonCommercial 4.0 International (CC BY‑NC 4.0). See LICENSE.

Acknowledgements
- cryptography, pointycastle, flutter_secure_storage, flutter_webrtc and the Flutter ecosystem.

---
