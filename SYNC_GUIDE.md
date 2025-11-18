# Device Sync (PIN) Guide

Audience
- End users performing device-to-device sync.
- Operators running the rendezvous server.

What this covers
- PIN pairing flow, prerequisites, expected logs, and targeted troubleshooting.

## Prerequisites
- Both devices have Q‑Safe Vault installed and a vault open.
- Trusted peers: Exchange device public keys (base64) and add them to each other’s trusted list (one‑time).
- Rendezvous server: App configured with QSV_SYNC_BASEURL (HTTPS preferred).
  - Example run: --dart-define=QSV_SYNC_BASEURL=https://qsafevault-server.vercel.app

## Quick Start

Sender (Device A)
1) Open Sync dialog → Select “Relay (PIN)” → Enter a 6‑digit PIN and a temporary transfer password → Start.
2) The app encrypts the vault with a key derived from PIN+password and uploads short‑lived chunks to /api/send.
3) Keep the screen open until the receiver finishes.

Receiver (Device B)
1) Open Sync dialog → Select “Relay (PIN)” → Enter the same PIN and transfer password → Join.
2) The app polls /api/receive and assembles chunks.
3) After assembly, it decrypts and applies the vault.

Identity verification
- Transfer password is ephemeral and never sent to the relay; only passwordHash namespaces the session.
- Device public keys are not required for the relay flow.

## What to expect in logs (debug)
- Sender:
  - [relay] POST /api/send → 200 { status: "waiting" } repeated per chunk
- Receiver:
  - [relay] GET /api/receive?pin=****** → 200 { status: "chunkAvailable", chunk: { ... } } until done
  - { status: "done" } after last chunk, or { status: "expired" } if TTL elapsed

Note: Relay never logs or stores plaintext; chunks are opaque and TTL‑bound.

## Troubleshooting

Common errors and fixes
- waiting (Receiver)
  - Sender has not uploaded chunks yet; verify PIN/password match; wait or retry.
- expired
  - TTL (60s) elapsed. Restart with a new PIN/password.
- done
  - All chunks delivered; if decryption fails, verify the password and PIN, then retry.
- Slow/partial transfers
  - Keep both apps in foreground. Chunks are deleted after delivery; receiver must assemble within TTL.

## Security & Privacy

- End‑to‑end encryption: Vault is encrypted with AES‑GCM using a key derived (Argon2id) from PIN + transfer password with deterministic salt; relay cannot read payloads.
- Stateless relay: Chunks are stored in memory only with a TTL (60s) and deleted upon delivery.
- Acknowledgment key: After receiving all chunks, the receiver sends an acknowledgment. The ack key persists separately for 60s even after the session is marked completed, ensuring reliable bidirectional sync.
- No persistent storage, databases, or logs on the relay.

## Server expectations (summary)

Endpoints
- POST /api/send → { status }
- GET  /api/receive?pin=XXXXXX&passwordHash=... → { status, chunk? }
  - status ∈ waiting | chunkAvailable | done | expired
  - chunk: { chunkIndex, totalChunks, data }
- POST /api/ack → marks transfer as acknowledged by receiver
- POST /api/ack-status → { acknowledged: boolean }

Behavior
- Keep chunks in memory only with TTL 60s; delete on delivery.
- Session lifecycle: After all chunks delivered, session transitions to 'completed' state. Acknowledgment key persists for an additional 60s to support bidirectional sync.
- Cleanup expired sessions/chunks on every invocation.
- No plaintext inspection or modification of payloads.

Notes
- The README has a high‑level overview; this guide focuses on practical usage and troubleshooting for PIN pairing.
