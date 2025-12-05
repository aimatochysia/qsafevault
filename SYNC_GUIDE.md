# Device Sync Guide

Audience
- End users performing device-to-device sync.
- Operators running the signaling server.

What this covers
- Invite code pairing flow, P2P sync, prerequisites, expected logs, and troubleshooting.

## Overview

QSafeVault uses a zero-trust, peer-to-peer synchronization system:
- **8-character invite codes** (case-sensitive alphanumeric) for peer discovery
- **CRDT-based merging** for conflict-free vault updates
- **WebRTC data channels** for direct P2P communication (preferred)
- **HTTP relay fallback** for restrictive network environments
- **End-to-end encryption** - server never sees plaintext data
- **Serverless signaling** - no database, ephemeral memory only

## Prerequisites
- Both devices have Q-Safe Vault installed and a vault open.
- Signaling server: App configured with QSV_SYNC_BASEURL (HTTPS preferred).
  - Example run: --dart-define=QSV_SYNC_BASEURL=https://qsafevault-server.vercel.app

## Quick Start

### Sender (Device A)
1. Open Sync dialog → Select "Send"
2. Enter a transfer password (min 6 characters)
3. Tap "Send" → An 8-character invite code is generated (e.g., `Ab3Xy9Zk`)
4. Share the invite code and password with the receiver
5. Keep the screen open until sync completes

### Receiver (Device B)
1. Open Sync dialog → Select "Receive"
2. Enter the 8-character invite code (case-sensitive!)
3. Enter the same transfer password
4. Tap "Receive" → Wait for data transfer
5. After receiving, the vault is merged automatically

### Bidirectional Sync
After the initial transfer:
- Receiver automatically sends their vault back to the sender
- Both devices end up with merged data from both vaults
- CRDT ensures conflict-free merging

## Invite Code Format
- **Length**: 8 characters
- **Characters**: A-Z, a-z, 0-9 (case-sensitive)
- **Example**: `Ab3Xy9Zk`, `xY7mNp2Q`
- **Validity**: 30 seconds for signaling, 60 seconds for relay

## Sync Modes

### P2P Mode (WebRTC)
- Direct device-to-device connection
- Uses STUN servers for NAT traversal (no TURN)
- Lowest latency, most efficient
- Requires both devices to support WebRTC

### Relay Mode (HTTP)
- Fallback when P2P is unavailable
- Data chunked and encrypted, uploaded to relay server
- Server stores chunks in memory with 60s TTL
- Works through any network configuration

## What to expect in logs (debug)

Sender:
```
[sync] session created inviteCode=Ab3Xy9Zk
[P2P] Initializing as initiator with invite code: Ab3Xy9Zk
[P2P] Registered peer with invite code
[P2P] ICE connection state: connected
[P2P] Data channel state: open
```

Receiver:
```
[P2P] Initializing as joiner with invite code: Ab3Xy9Zk
[P2P] Found remote peer: <peer_id>
[P2P] Received signal: offer from <peer_id>
[P2P] ICE connection state: connected
```

Relay fallback:
```
[sync] sending chunks=3
[RelayClient] POST /api/relay → 200
```

## Troubleshooting

### Common errors and fixes

**"Invite code must be 8 alphanumeric characters"**
- Ensure you're entering exactly 8 characters
- Invite codes are case-sensitive (Ab3X ≠ ab3x)

**"Peer not found for invite code"**
- Code has expired (>30s for signaling)
- Sender closed the app or left the sync screen

**"Expired or incomplete"**
- Session TTL (60s) elapsed
- Restart with a new invite code

**P2P connection fails**
- Check if both devices support WebRTC
- May need to wait longer for ICE negotiation
- System automatically falls back to relay mode

**Slow or partial transfers**
- Keep both apps in foreground
- Ensure stable network connection

## Security & Privacy

- **Zero-trust**: Server cannot read any user data
- **End-to-end encryption**: All data encrypted with key derived from invite code + password
- **Serverless**: No database, no persistent storage
- **Ephemeral**: All signaling data stored in memory only with short TTL
- **STUN only**: No TURN servers, no media relay that could inspect traffic
- **CRDT**: Conflict-free merging without central authority

## CRDT (Conflict-free Replicated Data Type)

QSafeVault uses a Last-Writer-Wins (LWW) CRDT strategy:
- Each vault entry has a unique ID, timestamp, and device ID
- Conflicts resolved by preferring higher timestamp
- Tie-breaker: lexicographic comparison of device IDs
- Deleted entries are tombstoned, not removed
- Offline changes sync automatically when devices reconnect

## Server Specification (qsafevault-server)

### Endpoints

**POST /api/relay**

Actions:
- `register`: Register peer with invite code for discovery
- `lookup`: Look up peer by invite code
- `signal`: Send WebRTC signaling message
- `poll`: Poll for signaling messages
- `send`: Upload encrypted chunk (relay fallback)
- `receive`: Poll for chunks (relay fallback)
- `ack`: Acknowledge receipt
- `ack-status`: Check acknowledgment status

### WebRTC Signaling

```json
// Register peer
{ "action": "register", "inviteCode": "Ab3Xy9Zk", "peerId": "<uuid>" }

// Look up peer
{ "action": "lookup", "inviteCode": "Ab3Xy9Zk" }

// Send signal (offer/answer/ICE)
{ "action": "signal", "from": "<peerId>", "to": "<peerId>", "type": "offer", "payload": "<encrypted>" }

// Poll for signals
{ "action": "poll", "peerId": "<uuid>" }
```

### Relay (Fallback)

```json
// Send chunk
{ "action": "send", "pin": "<inviteCode>", "passwordHash": "<hash>", "chunkIndex": 0, "totalChunks": 3, "data": "<base64>" }

// Receive chunk
{ "action": "receive", "pin": "<inviteCode>", "passwordHash": "<hash>" }
// Response: { "status": "chunkAvailable", "chunk": { ... } } or { "status": "waiting" | "done" | "expired" }
```

### Constraints

- No persistent storage (Redis/MongoDB prohibited)
- No logging of sensitive content
- Ephemeral memory only
- 30s TTL for signaling, 60s TTL for relay
- Scalable on Vercel serverless functions

## Notes

- The invite code replaces the previous 6-digit PIN system
- Invite codes provide more entropy (62^8 vs 10^6)
- Case-sensitivity is intentional for security
- For maximum security, share the transfer password through a different channel than the invite code
