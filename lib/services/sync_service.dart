import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:meta/meta.dart';
import '../config/sync_config.dart';
import 'secure_storage.dart';
import 'crypto_service.dart';
import 'relay_client.dart';
import 'app_logger.dart';

@immutable
class RelaySession {
  final String pin;
  final String passwordHash;
  const RelaySession({required this.pin, required this.passwordHash});
}

class SyncService {
  final _cfg = SyncConfig.defaults();
  final SecureStorage _secure = SecureStorage();
  final CryptoService _crypto = CryptoService();
  final RelayClient _relay = RelayClient(config: SyncConfig.defaults());

  StreamController<SyncEvent>? _events;
  SyncStatus status = SyncStatus.idle;

  void _log(String msg) {
    try { AppLogger.instance.write('[relay] $msg'); } catch (_) {}
  }

  Stream<SyncEvent>? get events => _events?.stream;

  Future<void> init() async {
    if (_events != null) return;
    _events = StreamController<SyncEvent>.broadcast();
  }

  // Generate 6-digit PIN
  String _genPin() {
    final n = Random.secure().nextInt(1000000);
    return n.toString().padLeft(6, '0');
  }

  Future<RelaySession> createRelaySession({required String password, String? pinOverride}) async {
    await init();
    final pin = pinOverride ?? _genPin();
    final passwordHash = _relay.passwordHash(pin: pin, password: password);
    _log('session created pin=$pin');
    return RelaySession(pin: pin, passwordHash: passwordHash);
  }

  Future<void> sendVaultRelay({
    required RelaySession session,
    required String transferPassword,
    required Future<String> Function() getVaultJson,
  }) async {
    await init();
    status = SyncStatus.signaling;
    final key = await _relay.deriveTransferKey(pin: session.pin, password: transferPassword);
    final vaultJson = await getVaultJson();
    final envelopeBytes = await _relay.encryptPayload(key, vaultJson);
    final chunks = _relay.chunk(envelopeBytes, size: 32 * 1024);
    _log('sending chunks=${chunks.length}');
    for (int i = 0; i < chunks.length; i++) {
      await _relay.sendChunk(
        pin: session.pin,
        passwordHash: session.passwordHash,
        chunkIndex: i,
        totalChunks: chunks.length,
        chunkData: chunks[i],
      );
      _events?.add(SyncEvent.dataSent());
    }
    status = SyncStatus.connected;
  }

  Future<String?> receiveVaultRelay({
    required RelaySession session,
    required String transferPassword,
    Duration? maxWait,
  }) async {
    await init();
    status = SyncStatus.signaling;
    final deadline = DateTime.now().add(maxWait ?? _cfg.pollMaxWait);
    final buffers = <int, Uint8List>{};
    int? total;
    while (DateTime.now().isBefore(deadline)) {
      final r = await _relay.pollNext(pin: session.pin, passwordHash: session.passwordHash);
      if (r.status == 'chunkAvailable' && r.index != null && r.data != null) {
        buffers[r.index!] = r.data!;
        total ??= r.total!;
        _events?.add(SyncEvent.dataReceived());
        if (total != null && buffers.length == total) {
          final ordered = List<int>.generate(total!, (i) => i).map((i) => buffers[i]!).toList();
          final merged = _concat(ordered);
          final key = await _relay.deriveTransferKey(pin: session.pin, password: transferPassword);
          final plaintext = await _relay.decryptPayload(key, merged);
          status = SyncStatus.connected;
          _events?.add(SyncEvent.handshakeComplete());
          return plaintext;
        }
      } else if (r.status == 'done') {
        break;
      } else if (r.status == 'expired') {
        _log('session expired');
        return null;
      }
      await Future.delayed(_jitter(_cfg.pollInterval));
    }
    return null;
  }

  Uint8List _concat(List<Uint8List> parts) {
    final total = parts.fold<int>(0, (a, b) => a + b.length);
    final out = Uint8List(total);
    int o = 0;
    for (final p in parts) { out.setRange(o, o + p.length, p); o += p.length; }
    return out;
  }

  Duration _jitter(Duration base) {
    final ms = base.inMilliseconds;
    final r = 0.8 + Random.secure().nextDouble() * 0.4;
    return Duration(milliseconds: (ms * r).toInt());
  }

  Future<void> stop() async {
    status = SyncStatus.idle;
    await _events?.close();
    _events = null;
  }
}

enum SyncStatus { idle, signaling, connected }

abstract class SyncEvent {
  const SyncEvent();
  factory SyncEvent.handshakeComplete() = HandshakeCompleteEvent;
  factory SyncEvent.dataSent() = DataSentEvent;
  factory SyncEvent.dataReceived() = DataReceivedEvent;
  factory SyncEvent.error(String message) = ErrorEvent;
  factory SyncEvent.untrustedPeer(String pubKeyB64) = UntrustedPeerEvent;
  factory SyncEvent.peerAuthenticated(String pubKeyB64) = PeerAuthenticatedEvent;
  factory SyncEvent.trustedPeersUpdated(List<String> peers) = TrustedPeersUpdatedEvent;
  factory SyncEvent.vaultRequested() = VaultRequestedEvent;
}

class HandshakeCompleteEvent extends SyncEvent {
  const HandshakeCompleteEvent();
}

class DataSentEvent extends SyncEvent {
  const DataSentEvent();
}

class DataReceivedEvent extends SyncEvent {
  const DataReceivedEvent();
}

class ErrorEvent extends SyncEvent {
  final String message;
  const ErrorEvent(this.message);
}

class UntrustedPeerEvent extends SyncEvent {
  final String pubKeyB64;
  const UntrustedPeerEvent(this.pubKeyB64);
}

class PeerAuthenticatedEvent extends SyncEvent {
  final String pubKeyB64;
  const PeerAuthenticatedEvent(this.pubKeyB64);
}

class TrustedPeersUpdatedEvent extends SyncEvent {
  final List<String> peers;
  const TrustedPeersUpdatedEvent(this.peers);
}

class VaultRequestedEvent extends SyncEvent {
  const VaultRequestedEvent();
}
