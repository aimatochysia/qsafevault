import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:meta/meta.dart';
import '../config/sync_config.dart';
import 'secure_storage.dart';
import 'fips_crypto_service.dart';
import 'relay_client.dart';
import 'app_logger.dart';
import 'crdt_service.dart';
import 'p2p_peer_service.dart';
import 'invite_code_utils.dart';

/// Represents a relay session with invite code.
/// Now uses 8-character alphanumeric codes instead of 6-digit PINs.
@immutable
class RelaySession {
  final String inviteCode; // 8-char alphanumeric (was 'pin')
  final String passwordHash;
  
  const RelaySession({required this.inviteCode, required this.passwordHash});
  
  // Legacy alias for backward compatibility
  String get pin => inviteCode;
}

/// Sync mode selection
enum SyncMode {
  /// HTTP relay-based sync (fallback, works through any NAT)
  relay,
  /// WebRTC peer-to-peer sync (preferred, direct connection)
  p2p,
}

/// Unified Sync Service supporting both relay and P2P modes.
/// 
/// Features:
/// - 8-character case-sensitive alphanumeric invite codes
/// - CRDT-based conflict-free merging
/// - WebRTC data channels for P2P communication
/// - End-to-end encryption using FIPS-compliant Rust FFI
/// - Fallback to HTTP relay when P2P fails
class SyncService {
  final _cfg = SyncConfig.defaults();
  final SecureStorage _secure = SecureStorage();
  final FipsCryptoService _crypto = FipsCryptoService();
  final RelayClient _relay = RelayClient(config: SyncConfig.defaults());
  
  CrdtService? _crdt;
  P2pPeerService? _p2p;

  StreamController<SyncEvent>? _events;
  SyncStatus status = SyncStatus.idle;
  SyncMode _currentMode = SyncMode.relay;

  void _log(String msg) {
    try { AppLogger.instance.write('[sync] $msg'); } catch (_) {}
  }

  Stream<SyncEvent>? get events => _events?.stream;
  
  /// Current sync mode
  SyncMode get currentMode => _currentMode;
  
  /// CRDT service instance
  CrdtService? get crdt => _crdt;

  Future<void> init() async {
    if (_events != null) return;
    _events = StreamController<SyncEvent>.broadcast();
    
    // Initialize CRDT service
    _crdt = CrdtService(crypto: _crypto);
    await _crdt!.init();
    _log('CRDT service initialized with device ID: ${_crdt!.deviceId}');
  }
  
  /// Create a relay session with invite code
  Future<RelaySession> createRelaySession({
    required String password, 
    String? inviteCodeOverride,
  }) async {
    await init();
    final inviteCode = inviteCodeOverride ?? InviteCodeUtils.generate();
    final passwordHash = _relay.passwordHash(pin: inviteCode, password: password);
    _log('session created inviteCode=$inviteCode');
    return RelaySession(inviteCode: inviteCode, passwordHash: passwordHash);
  }

  // ==================== Relay-based Sync (HTTP) ====================

  Future<void> sendVaultRelay({
    required RelaySession session,
    required String transferPassword,
    required Future<String> Function() getVaultJson,
  }) async {
    await init();
    _currentMode = SyncMode.relay;
    status = SyncStatus.signaling;
    
    final key = _relay.deriveTransferKey(pin: session.inviteCode, password: transferPassword);
    final vaultJson = await getVaultJson();
    final envelopeBytes = _relay.encryptPayload(key, vaultJson);
    final chunks = _relay.chunk(envelopeBytes, size: 32 * 1024);
    _log('sending chunks=${chunks.length}');
    for (int i = 0; i < chunks.length; i++) {
      await _relay.sendChunk(
        pin: session.inviteCode,
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
    _currentMode = SyncMode.relay;
    status = SyncStatus.signaling;
    
    final deadline = DateTime.now().add(maxWait ?? _cfg.pollMaxWait);
    final buffers = <int, Uint8List>{};
    int? total;
    while (DateTime.now().isBefore(deadline)) {
      final r = await _relay.pollNext(pin: session.inviteCode, passwordHash: session.passwordHash);
      if (r.status == 'chunkAvailable' && r.index != null && r.data != null) {
        buffers[r.index!] = r.data!;
        total ??= r.total!;
        _events?.add(SyncEvent.dataReceived());
        if (total != null && buffers.length == total) {
          final ordered = List<int>.generate(total!, (i) => i).map((i) => buffers[i]!).toList();
          final merged = _concat(ordered);
          final key = _relay.deriveTransferKey(pin: session.inviteCode, password: transferPassword);
          final plaintext = _relay.decryptPayload(key, merged);
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

  // ==================== P2P Sync (WebRTC) ====================

  /// Start P2P sync as initiator (creates invite code)
  Future<String> startP2pSync({
    required String transferPassword,
    required Future<String> Function() getVaultJson,
  }) async {
    await init();
    _currentMode = SyncMode.p2p;
    status = SyncStatus.signaling;
    
    _p2p = P2pPeerService(config: _cfg);
    
    // Listen for P2P events
    _p2p!.states.listen((state) {
      _log('P2P state: $state');
      if (state == P2pState.connected) {
        status = SyncStatus.connected;
        _events?.add(SyncEvent.handshakeComplete());
      } else if (state == P2pState.disconnected) {
        status = SyncStatus.idle;
      }
    });
    
    _p2p!.messages.listen((msg) async {
      await _handleP2pMessage(msg, getVaultJson);
    });
    
    final inviteCode = await _p2p!.initAsInitiator(transferPassword: transferPassword);
    _log('P2P initiator ready with invite code: $inviteCode');
    
    return inviteCode;
  }
  
  /// Join P2P sync with invite code
  Future<void> joinP2pSync({
    required String inviteCode,
    required String transferPassword,
    required Function(String vaultJson) onReceiveData,
  }) async {
    await init();
    _currentMode = SyncMode.p2p;
    status = SyncStatus.signaling;
    
    _p2p = P2pPeerService(config: _cfg);
    
    // Listen for P2P events
    _p2p!.states.listen((state) {
      _log('P2P state: $state');
      if (state == P2pState.connected) {
        status = SyncStatus.connected;
        _events?.add(SyncEvent.handshakeComplete());
        // Request sync data once connected
        _p2p!.sendMessage(P2pMessage.syncRequest());
      } else if (state == P2pState.disconnected) {
        status = SyncStatus.idle;
      }
    });
    
    _p2p!.messages.listen((msg) async {
      if (msg.type == P2pMessageType.syncData) {
        final crdtJson = msg.data['crdt'] as String?;
        if (crdtJson != null) {
          onReceiveData(crdtJson);
          _events?.add(SyncEvent.dataReceived());
          await _p2p!.sendMessage(P2pMessage.syncAck());
        }
      }
    });
    
    await _p2p!.initAsJoiner(
      inviteCode: inviteCode,
      transferPassword: transferPassword,
    );
    
    // Signal ready to initiator
    await _p2p!.signalReady();
    _log('P2P joiner ready');
  }
  
  Future<void> _handleP2pMessage(P2pMessage msg, Future<String> Function() getVaultJson) async {
    switch (msg.type) {
      case P2pMessageType.syncRequest:
        // Send vault data
        final vaultJson = await getVaultJson();
        await _p2p!.sendMessage(P2pMessage.syncData(vaultJson));
        _events?.add(SyncEvent.dataSent());
        break;
        
      case P2pMessageType.syncAck:
        _log('Sync acknowledged by peer');
        break;
        
      default:
        break;
    }
  }

  // ==================== CRDT Integration ====================

  /// Merge received vault data using CRDT
  Future<List<CrdtEntry>> mergeVaultData(String vaultJson) async {
    if (_crdt == null) throw StateError('CRDT not initialized');
    
    // Parse received data as CRDT document
    try {
      final remote = CrdtDocument.fromJson(jsonDecode(vaultJson) as Map<String, dynamic>);
      return await _crdt!.mergeRemote(remote);
    } catch (_) {
      // Fallback: try to import as legacy JSON array
      await _crdt!.importFromJson(vaultJson);
      return [];
    }
  }
  
  /// Export vault as CRDT document JSON
  String exportVaultAsCrdt() {
    if (_crdt == null) throw StateError('CRDT not initialized');
    return jsonEncode(_crdt!.document!.toJson());
  }
  
  /// Export vault as legacy JSON array
  String exportVaultAsLegacy() {
    if (_crdt == null) throw StateError('CRDT not initialized');
    return _crdt!.exportToJson();
  }

  // ==================== Utilities ====================

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
    await _p2p?.close();
    _p2p = null;
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
