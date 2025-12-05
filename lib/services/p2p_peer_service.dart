import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:cryptography/cryptography.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:http/http.dart' as http;
import '../config/sync_config.dart';
import 'app_logger.dart';
import 'invite_code_utils.dart';

/// WebRTC Peer Connection Manager for P2P sync.
/// Uses STUN servers only for NAT traversal (no TURN).
/// All data is end-to-end encrypted.
class P2pPeerService {
  final SyncConfig _config;
  final http.Client _http;
  
  RTCPeerConnection? _peerConnection;
  RTCDataChannel? _dataChannel;
  RTCSessionDescription? _localOffer; // Store local offer for later use
  
  String? _localPeerId;
  String? _remotePeerId;
  String? _inviteCode;
  
  SecretKey? _encryptionKey;
  
  bool _isInitiator = false;
  bool _isConnected = false;
  
  final _messageController = StreamController<P2pMessage>.broadcast();
  final _stateController = StreamController<P2pState>.broadcast();
  
  Timer? _pollingTimer;
  
  P2pPeerService({
    SyncConfig? config,
    http.Client? httpClient,
  }) : _config = config ?? SyncConfig.defaults(),
       _http = httpClient ?? http.Client();
  
  /// Stream of incoming messages
  Stream<P2pMessage> get messages => _messageController.stream;
  
  /// Stream of connection state changes
  Stream<P2pState> get states => _stateController.stream;
  
  /// Whether connected to peer
  bool get isConnected => _isConnected;
  
  /// Local peer ID
  String? get localPeerId => _localPeerId;
  
  /// Remote peer ID
  String? get remotePeerId => _remotePeerId;
  
  /// Current invite code (if initiator)
  String? get inviteCode => _inviteCode;
  
  void _log(String msg) {
    try { AppLogger.instance.write('[P2P] $msg'); } catch (_) {}
    print('[P2P] $msg');
  }
  
  /// Initialize peer connection as initiator (creates invite code)
  Future<String> initAsInitiator({required String transferPassword}) async {
    _isInitiator = true;
    _localPeerId = _generatePeerId();
    _inviteCode = InviteCodeUtils.generate();
    
    // Derive encryption key from invite code + password
    _encryptionKey = await _deriveKey(_inviteCode!, transferPassword);
    
    _log('Initializing as initiator with invite code: $_inviteCode');
    
    // Register with signaling server
    await _registerPeer(_inviteCode!, _localPeerId!);
    
    // Create peer connection
    await _createPeerConnection();
    
    // Create data channel
    await _createDataChannel();
    
    // Start polling for signals
    _startPolling();
    
    _stateController.add(P2pState.waitingForPeer);
    
    return _inviteCode!;
  }
  
  /// Initialize peer connection as joiner (uses invite code)
  Future<void> initAsJoiner({
    required String inviteCode,
    required String transferPassword,
  }) async {
    if (!InviteCodeUtils.isValid(inviteCode)) {
      throw ArgumentError('Invalid invite code format');
    }
    
    _isInitiator = false;
    _localPeerId = _generatePeerId();
    _inviteCode = inviteCode;
    
    // Derive encryption key from invite code + password
    _encryptionKey = await _deriveKey(inviteCode, transferPassword);
    
    _log('Initializing as joiner with invite code: $inviteCode');
    
    // Look up initiator's peer ID
    final result = await _lookupPeer(inviteCode);
    if (result == null) {
      throw Exception('Peer not found for invite code');
    }
    _remotePeerId = result;
    _log('Found remote peer: $_remotePeerId');
    
    // Create peer connection
    await _createPeerConnection();
    
    // Start polling for signals (need to receive offer)
    _startPolling();
    
    _stateController.add(P2pState.connecting);
  }
  
  String _generatePeerId() {
    final random = Random.secure();
    final bytes = List<int>.generate(16, (_) => random.nextInt(256));
    return base64Url.encode(bytes);
  }
  
  Future<SecretKey> _deriveKey(String inviteCode, String password) async {
    final tag = 'qsv-p2p-v1|$inviteCode|$password';
    final digest = crypto.sha256.convert(utf8.encode(tag));
    final salt = Uint8List.fromList(digest.bytes.sublist(0, 16));
    
    final argon2 = Argon2id(
      memory: 65536,
      iterations: 2,
      parallelism: 1,
      hashLength: 32,
    );
    
    return await argon2.deriveKey(
      secretKey: SecretKey(utf8.encode(password)),
      nonce: salt,
    );
  }
  
  Future<void> _createPeerConnection() async {
    // Use only STUN servers (no TURN)
    final config = {
      'iceServers': [
        {'urls': 'stun:stun.l.google.com:19302'},
        {'urls': 'stun:stun1.l.google.com:19302'},
        {'urls': 'stun:stun2.l.google.com:19302'},
        {'urls': 'stun:stun3.l.google.com:19302'},
        {'urls': 'stun:stun4.l.google.com:19302'},
      ],
      'sdpSemantics': 'unified-plan',
    };
    
    _peerConnection = await createPeerConnection(config);
    
    _peerConnection!.onIceCandidate = (candidate) {
      if (candidate.candidate != null) {
        _log('ICE candidate: ${candidate.candidate}');
        _sendSignal('ice-candidate', {
          'candidate': candidate.candidate,
          'sdpMLineIndex': candidate.sdpMLineIndex,
          'sdpMid': candidate.sdpMid,
        });
      }
    };
    
    _peerConnection!.onIceConnectionState = (state) {
      _log('ICE connection state: $state');
      if (state == RTCIceConnectionState.RTCIceConnectionStateConnected ||
          state == RTCIceConnectionState.RTCIceConnectionStateCompleted) {
        _isConnected = true;
        _stateController.add(P2pState.connected);
      } else if (state == RTCIceConnectionState.RTCIceConnectionStateFailed ||
                 state == RTCIceConnectionState.RTCIceConnectionStateDisconnected) {
        _isConnected = false;
        _stateController.add(P2pState.disconnected);
      }
    };
    
    _peerConnection!.onDataChannel = (channel) {
      _log('Remote data channel received: ${channel.label}');
      _setupDataChannel(channel);
    };
  }
  
  Future<void> _createDataChannel() async {
    final channelConfig = RTCDataChannelInit()
      ..ordered = true
      ..maxRetransmits = 30;
    
    _dataChannel = await _peerConnection!.createDataChannel(
      'qsv-sync',
      channelConfig,
    );
    
    _setupDataChannel(_dataChannel!);
    
    // Create and send offer
    final offer = await _peerConnection!.createOffer();
    await _peerConnection!.setLocalDescription(offer);
    _localOffer = offer; // Store for later use
    
    _log('Created offer, waiting for joiner...');
    
    // Don't send offer yet - wait for joiner to connect
    // The offer will be sent when we detect the joiner
  }
  
  void _setupDataChannel(RTCDataChannel channel) {
    _dataChannel = channel;
    
    channel.onDataChannelState = (state) {
      _log('Data channel state: $state');
      if (state == RTCDataChannelState.RTCDataChannelOpen) {
        _isConnected = true;
        _stateController.add(P2pState.connected);
      } else if (state == RTCDataChannelState.RTCDataChannelClosed) {
        _isConnected = false;
        _stateController.add(P2pState.disconnected);
      }
    };
    
    channel.onMessage = (message) async {
      try {
        final decrypted = await _decryptMessage(message.binary);
        final json = jsonDecode(decrypted) as Map<String, dynamic>;
        _messageController.add(P2pMessage.fromJson(json));
      } catch (e) {
        _log('Error processing message: $e');
      }
    };
  }
  
  /// Send a message to the connected peer
  Future<void> sendMessage(P2pMessage message) async {
    if (_dataChannel == null || !_isConnected) {
      throw StateError('Not connected to peer');
    }
    
    final json = jsonEncode(message.toJson());
    final encrypted = await _encryptMessage(json);
    
    _dataChannel!.send(RTCDataChannelMessage.fromBinary(encrypted));
  }
  
  Future<Uint8List> _encryptMessage(String plaintext) async {
    if (_encryptionKey == null) throw StateError('No encryption key');
    
    final aes = AesGcm.with256bits();
    final nonce = aes.newNonce();
    final secretBox = await aes.encrypt(
      utf8.encode(plaintext),
      secretKey: _encryptionKey!,
      nonce: nonce,
    );
    
    final output = BytesBuilder();
    output.add(secretBox.nonce);
    output.add(secretBox.cipherText);
    output.add(secretBox.mac.bytes);
    return Uint8List.fromList(output.toBytes());
  }
  
  Future<String> _decryptMessage(Uint8List data) async {
    if (_encryptionKey == null) throw StateError('No encryption key');
    
    final aes = AesGcm.with256bits();
    const nonceLen = 12;
    const macLen = 16;
    
    final nonce = data.sublist(0, nonceLen);
    final cipherText = data.sublist(nonceLen, data.length - macLen);
    final mac = Mac(data.sublist(data.length - macLen));
    
    final secretBox = SecretBox(cipherText, nonce: nonce, mac: mac);
    final clear = await aes.decrypt(secretBox, secretKey: _encryptionKey!);
    return utf8.decode(clear);
  }
  
  // ==================== Signaling ====================
  
  String get _baseUrl {
    final raw = _config.baseUrl.trim();
    return raw.replaceAll(RegExp(r'/+$'), '');
  }
  
  Future<void> _registerPeer(String inviteCode, String peerId) async {
    final url = Uri.parse('$_baseUrl/api/relay');
    final body = jsonEncode({
      'action': 'register',
      'inviteCode': inviteCode,
      'peerId': peerId,
    });
    
    final resp = await _http.post(
      url,
      headers: {'Content-Type': 'application/json'},
      body: body,
    ).timeout(_config.httpTimeout);
    
    if (resp.statusCode != 200) {
      final error = jsonDecode(resp.body)['error'] ?? 'unknown';
      throw Exception('Failed to register peer: $error');
    }
    
    _log('Registered peer with invite code');
  }
  
  Future<String?> _lookupPeer(String inviteCode) async {
    final url = Uri.parse('$_baseUrl/api/relay');
    final body = jsonEncode({
      'action': 'lookup',
      'inviteCode': inviteCode,
    });
    
    final resp = await _http.post(
      url,
      headers: {'Content-Type': 'application/json'},
      body: body,
    ).timeout(_config.httpTimeout);
    
    if (resp.statusCode != 200) {
      return null;
    }
    
    final json = jsonDecode(resp.body) as Map<String, dynamic>;
    return json['peerId'] as String?;
  }
  
  Future<void> _sendSignal(String type, Map<String, dynamic> payload) async {
    if (_remotePeerId == null && !_isInitiator) {
      _log('Cannot send signal: no remote peer ID');
      return;
    }
    
    final to = _remotePeerId ?? 'pending';
    
    final url = Uri.parse('$_baseUrl/api/relay');
    final body = jsonEncode({
      'action': 'signal',
      'from': _localPeerId,
      'to': to,
      'type': type,
      'payload': jsonEncode(payload),
    });
    
    await _http.post(
      url,
      headers: {'Content-Type': 'application/json'},
      body: body,
    ).timeout(_config.httpTimeout);
  }
  
  void _startPolling() {
    _pollingTimer?.cancel();
    _pollingTimer = Timer.periodic(const Duration(milliseconds: 500), (_) {
      _pollSignals();
    });
  }
  
  Future<void> _pollSignals() async {
    if (_localPeerId == null) return;
    
    try {
      final url = Uri.parse('$_baseUrl/api/relay');
      final body = jsonEncode({
        'action': 'poll',
        'peerId': _localPeerId,
      });
      
      final resp = await _http.post(
        url,
        headers: {'Content-Type': 'application/json'},
        body: body,
      ).timeout(_config.httpTimeout);
      
      if (resp.statusCode != 200) return;
      
      final json = jsonDecode(resp.body) as Map<String, dynamic>;
      final messages = json['messages'] as List<dynamic>? ?? [];
      
      for (final msg in messages) {
        await _handleSignal(msg as Map<String, dynamic>);
      }
    } catch (e) {
      _log('Poll error: $e');
    }
  }
  
  Future<void> _handleSignal(Map<String, dynamic> signal) async {
    final from = signal['from'] as String;
    final type = signal['type'] as String;
    final payload = jsonDecode(signal['payload'] as String) as Map<String, dynamic>;
    
    _log('Received signal: $type from $from');
    
    // Track remote peer
    if (_remotePeerId == null) {
      _remotePeerId = from;
    }
    
    switch (type) {
      case 'offer':
        if (!_isInitiator) {
          final sdp = RTCSessionDescription(
            payload['sdp'] as String,
            payload['type'] as String,
          );
          await _peerConnection!.setRemoteDescription(sdp);
          
          final answer = await _peerConnection!.createAnswer();
          await _peerConnection!.setLocalDescription(answer);
          
          _sendSignal('answer', {
            'type': answer.type,
            'sdp': answer.sdp,
          });
        }
        break;
        
      case 'answer':
        if (_isInitiator) {
          final sdp = RTCSessionDescription(
            payload['sdp'] as String,
            payload['type'] as String,
          );
          await _peerConnection!.setRemoteDescription(sdp);
        }
        break;
        
      case 'ice-candidate':
        final candidate = RTCIceCandidate(
          payload['candidate'] as String,
          payload['sdpMid'] as String?,
          payload['sdpMLineIndex'] as int?,
        );
        await _peerConnection!.addCandidate(candidate);
        break;
        
      case 'ready':
        // Joiner is ready, send offer
        if (_isInitiator && _localOffer != null) {
          _remotePeerId = from;
          _sendSignal('offer', {
            'type': _localOffer!.type,
            'sdp': _localOffer!.sdp,
          });
        }
        break;
    }
  }
  
  /// Notify initiator that we're ready
  Future<void> signalReady() async {
    if (!_isInitiator && _remotePeerId != null) {
      _sendSignal('ready', {});
    }
  }
  
  /// Close the peer connection
  Future<void> close() async {
    _pollingTimer?.cancel();
    await _dataChannel?.close();
    await _peerConnection?.close();
    await _messageController.close();
    await _stateController.close();
    
    _peerConnection = null;
    _dataChannel = null;
    _isConnected = false;
  }
}

/// P2P connection states
enum P2pState {
  idle,
  waitingForPeer,
  connecting,
  connected,
  disconnected,
  error,
}

/// Message types for P2P sync
enum P2pMessageType {
  syncRequest,
  syncData,
  syncAck,
  deltaRequest,
  deltaData,
}

/// P2P message wrapper
class P2pMessage {
  final P2pMessageType type;
  final Map<String, dynamic> data;
  final int timestamp;
  
  P2pMessage({
    required this.type,
    required this.data,
    int? timestamp,
  }) : timestamp = timestamp ?? DateTime.now().millisecondsSinceEpoch;
  
  Map<String, dynamic> toJson() => {
    'type': type.name,
    'data': data,
    'timestamp': timestamp,
  };
  
  factory P2pMessage.fromJson(Map<String, dynamic> json) => P2pMessage(
    type: P2pMessageType.values.firstWhere(
      (t) => t.name == json['type'],
      orElse: () => P2pMessageType.syncRequest,
    ),
    data: json['data'] as Map<String, dynamic>? ?? {},
    timestamp: json['timestamp'] as int?,
  );
  
  // Factory constructors for common message types
  factory P2pMessage.syncRequest({int? sinceTimestamp}) => P2pMessage(
    type: P2pMessageType.syncRequest,
    data: {'sinceTimestamp': sinceTimestamp ?? 0},
  );
  
  factory P2pMessage.syncData(String crdtJson) => P2pMessage(
    type: P2pMessageType.syncData,
    data: {'crdt': crdtJson},
  );
  
  factory P2pMessage.syncAck() => P2pMessage(
    type: P2pMessageType.syncAck,
    data: {},
  );
}
