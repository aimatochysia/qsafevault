import 'dart:convert';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import '../config/sync_config.dart';
import 'fips_crypto_service.dart';
import 'app_logger.dart';

class RelayClient {
  final SyncConfig config;
  final http.Client _http;
  final FipsCryptoService _crypto;

  late final String _baseNoSlash;

  RelayClient({
    SyncConfig? config,
    http.Client? httpClient,
    FipsCryptoService? crypto,
  })  : config = config ?? SyncConfig.defaults(),
        _http = httpClient ?? http.Client(),
        _crypto = crypto ?? FipsCryptoService() {
    final raw = this.config.baseUrl.trim();
    _baseNoSlash = raw.replaceAll(RegExp(r'/+$'), '');
  }

  Uri _u(String path, [Map<String, String>? query]) {
    final p = path.startsWith('/') ? path : '/$path';
    final uri = Uri.parse('$_baseNoSlash$p');
    if (query == null || query.isEmpty) return uri;
    return uri.replace(queryParameters: query);
  }

  /// Derive transfer key using PBKDF2-HMAC-SHA256 (FIPS-compliant)
  Uint8List deriveTransferKey({required String pin, required String password}) {
    final tag = 'qsv-relay-v1|$pin|$password';
    final digest = _crypto.sha256String(tag);
    final salt = Uint8List.fromList(digest.sublist(0, 16));
    return _crypto.deriveKeyFromPassword(
      password: password,
      salt: salt,
      iterations: 100000,  // FIPS-compliant iteration count
    );
  }

  String passwordHash({required String pin, required String password}) {
    final tag = 'qsv-relay-v1-hash|$pin|$password';
    final digest = _crypto.sha256String(tag);
    return base64Encode(digest);
  }

  /// Encrypt payload using AES-256-GCM (FIPS 197)
  Uint8List encryptPayload(Uint8List key, String plaintext) {
    final clear = Uint8List.fromList(utf8.encode(plaintext));
    final encrypted = _crypto.encrypt(key: key, plaintext: clear);
    // Format: nonce (12) || ciphertext || tag (16)
    final env = {
      'v': 1,
      'ctB64': base64Encode(encrypted),
    };
    return Uint8List.fromList(utf8.encode(jsonEncode(env)));
  }

  /// Decrypt payload using AES-256-GCM (FIPS 197)
  String decryptPayload(Uint8List key, Uint8List envelopeBytes) {
    final obj = jsonDecode(utf8.decode(envelopeBytes)) as Map<String, dynamic>;
    final ctAll = base64Decode(obj['ctB64'] as String);
    final clear = _crypto.decrypt(key: key, ciphertext: ctAll);
    return utf8.decode(clear);
  }

  List<Uint8List> chunk(Uint8List bytes, {int size = 32 * 1024}) {
    final out = <Uint8List>[];
    for (int i = 0; i < bytes.length; i += size) {
      final end = (i + size < bytes.length) ? i + size : bytes.length;
      out.add(Uint8List.sublistView(bytes, i, end));
    }
    return out;
  }

  Future<void> sendChunk({
    required String pin,
    required String passwordHash,
    required int chunkIndex,
    required int totalChunks,
    required Uint8List chunkData,
  }) async {
    // Server lifecycle note: Chunks sent via 'send' action are stored with 60s TTL.
    // After all chunks delivered, session moves to 'completed' state but ack key persists.
    final uri = _u('/api/relay');
    final body = jsonEncode({
      'action': 'send',
      'pin': pin,
      'passwordHash': passwordHash,
      'chunkIndex': chunkIndex,
      'totalChunks': totalChunks,
      'data': base64Encode(chunkData),
    });
    final logMsg = '[RelayClient] Sending to host: $_baseNoSlash\n[RelayClient] POST /api/relay body: $body';
    print(logMsg);
    try { AppLogger.instance.write(logMsg); } catch (_) {}
    final resp = await _http
        .post(uri, headers: {'content-type': 'application/json'}, body: body)
        .timeout(config.httpTimeout);
    final respMsg = '[RelayClient] Response (${resp.statusCode}): ${resp.body}';
    print(respMsg);
    try { AppLogger.instance.write(respMsg); } catch (_) {}
    if (resp.statusCode != 200) {
      throw Exception('sendChunk failed: ${resp.statusCode}');
    }
  }

  Future<({String status, int? index, int? total, Uint8List? data})> pollNext({
    required String pin,
    required String passwordHash,
  }) async {
    // Server lifecycle note: 'receive' action polls for chunks with 60s TTL.
    // Status can be: 'waiting', 'chunkAvailable', 'done' (all delivered), or 'expired'.
    // After all chunks delivered, subsequent polls return 'done' and session is marked completed.
    final uri = _u('/api/relay');
    final body = jsonEncode({
      'action': 'receive',
      'pin': pin,
      'passwordHash': passwordHash,
    });
    final logMsg = '[RelayClient] Sending to host: $_baseNoSlash\n[RelayClient] POST /api/relay body: $body';
    print(logMsg);
    try { AppLogger.instance.write(logMsg); } catch (_) {}
    final resp = await _http
        .post(uri, headers: {'content-type': 'application/json'}, body: body)
        .timeout(config.httpTimeout);
    final respMsg = '[RelayClient] Response (${resp.statusCode}): ${resp.body}';
    print(respMsg);
    try { AppLogger.instance.write(respMsg); } catch (_) {}
    if (resp.statusCode != 200) throw Exception('receive failed: ${resp.statusCode}');
    final obj = jsonDecode(resp.body) as Map<String, dynamic>;
    final status = (obj['status'] ?? 'waiting') as String;
    if (status == 'chunkAvailable') {
      final chunk = obj['chunk'] as Map<String, dynamic>;
      final idx = (chunk['chunkIndex'] as num).toInt();
      final total = (chunk['totalChunks'] as num).toInt();
      final data = base64Decode(chunk['data'] as String);
      return (status: status, index: idx, total: total, data: data);
    }
    return (status: status, index: null, total: null, data: null);
  }
}
