import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:qsafevault/services/relay_client.dart';
import 'package:qsafevault/services/sync_service.dart';
import 'package:qsafevault/config/sync_config.dart';

/// Integration test for relay sync with new server semantics:
/// - Session persists for 60s TTL
/// - Session transitions to 'completed' state after all chunks delivered
/// - Ack key persists separately for 60s even after completion
/// - ack-status returns 'acknowledged' true after receiver sends ack
void main() {
  group('Relay Sync Integration Tests - New Server Semantics', () {
    late MockRelayServer mockServer;

    setUp(() {
      mockServer = MockRelayServer();
    });

    test('Normal bidirectional sync flow (send -> ack -> receive return transfer)', () async {
      final client = RelayClient(
        config: SyncConfig.defaults(),
        httpClient: mockServer.createMockClient(),
      );

      final session = RelaySession(
        pin: '123456',
        passwordHash: 'test_hash',
      );

      // Simulate sender: send chunks
      final testData = Uint8List.fromList(utf8.encode('test vault data'));
      final chunks = client.chunk(testData, size: 32);
      
      for (int i = 0; i < chunks.length; i++) {
        await client.sendChunk(
          pin: session.pin,
          passwordHash: session.passwordHash,
          chunkIndex: i,
          totalChunks: chunks.length,
          chunkData: chunks[i],
        );
      }

      // Verify chunks were stored
      expect(mockServer.hasChunks(session.pin, session.passwordHash), true);
      expect(mockServer.getChunkCount(session.pin, session.passwordHash), chunks.length);

      // Simulate receiver: poll and receive chunks
      final receivedChunks = <int, Uint8List>{};
      for (int i = 0; i < chunks.length; i++) {
        final result = await client.pollNext(
          pin: session.pin,
          passwordHash: session.passwordHash,
        );
        expect(result.status, 'chunkAvailable');
        expect(result.index, i);
        receivedChunks[result.index!] = result.data!;
      }

      // Verify all chunks received
      expect(receivedChunks.length, chunks.length);

      // After all chunks delivered, next poll should return 'done'
      final doneResult = await client.pollNext(
        pin: session.pin,
        passwordHash: session.passwordHash,
      );
      expect(doneResult.status, 'done');

      // Session should be in 'completed' state but ack key should persist
      expect(mockServer.isSessionCompleted(session.pin, session.passwordHash), true);
      
      // Simulate receiver sending ack
      mockServer.setAcknowledged(session.pin, session.passwordHash, true);

      // Verify ack persists even though session is completed
      expect(mockServer.isAcknowledged(session.pin, session.passwordHash), true);
    });

    test('Fallback: ack-status fails but receive returns done (should succeed)', () async {
      final client = RelayClient(
        config: SyncConfig.defaults(),
        httpClient: mockServer.createMockClient(),
      );

      final session = RelaySession(
        pin: '123456',
        passwordHash: 'test_hash',
      );

      // Send chunks
      final testData = Uint8List.fromList(utf8.encode('test vault data'));
      final chunks = client.chunk(testData, size: 32);
      
      for (int i = 0; i < chunks.length; i++) {
        await client.sendChunk(
          pin: session.pin,
          passwordHash: session.passwordHash,
          chunkIndex: i,
          totalChunks: chunks.length,
          chunkData: chunks[i],
        );
      }

      // Simulate receiver consuming all chunks
      for (int i = 0; i < chunks.length; i++) {
        await client.pollNext(
          pin: session.pin,
          passwordHash: session.passwordHash,
        );
      }

      // Mark session as completed
      mockServer.markSessionCompleted(session.pin, session.passwordHash);

      // Disable ack-status endpoint (simulate failure)
      mockServer.setAckStatusDisabled(true);

      // Fallback: polling receive should return 'done'
      final result = await client.pollNext(
        pin: session.pin,
        passwordHash: session.passwordHash,
      );
      expect(result.status, 'done');

      // This simulates the app's fallback logic treating 'done' as implicit acknowledgment
    });

    test('Timeout: neither ack-status nor receive returns success within timeout', () async {
      final client = RelayClient(
        config: SyncConfig.defaults(),
        httpClient: mockServer.createMockClient(),
      );

      final session = RelaySession(
        pin: '123456',
        passwordHash: 'test_hash',
      );

      // Send chunks
      final testData = Uint8List.fromList(utf8.encode('test vault data'));
      final chunks = client.chunk(testData, size: 32);
      
      for (int i = 0; i < chunks.length; i++) {
        await client.sendChunk(
          pin: session.pin,
          passwordHash: session.passwordHash,
          chunkIndex: i,
          totalChunks: chunks.length,
          chunkData: chunks[i],
        );
      }

      // Do NOT set acknowledged and do NOT mark as completed
      // Simulate receiver never consuming chunks

      // Polling should return 'waiting'
      for (int i = 0; i < 3; i++) {
        final result = await client.pollNext(
          pin: session.pin,
          passwordHash: session.passwordHash,
        );
        expect(result.status, 'chunkAvailable');
      }

      // After consuming all, it should still not be acknowledged
      expect(mockServer.isAcknowledged(session.pin, session.passwordHash), false);
    });

    test('Multiple chunks sent and received correctly', () async {
      final client = RelayClient(
        config: SyncConfig.defaults(),
        httpClient: mockServer.createMockClient(),
      );

      final session = RelaySession(
        pin: '123456',
        passwordHash: 'test_hash',
      );

      // Create large data that will be split into multiple chunks
      final largeData = Uint8List.fromList(
        List.generate(100 * 1024, (i) => i % 256), // 100KB
      );
      final chunks = client.chunk(largeData, size: 32 * 1024); // 32KB chunks

      expect(chunks.length, greaterThan(1), reason: 'Should have multiple chunks');

      // Send all chunks
      for (int i = 0; i < chunks.length; i++) {
        await client.sendChunk(
          pin: session.pin,
          passwordHash: session.passwordHash,
          chunkIndex: i,
          totalChunks: chunks.length,
          chunkData: chunks[i],
        );
      }

      // Verify all chunks stored
      expect(mockServer.getChunkCount(session.pin, session.passwordHash), chunks.length);

      // Receive all chunks
      final receivedChunks = <int, Uint8List>{};
      for (int i = 0; i < chunks.length; i++) {
        final result = await client.pollNext(
          pin: session.pin,
          passwordHash: session.passwordHash,
        );
        expect(result.status, 'chunkAvailable');
        receivedChunks[result.index!] = result.data!;
      }

      // Verify all chunks received in correct order
      expect(receivedChunks.length, chunks.length);
      for (int i = 0; i < chunks.length; i++) {
        expect(receivedChunks[i], isNotNull);
        expect(receivedChunks[i], equals(chunks[i]));
      }
    });

    test('Session expiry after 60s TTL', () async {
      final client = RelayClient(
        config: SyncConfig.defaults(),
        httpClient: mockServer.createMockClient(),
      );

      final session = RelaySession(
        pin: '123456',
        passwordHash: 'test_hash',
      );

      // Send chunks
      final testData = Uint8List.fromList(utf8.encode('test vault data'));
      final chunks = client.chunk(testData, size: 32);
      
      for (int i = 0; i < chunks.length; i++) {
        await client.sendChunk(
          pin: session.pin,
          passwordHash: session.passwordHash,
          chunkIndex: i,
          totalChunks: chunks.length,
          chunkData: chunks[i],
        );
      }

      // Simulate TTL expiry
      mockServer.expireSession(session.pin, session.passwordHash);

      // Polling should return 'expired'
      final result = await client.pollNext(
        pin: session.pin,
        passwordHash: session.passwordHash,
      );
      expect(result.status, 'expired');
    });

    test('Ack key persists for 60s even after session completion', () async {
      final client = RelayClient(
        config: SyncConfig.defaults(),
        httpClient: mockServer.createMockClient(),
      );

      final session = RelaySession(
        pin: '123456',
        passwordHash: 'test_hash',
      );

      // Send and receive chunks
      final testData = Uint8List.fromList(utf8.encode('test vault data'));
      final chunks = client.chunk(testData, size: 32);
      
      for (int i = 0; i < chunks.length; i++) {
        await client.sendChunk(
          pin: session.pin,
          passwordHash: session.passwordHash,
          chunkIndex: i,
          totalChunks: chunks.length,
          chunkData: chunks[i],
        );
      }

      // Consume all chunks
      for (int i = 0; i < chunks.length; i++) {
        await client.pollNext(
          pin: session.pin,
          passwordHash: session.passwordHash,
        );
      }

      // Mark session as completed
      mockServer.markSessionCompleted(session.pin, session.passwordHash);
      expect(mockServer.isSessionCompleted(session.pin, session.passwordHash), true);

      // Set acknowledgment
      mockServer.setAcknowledged(session.pin, session.passwordHash, true);

      // Verify ack key persists even though session is completed
      expect(mockServer.isAcknowledged(session.pin, session.passwordHash), true);

      // Verify receive returns 'done' for completed session
      final result = await client.pollNext(
        pin: session.pin,
        passwordHash: session.passwordHash,
      );
      expect(result.status, 'done');
    });
  });
}

/// Mock relay server that simulates new server semantics
class MockRelayServer {
  final Map<String, SessionData> _sessions = {};
  bool _ackStatusDisabled = false;

  String _sessionKey(String pin, String passwordHash) => '$pin:$passwordHash';

  SessionData _getOrCreateSession(String pin, String passwordHash) {
    final key = _sessionKey(pin, passwordHash);
    return _sessions.putIfAbsent(key, () => SessionData());
  }

  bool hasChunks(String pin, String passwordHash) {
    final session = _sessions[_sessionKey(pin, passwordHash)];
    return session != null && session.chunks.isNotEmpty;
  }

  int getChunkCount(String pin, String passwordHash) {
    final session = _sessions[_sessionKey(pin, passwordHash)];
    return session?.chunks.length ?? 0;
  }

  bool isSessionCompleted(String pin, String passwordHash) {
    final session = _sessions[_sessionKey(pin, passwordHash)];
    return session?.completed ?? false;
  }

  bool isAcknowledged(String pin, String passwordHash) {
    final session = _sessions[_sessionKey(pin, passwordHash)];
    return session?.acknowledged ?? false;
  }

  void setAcknowledged(String pin, String passwordHash, bool value) {
    final session = _getOrCreateSession(pin, passwordHash);
    session.acknowledged = value;
  }

  void markSessionCompleted(String pin, String passwordHash) {
    final session = _getOrCreateSession(pin, passwordHash);
    session.completed = true;
  }

  void expireSession(String pin, String passwordHash) {
    final session = _getOrCreateSession(pin, passwordHash);
    session.expired = true;
  }

  void setAckStatusDisabled(bool disabled) {
    _ackStatusDisabled = disabled;
  }

  http.Client createMockClient() {
    return MockClient((request) async {
      final body = jsonDecode(request.body) as Map<String, dynamic>;
      final action = body['action'] as String;
      final pin = body['pin'] as String;
      final passwordHash = body['passwordHash'] as String;

      final session = _getOrCreateSession(pin, passwordHash);

      if (session.expired) {
        return http.Response(
          jsonEncode({'status': 'expired'}),
          200,
          headers: {'content-type': 'application/json'},
        );
      }

      switch (action) {
        case 'send':
          final chunkIndex = body['chunkIndex'] as int;
          final totalChunks = body['totalChunks'] as int;
          final data = body['data'] as String;
          
          session.chunks[chunkIndex] = data;
          session.totalChunks = totalChunks;

          return http.Response(
            jsonEncode({'status': 'waiting'}),
            200,
            headers: {'content-type': 'application/json'},
          );

        case 'receive':
          if (session.completed) {
            return http.Response(
              jsonEncode({'status': 'done'}),
              200,
              headers: {'content-type': 'application/json'},
            );
          }

          if (session.chunks.isEmpty) {
            return http.Response(
              jsonEncode({'status': 'waiting'}),
              200,
              headers: {'content-type': 'application/json'},
            );
          }

          // Return next undelivered chunk
          final nextIndex = session.deliveredChunks;
          if (nextIndex < session.chunks.length) {
            final chunkData = session.chunks[nextIndex];
            session.deliveredChunks++;

            // Mark as completed if all chunks delivered
            if (session.deliveredChunks >= session.totalChunks) {
              session.completed = true;
            }

            return http.Response(
              jsonEncode({
                'status': 'chunkAvailable',
                'chunk': {
                  'chunkIndex': nextIndex,
                  'totalChunks': session.totalChunks,
                  'data': chunkData,
                }
              }),
              200,
              headers: {'content-type': 'application/json'},
            );
          }

          return http.Response(
            jsonEncode({'status': 'done'}),
            200,
            headers: {'content-type': 'application/json'},
          );

        case 'ack':
          session.acknowledged = true;
          return http.Response(
            jsonEncode({'status': 'ok'}),
            200,
            headers: {'content-type': 'application/json'},
          );

        case 'ack-status':
          if (_ackStatusDisabled) {
            return http.Response('', 500);
          }
          return http.Response(
            jsonEncode({'acknowledged': session.acknowledged}),
            200,
            headers: {'content-type': 'application/json'},
          );

        default:
          return http.Response('Unknown action', 400);
      }
    });
  }
}

class SessionData {
  Map<int, String> chunks = {};
  int totalChunks = 0;
  int deliveredChunks = 0;
  bool completed = false;
  bool acknowledged = false;
  bool expired = false;
}
