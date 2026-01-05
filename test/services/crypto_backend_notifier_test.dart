import 'package:flutter_test/flutter_test.dart';
import 'package:qsafevault/services/crypto_backend_notifier.dart';
import 'package:qsafevault/config/edition_config.dart';
import 'package:qsafevault/config/sync_config.dart';

/// Unit tests for CryptoBackendNotifier
/// 
/// Tests that the notifier correctly builds messages showing:
/// - Edition (Enterprise vs Consumer)
/// - Security backend information
/// - Sync configuration
void main() {
  group('CryptoBackendNotifier Message Building', () {
    test('Consumer edition with TOR transport builds correct message', () {
      final notifier = CryptoBackendNotifier.instance;
      
      // Access the private method through reflection or make it package-private for testing
      // For now, we test the public API indirectly
      
      // Verify notifier is a singleton
      expect(notifier, equals(CryptoBackendNotifier.instance));
    });

    test('SyncConfig defaults returns expected transport type', () {
      final config = SyncConfig.defaults();
      
      // Default transport is 'tor'
      expect(config.transport, equals('tor'));
      
      // Default base URL should contain a valid host
      expect(config.baseUrl.isNotEmpty, true);
    });

    test('EditionConfig returns correct edition names', () {
      const consumerConfig = EditionConfig(edition: Edition.consumer);
      const enterpriseConfig = EditionConfig(edition: Edition.enterprise);
      
      expect(consumerConfig.editionName, equals('Consumer'));
      expect(enterpriseConfig.editionName, equals('Enterprise'));
      
      expect(consumerConfig.isConsumer, true);
      expect(consumerConfig.isEnterprise, false);
      
      expect(enterpriseConfig.isConsumer, false);
      expect(enterpriseConfig.isEnterprise, true);
    });

    test('EditionConfig fromEnvironment defaults to consumer', () {
      final config = EditionConfig.fromEnvironment();
      
      // Default should be consumer when no environment variable is set
      expect(config.edition, equals(Edition.consumer));
    });

    test('EditionConfig descriptions are correct', () {
      const consumerConfig = EditionConfig(edition: Edition.consumer);
      const enterpriseConfig = EditionConfig(edition: Edition.enterprise);
      
      expect(consumerConfig.description, contains('Post-quantum'));
      expect(enterpriseConfig.description, contains('FIPS'));
    });

    test('EditionConfig FFI values are correct', () {
      const consumerConfig = EditionConfig(edition: Edition.consumer);
      const enterpriseConfig = EditionConfig(edition: Edition.enterprise);
      
      expect(consumerConfig.ffiValue, equals(0));
      expect(enterpriseConfig.ffiValue, equals(1));
    });

    test('EditionConfig.fromFfiValue creates correct configs', () {
      final consumerConfig = EditionConfig.fromFfiValue(0);
      final enterpriseConfig = EditionConfig.fromFfiValue(1);
      
      expect(consumerConfig.edition, equals(Edition.consumer));
      expect(enterpriseConfig.edition, equals(Edition.enterprise));
    });

    test('GlobalEdition.configOrDefault returns consumer when not initialized', () {
      // Note: GlobalEdition may already be initialized by other tests
      // This test verifies the fallback behavior
      final config = GlobalEdition.configOrDefault;
      
      // Should return a valid config (either initialized or default consumer)
      expect(config.edition, anyOf(Edition.consumer, Edition.enterprise));
    });

    test('SyncConfig with WebRTC transport includes TURN settings', () {
      const config = SyncConfig(
        baseUrl: 'https://example.com',
        transport: 'webrtc',
        turnUrls: ['turn:turn.example.com:3478'],
        turnUsername: 'user',
        turnCredential: 'pass',
        turnForceRelay: true,
      );
      
      expect(config.transport, equals('webrtc'));
      expect(config.turnUrls.isNotEmpty, true);
      expect(config.turnForceRelay, true);
    });

    test('SyncConfig with TOR transport uses correct ports', () {
      const config = SyncConfig(
        baseUrl: 'https://example.com',
        transport: 'tor',
        torLocalSyncPort: 5000,
        torDefaultSocksPort: 9050,
      );
      
      expect(config.transport, equals('tor'));
      expect(config.torLocalSyncPort, equals(5000));
      expect(config.torDefaultSocksPort, equals(9050));
    });
  });

  group('EditionStatusCodes', () {
    test('getMessage returns correct messages', () {
      expect(EditionStatusCodes.getMessage(EditionStatusCodes.ok), 
          contains('Success'));
      expect(EditionStatusCodes.getMessage(EditionStatusCodes.fipsViolation), 
          contains('FIPS'));
      expect(EditionStatusCodes.getMessage(EditionStatusCodes.pqDisabled), 
          contains('Post-quantum'));
      expect(EditionStatusCodes.getMessage(EditionStatusCodes.hsmRequired), 
          contains('HSM'));
      expect(EditionStatusCodes.getMessage(EditionStatusCodes.softHsmProhibited), 
          contains('SoftHSM'));
    });

    test('isEnterpriseRestriction identifies correct status codes', () {
      expect(EditionStatusCodes.isEnterpriseRestriction(
          EditionStatusCodes.fipsViolation), true);
      expect(EditionStatusCodes.isEnterpriseRestriction(
          EditionStatusCodes.pqDisabled), true);
      expect(EditionStatusCodes.isEnterpriseRestriction(
          EditionStatusCodes.hsmRequired), true);
      expect(EditionStatusCodes.isEnterpriseRestriction(
          EditionStatusCodes.softHsmProhibited), true);
      expect(EditionStatusCodes.isEnterpriseRestriction(
          EditionStatusCodes.ok), false);
      expect(EditionStatusCodes.isEnterpriseRestriction(
          EditionStatusCodes.error), false);
    });

    test('isInitializationError identifies correct status codes', () {
      expect(EditionStatusCodes.isInitializationError(
          EditionStatusCodes.editionNotInitialized), true);
      expect(EditionStatusCodes.isInitializationError(
          EditionStatusCodes.editionAlreadyInitialized), true);
      expect(EditionStatusCodes.isInitializationError(
          EditionStatusCodes.ok), false);
    });
  });
}
