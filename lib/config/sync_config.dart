import 'dart:math';
import 'edition_config.dart';
import '../services/api_endpoint_service.dart';

class SyncConfig {
  final String baseUrl;
  final Duration httpTimeout;
  final Duration pollInterval;
  final Duration pollMaxWait;
  final Duration backoffMax;
  final List<String> turnUrls;
  final String? turnUsername;
  final String? turnCredential;
  final bool turnForceRelay;

  final String transport;
  final int torLocalSyncPort;
  final int torDefaultSocksPort;
  
  /// Whether sync is disabled (Enterprise mode without custom URL)
  final bool syncDisabled;

  const SyncConfig({
    required this.baseUrl,
    this.httpTimeout = const Duration(seconds: 8),
    this.pollInterval = const Duration(milliseconds: 800),
    this.pollMaxWait = const Duration(seconds: 180),
    this.backoffMax = const Duration(seconds: 3),
    this.turnUrls = const [],
    this.turnUsername,
    this.turnCredential,
    this.turnForceRelay = false,
    this.transport = 'tor',
    this.torLocalSyncPort = 5000,
    this.torDefaultSocksPort = 9050,
    this.syncDisabled = false,
  });

  /// Placeholder for Enterprise - indicates no URL was configured
  static const String _enterpriseNoUrl = '';

  /// Create a SyncConfig using the user-configurable API endpoint.
  /// The endpoint is resolved at runtime from ApiEndpointService,
  /// which defaults to qsafevault-server.vercel.app and can be
  /// changed by the user.
  static SyncConfig defaults() {
    final edition = GlobalEdition.configOrDefault;
    
    // Get user-provided URL from environment (build-time override)
    final envUrl = const String.fromEnvironment(
      'QSV_SYNC_BASEURL',
      defaultValue: '',
    ).trim();
    
    // Resolve base URL:
    // 1. Build-time env var takes highest priority
    // 2. Runtime user-configured endpoint (from ApiEndpointService)
    // 3. Enterprise: sync disabled if nothing configured
    String baseUrl;
    bool syncDisabled = false;
    
    if (envUrl.isNotEmpty) {
      // Build-time override always wins
      baseUrl = envUrl;
    } else if (edition.isEnterprise) {
      // Enterprise: use runtime endpoint or disable sync
      final runtimeUrl = ApiEndpointService.instance.endpoint;
      if (runtimeUrl == ApiEndpointService.defaultEndpoint) {
        // Enterprise should not use the public relay by default
        baseUrl = _enterpriseNoUrl;
        syncDisabled = true;
      } else {
        baseUrl = runtimeUrl;
      }
    } else {
      // Consumer: use runtime user-configured endpoint
      baseUrl = ApiEndpointService.instance.endpoint;
    }
    
    final turnUrls = const String.fromEnvironment('QSV_TURN_URLS', defaultValue: '')
        .split(',')
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toList();
    final turnUser = const String.fromEnvironment('QSV_TURN_USERNAME', defaultValue: '').trim();
    final turnCred = const String.fromEnvironment('QSV_TURN_CREDENTIAL', defaultValue: '').trim();
    final forceRelayRaw = const String.fromEnvironment('QSV_TURN_FORCE_RELAY', defaultValue: 'false');
    final forceRelay = forceRelayRaw == '1' || forceRelayRaw.toLowerCase() == 'true';

    final transport = const String.fromEnvironment('QSV_TRANSPORT', defaultValue: 'tor').toLowerCase().trim();
    final localPortRaw = const String.fromEnvironment('QSV_TOR_LOCAL_PORT', defaultValue: '5000').trim();
    final socksPortRaw = const String.fromEnvironment('QSV_TOR_SOCKS_PORT', defaultValue: '9050').trim();
    int _parsePort(String s, int d) {
      final v = int.tryParse(s);
      return (v != null && v > 0 && v < 65536) ? v : d;
    }

    return SyncConfig(
      baseUrl: baseUrl,
      turnUrls: turnUrls,
      turnUsername: turnUser.isEmpty ? null : turnUser,
      turnCredential: turnCred.isEmpty ? null : turnCred,
      turnForceRelay: forceRelay,
      transport: (transport == 'webrtc' || transport == 'tor') ? transport : 'tor',
      torLocalSyncPort: _parsePort(localPortRaw, 5000),
      torDefaultSocksPort: _parsePort(socksPortRaw, 9050),
      syncDisabled: syncDisabled,
    );
  }
}

Duration jitter(Duration base, {int msJitter = 150}) {
  final r = Random.secure().nextInt(msJitter * 2) - msJitter;
  final t = base + Duration(milliseconds: r);
  return t.isNegative ? Duration.zero : t;
}
