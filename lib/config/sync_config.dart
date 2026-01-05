import 'dart:math';
import 'edition_config.dart';

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

  /// Default consumer sync URL (public relay)
  static const String _consumerDefaultUrl = 'https://qsafevault-server.vercel.app';
  
  /// Placeholder for Enterprise - indicates no URL was configured
  static const String _enterpriseNoUrl = '';

  static SyncConfig defaults() {
    final edition = GlobalEdition.configOrDefault;
    
    // Get user-provided URL from environment
    final userProvidedUrl = const String.fromEnvironment(
      'QSV_SYNC_BASEURL',
      defaultValue: '',
    ).trim();
    
    // Determine base URL based on edition
    // - Consumer: Use user URL if provided, otherwise default to public relay
    // - Enterprise: MUST provide their own URL, sync disabled if not provided
    String baseUrl;
    bool syncDisabled = false;
    
    if (edition.isEnterprise) {
      if (userProvidedUrl.isEmpty) {
        // Enterprise mode requires explicit backend URL
        // Sync is disabled until user configures their own server
        baseUrl = _enterpriseNoUrl;
        syncDisabled = true;
      } else {
        baseUrl = userProvidedUrl;
      }
    } else {
      // Consumer mode: use provided URL or fall back to public relay
      baseUrl = userProvidedUrl.isNotEmpty ? userProvidedUrl : _consumerDefaultUrl;
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
