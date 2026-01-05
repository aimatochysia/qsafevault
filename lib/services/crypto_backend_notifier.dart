import 'dart:convert';
import 'package:flutter/material.dart';
import '../ffi/rust_crypto_service.dart';
import '../config/edition_config.dart';
import '../config/sync_config.dart';

/// Service to show cryptographic backend status notifications
/// 
/// Displays information about:
/// - Edition (Enterprise vs Consumer)
/// - Security backend (TPM2, SoftHSM, Secure Enclave, or Software fallback)
/// - Sync configuration (transport mode, relay URL, WebRTC settings)
class CryptoBackendNotifier {
  static final CryptoBackendNotifier _instance = CryptoBackendNotifier._internal();
  static CryptoBackendNotifier get instance => _instance;
  
  CryptoBackendNotifier._internal();

  /// Show backend status as a fleeting snackbar notification
  /// 
  /// [context] - Build context for showing the snackbar
  /// [cryptoService] - Optional RustCryptoService for backend info
  /// [syncConfig] - Optional SyncConfig for sync settings (defaults to SyncConfig.defaults())
  void showBackendStatus(
    BuildContext context, 
    RustCryptoService? cryptoService, {
    SyncConfig? syncConfig,
  }) {
    try {
      // Get edition configuration
      final edition = GlobalEdition.configOrDefault;
      
      // Get sync configuration
      final sync = syncConfig ?? SyncConfig.defaults();
      
      // Get backend information if cryptoService is available
      String backendType = 'Unknown';
      bool tpmAvailable = false;
      bool softhsmAvailable = false;
      bool platformSecureAvailable = false;
      
      if (cryptoService != null) {
        // Initialize logging at Info level
        try {
          cryptoService.initLogging(2);
        } catch (e) {
          debugPrint('Failed to initialize logging: $e');
          // Continue anyway, logging is optional
        }

        // Get backend information
        try {
          final backendInfoJson = cryptoService.getBackendInfo();
          final backendInfo = json.decode(backendInfoJson) as Map<String, dynamic>;

          // Parse backend detection
          tpmAvailable = backendInfo['tpm_available'] as bool? ?? false;
          softhsmAvailable = backendInfo['softhsm_available'] as bool? ?? false;
          platformSecureAvailable = backendInfo['platform_secure_available'] as bool? ?? false;
          backendType = backendInfo['backend_type'] as String? ?? 'Unknown';
        } catch (e) {
          debugPrint('Failed to get backend info: $e');
        }
      } else {
        debugPrint('RustCryptoService not available, using limited backend status');
      }

      // Build notification message
      final message = _buildNotificationMessage(
        edition: edition,
        tpm: tpmAvailable,
        softhsm: softhsmAvailable,
        platformSecure: platformSecureAvailable,
        backendType: backendType,
        syncConfig: sync,
      );

      // Show fleeting snackbar (4 seconds - slightly longer to read all info)
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Row(
              children: [
                Icon(
                  edition.isEnterprise ? Icons.business : Icons.security, 
                  color: Colors.white, 
                  size: 20,
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    message,
                    style: const TextStyle(fontSize: 12),
                  ),
                ),
              ],
            ),
            backgroundColor: _getBackgroundColor(backendType, edition),
            duration: const Duration(seconds: 4),
            behavior: SnackBarBehavior.floating,
            margin: const EdgeInsets.all(16),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(8),
            ),
          ),
        );
      }
    } catch (e) {
      // Silently fail - backend status is informational only
      debugPrint('Failed to get backend status: $e');
    }
  }

  String _buildNotificationMessage({
    required EditionConfig edition,
    required bool tpm,
    required bool softhsm,
    required bool platformSecure,
    required String backendType,
    required SyncConfig syncConfig,
  }) {
    // Edition string
    final editionStr = edition.editionName;
    
    // Determine backend string
    String backend;
    if (tpm && softhsm) {
      backend = 'TPM2+SoftHSM (dual)';
    } else if (tpm) {
      backend = 'TPM2';
    } else if (softhsm) {
      backend = 'SoftHSM';
    } else if (platformSecure) {
      backend = 'Secure Enclave';
    } else {
      backend = 'Software (fallback)';
    }

    // Build sync info string
    final syncInfo = _buildSyncInfo(syncConfig);

    // Crypto algorithms
    final cryptoAlgo = edition.isEnterprise 
        ? 'AES-256-GCM (FIPS)' 
        : 'ML-KEM 768 + X25519';

    return '$editionStr | $backend | $cryptoAlgo | Sync: $syncInfo';
  }

  /// Build sync configuration info string
  String _buildSyncInfo(SyncConfig syncConfig) {
    // If sync is disabled (Enterprise without custom URL), show that
    if (syncConfig.syncDisabled) {
      return 'disabled (set QSV_SYNC_BASEURL)';
    }
    
    final parts = <String>[];
    
    // Transport mode (tor or webrtc)
    final transport = syncConfig.transport.toUpperCase();
    parts.add(transport);
    
    // If WebRTC transport, show TURN/STUN configuration
    if (syncConfig.transport == 'webrtc') {
      if (syncConfig.turnUrls.isNotEmpty) {
        parts.add('TURN');
        if (syncConfig.turnForceRelay) {
          parts.add('relay-only');
        }
      }
      // Note: When no TURN is configured, WebRTC uses default Google STUN servers
      // defined in P2pPeerService. We don't show STUN explicitly to avoid confusion.
    }
    
    // Show relay host (shortened)
    final relayHost = _shortenUrl(syncConfig.baseUrl);
    parts.add(relayHost);
    
    return parts.join('/');
  }

  /// Shorten URL to just the host for display
  String _shortenUrl(String url) {
    try {
      final uri = Uri.parse(url);
      return uri.host;
    } catch (_) {
      // If parsing fails, return a truncated version
      if (url.length > 20) {
        return '${url.substring(0, 17)}...';
      }
      return url;
    }
  }

  Color _getBackgroundColor(String backendType, EditionConfig edition) {
    // Enterprise mode gets a distinct purple shade
    if (edition.isEnterprise) {
      return Colors.purple.shade700;
    }
    
    switch (backendType.toLowerCase()) {
      case 'tpmandsofthsm':
        return Colors.green.shade700; // Dual-seal - best security
      case 'tpm':
        return Colors.blue.shade700; // Hardware TPM
      case 'softhsm':
        return Colors.orange.shade700; // Software HSM
      case 'fallback':
        return Colors.grey.shade700; // Software fallback
      default:
        return Colors.blue.shade700; // Platform secure or unknown
    }
  }
}
