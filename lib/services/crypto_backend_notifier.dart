import 'dart:convert';
import 'package:flutter/material.dart';
import '../ffi/rust_crypto_service.dart';

/// Service to show cryptographic backend status notifications
class CryptoBackendNotifier {
  static final CryptoBackendNotifier _instance = CryptoBackendNotifier._internal();
  static CryptoBackendNotifier get instance => _instance;
  
  CryptoBackendNotifier._internal();

  /// Show backend status as a fleeting snackbar notification
  void showBackendStatus(BuildContext context, RustCryptoService cryptoService) {
    try {
      // Initialize logging at Info level
      cryptoService.initLogging(2);

      // Get backend information
      final backendInfoJson = cryptoService.getBackendInfo();
      final backendInfo = json.decode(backendInfoJson) as Map<String, dynamic>;

      // Parse backend detection
      final tpmAvailable = backendInfo['tpm_available'] as bool? ?? false;
      final softhsmAvailable = backendInfo['softhsm_available'] as bool? ?? false;
      final platformSecureAvailable = backendInfo['platform_secure_available'] as bool? ?? false;
      final backendType = backendInfo['backend_type'] as String? ?? 'Unknown';

      // Build notification message
      final message = _buildNotificationMessage(
        tpmAvailable,
        softhsmAvailable,
        platformSecureAvailable,
        backendType,
      );

      // Show fleeting snackbar (3 seconds)
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Row(
              children: [
                const Icon(Icons.security, color: Colors.white, size: 20),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    message,
                    style: const TextStyle(fontSize: 13),
                  ),
                ),
              ],
            ),
            backgroundColor: _getBackgroundColor(backendType),
            duration: const Duration(seconds: 3),
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

  String _buildNotificationMessage(
    bool tpm,
    bool softhsm,
    bool platformSecure,
    String backendType,
  ) {
    // Determine backend string
    String backend;
    if (tpm && softhsm) {
      backend = 'TPM2 + SoftHSM (dual-seal)';
    } else if (tpm) {
      backend = 'TPM2';
    } else if (softhsm) {
      backend = 'SoftHSM';
    } else if (platformSecure) {
      backend = 'Secure Enclave';
    } else {
      backend = 'Software fallback';
    }

    // Always mention PQC
    return 'Security: $backend | Kyber ML-KEM 768 + X25519';
  }

  Color _getBackgroundColor(String backendType) {
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
