import 'dart:math';
import 'dart:typed_data';
import '../fips_crypto_service.dart';
import 'storage_constants.dart' as sc;
import 'storage_crypto_helpers.dart' as sh;

/// Calibrate PBKDF2-HMAC-SHA256 iterations for target time
/// FIPS-compliant replacement for Argon2id calibration
Future<({int iterations})> calibratePbkdf2(
  FipsCryptoService cryptoService, {
  required int targetMs,
}) async {
  final testSalt = sh.secureRandomBytes(16);
  const testPassword = 'qsv-calibration';
  
  // Start with minimum FIPS-compliant iterations
  int iterations = max(sc.minPbkdf2Iterations, 100000);
  Duration took;
  
  do {
    final sw = Stopwatch()..start();
    cryptoService.deriveKeyFromPassword(
      password: testPassword,
      salt: testSalt,
      iterations: iterations,
    );
    sw.stop();
    took = sw.elapsed;
    
    if (took.inMilliseconds < targetMs) {
      iterations = (iterations * 2).clamp(sc.minPbkdf2Iterations, 10000000);
    }
  } while (took.inMilliseconds < targetMs && iterations < 10000000);
  
  return (iterations: iterations);
}

/// Derive fast key using PBKDF2-HMAC-SHA256 (FIPS-compliant)
Uint8List deriveFastKeyPbkdf2(
  FipsCryptoService cryptoService,
  String password,
  List<int> salt, {
  required int iterations,
}) {
  return cryptoService.deriveKeyFromPassword(
    password: password,
    salt: salt,
    iterations: iterations,
  );
}
