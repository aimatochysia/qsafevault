import 'dart:convert';
import 'dart:typed_data';
import '../fips_crypto_service.dart';
import 'storage_constants.dart' as sc;

// Use FipsCryptoService for all cryptographic operations
final FipsCryptoService _fipsCrypto = FipsCryptoService();

List<int> secureRandomBytes(int length) =>
    _fipsCrypto.generateRandomBytes(length);

void zeroBytes(List<int> bytes) {
  for (var i = 0; i < bytes.length; i++) bytes[i] = 0;
}

bool constantTimeEquals(List<int> a, List<int> b) {
  return _fipsCrypto.constantTimeEquals(a, b);
}

/// Make verifier using HMAC-SHA512 (FIPS 198-1)
Uint8List makeVerifier(Uint8List keyBytes) {
  try {
    return _fipsCrypto.hmacSha512(
      key: keyBytes, 
      data: Uint8List.fromList(utf8.encode(sc.verifierLabel)),
    );
  } finally {
    zeroBytes(keyBytes);
  }
}

String _canonicalFastParamsString(Map<String, dynamic> m) {
  final kdf = (m['kdf'] as String?) ?? 'pbkdf2';
  final iterations = (m['iterations'] as int?) ?? 0;
  final salt = (m['salt'] as String?) ?? '';
  return 'k=$kdf;i=$iterations;s=$salt';
}

/// Sign fast parameters using HMAC-SHA512 (FIPS 198-1)
Uint8List signFastParams(Uint8List masterKeyBytes, Map<String, dynamic> fastMeta) {
  try {
    final canonical = _canonicalFastParamsString(fastMeta);
    final data = Uint8List.fromList(utf8.encode('${sc.fastSigLabel}|$canonical'));
    return _fipsCrypto.hmacSha512(key: masterKeyBytes, data: data);
  } finally {
    zeroBytes(masterKeyBytes);
  }
}

/// Compute wrap nonce using HMAC-SHA256 (FIPS 198-1)
Uint8List computeWrapNonce(Uint8List wrappingKeyBytes, int counter) {
  try {
    final msg = Uint8List.fromList(utf8.encode('${sc.keyWrapLabel}|ctr:$counter'));
    final digest = _fipsCrypto.hmacSha256(key: wrappingKeyBytes, data: msg);
    return Uint8List.fromList(digest.sublist(0, 12));
  } finally {
    zeroBytes(wrappingKeyBytes);
  }
}

/// Wrap key using AES-256-GCM (FIPS 197)
Uint8List wrapKeyWithAesGcm({
  required Uint8List wrappingKey,
  required List<int> toWrap,
  required Uint8List nonce,
}) {
  final labelBytes = utf8.encode(sc.keyWrapLabel);
  final msg = Uint8List(labelBytes.length + toWrap.length)
    ..setRange(0, labelBytes.length, labelBytes)
    ..setRange(labelBytes.length, labelBytes.length + toWrap.length, toWrap);
  
  // AES-GCM encryption returns nonce || ciphertext || tag
  final encrypted = _fipsCrypto.encrypt(key: wrappingKey, plaintext: msg);
  return encrypted;
}

/// Unwrap key using AES-256-GCM (FIPS 197)
Uint8List unwrapKeyWithAesGcm(Uint8List wrappingKey, List<int> blob) {
  if (blob.length < 12 + 16) throw Exception('Invalid wrapped blob.');
  
  final plain = _fipsCrypto.decrypt(key: wrappingKey, ciphertext: Uint8List.fromList(blob));
  final labelBytes = utf8.encode(sc.keyWrapLabel);
  if (plain.length <= labelBytes.length) {
    throw Exception('Wrapped key payload too short.');
  }
  for (var i = 0; i < labelBytes.length; i++) {
    if (plain[i] != labelBytes[i]) {
      throw Exception('Wrapped key label mismatch.');
    }
  }
  final keyBytes = Uint8List.fromList(plain.sublist(labelBytes.length));
  zeroBytes(plain);
  return keyBytes;
}

/// Compute entry nonce using HMAC-SHA256 (FIPS 198-1)
Uint8List computeEntryNonce(
  Uint8List masterKeyBytes,
  int counter, {
  String? entryId,
}) {
  try {
    final sb = StringBuffer('${sc.entryNonceLabel}|nonce|ctr:$counter');
    if (entryId != null) sb.write('|id:$entryId');
    final msg = Uint8List.fromList(utf8.encode(sb.toString()));
    final digest = _fipsCrypto.hmacSha256(key: masterKeyBytes, data: msg);
    return Uint8List.fromList(digest.sublist(0, 12));
  } finally {
    zeroBytes(masterKeyBytes);
  }
}

/// Compute entry accept tag using HMAC-SHA512 (FIPS 198-1)
Uint8List computeEntryAcceptTag(
  Uint8List masterKeyBytes,
  int counter,
  Uint8List challenge, {
  String? entryId,
}) {
  try {
    final sb = StringBuffer('${sc.entryNonceLabel}|accept|ctr:$counter');
    if (entryId != null) sb.write('|id:$entryId');
    final prefix = sb.toString() + '|chal:';
    final data = Uint8List(prefix.length + challenge.length)
      ..setRange(0, prefix.length, utf8.encode(prefix))
      ..setRange(prefix.length, prefix.length + challenge.length, challenge);
    return _fipsCrypto.hmacSha512(key: masterKeyBytes, data: data);
  } finally {
    zeroBytes(masterKeyBytes);
  }
}

/// Compute folder key ID using SHA-256 (FIPS 180-4)
String folderKeyId(String folderPath) {
  final h = _fipsCrypto.sha256String(folderPath);
  final b64 = base64UrlEncode(h);
  return 'qsv_wrapped_$b64';
}
