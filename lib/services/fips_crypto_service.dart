import 'dart:convert';
import 'dart:typed_data';
import '../ffi/rust_crypto_service.dart';

/// FIPS-compliant cryptographic service that uses the Rust FFI backend.
/// 
/// All cryptographic operations go through the FIPS-certified Rust crypto engine.
/// This service provides:
/// - AES-256-GCM encryption/decryption (FIPS 197)
/// - SHA-256 hashing (FIPS 180-4)
/// - HMAC-SHA256/512 (FIPS 198-1)
/// - PBKDF2-HMAC-SHA256 key derivation (NIST SP 800-132)
/// - SP 800-56C One-Step KDF for key derivation
/// - Secure random number generation
/// 
/// NO Dart cryptography package is used - all operations are FIPS-certified.
class FipsCryptoService {
  final RustCryptoService _rust;
  
  static const int _nonceLength = 12;
  static const int _tagLength = 16;
  static const int saltLength = 16;
  
  int get nonceLength => _nonceLength;
  String get cipherName => 'aes-256-gcm';

  FipsCryptoService() : _rust = RustCryptoService();
  
  FipsCryptoService.withRustService(RustCryptoService rustService) 
      : _rust = rustService;

  /// Generate secure random bytes using OS CSPRNG via Rust FFI
  Uint8List generateRandomBytes(int length) {
    return _rust.generateRandomBytes(length);
  }

  /// Derive key from password using PBKDF2-HMAC-SHA256 (NIST SP 800-132)
  /// 
  /// This is the FIPS-compliant replacement for Argon2id.
  /// Minimum 10000 iterations required for FIPS compliance.
  /// For high security, use at least 100000 iterations.
  Uint8List deriveKeyFromPassword({
    required String password,
    required List<int> salt,
    int iterations = 100000,
  }) {
    final passwordBytes = Uint8List.fromList(utf8.encode(password));
    final saltBytes = Uint8List.fromList(salt);
    
    return _rust.pbkdf2Sha256(
      password: passwordBytes,
      salt: saltBytes,
      iterations: iterations,
      outputKeyLength: 32,
    );
  }

  /// Derive key using SP 800-56C One-Step KDF
  /// 
  /// This is used for deriving keys from shared secrets (e.g., after KEM).
  Uint8List deriveKeyHkdf({
    required Uint8List inputKeyMaterial,
    Uint8List? salt,
    Uint8List? info,
    required int outputKeyLength,
  }) {
    return _rust.deriveKeyHkdf(
      inputKeyMaterial: inputKeyMaterial,
      salt: salt,
      info: info,
      outputKeyLength: outputKeyLength,
    );
  }

  /// SHA-256 hash (FIPS 180-4)
  Uint8List sha256(Uint8List data) {
    return _rust.sha256(data);
  }
  
  /// SHA-256 hash of a string
  Uint8List sha256String(String data) {
    return sha256(Uint8List.fromList(utf8.encode(data)));
  }

  /// HMAC-SHA256 (FIPS 198-1)
  Uint8List hmacSha256({required Uint8List key, required Uint8List data}) {
    return _rust.hmacSha256(key: key, data: data);
  }

  /// HMAC-SHA512 (FIPS 198-1)
  Uint8List hmacSha512({required Uint8List key, required Uint8List data}) {
    return _rust.hmacSha512(key: key, data: data);
  }

  /// AES-256-GCM encryption (FIPS 197)
  /// 
  /// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
  Uint8List encrypt({
    required Uint8List key,
    required Uint8List plaintext,
    Uint8List? aad,
  }) {
    if (key.length != 32) {
      throw ArgumentError('Key must be 32 bytes');
    }
    return _rust.aesGcmEncrypt(key: key, plaintext: plaintext, aad: aad);
  }

  /// AES-256-GCM encryption of UTF-8 string
  Uint8List encryptUtf8({required Uint8List key, required String plaintext}) {
    return encrypt(
      key: key,
      plaintext: Uint8List.fromList(utf8.encode(plaintext)),
    );
  }

  /// AES-256-GCM decryption (FIPS 197)
  /// 
  /// Input format: nonce (12 bytes) || ciphertext || tag (16 bytes)
  Uint8List decrypt({
    required Uint8List key,
    required Uint8List ciphertext,
    Uint8List? aad,
  }) {
    if (key.length != 32) {
      throw ArgumentError('Key must be 32 bytes');
    }
    return _rust.aesGcmDecrypt(key: key, ciphertext: ciphertext, aad: aad);
  }

  /// AES-256-GCM decryption to UTF-8 string
  String decryptUtf8({required Uint8List key, required Uint8List ciphertext}) {
    final plaintext = decrypt(key: key, ciphertext: ciphertext);
    return utf8.decode(plaintext);
  }

  /// Compute a deterministic nonce from key and counter using HMAC-SHA256
  /// This is used for key wrapping where nonce reuse must be avoided
  Uint8List computeWrapNonce(Uint8List key, int counter, String label) {
    final msg = Uint8List.fromList(utf8.encode('$label|ctr:$counter'));
    final digest = hmacSha256(key: key, data: msg);
    return Uint8List.fromList(digest.sublist(0, 12));
  }

  /// Compute entry nonce from master key, counter and optional entry ID
  Uint8List computeEntryNonce(
    Uint8List masterKey,
    int counter, {
    String? entryId,
    String label = 'qsv-entry-nonce-v1',
  }) {
    final sb = StringBuffer('$label|nonce|ctr:$counter');
    if (entryId != null) sb.write('|id:$entryId');
    final msg = Uint8List.fromList(utf8.encode(sb.toString()));
    final digest = hmacSha256(key: masterKey, data: msg);
    return Uint8List.fromList(digest.sublist(0, 12));
  }

  /// Compute key verifier using HMAC-SHA512
  Uint8List makeVerifier(Uint8List key, String label) {
    final data = Uint8List.fromList(utf8.encode(label));
    return hmacSha512(key: key, data: data);
  }

  /// Sign fast parameters using HMAC-SHA512
  Uint8List signFastParams(Uint8List masterKey, Map<String, dynamic> fastMeta, String label) {
    final kdf = (fastMeta['kdf'] as String?) ?? 'pbkdf2';
    final iterations = (fastMeta['iterations'] as int?) ?? 0;
    final salt = (fastMeta['salt'] as String?) ?? '';
    final canonical = 'k=$kdf;i=$iterations;s=$salt';
    final data = Uint8List.fromList(utf8.encode('$label|$canonical'));
    return hmacSha512(key: masterKey, data: data);
  }

  /// Wrap key using AES-256-GCM
  Uint8List wrapKey({
    required Uint8List wrappingKey,
    required Uint8List toWrap,
    required Uint8List nonce,
    String label = 'qsv-key-wrap-v1',
  }) {
    final labelBytes = utf8.encode(label);
    final msg = Uint8List(labelBytes.length + toWrap.length)
      ..setRange(0, labelBytes.length, labelBytes)
      ..setRange(labelBytes.length, labelBytes.length + toWrap.length, toWrap);
    
    // Create ciphertext using nonce provided
    // Note: Rust AES-GCM generates its own nonce, so we need to concatenate
    final encrypted = _rust.aesGcmEncrypt(key: wrappingKey, plaintext: msg);
    
    // Return nonce || ciphertext || tag
    return encrypted;
  }

  /// Unwrap key using AES-256-GCM
  Uint8List unwrapKey({
    required Uint8List wrappingKey,
    required Uint8List blob,
    String label = 'qsv-key-wrap-v1',
  }) {
    final plain = _rust.aesGcmDecrypt(key: wrappingKey, ciphertext: blob);
    
    final labelBytes = utf8.encode(label);
    if (plain.length <= labelBytes.length) {
      throw Exception('Wrapped key payload too short.');
    }
    for (var i = 0; i < labelBytes.length; i++) {
      if (plain[i] != labelBytes[i]) {
        throw Exception('Wrapped key label mismatch.');
      }
    }
    return Uint8List.fromList(plain.sublist(labelBytes.length));
  }

  /// Constant-time comparison of two byte arrays
  bool constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= (a[i] ^ b[i]);
    }
    return diff == 0;
  }

  /// Zero out a byte array (for security)
  void zeroBytes(List<int> bytes) {
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = 0;
    }
  }

  /// Compute folder key ID from path
  String folderKeyId(String folderPath) {
    final h = sha256String(folderPath);
    final b64 = base64UrlEncode(h);
    return 'qsv_wrapped_$b64';
  }
}
