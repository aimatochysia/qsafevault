import 'dart:ffi' as ffi;
import 'dart:io';
import 'package:ffi/ffi.dart';

/// Load the native crypto library based on platform
ffi.DynamicLibrary loadCryptoLibrary() {
  if (Platform.isLinux) {
    // Desktop Linux: Try multiple locations
    final paths = [
      'linux/libs/libcrypto_engine.so',           // Pre-built from CI
      'crypto_engine/target/release/libcrypto_engine.so',  // Local release build
      'crypto_engine/target/debug/libcrypto_engine.so',    // Local debug build
    ];
    for (final path in paths) {
      try {
        return ffi.DynamicLibrary.open(path);
      } catch (_) {
        continue;
      }
    }
    throw UnsupportedError(
      'Rust crypto library not found on Linux. '
      'Please build the Rust library or run the CI workflow to generate binaries.'
    );
  } else if (Platform.isAndroid) {
    // Android: Library must be bundled in android/app/src/main/jniLibs/<abi>/libcrypto_engine.so
    // Flutter will automatically find it when we just use the library name
    try {
      return ffi.DynamicLibrary.open('libcrypto_engine.so');
    } catch (e) {
      // If Rust library not found, throw descriptive error
      throw UnsupportedError(
        'Rust crypto library not found on Android. '
        'Please build the Rust library for Android and place it in android/app/src/main/jniLibs/. '
        'Error: $e'
      );
    }
  } else if (Platform.isMacOS) {
    // Desktop macOS: Try multiple locations
    final paths = [
      'macos/libs/libcrypto_engine.dylib',        // Pre-built from CI
      'crypto_engine/target/release/libcrypto_engine.dylib',  // Local release build
      'crypto_engine/target/debug/libcrypto_engine.dylib',    // Local debug build
    ];
    for (final path in paths) {
      try {
        return ffi.DynamicLibrary.open(path);
      } catch (_) {
        continue;
      }
    }
    throw UnsupportedError(
      'Rust crypto library not found on macOS. '
      'Please build the Rust library or run the CI workflow to generate binaries.'
    );
  } else if (Platform.isIOS) {
    // iOS: Library must be embedded in the app bundle as a framework
    // Use DynamicLibrary.process() to access symbols from the app itself
    try {
      return ffi.DynamicLibrary.process();
    } catch (e) {
      throw UnsupportedError(
        'Rust crypto library not found on iOS. '
        'Please build the Rust library for iOS and link it with the app. '
        'Error: $e'
      );
    }
  } else if (Platform.isWindows) {
    // Desktop Windows: Try multiple locations
    final paths = [
      'windows/libs/crypto_engine.dll',           // Pre-built from CI
      'crypto_engine/target/release/crypto_engine.dll',  // Local release build
      'crypto_engine/target/debug/crypto_engine.dll',    // Local debug build
    ];
    for (final path in paths) {
      try {
        return ffi.DynamicLibrary.open(path);
      } catch (_) {
        continue;
      }
    }
    throw UnsupportedError(
      'Rust crypto library not found on Windows. '
      'Please build the Rust library or run the CI workflow to generate binaries.'
    );
  } else {
    throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
  }
}

/// Status codes matching Rust FFI
const int statusOk = 0;
const int statusError = -1;
const int statusInvalidParam = -2;
const int statusNotFound = -3;

/// Native function signatures
typedef NativeGenerateKeypair = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint64> keypairHandleOut,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> pqcPublicKeyOut,
  ffi.Pointer<ffi.Size> pqcPublicKeyLenOut,
  ffi.Pointer<ffi.Uint8> classicalPublicKeyOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef NativeHybridEncrypt = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8> pqcPublicKey,
  ffi.Size pqcPublicKeyLen,
  ffi.Pointer<ffi.Uint8> classicalPublicKey,
  ffi.Pointer<ffi.Uint8> masterKey,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> sealedBlobOut,
  ffi.Pointer<ffi.Size> sealedBlobLenOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef NativeHybridDecrypt = ffi.Int32 Function(
  ffi.Uint64 keypairHandle,
  ffi.Pointer<ffi.Uint8> sealedBlob,
  ffi.Size sealedBlobLen,
  ffi.Pointer<ffi.Uint8> masterKeyOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef NativeSealKey = ffi.Int32 Function(
  ffi.Uint64 keypairHandle,
  ffi.Pointer<ffi.Char> keyId,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef NativeUnsealKey = ffi.Int32 Function(
  ffi.Pointer<ffi.Char> keyId,
  ffi.Pointer<ffi.Uint8> pqcPublicKey,
  ffi.Size pqcPublicKeyLen,
  ffi.Pointer<ffi.Uint8> classicalPublicKey,
  ffi.Pointer<ffi.Uint64> keypairHandleOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef NativeEncryptVault = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8> masterKey,
  ffi.Pointer<ffi.Uint8> plaintext,
  ffi.Size plaintextLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> sealedBlobOut,
  ffi.Pointer<ffi.Size> sealedBlobLenOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef NativeDecryptVault = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8> masterKey,
  ffi.Pointer<ffi.Uint8> sealedBlob,
  ffi.Size sealedBlobLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> plaintextOut,
  ffi.Pointer<ffi.Size> plaintextLenOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef NativeFreeHandle = ffi.Int32 Function(ffi.Uint64 handle);
typedef NativeFreeMemory = ffi.Void Function(ffi.Pointer<ffi.Uint8> ptr);
typedef NativeFreeString = ffi.Void Function(ffi.Pointer<ffi.Char> ptr);

typedef NativeGetBackendInfo = ffi.Int32 Function(
  ffi.Pointer<ffi.Pointer<ffi.Char>> infoOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef NativeInitLogging = ffi.Int32 Function(ffi.Int32 level);

/// Dart function signatures
typedef DartGenerateKeypair = int Function(
  ffi.Pointer<ffi.Uint64> keypairHandleOut,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> pqcPublicKeyOut,
  ffi.Pointer<ffi.Size> pqcPublicKeyLenOut,
  ffi.Pointer<ffi.Uint8> classicalPublicKeyOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef DartHybridEncrypt = int Function(
  ffi.Pointer<ffi.Uint8> pqcPublicKey,
  int pqcPublicKeyLen,
  ffi.Pointer<ffi.Uint8> classicalPublicKey,
  ffi.Pointer<ffi.Uint8> masterKey,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> sealedBlobOut,
  ffi.Pointer<ffi.Size> sealedBlobLenOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef DartHybridDecrypt = int Function(
  int keypairHandle,
  ffi.Pointer<ffi.Uint8> sealedBlob,
  int sealedBlobLen,
  ffi.Pointer<ffi.Uint8> masterKeyOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef DartSealKey = int Function(
  int keypairHandle,
  ffi.Pointer<ffi.Char> keyId,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef DartUnsealKey = int Function(
  ffi.Pointer<ffi.Char> keyId,
  ffi.Pointer<ffi.Uint8> pqcPublicKey,
  int pqcPublicKeyLen,
  ffi.Pointer<ffi.Uint8> classicalPublicKey,
  ffi.Pointer<ffi.Uint64> keypairHandleOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef DartEncryptVault = int Function(
  ffi.Pointer<ffi.Uint8> masterKey,
  ffi.Pointer<ffi.Uint8> plaintext,
  int plaintextLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> sealedBlobOut,
  ffi.Pointer<ffi.Size> sealedBlobLenOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef DartDecryptVault = int Function(
  ffi.Pointer<ffi.Uint8> masterKey,
  ffi.Pointer<ffi.Uint8> sealedBlob,
  int sealedBlobLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> plaintextOut,
  ffi.Pointer<ffi.Size> plaintextLenOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef DartFreeHandle = int Function(int handle);
typedef DartFreeMemory = void Function(ffi.Pointer<ffi.Uint8> ptr);
typedef DartFreeString = void Function(ffi.Pointer<ffi.Char> ptr);

typedef DartGetBackendInfo = int Function(
  ffi.Pointer<ffi.Pointer<ffi.Char>> infoOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef DartInitLogging = int Function(int level);

/// Additional native function signatures for crypto primitives
typedef NativeGenerateRandomBytes = ffi.Int32 Function(
  ffi.Size length,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> bytesOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef NativeDeriveKeyHkdf = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8> inputKeyMaterial,
  ffi.Size ikmLen,
  ffi.Pointer<ffi.Uint8> salt,
  ffi.Size saltLen,
  ffi.Pointer<ffi.Uint8> info,
  ffi.Size infoLen,
  ffi.Size outputKeyLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> outputKeyOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef NativeGetVersion = ffi.Int32 Function(
  ffi.Pointer<ffi.Pointer<ffi.Char>> versionOut,
);

/// Dart function signatures for crypto primitives
typedef DartGenerateRandomBytes = int Function(
  int length,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> bytesOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef DartDeriveKeyHkdf = int Function(
  ffi.Pointer<ffi.Uint8> inputKeyMaterial,
  int ikmLen,
  ffi.Pointer<ffi.Uint8> salt,
  int saltLen,
  ffi.Pointer<ffi.Uint8> info,
  int infoLen,
  int outputKeyLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> outputKeyOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

typedef DartGetVersion = int Function(
  ffi.Pointer<ffi.Pointer<ffi.Char>> versionOut,
);

// =============================================================================
// FIPS-Compliant Symmetric Cryptography FFI Signatures
// =============================================================================

/// Native function signature for AES-256-GCM encryption
typedef NativeAesGcmEncrypt = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8> key,           // 32 bytes
  ffi.Pointer<ffi.Uint8> plaintext,
  ffi.Size plaintextLen,
  ffi.Pointer<ffi.Uint8> aad,           // Optional
  ffi.Size aadLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> ciphertextOut,
  ffi.Pointer<ffi.Size> ciphertextLenOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Native function signature for AES-256-GCM decryption
typedef NativeAesGcmDecrypt = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8> key,           // 32 bytes
  ffi.Pointer<ffi.Uint8> ciphertext,    // nonce || ciphertext || tag
  ffi.Size ciphertextLen,
  ffi.Pointer<ffi.Uint8> aad,           // Optional
  ffi.Size aadLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> plaintextOut,
  ffi.Pointer<ffi.Size> plaintextLenOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Native function signature for SHA-256 hash
typedef NativeSha256 = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8> data,
  ffi.Size dataLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> hashOut,  // 32 bytes
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Native function signature for HMAC-SHA256
typedef NativeHmacSha256 = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8> key,
  ffi.Size keyLen,
  ffi.Pointer<ffi.Uint8> data,
  ffi.Size dataLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> macOut,   // 32 bytes
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Native function signature for HMAC-SHA512
typedef NativeHmacSha512 = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8> key,
  ffi.Size keyLen,
  ffi.Pointer<ffi.Uint8> data,
  ffi.Size dataLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> macOut,   // 64 bytes
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Native function signature for PBKDF2-HMAC-SHA256
typedef NativePbkdf2Sha256 = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8> password,
  ffi.Size passwordLen,
  ffi.Pointer<ffi.Uint8> salt,
  ffi.Size saltLen,
  ffi.Uint32 iterations,
  ffi.Size outputKeyLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> outputKeyOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Dart function signature for AES-256-GCM encryption
typedef DartAesGcmEncrypt = int Function(
  ffi.Pointer<ffi.Uint8> key,
  ffi.Pointer<ffi.Uint8> plaintext,
  int plaintextLen,
  ffi.Pointer<ffi.Uint8> aad,
  int aadLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> ciphertextOut,
  ffi.Pointer<ffi.Size> ciphertextLenOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Dart function signature for AES-256-GCM decryption
typedef DartAesGcmDecrypt = int Function(
  ffi.Pointer<ffi.Uint8> key,
  ffi.Pointer<ffi.Uint8> ciphertext,
  int ciphertextLen,
  ffi.Pointer<ffi.Uint8> aad,
  int aadLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> plaintextOut,
  ffi.Pointer<ffi.Size> plaintextLenOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Dart function signature for SHA-256 hash
typedef DartSha256 = int Function(
  ffi.Pointer<ffi.Uint8> data,
  int dataLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> hashOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Dart function signature for HMAC-SHA256
typedef DartHmacSha256 = int Function(
  ffi.Pointer<ffi.Uint8> key,
  int keyLen,
  ffi.Pointer<ffi.Uint8> data,
  int dataLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> macOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Dart function signature for HMAC-SHA512
typedef DartHmacSha512 = int Function(
  ffi.Pointer<ffi.Uint8> key,
  int keyLen,
  ffi.Pointer<ffi.Uint8> data,
  int dataLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> macOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Dart function signature for PBKDF2-HMAC-SHA256
typedef DartPbkdf2Sha256 = int Function(
  ffi.Pointer<ffi.Uint8> password,
  int passwordLen,
  ffi.Pointer<ffi.Uint8> salt,
  int saltLen,
  int iterations,
  int outputKeyLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> outputKeyOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

// =============================================================================
// Edition System FFI Signatures
// =============================================================================

/// Native function signature for initializing edition
typedef NativeInitializeEdition = ffi.Int32 Function(
  ffi.Int32 edition,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Native function signature for getting current edition
typedef NativeGetEdition = ffi.Int32 Function(
  ffi.Pointer<ffi.Int32> editionOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Native function signature for checking if edition is initialized
typedef NativeIsEditionInitialized = ffi.Int32 Function();

/// Native function signature for getting edition info as JSON
typedef NativeGetEditionInfo = ffi.Int32 Function(
  ffi.Pointer<ffi.Pointer<ffi.Char>> infoOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Native function signature for verifying algorithm is permitted
typedef NativeVerifyAlgorithmPermitted = ffi.Int32 Function(
  ffi.Int32 algorithmId,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Native function signature for verifying server edition compatibility
typedef NativeVerifyServerEdition = ffi.Int32 Function(
  ffi.Int32 clientEdition,
  ffi.Int32 serverEdition,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Dart function signature for initializing edition
typedef DartInitializeEdition = int Function(
  int edition,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Dart function signature for getting current edition
typedef DartGetEdition = int Function(
  ffi.Pointer<ffi.Int32> editionOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Dart function signature for checking if edition is initialized
typedef DartIsEditionInitialized = int Function();

/// Dart function signature for getting edition info as JSON
typedef DartGetEditionInfo = int Function(
  ffi.Pointer<ffi.Pointer<ffi.Char>> infoOut,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Dart function signature for verifying algorithm is permitted
typedef DartVerifyAlgorithmPermitted = int Function(
  int algorithmId,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

/// Dart function signature for verifying server edition compatibility
typedef DartVerifyServerEdition = int Function(
  int clientEdition,
  int serverEdition,
  ffi.Pointer<ffi.Pointer<ffi.Char>> errorMsgOut,
);

