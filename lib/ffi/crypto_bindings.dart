import 'dart:ffi' as ffi;
import 'dart:io';
import 'package:ffi/ffi.dart';

/// Load the native crypto library based on platform
ffi.DynamicLibrary loadCryptoLibrary() {
  // Try release build first, fall back to debug
  if (Platform.isLinux) {
    try {
      return ffi.DynamicLibrary.open('crypto_engine/target/release/libcrypto_engine.so');
    } catch (_) {
      return ffi.DynamicLibrary.open('crypto_engine/target/debug/libcrypto_engine.so');
    }
  } else if (Platform.isAndroid) {
    return ffi.DynamicLibrary.open('libcrypto_engine.so');
  } else if (Platform.isMacOS) {
    try {
      return ffi.DynamicLibrary.open('crypto_engine/target/release/libcrypto_engine.dylib');
    } catch (_) {
      return ffi.DynamicLibrary.open('crypto_engine/target/debug/libcrypto_engine.dylib');
    }
  } else if (Platform.isIOS) {
    return ffi.DynamicLibrary.process();
  } else if (Platform.isWindows) {
    try {
      return ffi.DynamicLibrary.open('crypto_engine/target/release/crypto_engine.dll');
    } catch (_) {
      return ffi.DynamicLibrary.open('crypto_engine/target/debug/crypto_engine.dll');
    }
  } else {
    throw UnsupportedError('Unsupported platform');
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
