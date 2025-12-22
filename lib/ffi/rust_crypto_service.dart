import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'crypto_bindings.dart';

/// Rust FFI Crypto Service
/// All cryptographic operations go through the Rust backend
class RustCryptoService {
  late final ffi.DynamicLibrary _lib;
  late final DartGenerateKeypair _generateKeypair;
  late final DartHybridEncrypt _hybridEncrypt;
  late final DartHybridDecrypt _hybridDecrypt;
  late final DartSealKey _sealKey;
  late final DartUnsealKey _unsealKey;
  late final DartEncryptVault _encryptVault;
  late final DartDecryptVault _decryptVault;
  late final DartFreeHandle _freeHandle;
  late final DartFreeMemory _freeMemory;
  late final DartFreeString _freeString;
  late final DartGetBackendInfo _getBackendInfo;
  late final DartInitLogging _initLogging;

  RustCryptoService() {
    _lib = loadCryptoLibrary();
    
    _generateKeypair = _lib
        .lookup<ffi.NativeFunction<NativeGenerateKeypair>>('pqcrypto_generate_hybrid_keypair')
        .asFunction();
    
    _hybridEncrypt = _lib
        .lookup<ffi.NativeFunction<NativeHybridEncrypt>>('pqcrypto_hybrid_encrypt_master_key')
        .asFunction();
    
    _hybridDecrypt = _lib
        .lookup<ffi.NativeFunction<NativeHybridDecrypt>>('pqcrypto_hybrid_decrypt_master_key')
        .asFunction();
    
    _sealKey = _lib
        .lookup<ffi.NativeFunction<NativeSealKey>>('pqcrypto_seal_private_key_with_platform_keystore')
        .asFunction();
    
    _unsealKey = _lib
        .lookup<ffi.NativeFunction<NativeUnsealKey>>('pqcrypto_unseal_private_key_from_platform_keystore')
        .asFunction();
    
    _encryptVault = _lib
        .lookup<ffi.NativeFunction<NativeEncryptVault>>('pqcrypto_encrypt_vault')
        .asFunction();
    
    _decryptVault = _lib
        .lookup<ffi.NativeFunction<NativeDecryptVault>>('pqcrypto_decrypt_vault')
        .asFunction();
    
    _freeHandle = _lib
        .lookup<ffi.NativeFunction<NativeFreeHandle>>('pqcrypto_free_handle')
        .asFunction();
    
    _freeMemory = _lib
        .lookup<ffi.NativeFunction<NativeFreeMemory>>('pqcrypto_free_memory')
        .asFunction();
    
    _freeString = _lib
        .lookup<ffi.NativeFunction<NativeFreeString>>('pqcrypto_free_string')
        .asFunction();
    
    _getBackendInfo = _lib
        .lookup<ffi.NativeFunction<NativeGetBackendInfo>>('pqcrypto_get_backend_info')
        .asFunction();
    
    _initLogging = _lib
        .lookup<ffi.NativeFunction<NativeInitLogging>>('pqcrypto_init_logging')
        .asFunction();
  }

  /// Generate a new hybrid keypair
  ({int handle, Uint8List pqcPublicKey, Uint8List classicalPublicKey}) generateHybridKeypair() {
    final handlePtr = calloc<ffi.Uint64>();
    final pqcPkPtr = calloc<ffi.Pointer<ffi.Uint8>>();
    final pqcPkLenPtr = calloc<ffi.Size>();
    final classicalPk = calloc<ffi.Uint8>(32);
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      final status = _generateKeypair(
        handlePtr,
        pqcPkPtr,
        pqcPkLenPtr,
        classicalPk,
        errorPtr,
      );

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw Exception('Failed to generate keypair: $error');
      }

      final handle = handlePtr.value;
      final pqcPkLen = pqcPkLenPtr.value;
      final pqcPk = Uint8List.fromList(
        pqcPkPtr.value.asTypedList(pqcPkLen),
      );
      final classicalPkBytes = Uint8List.fromList(
        classicalPk.asTypedList(32),
      );

      // Free the allocated PQC public key
      _freeMemory(pqcPkPtr.value);

      return (
        handle: handle,
        pqcPublicKey: pqcPk,
        classicalPublicKey: classicalPkBytes,
      );
    } finally {
      calloc.free(handlePtr);
      calloc.free(pqcPkPtr);
      calloc.free(pqcPkLenPtr);
      calloc.free(classicalPk);
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// Encrypt a master key using hybrid KEM
  Uint8List hybridEncryptMasterKey(
    Uint8List pqcPublicKey,
    Uint8List classicalPublicKey,
    Uint8List masterKey,
  ) {
    if (classicalPublicKey.length != 32) {
      throw ArgumentError('Classical public key must be 32 bytes');
    }
    if (masterKey.length != 32) {
      throw ArgumentError('Master key must be 32 bytes');
    }

    final pqcPkPtr = calloc<ffi.Uint8>(pqcPublicKey.length);
    final classicalPkPtr = calloc<ffi.Uint8>(32);
    final masterKeyPtr = calloc<ffi.Uint8>(32);
    final sealedBlobPtr = calloc<ffi.Pointer<ffi.Uint8>>();
    final sealedBlobLenPtr = calloc<ffi.Size>();
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      // Copy data
      for (int i = 0; i < pqcPublicKey.length; i++) {
        pqcPkPtr[i] = pqcPublicKey[i];
      }
      for (int i = 0; i < 32; i++) {
        classicalPkPtr[i] = classicalPublicKey[i];
        masterKeyPtr[i] = masterKey[i];
      }

      final status = _hybridEncrypt(
        pqcPkPtr,
        pqcPublicKey.length,
        classicalPkPtr,
        masterKeyPtr,
        sealedBlobPtr,
        sealedBlobLenPtr,
        errorPtr,
      );

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw Exception('Failed to encrypt master key: $error');
      }

      final sealedBlobLen = sealedBlobLenPtr.value;
      final sealedBlob = Uint8List.fromList(
        sealedBlobPtr.value.asTypedList(sealedBlobLen),
      );

      // Free the allocated sealed blob
      _freeMemory(sealedBlobPtr.value);

      return sealedBlob;
    } finally {
      calloc.free(pqcPkPtr);
      calloc.free(classicalPkPtr);
      calloc.free(masterKeyPtr);
      calloc.free(sealedBlobPtr);
      calloc.free(sealedBlobLenPtr);
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// Decrypt a master key using hybrid KEM
  Uint8List hybridDecryptMasterKey(int keypairHandle, Uint8List sealedBlob) {
    final sealedBlobPtr = calloc<ffi.Uint8>(sealedBlob.length);
    final masterKeyPtr = calloc<ffi.Uint8>(32);
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      // Copy data
      for (int i = 0; i < sealedBlob.length; i++) {
        sealedBlobPtr[i] = sealedBlob[i];
      }

      final status = _hybridDecrypt(
        keypairHandle,
        sealedBlobPtr,
        sealedBlob.length,
        masterKeyPtr,
        errorPtr,
      );

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw Exception('Failed to decrypt master key: $error');
      }

      return Uint8List.fromList(masterKeyPtr.asTypedList(32));
    } finally {
      calloc.free(sealedBlobPtr);
      calloc.free(masterKeyPtr);
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// Seal private key to platform keystore
  void sealPrivateKey(int keypairHandle, String keyId) {
    final keyIdPtr = keyId.toNativeUtf8().cast<ffi.Char>();
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      final status = _sealKey(keypairHandle, keyIdPtr, errorPtr);

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw Exception('Failed to seal private key: $error');
      }
    } finally {
      calloc.free(keyIdPtr);
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// Unseal private key from platform keystore
  int unsealPrivateKey(
    String keyId,
    Uint8List pqcPublicKey,
    Uint8List classicalPublicKey,
  ) {
    if (classicalPublicKey.length != 32) {
      throw ArgumentError('Classical public key must be 32 bytes');
    }

    final keyIdPtr = keyId.toNativeUtf8().cast<ffi.Char>();
    final pqcPkPtr = calloc<ffi.Uint8>(pqcPublicKey.length);
    final classicalPkPtr = calloc<ffi.Uint8>(32);
    final handlePtr = calloc<ffi.Uint64>();
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      // Copy data
      for (int i = 0; i < pqcPublicKey.length; i++) {
        pqcPkPtr[i] = pqcPublicKey[i];
      }
      for (int i = 0; i < 32; i++) {
        classicalPkPtr[i] = classicalPublicKey[i];
      }

      final status = _unsealKey(
        keyIdPtr,
        pqcPkPtr,
        pqcPublicKey.length,
        classicalPkPtr,
        handlePtr,
        errorPtr,
      );

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw Exception('Failed to unseal private key: $error');
      }

      return handlePtr.value;
    } finally {
      calloc.free(keyIdPtr);
      calloc.free(pqcPkPtr);
      calloc.free(classicalPkPtr);
      calloc.free(handlePtr);
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// Encrypt vault data
  Uint8List encryptVault(Uint8List masterKey, Uint8List plaintext) {
    if (masterKey.length != 32) {
      throw ArgumentError('Master key must be 32 bytes');
    }

    final masterKeyPtr = calloc<ffi.Uint8>(32);
    final plaintextPtr = calloc<ffi.Uint8>(plaintext.length);
    final sealedBlobPtr = calloc<ffi.Pointer<ffi.Uint8>>();
    final sealedBlobLenPtr = calloc<ffi.Size>();
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      // Copy data
      for (int i = 0; i < 32; i++) {
        masterKeyPtr[i] = masterKey[i];
      }
      for (int i = 0; i < plaintext.length; i++) {
        plaintextPtr[i] = plaintext[i];
      }

      final status = _encryptVault(
        masterKeyPtr,
        plaintextPtr,
        plaintext.length,
        sealedBlobPtr,
        sealedBlobLenPtr,
        errorPtr,
      );

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw Exception('Failed to encrypt vault: $error');
      }

      final sealedBlobLen = sealedBlobLenPtr.value;
      final sealedBlob = Uint8List.fromList(
        sealedBlobPtr.value.asTypedList(sealedBlobLen),
      );

      // Free the allocated sealed blob
      _freeMemory(sealedBlobPtr.value);

      return sealedBlob;
    } finally {
      calloc.free(masterKeyPtr);
      calloc.free(plaintextPtr);
      calloc.free(sealedBlobPtr);
      calloc.free(sealedBlobLenPtr);
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// Decrypt vault data
  Uint8List decryptVault(Uint8List masterKey, Uint8List sealedBlob) {
    if (masterKey.length != 32) {
      throw ArgumentError('Master key must be 32 bytes');
    }

    final masterKeyPtr = calloc<ffi.Uint8>(32);
    final sealedBlobPtr = calloc<ffi.Uint8>(sealedBlob.length);
    final plaintextPtr = calloc<ffi.Pointer<ffi.Uint8>>();
    final plaintextLenPtr = calloc<ffi.Size>();
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      // Copy data
      for (int i = 0; i < 32; i++) {
        masterKeyPtr[i] = masterKey[i];
      }
      for (int i = 0; i < sealedBlob.length; i++) {
        sealedBlobPtr[i] = sealedBlob[i];
      }

      final status = _decryptVault(
        masterKeyPtr,
        sealedBlobPtr,
        sealedBlob.length,
        plaintextPtr,
        plaintextLenPtr,
        errorPtr,
      );

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw Exception('Failed to decrypt vault: $error');
      }

      final plaintextLen = plaintextLenPtr.value;
      final plaintext = Uint8List.fromList(
        plaintextPtr.value.asTypedList(plaintextLen),
      );

      // Free the allocated plaintext
      _freeMemory(plaintextPtr.value);

      return plaintext;
    } finally {
      calloc.free(masterKeyPtr);
      calloc.free(sealedBlobPtr);
      calloc.free(plaintextPtr);
      calloc.free(plaintextLenPtr);
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// Free a keypair handle
  void freeHandle(int handle) {
    _freeHandle(handle);
  }

  /// Get backend information (TPM2, SoftHSM detection status)
  String getBackendInfo() {
    final infoPtr = calloc<ffi.Pointer<ffi.Char>>();
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      final status = _getBackendInfo(infoPtr, errorPtr);

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw Exception('Failed to get backend info: $error');
      }

      if (infoPtr.value != ffi.nullptr) {
        final info = infoPtr.value.cast<Utf8>().toDartString();
        _freeString(infoPtr.value);
        return info;
      }
      return '{}';
    } finally {
      calloc.free(infoPtr);
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// Initialize logging system
  /// Level: 0=Error, 1=Warn, 2=Info, 3=Debug, 4=Trace
  void initLogging(int level) {
    _initLogging(level);
  }

  /// Generate secure random bytes using Rust's OS CSPRNG
  Uint8List generateRandomBytes(int length) {
    final bytesPtr = calloc<ffi.Pointer<ffi.Uint8>>();
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      final generateRandom = _lib
          .lookup<ffi.NativeFunction<NativeGenerateRandomBytes>>('pqcrypto_generate_random_bytes')
          .asFunction<DartGenerateRandomBytes>();

      final status = generateRandom(length, bytesPtr, errorPtr);

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw Exception('Failed to generate random bytes: $error');
      }

      if (bytesPtr.value == ffi.nullptr) {
        throw Exception('Failed to generate random bytes: null pointer');
      }

      final bytes = Uint8List.fromList(bytesPtr.value.asTypedList(length));
      _freeMemory(bytesPtr.value);

      return bytes;
    } finally {
      calloc.free(bytesPtr);
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// Derive a key using HKDF-SHA3-256
  Uint8List deriveKeyHkdf({
    required Uint8List inputKeyMaterial,
    Uint8List? salt,
    Uint8List? info,
    required int outputKeyLength,
  }) {
    final ikmPtr = calloc<ffi.Uint8>(inputKeyMaterial.length);
    final saltPtr = salt != null ? calloc<ffi.Uint8>(salt.length) : ffi.nullptr.cast<ffi.Uint8>();
    final infoPtr = info != null ? calloc<ffi.Uint8>(info.length) : ffi.nullptr.cast<ffi.Uint8>();
    final outputPtr = calloc<ffi.Pointer<ffi.Uint8>>();
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      // Copy input data
      for (int i = 0; i < inputKeyMaterial.length; i++) {
        ikmPtr[i] = inputKeyMaterial[i];
      }
      if (salt != null) {
        for (int i = 0; i < salt.length; i++) {
          saltPtr[i] = salt[i];
        }
      }
      if (info != null) {
        for (int i = 0; i < info.length; i++) {
          infoPtr[i] = info[i];
        }
      }

      final deriveKey = _lib
          .lookup<ffi.NativeFunction<NativeDeriveKeyHkdf>>('pqcrypto_derive_key_hkdf')
          .asFunction<DartDeriveKeyHkdf>();

      final status = deriveKey(
        ikmPtr,
        inputKeyMaterial.length,
        saltPtr,
        salt?.length ?? 0,
        infoPtr,
        info?.length ?? 0,
        outputKeyLength,
        outputPtr,
        errorPtr,
      );

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw Exception('Failed to derive key: $error');
      }

      if (outputPtr.value == ffi.nullptr) {
        throw Exception('Failed to derive key: null pointer');
      }

      final derivedKey = Uint8List.fromList(outputPtr.value.asTypedList(outputKeyLength));
      _freeMemory(outputPtr.value);

      return derivedKey;
    } finally {
      calloc.free(ikmPtr);
      if (salt != null) calloc.free(saltPtr);
      if (info != null) calloc.free(infoPtr);
      calloc.free(outputPtr);
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// Get version and algorithm information
  String getVersion() {
    final versionPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      final getVersion = _lib
          .lookup<ffi.NativeFunction<NativeGetVersion>>('pqcrypto_get_version')
          .asFunction<DartGetVersion>();

      final status = getVersion(versionPtr);

      if (status != statusOk) {
        throw Exception('Failed to get version');
      }

      if (versionPtr.value != ffi.nullptr) {
        final version = versionPtr.value.cast<Utf8>().toDartString();
        _freeString(versionPtr.value);
        return version;
      }
      return '{}';
    } finally {
      calloc.free(versionPtr);
    }
  }

  String _getError(ffi.Pointer<ffi.Pointer<ffi.Char>> errorPtr) {
    if (errorPtr.value != ffi.nullptr) {
      final error = errorPtr.value.cast<Utf8>().toDartString();
      return error;
    }
    return 'Unknown error';
  }

  void _freeErrorPtr(ffi.Pointer<ffi.Pointer<ffi.Char>> errorPtr) {
    if (errorPtr.value != ffi.nullptr) {
      _freeString(errorPtr.value);
    }
  }
}
