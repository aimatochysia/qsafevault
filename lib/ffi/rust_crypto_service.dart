import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'crypto_bindings.dart';
import '../config/edition_config.dart';

/// Rust FFI Crypto Service
/// All cryptographic operations go through the Rust backend
/// 
/// EDITION SYSTEM:
/// Edition MUST be initialized before any cryptographic operations.
/// Use initializeEdition() before calling any other methods.
/// Enterprise mode enforces FIPS-only algorithms and requires external HSM.
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
  
  // Edition functions
  late final DartInitializeEdition _initializeEdition;
  late final DartGetEdition _getEdition;
  late final DartIsEditionInitialized _isEditionInitialized;
  late final DartGetEditionInfo _getEditionInfo;
  late final DartVerifyAlgorithmPermitted _verifyAlgorithmPermitted;
  late final DartVerifyServerEdition _verifyServerEdition;

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
    
    // Initialize edition functions
    _initializeEdition = _lib
        .lookup<ffi.NativeFunction<NativeInitializeEdition>>('pqcrypto_initialize_edition')
        .asFunction();
    
    _getEdition = _lib
        .lookup<ffi.NativeFunction<NativeGetEdition>>('pqcrypto_get_edition')
        .asFunction();
    
    _isEditionInitialized = _lib
        .lookup<ffi.NativeFunction<NativeIsEditionInitialized>>('pqcrypto_is_edition_initialized')
        .asFunction();
    
    _getEditionInfo = _lib
        .lookup<ffi.NativeFunction<NativeGetEditionInfo>>('pqcrypto_get_edition_info')
        .asFunction();
    
    _verifyAlgorithmPermitted = _lib
        .lookup<ffi.NativeFunction<NativeVerifyAlgorithmPermitted>>('pqcrypto_verify_algorithm_permitted')
        .asFunction();
    
    _verifyServerEdition = _lib
        .lookup<ffi.NativeFunction<NativeVerifyServerEdition>>('pqcrypto_verify_server_edition')
        .asFunction();
  }

  // ==========================================================================
  // Edition System Methods
  // ==========================================================================

  /// Initialize the edition in the Rust crypto engine
  /// This MUST be called before any cryptographic operations
  /// 
  /// Edition values: 0 = Consumer, 1 = Enterprise
  /// 
  /// Throws [EditionException] if initialization fails
  void initializeEdition(EditionConfig config) {
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      final status = _initializeEdition(config.ffiValue, errorPtr);

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw EditionException(status, error);
      }
      
      // Also initialize the Dart-side global edition
      if (!GlobalEdition.isInitialized) {
        GlobalEdition.initialize(config);
      }
    } finally {
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// Get the current edition from the Rust crypto engine
  /// Returns the EditionConfig
  EditionConfig getEdition() {
    final editionPtr = calloc<ffi.Int32>();
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      final status = _getEdition(editionPtr, errorPtr);

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw EditionException(status, error);
      }

      return EditionConfig.fromFfiValue(editionPtr.value);
    } finally {
      calloc.free(editionPtr);
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// Check if the edition has been initialized in Rust
  bool isEditionInitialized() {
    return _isEditionInitialized() == 1;
  }

  /// Get edition information as JSON string
  /// Returns JSON with: edition, crypto_policy, is_enterprise, pq_allowed, fips_only
  String getEditionInfo() {
    final infoPtr = calloc<ffi.Pointer<ffi.Char>>();
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      final status = _getEditionInfo(infoPtr, errorPtr);

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw EditionException(status, error);
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

  /// Verify that an algorithm is permitted under current edition policy
  /// 
  /// Algorithm IDs:
  ///   FIPS: 0=AES256GCM, 1=SHA256, 2=SHA384, 3=HKDF_SHA256, 4=PBKDF2_HMAC_SHA256
  ///   Non-FIPS: 10=ML_KEM_768, 11=DILITHIUM3, 12=X25519, 13=SHA3_256, 14=HKDF_SHA3_256, 15=ARGON2ID
  /// 
  /// Throws [EditionException] if algorithm is not permitted
  void verifyAlgorithmPermitted(int algorithmId) {
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      final status = _verifyAlgorithmPermitted(algorithmId, errorPtr);

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw EditionException(status, error);
      }
    } finally {
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// Verify server edition compatibility
  /// Enterprise clients cannot connect to Consumer servers
  /// 
  /// Throws [EditionException] if editions are incompatible
  void verifyServerEdition(EditionConfig clientEdition, EditionConfig serverEdition) {
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      final status = _verifyServerEdition(
        clientEdition.ffiValue,
        serverEdition.ffiValue,
        errorPtr,
      );

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw EditionException(status, error);
      }
    } finally {
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  // ==========================================================================
  // Cryptographic Operations
  // ==========================================================================

  /// Generate a new hybrid keypair (PQC + Classical)
  /// 
  /// NOTE: This uses post-quantum algorithms (ML-KEM 768, X25519)
  /// It is PROHIBITED in Enterprise mode and will throw [EditionException]
  /// with status STATUS_PQ_DISABLED
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

  /// Derive a key using SP 800-56C One-Step KDF with SHA-256 (NIST SP 800-56C Rev 2)
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
      // Copy input data using efficient setAll
      ikmPtr.asTypedList(inputKeyMaterial.length).setAll(0, inputKeyMaterial);
      if (salt != null) {
        saltPtr.asTypedList(salt.length).setAll(0, salt);
      }
      if (info != null) {
        infoPtr.asTypedList(info.length).setAll(0, info);
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

  // ==========================================================================
  // FIPS-Compliant Symmetric Cryptography Methods
  // ==========================================================================

  /// AES-256-GCM encryption (FIPS 197)
  /// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
  Uint8List aesGcmEncrypt({
    required Uint8List key,
    required Uint8List plaintext,
    Uint8List? aad,
  }) {
    if (key.length != 32) {
      throw ArgumentError('Key must be 32 bytes');
    }

    final keyPtr = calloc<ffi.Uint8>(32);
    final plaintextPtr = calloc<ffi.Uint8>(plaintext.length);
    final aadPtr = aad != null ? calloc<ffi.Uint8>(aad.length) : ffi.nullptr.cast<ffi.Uint8>();
    final ciphertextPtr = calloc<ffi.Pointer<ffi.Uint8>>();
    final ciphertextLenPtr = calloc<ffi.Size>();
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      keyPtr.asTypedList(32).setAll(0, key);
      plaintextPtr.asTypedList(plaintext.length).setAll(0, plaintext);
      if (aad != null) {
        aadPtr.asTypedList(aad.length).setAll(0, aad);
      }

      final aesGcmEncrypt = _lib
          .lookup<ffi.NativeFunction<NativeAesGcmEncrypt>>('pqcrypto_aes_gcm_encrypt')
          .asFunction<DartAesGcmEncrypt>();

      final status = aesGcmEncrypt(
        keyPtr,
        plaintextPtr,
        plaintext.length,
        aadPtr,
        aad?.length ?? 0,
        ciphertextPtr,
        ciphertextLenPtr,
        errorPtr,
      );

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw Exception('AES-GCM encryption failed: $error');
      }

      if (ciphertextPtr.value == ffi.nullptr) {
        throw Exception('AES-GCM encryption failed: null pointer');
      }

      final ciphertextLen = ciphertextLenPtr.value;
      final ciphertext = Uint8List.fromList(ciphertextPtr.value.asTypedList(ciphertextLen));
      _freeMemory(ciphertextPtr.value);

      return ciphertext;
    } finally {
      calloc.free(keyPtr);
      calloc.free(plaintextPtr);
      if (aad != null) calloc.free(aadPtr);
      calloc.free(ciphertextPtr);
      calloc.free(ciphertextLenPtr);
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// AES-256-GCM decryption (FIPS 197)
  /// Input format: nonce (12 bytes) || ciphertext || tag (16 bytes)
  Uint8List aesGcmDecrypt({
    required Uint8List key,
    required Uint8List ciphertext,
    Uint8List? aad,
  }) {
    if (key.length != 32) {
      throw ArgumentError('Key must be 32 bytes');
    }

    final keyPtr = calloc<ffi.Uint8>(32);
    final ciphertextPtr = calloc<ffi.Uint8>(ciphertext.length);
    final aadPtr = aad != null ? calloc<ffi.Uint8>(aad.length) : ffi.nullptr.cast<ffi.Uint8>();
    final plaintextPtr = calloc<ffi.Pointer<ffi.Uint8>>();
    final plaintextLenPtr = calloc<ffi.Size>();
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      keyPtr.asTypedList(32).setAll(0, key);
      ciphertextPtr.asTypedList(ciphertext.length).setAll(0, ciphertext);
      if (aad != null) {
        aadPtr.asTypedList(aad.length).setAll(0, aad);
      }

      final aesGcmDecrypt = _lib
          .lookup<ffi.NativeFunction<NativeAesGcmDecrypt>>('pqcrypto_aes_gcm_decrypt')
          .asFunction<DartAesGcmDecrypt>();

      final status = aesGcmDecrypt(
        keyPtr,
        ciphertextPtr,
        ciphertext.length,
        aadPtr,
        aad?.length ?? 0,
        plaintextPtr,
        plaintextLenPtr,
        errorPtr,
      );

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw Exception('AES-GCM decryption failed: $error');
      }

      if (plaintextPtr.value == ffi.nullptr) {
        throw Exception('AES-GCM decryption failed: null pointer');
      }

      final plaintextLen = plaintextLenPtr.value;
      final plaintext = Uint8List.fromList(plaintextPtr.value.asTypedList(plaintextLen));
      _freeMemory(plaintextPtr.value);

      return plaintext;
    } finally {
      calloc.free(keyPtr);
      calloc.free(ciphertextPtr);
      if (aad != null) calloc.free(aadPtr);
      calloc.free(plaintextPtr);
      calloc.free(plaintextLenPtr);
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// SHA-256 hash (FIPS 180-4)
  Uint8List sha256(Uint8List data) {
    final dataPtr = calloc<ffi.Uint8>(data.length);
    final hashPtr = calloc<ffi.Pointer<ffi.Uint8>>();
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      dataPtr.asTypedList(data.length).setAll(0, data);

      final sha256Fn = _lib
          .lookup<ffi.NativeFunction<NativeSha256>>('pqcrypto_sha256')
          .asFunction<DartSha256>();

      final status = sha256Fn(dataPtr, data.length, hashPtr, errorPtr);

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw Exception('SHA-256 failed: $error');
      }

      if (hashPtr.value == ffi.nullptr) {
        throw Exception('SHA-256 failed: null pointer');
      }

      final hash = Uint8List.fromList(hashPtr.value.asTypedList(32));
      _freeMemory(hashPtr.value);

      return hash;
    } finally {
      calloc.free(dataPtr);
      calloc.free(hashPtr);
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// HMAC-SHA256 (FIPS 198-1)
  Uint8List hmacSha256({required Uint8List key, required Uint8List data}) {
    final keyPtr = calloc<ffi.Uint8>(key.length);
    final dataPtr = calloc<ffi.Uint8>(data.length);
    final macPtr = calloc<ffi.Pointer<ffi.Uint8>>();
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      keyPtr.asTypedList(key.length).setAll(0, key);
      dataPtr.asTypedList(data.length).setAll(0, data);

      final hmacSha256Fn = _lib
          .lookup<ffi.NativeFunction<NativeHmacSha256>>('pqcrypto_hmac_sha256')
          .asFunction<DartHmacSha256>();

      final status = hmacSha256Fn(keyPtr, key.length, dataPtr, data.length, macPtr, errorPtr);

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw Exception('HMAC-SHA256 failed: $error');
      }

      if (macPtr.value == ffi.nullptr) {
        throw Exception('HMAC-SHA256 failed: null pointer');
      }

      final mac = Uint8List.fromList(macPtr.value.asTypedList(32));
      _freeMemory(macPtr.value);

      return mac;
    } finally {
      calloc.free(keyPtr);
      calloc.free(dataPtr);
      calloc.free(macPtr);
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// HMAC-SHA512 (FIPS 198-1)
  Uint8List hmacSha512({required Uint8List key, required Uint8List data}) {
    final keyPtr = calloc<ffi.Uint8>(key.length);
    final dataPtr = calloc<ffi.Uint8>(data.length);
    final macPtr = calloc<ffi.Pointer<ffi.Uint8>>();
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      keyPtr.asTypedList(key.length).setAll(0, key);
      dataPtr.asTypedList(data.length).setAll(0, data);

      final hmacSha512Fn = _lib
          .lookup<ffi.NativeFunction<NativeHmacSha512>>('pqcrypto_hmac_sha512')
          .asFunction<DartHmacSha512>();

      final status = hmacSha512Fn(keyPtr, key.length, dataPtr, data.length, macPtr, errorPtr);

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw Exception('HMAC-SHA512 failed: $error');
      }

      if (macPtr.value == ffi.nullptr) {
        throw Exception('HMAC-SHA512 failed: null pointer');
      }

      final mac = Uint8List.fromList(macPtr.value.asTypedList(64));
      _freeMemory(macPtr.value);

      return mac;
    } finally {
      calloc.free(keyPtr);
      calloc.free(dataPtr);
      calloc.free(macPtr);
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
    }
  }

  /// PBKDF2-HMAC-SHA256 key derivation (NIST SP 800-132)
  /// Minimum 10000 iterations required for FIPS compliance
  Uint8List pbkdf2Sha256({
    required Uint8List password,
    required Uint8List salt,
    required int iterations,
    required int outputKeyLength,
  }) {
    if (iterations < 10000) {
      throw ArgumentError('Iterations must be at least 10000 for FIPS compliance');
    }

    final passwordPtr = calloc<ffi.Uint8>(password.length);
    final saltPtr = calloc<ffi.Uint8>(salt.length);
    final outputKeyPtr = calloc<ffi.Pointer<ffi.Uint8>>();
    final errorPtr = calloc<ffi.Pointer<ffi.Char>>();

    try {
      passwordPtr.asTypedList(password.length).setAll(0, password);
      saltPtr.asTypedList(salt.length).setAll(0, salt);

      final pbkdf2Fn = _lib
          .lookup<ffi.NativeFunction<NativePbkdf2Sha256>>('pqcrypto_pbkdf2_sha256')
          .asFunction<DartPbkdf2Sha256>();

      final status = pbkdf2Fn(
        passwordPtr,
        password.length,
        saltPtr,
        salt.length,
        iterations,
        outputKeyLength,
        outputKeyPtr,
        errorPtr,
      );

      if (status != statusOk) {
        final error = _getError(errorPtr);
        throw Exception('PBKDF2-SHA256 failed: $error');
      }

      if (outputKeyPtr.value == ffi.nullptr) {
        throw Exception('PBKDF2-SHA256 failed: null pointer');
      }

      final outputKey = Uint8List.fromList(outputKeyPtr.value.asTypedList(outputKeyLength));
      _freeMemory(outputKeyPtr.value);

      return outputKey;
    } finally {
      calloc.free(passwordPtr);
      calloc.free(saltPtr);
      calloc.free(outputKeyPtr);
      _freeErrorPtr(errorPtr);
      calloc.free(errorPtr);
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
