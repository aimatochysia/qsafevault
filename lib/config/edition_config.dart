/// Edition configuration for QSafeVault
/// 
/// The Edition determines the cryptographic policy and key provider requirements.
/// This is set at build time (via --dart-define) or initialization and is
/// immutable for the lifetime of the process.
/// 
/// SECURITY NOTE: Flutter is NOT a security boundary.
/// The Rust FFI layer is the enforcement boundary.
/// All edition policy enforcement happens in Rust.

/// Product edition values
enum Edition {
  /// Consumer Grade: Post-quantum first, flexibility allowed
  /// - May use post-quantum algorithms (ML-KEM 768, Dilithium3)
  /// - May use TPM / Secure Enclave
  /// - May allow SoftHSM (explicitly non-production)
  consumer,

  /// Enterprise Grade: FIPS-only, production-grade
  /// - MUST use ONLY FIPS-approved cryptographic algorithms
  /// - ALL non-FIPS algorithms are STRICTLY PROHIBITED
  /// - Post-quantum algorithms are DISABLED until FIPS-approved
  /// - External HSM REQUIRED for root key operations
  /// - SoftHSM is PROHIBITED
  enterprise,
}

/// Edition configuration derived from build-time settings
class EditionConfig {
  /// The current edition
  final Edition edition;

  /// Whether this is Enterprise mode
  bool get isEnterprise => edition == Edition.enterprise;

  /// Whether this is Consumer mode
  bool get isConsumer => edition == Edition.consumer;

  /// Human-readable edition name
  String get editionName {
    switch (edition) {
      case Edition.consumer:
        return 'Consumer';
      case Edition.enterprise:
        return 'Enterprise';
    }
  }

  /// Description of the edition
  String get description {
    switch (edition) {
      case Edition.consumer:
        return 'Post-quantum cryptography enabled. Flexible key providers.';
      case Edition.enterprise:
        return 'FIPS-only cryptography. External HSM required.';
    }
  }

  const EditionConfig({required this.edition});

  /// Get edition from build-time configuration
  /// Use: flutter run --dart-define=QSAFEVAULT_EDITION=enterprise
  factory EditionConfig.fromEnvironment() {
    const editionStr = String.fromEnvironment(
      'QSAFEVAULT_EDITION',
      defaultValue: 'consumer',
    );

    final edition = editionStr.toLowerCase() == 'enterprise'
        ? Edition.enterprise
        : Edition.consumer;

    return EditionConfig(edition: edition);
  }

  /// Get FFI edition value (matches Rust enum)
  /// Consumer = 0, Enterprise = 1
  int get ffiValue {
    switch (edition) {
      case Edition.consumer:
        return 0;
      case Edition.enterprise:
        return 1;
    }
  }

  /// Create from FFI value
  factory EditionConfig.fromFfiValue(int value) {
    final edition = value == 1 ? Edition.enterprise : Edition.consumer;
    return EditionConfig(edition: edition);
  }

  @override
  String toString() => 'EditionConfig(edition: $editionName)';
}

/// Global edition configuration
/// Initialized once at app startup
class GlobalEdition {
  static EditionConfig? _config;

  /// Initialize the global edition (call once at startup)
  static void initialize(EditionConfig config) {
    if (_config != null) {
      throw StateError('Edition already initialized');
    }
    _config = config;
  }

  /// Get the current edition configuration
  /// Throws if not initialized
  static EditionConfig get config {
    if (_config == null) {
      throw StateError('Edition not initialized. Call GlobalEdition.initialize() first.');
    }
    return _config!;
  }

  /// Check if edition has been initialized
  static bool get isInitialized => _config != null;

  /// Get edition or default to consumer
  static EditionConfig get configOrDefault {
    return _config ?? const EditionConfig(edition: Edition.consumer);
  }
}

/// Edition-specific error codes from Rust FFI
class EditionStatusCodes {
  static const int ok = 0;
  static const int error = -1;
  static const int invalidParam = -2;
  static const int notFound = -3;
  
  // Edition-specific
  static const int editionNotInitialized = -10;
  static const int editionAlreadyInitialized = -11;
  static const int fipsViolation = -20;
  static const int pqDisabled = -21;
  static const int hsmRequired = -22;
  static const int softHsmProhibited = -23;
  static const int serverEditionMismatch = -30;

  /// Get human-readable error message for status code
  static String getMessage(int statusCode) {
    switch (statusCode) {
      case ok:
        return 'Success';
      case error:
        return 'General error';
      case invalidParam:
        return 'Invalid parameter';
      case notFound:
        return 'Not found';
      case editionNotInitialized:
        return 'Edition not initialized';
      case editionAlreadyInitialized:
        return 'Edition already initialized';
      case fipsViolation:
        return 'FIPS violation: Non-FIPS algorithm prohibited in Enterprise mode';
      case pqDisabled:
        return 'Post-quantum algorithms disabled in Enterprise mode';
      case hsmRequired:
        return 'External HSM required in Enterprise mode';
      case softHsmProhibited:
        return 'SoftHSM prohibited in Enterprise mode';
      case serverEditionMismatch:
        return 'Server edition mismatch';
      default:
        return 'Unknown error: $statusCode';
    }
  }

  /// Check if status code indicates Enterprise mode restriction
  static bool isEnterpriseRestriction(int statusCode) {
    return statusCode == fipsViolation ||
        statusCode == pqDisabled ||
        statusCode == hsmRequired ||
        statusCode == softHsmProhibited;
  }
}

/// Exception for Edition-related errors
class EditionException implements Exception {
  final int statusCode;
  final String message;

  EditionException(this.statusCode, [String? message])
      : message = message ?? EditionStatusCodes.getMessage(statusCode);

  @override
  String toString() => 'EditionException: $message (code: $statusCode)';

  /// Whether this is a fatal error that should stop the application
  bool get isFatal => GlobalEdition.configOrDefault.isEnterprise;
}
