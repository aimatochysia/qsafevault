// Edition module: Product mode definitions and cryptographic policy enforcement
// This module defines the security boundary for Consumer vs Enterprise editions

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

/// Global edition configuration - set once at initialization, immutable thereafter
static EDITION: OnceLock<Edition> = OnceLock::new();
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Product edition - selected at build time or initialization
/// This is immutable for the lifetime of the process
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum Edition {
    /// Consumer Grade: Post-quantum first, flexibility allowed
    /// - May use post-quantum algorithms (ML-KEM 768, Dilithium3)
    /// - May use TPM / Secure Enclave
    /// - May allow SoftHSM (explicitly non-production)
    Consumer = 0,

    /// Enterprise Grade: FIPS-only, production-grade
    /// - MUST use ONLY FIPS-approved cryptographic algorithms
    /// - ALL non-FIPS algorithms are STRICTLY PROHIBITED
    /// - Post-quantum algorithms are DISABLED until FIPS-approved
    /// - External HSM REQUIRED
    /// - SoftHSM MUST be rejected
    Enterprise = 1,
}

/// Cryptographic policy derived from Edition
/// This determines which algorithms and key providers are permitted
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoPolicy {
    /// Post-quantum algorithms allowed (Consumer mode)
    /// Permits: ML-KEM 768, Dilithium3, X25519, AES-256-GCM, HKDF-SHA3, Argon2id
    PQAllowed,

    /// FIPS-only mode (Enterprise mode)
    /// Permits ONLY: AES-256-GCM, SHA-256/384, HKDF (FIPS hash), RSA, ECDH/ECDSA (FIPS validated)
    /// PROHIBITS: ML-KEM, Dilithium, X25519, SHA3, Argon2id (unless policy explicitly permits)
    FipsOnly,
}

/// Key provider type for edition-specific key management
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProviderType {
    /// Local software-based key generation (Consumer only)
    LocalSoftware,
    /// TPM-backed key storage
    TPM,
    /// Secure Enclave (iOS/macOS)
    SecureEnclave,
    /// Android StrongBox
    StrongBox,
    /// SoftHSM (Consumer only, development/testing)
    SoftHSM,
    /// External Hardware Security Module (required for Enterprise)
    ExternalHSM,
}

/// Algorithm identifier with FIPS compliance information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    // FIPS-approved algorithms (Classical)
    Aes256Gcm,
    Sha256,
    Sha384,
    HkdfSha256,
    Pbkdf2HmacSha256,
    EcdsaP256,
    EcdsaP384,
    RsaOaep,
    EcdhP256,
    EcdhP384,

    // FIPS-approved Post-Quantum algorithms (FIPS 203, 204, 205)
    MlKem1024,      // FIPS 203: ML-KEM-1024
    MlDsa65,        // FIPS 204: ML-DSA-65
    SlhDsaSha2128s, // FIPS 205: SLH-DSA-SHA2-128s

    // Legacy/Deprecated (kept for compatibility, not FIPS)
    MlKem768,       // Deprecated: Use MlKem1024 instead
    Dilithium3,     // Deprecated: Use MlDsa65 instead
    
    // Non-FIPS algorithms (Consumer only when hybrid mode needed)
    X25519,
    Sha3_256,
    HkdfSha3_256,
    Argon2id,
}

impl Algorithm {
    /// Check if this algorithm is FIPS-approved
    /// Now includes FIPS 203/204/205 post-quantum algorithms
    pub fn is_fips_approved(&self) -> bool {
        matches!(
            self,
            // Classical FIPS algorithms
            Algorithm::Aes256Gcm
                | Algorithm::Sha256
                | Algorithm::Sha384
                | Algorithm::HkdfSha256
                | Algorithm::Pbkdf2HmacSha256
                | Algorithm::EcdsaP256
                | Algorithm::EcdsaP384
                | Algorithm::RsaOaep
                | Algorithm::EcdhP256
                | Algorithm::EcdhP384
                // FIPS 203/204/205 Post-Quantum algorithms
                | Algorithm::MlKem1024
                | Algorithm::MlDsa65
                | Algorithm::SlhDsaSha2128s
        )
    }

    /// Check if this algorithm is post-quantum
    pub fn is_post_quantum(&self) -> bool {
        matches!(
            self, 
            Algorithm::MlKem1024 
                | Algorithm::MlDsa65 
                | Algorithm::SlhDsaSha2128s
                | Algorithm::MlKem768  // Legacy
                | Algorithm::Dilithium3  // Legacy
        )
    }
    
    /// Check if this algorithm is FIPS-certified post-quantum (FIPS 203/204/205)
    pub fn is_fips_post_quantum(&self) -> bool {
        matches!(
            self,
            Algorithm::MlKem1024 | Algorithm::MlDsa65 | Algorithm::SlhDsaSha2128s
        )
    }
    
    /// Check if this algorithm is deprecated
    pub fn is_deprecated(&self) -> bool {
        matches!(self, Algorithm::MlKem768 | Algorithm::Dilithium3)
    }
}

/// Errors related to edition and policy violations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditionError {
    /// Edition already initialized
    AlreadyInitialized,
    /// Edition not yet initialized
    NotInitialized,
    /// Non-FIPS algorithm requested in Enterprise mode
    NonFipsAlgorithmProhibited(Algorithm),
    /// SoftHSM not allowed in Enterprise mode
    SoftHsmProhibited,
    /// Local key generation not allowed in Enterprise mode
    LocalKeyGenerationProhibited,
    /// External HSM required but not available
    ExternalHsmRequired,
    /// HSM is not FIPS-validated
    HsmNotFipsValidated,
    /// Post-quantum algorithms disabled in Enterprise mode (legacy error, kept for compatibility)
    PostQuantumDisabled,
    /// Deprecated algorithm used - upgrade to FIPS-certified version
    DeprecatedAlgorithm(Algorithm),
    /// Server edition mismatch (Enterprise client to Consumer server)
    ServerEditionMismatch { client: Edition, server: Edition },
    /// Server does not support required Enterprise features
    ServerMissingEnterpriseFeatures(String),
    /// Configuration error
    ConfigurationError(String),
}

impl std::fmt::Display for EditionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EditionError::AlreadyInitialized => {
                write!(f, "Edition already initialized - edition is immutable")
            }
            EditionError::NotInitialized => {
                write!(f, "Edition not initialized - call initialize_edition first")
            }
            EditionError::NonFipsAlgorithmProhibited(alg) => {
                write!(f, "FIPS VIOLATION: Algorithm {:?} is not FIPS-approved and is prohibited in Enterprise mode", alg)
            }
            EditionError::SoftHsmProhibited => {
                write!(f, "ENTERPRISE: SoftHSM is not permitted in Enterprise mode - external HSM required")
            }
            EditionError::LocalKeyGenerationProhibited => {
                write!(f, "ENTERPRISE: Local key generation is not permitted - keys must be generated in external HSM")
            }
            EditionError::ExternalHsmRequired => {
                write!(f, "ENTERPRISE: External HSM is required but not available")
            }
            EditionError::HsmNotFipsValidated => {
                write!(f, "ENTERPRISE: HSM is not FIPS-validated")
            }
            EditionError::PostQuantumDisabled => {
                // Legacy error - kept for backward compatibility with older clients
                write!(f, "LEGACY ERROR: Post-quantum was previously disabled. This error is deprecated - FIPS 203/204/205 algorithms are now available.")
            }
            EditionError::DeprecatedAlgorithm(alg) => {
                write!(f, "DEPRECATED: Algorithm {:?} is deprecated. Use FIPS-certified alternatives: ML-KEM-1024 (FIPS 203), ML-DSA-65 (FIPS 204), SLH-DSA (FIPS 205)", alg)
            }
            EditionError::ServerEditionMismatch { client, server } => {
                write!(f, "ENTERPRISE: Edition mismatch - {:?} client cannot connect to {:?} server", client, server)
            }
            EditionError::ServerMissingEnterpriseFeatures(features) => {
                write!(f, "ENTERPRISE: Server missing required features: {}", features)
            }
            EditionError::ConfigurationError(msg) => {
                write!(f, "Configuration error: {}", msg)
            }
        }
    }
}

impl Edition {
    /// Get the cryptographic policy for this edition
    pub fn crypto_policy(&self) -> CryptoPolicy {
        match self {
            Edition::Consumer => CryptoPolicy::PQAllowed,
            Edition::Enterprise => CryptoPolicy::FipsOnly,
        }
    }

    /// Check if an algorithm is permitted for this edition
    pub fn is_algorithm_permitted(&self, algorithm: Algorithm) -> Result<(), EditionError> {
        // Check for deprecated algorithms
        if algorithm.is_deprecated() {
            return Err(EditionError::DeprecatedAlgorithm(algorithm));
        }
        
        match self.crypto_policy() {
            CryptoPolicy::PQAllowed => Ok(()),
            CryptoPolicy::FipsOnly => {
                if algorithm.is_fips_approved() {
                    Ok(())
                } else {
                    Err(EditionError::NonFipsAlgorithmProhibited(algorithm))
                }
            }
        }
    }

    /// Check if a key provider is permitted for this edition
    pub fn is_key_provider_permitted(&self, provider: KeyProviderType) -> Result<(), EditionError> {
        match self {
            Edition::Consumer => Ok(()), // All providers allowed in Consumer mode
            Edition::Enterprise => match provider {
                KeyProviderType::ExternalHSM => Ok(()),
                KeyProviderType::TPM => Ok(()), // Allowed for device binding/attestation
                KeyProviderType::SecureEnclave | KeyProviderType::StrongBox => {
                    // Platform secure elements allowed for device binding
                    Ok(())
                }
                KeyProviderType::SoftHSM => Err(EditionError::SoftHsmProhibited),
                KeyProviderType::LocalSoftware => Err(EditionError::LocalKeyGenerationProhibited),
            },
        }
    }

    /// Check if local root key generation is permitted
    pub fn is_local_root_key_generation_permitted(&self) -> Result<(), EditionError> {
        match self {
            Edition::Consumer => Ok(()),
            Edition::Enterprise => Err(EditionError::LocalKeyGenerationProhibited),
        }
    }

    /// Verify server edition compatibility
    pub fn verify_server_edition(&self, server_edition: Edition) -> Result<(), EditionError> {
        match (self, server_edition) {
            // Enterprise client requires Enterprise server
            (Edition::Enterprise, Edition::Consumer) => Err(EditionError::ServerEditionMismatch {
                client: *self,
                server: server_edition,
            }),
            // All other combinations are acceptable
            _ => Ok(()),
        }
    }
}

/// Initialize the global edition configuration
/// This MUST be called once at startup and cannot be changed thereafter
pub fn initialize_edition(edition: Edition) -> Result<(), EditionError> {
    if INITIALIZED.load(Ordering::SeqCst) {
        return Err(EditionError::AlreadyInitialized);
    }

    EDITION
        .set(edition)
        .map_err(|_| EditionError::AlreadyInitialized)?;
    INITIALIZED.store(true, Ordering::SeqCst);

    log::info!("=================================================");
    log::info!("QSafeVault Crypto Engine initialized");
    log::info!("Edition: {:?}", edition);
    log::info!("Crypto Policy: {:?}", edition.crypto_policy());
    log::info!("=================================================");

    if edition == Edition::Enterprise {
        log::warn!("ENTERPRISE MODE: FIPS-only cryptography enforced");
        log::warn!("ENTERPRISE MODE: Post-quantum algorithms DISABLED");
        log::warn!("ENTERPRISE MODE: External HSM REQUIRED for root keys");
        log::warn!("ENTERPRISE MODE: SoftHSM is PROHIBITED");
    }

    Ok(())
}

/// Get the current edition
/// Returns an error if the edition has not been initialized
pub fn get_edition() -> Result<Edition, EditionError> {
    EDITION.get().copied().ok_or(EditionError::NotInitialized)
}

/// Get the current crypto policy
/// Returns an error if the edition has not been initialized
pub fn get_crypto_policy() -> Result<CryptoPolicy, EditionError> {
    get_edition().map(|e| e.crypto_policy())
}

/// Check if the edition has been initialized
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::SeqCst)
}

/// Enforce algorithm policy for the current edition
/// Returns an error if the algorithm is not permitted
pub fn enforce_algorithm(algorithm: Algorithm) -> Result<(), EditionError> {
    get_edition()?.is_algorithm_permitted(algorithm)
}

/// Enforce key provider policy for the current edition
/// Returns an error if the key provider is not permitted
pub fn enforce_key_provider(provider: KeyProviderType) -> Result<(), EditionError> {
    get_edition()?.is_key_provider_permitted(provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests need to run in separate processes because Edition is global
    // For unit testing, we test the Edition methods directly without global state

    #[test]
    fn test_consumer_edition_allows_fips_pq_algorithms() {
        let edition = Edition::Consumer;
        // FIPS 203/204/205 algorithms allowed
        assert!(edition.is_algorithm_permitted(Algorithm::MlKem1024).is_ok());
        assert!(edition.is_algorithm_permitted(Algorithm::MlDsa65).is_ok());
        assert!(edition.is_algorithm_permitted(Algorithm::SlhDsaSha2128s).is_ok());
        // Classical FIPS algorithms allowed
        assert!(edition.is_algorithm_permitted(Algorithm::Aes256Gcm).is_ok());
        assert!(edition.is_algorithm_permitted(Algorithm::Sha256).is_ok());
        // Non-FIPS algorithms allowed in Consumer mode
        assert!(edition.is_algorithm_permitted(Algorithm::Sha3_256).is_ok());
        assert!(edition.is_algorithm_permitted(Algorithm::Argon2id).is_ok());
    }
    
    #[test]
    fn test_consumer_edition_rejects_deprecated_algorithms() {
        let edition = Edition::Consumer;
        // Deprecated PQ algorithms should be rejected even in Consumer mode
        assert!(matches!(
            edition.is_algorithm_permitted(Algorithm::MlKem768),
            Err(EditionError::DeprecatedAlgorithm(_))
        ));
        assert!(matches!(
            edition.is_algorithm_permitted(Algorithm::Dilithium3),
            Err(EditionError::DeprecatedAlgorithm(_))
        ));
    }

    #[test]
    fn test_enterprise_edition_allows_fips_pq() {
        let edition = Edition::Enterprise;

        // FIPS 203/204/205 Post-Quantum algorithms should be allowed in Enterprise mode
        assert!(edition.is_algorithm_permitted(Algorithm::MlKem1024).is_ok());
        assert!(edition.is_algorithm_permitted(Algorithm::MlDsa65).is_ok());
        assert!(edition.is_algorithm_permitted(Algorithm::SlhDsaSha2128s).is_ok());
        
        // Classical FIPS algorithms should be allowed
        assert!(edition.is_algorithm_permitted(Algorithm::Aes256Gcm).is_ok());
        assert!(edition.is_algorithm_permitted(Algorithm::Sha256).is_ok());
        assert!(edition.is_algorithm_permitted(Algorithm::HkdfSha256).is_ok());
    }
    
    #[test]
    fn test_enterprise_edition_prohibits_non_fips() {
        let edition = Edition::Enterprise;

        // Non-FIPS algorithms should be prohibited
        assert!(edition.is_algorithm_permitted(Algorithm::Sha3_256).is_err());
        assert!(edition.is_algorithm_permitted(Algorithm::X25519).is_err());
        assert!(edition.is_algorithm_permitted(Algorithm::Argon2id).is_err());
    }
    
    #[test]
    fn test_enterprise_edition_rejects_deprecated_algorithms() {
        let edition = Edition::Enterprise;
        // Deprecated algorithms should be rejected
        assert!(matches!(
            edition.is_algorithm_permitted(Algorithm::MlKem768),
            Err(EditionError::DeprecatedAlgorithm(_))
        ));
        assert!(matches!(
            edition.is_algorithm_permitted(Algorithm::Dilithium3),
            Err(EditionError::DeprecatedAlgorithm(_))
        ));
    }

    #[test]
    fn test_consumer_edition_allows_all_key_providers() {
        let edition = Edition::Consumer;
        assert!(edition.is_key_provider_permitted(KeyProviderType::LocalSoftware).is_ok());
        assert!(edition.is_key_provider_permitted(KeyProviderType::SoftHSM).is_ok());
        assert!(edition.is_key_provider_permitted(KeyProviderType::TPM).is_ok());
        assert!(edition.is_key_provider_permitted(KeyProviderType::ExternalHSM).is_ok());
    }

    #[test]
    fn test_enterprise_edition_prohibits_softhsm() {
        let edition = Edition::Enterprise;
        assert!(matches!(
            edition.is_key_provider_permitted(KeyProviderType::SoftHSM),
            Err(EditionError::SoftHsmProhibited)
        ));
    }

    #[test]
    fn test_enterprise_edition_prohibits_local_key_generation() {
        let edition = Edition::Enterprise;
        assert!(matches!(
            edition.is_key_provider_permitted(KeyProviderType::LocalSoftware),
            Err(EditionError::LocalKeyGenerationProhibited)
        ));
    }

    #[test]
    fn test_enterprise_edition_allows_external_hsm() {
        let edition = Edition::Enterprise;
        assert!(edition.is_key_provider_permitted(KeyProviderType::ExternalHSM).is_ok());
    }

    #[test]
    fn test_enterprise_client_rejects_consumer_server() {
        let client = Edition::Enterprise;
        let server = Edition::Consumer;
        assert!(matches!(
            client.verify_server_edition(server),
            Err(EditionError::ServerEditionMismatch { .. })
        ));
    }

    #[test]
    fn test_consumer_client_accepts_any_server() {
        let client = Edition::Consumer;
        assert!(client.verify_server_edition(Edition::Consumer).is_ok());
        assert!(client.verify_server_edition(Edition::Enterprise).is_ok());
    }

    #[test]
    fn test_algorithm_fips_classification() {
        // FIPS approved (Classical)
        assert!(Algorithm::Aes256Gcm.is_fips_approved());
        assert!(Algorithm::Sha256.is_fips_approved());
        assert!(Algorithm::Sha384.is_fips_approved());
        assert!(Algorithm::HkdfSha256.is_fips_approved());
        assert!(Algorithm::Pbkdf2HmacSha256.is_fips_approved());
        
        // FIPS approved (Post-Quantum - FIPS 203/204/205)
        assert!(Algorithm::MlKem1024.is_fips_approved());
        assert!(Algorithm::MlDsa65.is_fips_approved());
        assert!(Algorithm::SlhDsaSha2128s.is_fips_approved());

        // Not FIPS approved (deprecated)
        assert!(!Algorithm::MlKem768.is_fips_approved());
        assert!(!Algorithm::Dilithium3.is_fips_approved());
        
        // Not FIPS approved (non-PQ)
        assert!(!Algorithm::X25519.is_fips_approved());
        assert!(!Algorithm::Sha3_256.is_fips_approved());
        assert!(!Algorithm::Argon2id.is_fips_approved());
    }

    #[test]
    fn test_algorithm_post_quantum_classification() {
        // FIPS-certified PQ
        assert!(Algorithm::MlKem1024.is_post_quantum());
        assert!(Algorithm::MlDsa65.is_post_quantum());
        assert!(Algorithm::SlhDsaSha2128s.is_post_quantum());
        
        // Legacy PQ (deprecated)
        assert!(Algorithm::MlKem768.is_post_quantum());
        assert!(Algorithm::Dilithium3.is_post_quantum());
        
        // Not PQ
        assert!(!Algorithm::Aes256Gcm.is_post_quantum());
        assert!(!Algorithm::X25519.is_post_quantum());
    }
    
    #[test]
    fn test_algorithm_fips_post_quantum() {
        // Only FIPS 203/204/205 algorithms
        assert!(Algorithm::MlKem1024.is_fips_post_quantum());
        assert!(Algorithm::MlDsa65.is_fips_post_quantum());
        assert!(Algorithm::SlhDsaSha2128s.is_fips_post_quantum());
        
        // Deprecated PQ are not FIPS PQ
        assert!(!Algorithm::MlKem768.is_fips_post_quantum());
        assert!(!Algorithm::Dilithium3.is_fips_post_quantum());
        
        // Classical are not PQ
        assert!(!Algorithm::Aes256Gcm.is_fips_post_quantum());
    }
    
    #[test]
    fn test_algorithm_deprecated() {
        assert!(Algorithm::MlKem768.is_deprecated());
        assert!(Algorithm::Dilithium3.is_deprecated());
        
        // New algorithms are not deprecated
        assert!(!Algorithm::MlKem1024.is_deprecated());
        assert!(!Algorithm::MlDsa65.is_deprecated());
        assert!(!Algorithm::SlhDsaSha2128s.is_deprecated());
    }

    #[test]
    fn test_crypto_policy_mapping() {
        assert_eq!(Edition::Consumer.crypto_policy(), CryptoPolicy::PQAllowed);
        assert_eq!(Edition::Enterprise.crypto_policy(), CryptoPolicy::FipsOnly);
    }
}
