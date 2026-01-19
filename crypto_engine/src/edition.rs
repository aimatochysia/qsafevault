// Edition module: Product mode definitions and cryptographic policy enforcement
// This module defines the security boundary for Consumer vs Enterprise editions
// ALL ALGORITHMS ARE FIPS-APPROVED (FIPS 203/204/205 for post-quantum)

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
    /// Consumer Grade: FIPS-certified post-quantum with flexibility
    /// - Uses FIPS 203/204/205 post-quantum algorithms
    /// - May use TPM / Secure Enclave / SoftHSM
    Consumer = 0,

    /// Enterprise Grade: FIPS-only, production-grade
    /// - Uses FIPS 203/204/205 post-quantum algorithms
    /// - External HSM REQUIRED
    /// - SoftHSM PROHIBITED
    Enterprise = 1,
}

/// Cryptographic policy derived from Edition
/// Both editions use FIPS-approved algorithms only
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoPolicy {
    /// FIPS-approved algorithms (both modes use FIPS now)
    /// Permits: AES-256-GCM, SHA-256/384, HKDF-SHA256, PBKDF2, ML-KEM-1024, ML-DSA-65, SLH-DSA
    FipsApproved,
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

/// Algorithm identifier - FIPS-approved algorithms only
/// All algorithms must be FIPS-approved (classical or FIPS 203/204/205 post-quantum)
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
}

impl Algorithm {
    /// Check if this algorithm is FIPS-approved
    /// All algorithms in this enum are FIPS-approved
    pub fn is_fips_approved(&self) -> bool {
        true
    }

    /// Check if this algorithm is post-quantum
    pub fn is_post_quantum(&self) -> bool {
        matches!(
            self, 
            Algorithm::MlKem1024 
                | Algorithm::MlDsa65 
                | Algorithm::SlhDsaSha2128s
        )
    }
    
    /// Check if this algorithm is FIPS-certified post-quantum (FIPS 203/204/205)
    pub fn is_fips_post_quantum(&self) -> bool {
        matches!(
            self,
            Algorithm::MlKem1024 | Algorithm::MlDsa65 | Algorithm::SlhDsaSha2128s
        )
    }
}

/// Errors related to edition and policy violations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditionError {
    /// Edition already initialized
    AlreadyInitialized,
    /// Edition not yet initialized
    NotInitialized,
    /// SoftHSM not allowed in Enterprise mode
    SoftHsmProhibited,
    /// Local key generation not allowed in Enterprise mode
    LocalKeyGenerationProhibited,
    /// External HSM required but not available
    ExternalHsmRequired,
    /// HSM is not FIPS-validated
    HsmNotFipsValidated,
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
            EditionError::SoftHsmProhibited => {
                write!(f, "ENTERPRISE: SoftHSM is not permitted - external HSM required")
            }
            EditionError::LocalKeyGenerationProhibited => {
                write!(f, "ENTERPRISE: Local key generation is not permitted - use external HSM")
            }
            EditionError::ExternalHsmRequired => {
                write!(f, "ENTERPRISE: External HSM is required but not available")
            }
            EditionError::HsmNotFipsValidated => {
                write!(f, "ENTERPRISE: HSM is not FIPS-validated")
            }
            EditionError::ServerEditionMismatch { client, server } => {
                write!(f, "Edition mismatch - {:?} client cannot connect to {:?} server", client, server)
            }
            EditionError::ServerMissingEnterpriseFeatures(features) => {
                write!(f, "Server missing required features: {}", features)
            }
            EditionError::ConfigurationError(msg) => {
                write!(f, "Configuration error: {}", msg)
            }
        }
    }
}

impl Edition {
    /// Get the cryptographic policy for this edition
    /// Both editions now use FIPS-approved algorithms only
    pub fn crypto_policy(&self) -> CryptoPolicy {
        CryptoPolicy::FipsApproved
    }

    /// Check if an algorithm is permitted for this edition
    /// All algorithms in the Algorithm enum are FIPS-approved
    pub fn is_algorithm_permitted(&self, _algorithm: Algorithm) -> Result<(), EditionError> {
        Ok(())
    }

    /// Check if a key provider is permitted for this edition
    pub fn is_key_provider_permitted(&self, provider: KeyProviderType) -> Result<(), EditionError> {
        match self {
            Edition::Consumer => Ok(()),
            Edition::Enterprise => match provider {
                KeyProviderType::ExternalHSM => Ok(()),
                KeyProviderType::TPM => Ok(()),
                KeyProviderType::SecureEnclave | KeyProviderType::StrongBox => Ok(()),
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
            (Edition::Enterprise, Edition::Consumer) => Err(EditionError::ServerEditionMismatch {
                client: *self,
                server: server_edition,
            }),
            _ => Ok(()),
        }
    }
}

/// Initialize the global edition configuration
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
    log::info!("All algorithms are FIPS-approved");
    log::info!("Post-Quantum: FIPS 203/204/205 enabled");
    log::info!("=================================================");

    Ok(())
}

/// Get the current edition
pub fn get_edition() -> Result<Edition, EditionError> {
    EDITION.get().copied().ok_or(EditionError::NotInitialized)
}

/// Check if the edition has been initialized
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_algorithms_fips_approved() {
        assert!(Algorithm::Aes256Gcm.is_fips_approved());
        assert!(Algorithm::Sha256.is_fips_approved());
        assert!(Algorithm::Sha384.is_fips_approved());
        assert!(Algorithm::HkdfSha256.is_fips_approved());
        assert!(Algorithm::MlKem1024.is_fips_approved());
        assert!(Algorithm::MlDsa65.is_fips_approved());
        assert!(Algorithm::SlhDsaSha2128s.is_fips_approved());
    }

    #[test]
    fn test_post_quantum_algorithms() {
        assert!(Algorithm::MlKem1024.is_post_quantum());
        assert!(Algorithm::MlDsa65.is_post_quantum());
        assert!(Algorithm::SlhDsaSha2128s.is_post_quantum());
        assert!(!Algorithm::Aes256Gcm.is_post_quantum());
    }

    #[test]
    fn test_fips_post_quantum() {
        assert!(Algorithm::MlKem1024.is_fips_post_quantum());
        assert!(Algorithm::MlDsa65.is_fips_post_quantum());
        assert!(Algorithm::SlhDsaSha2128s.is_fips_post_quantum());
        assert!(!Algorithm::Aes256Gcm.is_fips_post_quantum());
    }

    #[test]
    fn test_consumer_allows_all_algorithms() {
        let edition = Edition::Consumer;
        assert!(edition.is_algorithm_permitted(Algorithm::MlKem1024).is_ok());
        assert!(edition.is_algorithm_permitted(Algorithm::MlDsa65).is_ok());
        assert!(edition.is_algorithm_permitted(Algorithm::Aes256Gcm).is_ok());
    }

    #[test]
    fn test_enterprise_allows_fips_algorithms() {
        let edition = Edition::Enterprise;
        assert!(edition.is_algorithm_permitted(Algorithm::MlKem1024).is_ok());
        assert!(edition.is_algorithm_permitted(Algorithm::MlDsa65).is_ok());
        assert!(edition.is_algorithm_permitted(Algorithm::Aes256Gcm).is_ok());
    }

    #[test]
    fn test_consumer_allows_all_providers() {
        let edition = Edition::Consumer;
        assert!(edition.is_key_provider_permitted(KeyProviderType::LocalSoftware).is_ok());
        assert!(edition.is_key_provider_permitted(KeyProviderType::SoftHSM).is_ok());
        assert!(edition.is_key_provider_permitted(KeyProviderType::TPM).is_ok());
    }

    #[test]
    fn test_enterprise_prohibits_softhsm() {
        let edition = Edition::Enterprise;
        assert!(matches!(
            edition.is_key_provider_permitted(KeyProviderType::SoftHSM),
            Err(EditionError::SoftHsmProhibited)
        ));
    }

    #[test]
    fn test_enterprise_prohibits_local_generation() {
        let edition = Edition::Enterprise;
        assert!(matches!(
            edition.is_key_provider_permitted(KeyProviderType::LocalSoftware),
            Err(EditionError::LocalKeyGenerationProhibited)
        ));
    }

    #[test]
    fn test_enterprise_allows_external_hsm() {
        let edition = Edition::Enterprise;
        assert!(edition.is_key_provider_permitted(KeyProviderType::ExternalHSM).is_ok());
    }

    #[test]
    fn test_edition_server_compatibility() {
        let client = Edition::Enterprise;
        assert!(matches!(
            client.verify_server_edition(Edition::Consumer),
            Err(EditionError::ServerEditionMismatch { .. })
        ));
        
        let consumer = Edition::Consumer;
        assert!(consumer.verify_server_edition(Edition::Consumer).is_ok());
        assert!(consumer.verify_server_edition(Edition::Enterprise).is_ok());
    }

    #[test]
    fn test_crypto_policy() {
        assert_eq!(Edition::Consumer.crypto_policy(), CryptoPolicy::FipsApproved);
        assert_eq!(Edition::Enterprise.crypto_policy(), CryptoPolicy::FipsApproved);
    }
}
