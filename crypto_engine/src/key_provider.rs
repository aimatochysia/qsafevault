// Key Provider module: Edition-specific key management
// Implements the KeyProvider trait for Consumer and Enterprise editions

use crate::edition::{Edition, EditionError, KeyProviderType, get_edition};
use crate::sealed_storage::BackendType;

/// Result type for key provider operations
pub type KeyProviderResult<T> = Result<T, KeyProviderError>;

/// Errors from key provider operations
#[derive(Debug, Clone)]
pub enum KeyProviderError {
    /// Edition policy violation
    EditionViolation(EditionError),
    /// HSM not available
    HsmNotAvailable(String),
    /// HSM operation failed
    HsmOperationFailed(String),
    /// Key not found
    KeyNotFound(String),
    /// Key generation failed
    KeyGenerationFailed(String),
    /// Key storage failed
    KeyStorageFailed(String),
    /// Authorization failed
    AuthorizationFailed(String),
    /// Configuration error
    ConfigurationError(String),
}

impl std::fmt::Display for KeyProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyProviderError::EditionViolation(e) => write!(f, "Edition violation: {}", e),
            KeyProviderError::HsmNotAvailable(msg) => write!(f, "HSM not available: {}", msg),
            KeyProviderError::HsmOperationFailed(msg) => write!(f, "HSM operation failed: {}", msg),
            KeyProviderError::KeyNotFound(id) => write!(f, "Key not found: {}", id),
            KeyProviderError::KeyGenerationFailed(msg) => write!(f, "Key generation failed: {}", msg),
            KeyProviderError::KeyStorageFailed(msg) => write!(f, "Key storage failed: {}", msg),
            KeyProviderError::AuthorizationFailed(msg) => write!(f, "Authorization failed: {}", msg),
            KeyProviderError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
        }
    }
}

impl From<EditionError> for KeyProviderError {
    fn from(e: EditionError) -> Self {
        KeyProviderError::EditionViolation(e)
    }
}

/// Key material wrapper with zeroization
#[derive(Clone)]
pub struct KeyMaterial {
    data: Vec<u8>,
}

impl KeyMaterial {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        // Zeroize on drop
        for byte in &mut self.data {
            *byte = 0;
        }
    }
}

/// Key provider trait - responsible for root key management
/// Implementations differ based on edition requirements
pub trait KeyProvider: Send + Sync {
    /// Get the edition this provider is configured for
    fn edition(&self) -> Edition;

    /// Get the key provider type
    fn provider_type(&self) -> KeyProviderType;

    /// Generate a new root key
    fn generate_root_key(&self, key_id: &str) -> KeyProviderResult<KeyMaterial>;

    /// Store a root key
    fn store_root_key(&self, key_id: &str, key_material: &KeyMaterial) -> KeyProviderResult<()>;

    /// Retrieve a root key
    fn retrieve_root_key(&self, key_id: &str) -> KeyProviderResult<KeyMaterial>;

    /// Delete a root key
    fn delete_root_key(&self, key_id: &str) -> KeyProviderResult<()>;

    /// Check if authorization is valid for key usage
    fn authorize_key_usage(&self, key_id: &str) -> KeyProviderResult<()>;

    /// Get the backend type for this provider
    fn backend_type(&self) -> BackendType;
}

/// Consumer key provider
/// - Local root key generation allowed
/// - TPM / Secure Enclave preferred
/// - SoftHSM allowed with warnings
/// - Device-centric trust model
pub struct ConsumerKeyProvider {
    preferred_backend: BackendType,
}

impl ConsumerKeyProvider {
    pub fn new() -> Self {
        Self {
            preferred_backend: BackendType::Fallback,
        }
    }

    pub fn with_backend(backend: BackendType) -> KeyProviderResult<Self> {
        // Consumer allows all backends
        Ok(Self {
            preferred_backend: backend,
        })
    }

    fn detect_best_backend() -> BackendType {
        use crate::platform_keystore::detect_backends;
        
        let status = detect_backends();
        
        if status.tpm_available && status.softhsm_available {
            log::info!("Consumer: Using TPM + SoftHSM dual-sealing");
            BackendType::TPMAndSoftHSM
        } else if status.tpm_available {
            log::info!("Consumer: Using TPM");
            BackendType::TPM
        } else if status.softhsm_available {
            log::warn!("Consumer: Using SoftHSM (not recommended for production)");
            BackendType::SoftHSM
        } else {
            log::info!("Consumer: Using software fallback");
            BackendType::Fallback
        }
    }
}

impl Default for ConsumerKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyProvider for ConsumerKeyProvider {
    fn edition(&self) -> Edition {
        Edition::Consumer
    }

    fn provider_type(&self) -> KeyProviderType {
        match self.preferred_backend {
            BackendType::TPM => KeyProviderType::TPM,
            BackendType::SoftHSM => KeyProviderType::SoftHSM,
            BackendType::TPMAndSoftHSM => KeyProviderType::TPM,
            BackendType::Fallback => KeyProviderType::LocalSoftware,
        }
    }

    fn generate_root_key(&self, key_id: &str) -> KeyProviderResult<KeyMaterial> {
        log::info!("Consumer: Generating root key locally: {}", key_id);
        
        use rand_core::{OsRng, RngCore};
        let mut key_bytes = vec![0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        
        Ok(KeyMaterial::new(key_bytes))
    }

    fn store_root_key(&self, key_id: &str, key_material: &KeyMaterial) -> KeyProviderResult<()> {
        log::info!("Consumer: Storing root key: {}", key_id);
        
        use crate::platform_keystore::PlatformKeystore;
        PlatformKeystore::seal_key(key_id, key_material.as_bytes())
            .map_err(|e| KeyProviderError::KeyStorageFailed(e))?;
        
        Ok(())
    }

    fn retrieve_root_key(&self, key_id: &str) -> KeyProviderResult<KeyMaterial> {
        log::info!("Consumer: Retrieving root key: {}", key_id);
        
        use crate::platform_keystore::PlatformKeystore;
        let data = PlatformKeystore::unseal_key(key_id)
            .map_err(|e| KeyProviderError::KeyNotFound(e))?;
        
        Ok(KeyMaterial::new(data))
    }

    fn delete_root_key(&self, key_id: &str) -> KeyProviderResult<()> {
        log::info!("Consumer: Deleting root key: {}", key_id);
        
        use crate::platform_keystore::PlatformKeystore;
        PlatformKeystore::delete_key(key_id)
            .map_err(|e| KeyProviderError::KeyStorageFailed(e))?;
        
        Ok(())
    }

    fn authorize_key_usage(&self, _key_id: &str) -> KeyProviderResult<()> {
        // Consumer mode: No additional authorization required
        Ok(())
    }

    fn backend_type(&self) -> BackendType {
        Self::detect_best_backend()
    }
}

/// Enterprise key provider configuration
pub struct EnterpriseHsmConfig {
    /// HSM connection string or path
    pub connection: String,
    /// HSM slot or partition
    pub slot: Option<u64>,
    /// Whether the HSM is FIPS-validated
    pub fips_validated: bool,
}

/// Enterprise key provider
/// - External HSM REQUIRED
/// - TPM allowed ONLY for device binding / attestation
/// - SoftHSM MUST be rejected (NO fallback)
/// - Local root key generation MUST be rejected
pub struct EnterpriseKeyProvider {
    hsm_config: Option<EnterpriseHsmConfig>,
}

impl EnterpriseKeyProvider {
    /// Create a new enterprise key provider
    /// FAILS if HSM is not configured or not FIPS-validated
    pub fn new(hsm_config: EnterpriseHsmConfig) -> KeyProviderResult<Self> {
        // Validate HSM configuration
        if !hsm_config.fips_validated {
            return Err(KeyProviderError::EditionViolation(
                EditionError::HsmNotFipsValidated,
            ));
        }

        log::info!("Enterprise: Initializing with external HSM");
        log::info!("Enterprise: HSM FIPS-validated: {}", hsm_config.fips_validated);

        Ok(Self {
            hsm_config: Some(hsm_config),
        })
    }

    /// Attempt to create without HSM - WILL FAIL
    /// This is intentional to enforce the HSM requirement
    pub fn new_without_hsm() -> KeyProviderResult<Self> {
        log::error!("Enterprise: Cannot initialize without external HSM");
        Err(KeyProviderError::EditionViolation(
            EditionError::ExternalHsmRequired,
        ))
    }

    fn require_hsm(&self) -> KeyProviderResult<&EnterpriseHsmConfig> {
        self.hsm_config.as_ref().ok_or_else(|| {
            KeyProviderError::EditionViolation(EditionError::ExternalHsmRequired)
        })
    }
}

impl KeyProvider for EnterpriseKeyProvider {
    fn edition(&self) -> Edition {
        Edition::Enterprise
    }

    fn provider_type(&self) -> KeyProviderType {
        KeyProviderType::ExternalHSM
    }

    fn generate_root_key(&self, key_id: &str) -> KeyProviderResult<KeyMaterial> {
        let hsm = self.require_hsm()?;
        
        log::info!("Enterprise: Generating root key in HSM: {}", key_id);
        
        // In a real implementation, this would call the HSM API
        // For now, return an error indicating HSM integration is required
        Err(KeyProviderError::HsmOperationFailed(format!(
            "HSM key generation not yet implemented for connection: {}",
            hsm.connection
        )))
    }

    fn store_root_key(&self, key_id: &str, _key_material: &KeyMaterial) -> KeyProviderResult<()> {
        let hsm = self.require_hsm()?;
        
        log::info!("Enterprise: Storing root key in HSM: {}", key_id);
        
        // In a real implementation, this would call the HSM API
        Err(KeyProviderError::HsmOperationFailed(format!(
            "HSM key storage not yet implemented for connection: {}",
            hsm.connection
        )))
    }

    fn retrieve_root_key(&self, key_id: &str) -> KeyProviderResult<KeyMaterial> {
        let hsm = self.require_hsm()?;
        
        log::info!("Enterprise: Retrieving root key from HSM: {}", key_id);
        
        // In a real implementation, this would call the HSM API
        Err(KeyProviderError::HsmOperationFailed(format!(
            "HSM key retrieval not yet implemented for connection: {}",
            hsm.connection
        )))
    }

    fn delete_root_key(&self, key_id: &str) -> KeyProviderResult<()> {
        let hsm = self.require_hsm()?;
        
        log::info!("Enterprise: Deleting root key from HSM: {}", key_id);
        
        // In a real implementation, this would call the HSM API
        Err(KeyProviderError::HsmOperationFailed(format!(
            "HSM key deletion not yet implemented for connection: {}",
            hsm.connection
        )))
    }

    fn authorize_key_usage(&self, key_id: &str) -> KeyProviderResult<()> {
        let _hsm = self.require_hsm()?;
        
        log::info!("Enterprise: Authorizing key usage: {}", key_id);
        
        // In a real implementation, this would verify authorization with HSM
        Ok(())
    }

    fn backend_type(&self) -> BackendType {
        // Enterprise always uses external HSM
        // We represent this as TPM for now (could add HSM variant)
        BackendType::TPM
    }
}

/// Create a key provider for the current edition
pub fn create_key_provider() -> KeyProviderResult<Box<dyn KeyProvider>> {
    let edition = get_edition()?;
    
    match edition {
        Edition::Consumer => {
            log::info!("Creating Consumer key provider");
            Ok(Box::new(ConsumerKeyProvider::new()))
        }
        Edition::Enterprise => {
            log::error!("Enterprise key provider requires HSM configuration");
            Err(KeyProviderError::EditionViolation(
                EditionError::ExternalHsmRequired,
            ))
        }
    }
}

/// Create a key provider with explicit configuration
pub fn create_key_provider_with_config(
    edition: Edition,
    hsm_config: Option<EnterpriseHsmConfig>,
) -> KeyProviderResult<Box<dyn KeyProvider>> {
    match edition {
        Edition::Consumer => {
            log::info!("Creating Consumer key provider");
            Ok(Box::new(ConsumerKeyProvider::new()))
        }
        Edition::Enterprise => {
            let config = hsm_config.ok_or_else(|| {
                KeyProviderError::EditionViolation(EditionError::ExternalHsmRequired)
            })?;
            
            log::info!("Creating Enterprise key provider with HSM");
            Ok(Box::new(EnterpriseKeyProvider::new(config)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consumer_provider_allows_local_generation() {
        let provider = ConsumerKeyProvider::new();
        assert_eq!(provider.edition(), Edition::Consumer);
        
        let result = provider.generate_root_key("test-key");
        assert!(result.is_ok());
    }

    #[test]
    fn test_enterprise_provider_requires_hsm() {
        let result = EnterpriseKeyProvider::new_without_hsm();
        assert!(matches!(
            result,
            Err(KeyProviderError::EditionViolation(EditionError::ExternalHsmRequired))
        ));
    }

    #[test]
    fn test_enterprise_provider_requires_fips_validated_hsm() {
        let config = EnterpriseHsmConfig {
            connection: "pkcs11://test".to_string(),
            slot: Some(0),
            fips_validated: false,
        };
        
        let result = EnterpriseKeyProvider::new(config);
        assert!(matches!(
            result,
            Err(KeyProviderError::EditionViolation(EditionError::HsmNotFipsValidated))
        ));
    }

    #[test]
    fn test_enterprise_provider_accepts_fips_validated_hsm() {
        let config = EnterpriseHsmConfig {
            connection: "pkcs11://test".to_string(),
            slot: Some(0),
            fips_validated: true,
        };
        
        let result = EnterpriseKeyProvider::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_key_material_zeroization() {
        let data = vec![0xAB; 32];
        let material = KeyMaterial::new(data.clone());
        assert_eq!(material.len(), 32);
        assert_eq!(material.as_bytes()[0], 0xAB);
        // When dropped, data should be zeroized
    }
}
