// Sealed storage: Versioned sealed blob logic
use serde::{Serialize, Deserialize};

/// Version identifier for sealed blobs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlobVersion {
    V1,
    V2, // Multi-backend support
}

/// Algorithm identifier for sealed blobs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlgorithmId {
    HybridKemAes256Gcm,
    Aes256Gcm,
}

/// Backend identifier for sealed blobs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendType {
    TPM,
    SoftHSM,
    TPMAndSoftHSM, // Dual-sealing
    Fallback,
}

/// KDF information for sealed blobs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfInfo {
    pub algorithm: String,
    pub iterations: Option<u32>,
    pub salt: Option<Vec<u8>>,
}

/// Metadata for sealed blobs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMetadata {
    pub version: BlobVersion,
    pub algorithm: AlgorithmId,
    pub created_at: u64, // Unix timestamp
    pub key_id: Option<String>,
    pub backend: BackendType,
    pub kdf_info: Option<KdfInfo>,
    pub pkcs11_slot: Option<u64>,
}

/// Sealed blob containing encrypted data with metadata
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedBlob {
    pub metadata: BlobMetadata,
    pub ciphertext: Vec<u8>,
}

impl SealedBlob {
    /// Create a new sealed blob
    pub fn new(
        algorithm: AlgorithmId,
        ciphertext: Vec<u8>,
        key_id: Option<String>,
    ) -> Self {
        let metadata = BlobMetadata {
            version: BlobVersion::V1,
            algorithm,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            key_id,
            backend: BackendType::Fallback,
            kdf_info: None,
            pkcs11_slot: None,
        };
        
        Self {
            metadata,
            ciphertext,
        }
    }

    /// Create a new sealed blob with backend information
    #[allow(dead_code)]
    pub fn new_with_backend(
        algorithm: AlgorithmId,
        ciphertext: Vec<u8>,
        key_id: Option<String>,
        backend: BackendType,
        kdf_info: Option<KdfInfo>,
        pkcs11_slot: Option<u64>,
    ) -> Self {
        let metadata = BlobMetadata {
            version: BlobVersion::V2,
            algorithm,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            key_id,
            backend,
            kdf_info,
            pkcs11_slot,
        };
        
        Self {
            metadata,
            ciphertext,
        }
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| format!("Serialization error: {}", e))
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("Deserialization error: {}", e))
    }

    /// Serialize to bytes (bincode)
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| format!("Serialization error: {}", e))
    }

    /// Deserialize from bytes (bincode)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes).map_err(|e| format!("Deserialization error: {}", e))
    }

    /// Verify the blob version is supported
    pub fn verify_version(&self) -> Result<(), String> {
        match self.metadata.version {
            BlobVersion::V1 | BlobVersion::V2 => Ok(()),
        }
    }

    /// Verify the blob algorithm is supported
    pub fn verify_algorithm(&self) -> Result<(), String> {
        match self.metadata.algorithm {
            AlgorithmId::HybridKemAes256Gcm | AlgorithmId::Aes256Gcm => Ok(()),
        }
    }

    /// Validate the entire blob
    pub fn validate(&self) -> Result<(), String> {
        self.verify_version()?;
        self.verify_algorithm()?;
        
        if self.ciphertext.is_empty() {
            return Err("Empty ciphertext".to_string());
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sealed_blob_json_serialization() {
        let blob = SealedBlob::new(
            AlgorithmId::Aes256Gcm,
            vec![1, 2, 3, 4, 5],
            Some("key-123".to_string()),
        );

        let json = blob.to_json().unwrap();
        let blob2 = SealedBlob::from_json(&json).unwrap();

        assert_eq!(blob.metadata.version, blob2.metadata.version);
        assert_eq!(blob.metadata.algorithm, blob2.metadata.algorithm);
        assert_eq!(blob.ciphertext, blob2.ciphertext);
    }

    #[test]
    fn test_sealed_blob_binary_serialization() {
        let blob = SealedBlob::new(
            AlgorithmId::HybridKemAes256Gcm,
            vec![1, 2, 3, 4, 5],
            None,
        );

        let bytes = blob.to_bytes().unwrap();
        let blob2 = SealedBlob::from_bytes(&bytes).unwrap();

        assert_eq!(blob.metadata.version, blob2.metadata.version);
        assert_eq!(blob.metadata.algorithm, blob2.metadata.algorithm);
        assert_eq!(blob.ciphertext, blob2.ciphertext);
    }

    #[test]
    fn test_sealed_blob_validation() {
        let blob = SealedBlob::new(
            AlgorithmId::Aes256Gcm,
            vec![1, 2, 3, 4, 5],
            Some("key-123".to_string()),
        );

        assert!(blob.validate().is_ok());
    }

    #[test]
    fn test_sealed_blob_empty_ciphertext() {
        let blob = SealedBlob::new(
            AlgorithmId::Aes256Gcm,
            vec![],
            None,
        );

        assert!(blob.validate().is_err());
    }
}
