// Symmetric encryption: AES-256-GCM
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce, Key,
};
use zeroize::ZeroizeOnDrop;
use rand_core::{OsRng, RngCore};

const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

/// AES-256-GCM encryption key
#[derive(Clone, ZeroizeOnDrop)]
pub struct SymmetricKey {
    pub key: [u8; 32],
}

impl SymmetricKey {
    /// Create a new random symmetric key
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Create symmetric key from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { key: bytes }
    }

    /// Get key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

/// Encrypted data with nonce and authentication tag
pub struct EncryptedData {
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; TAG_SIZE],
}

/// Encrypt data with AES-256-GCM
pub fn encrypt(
    key: &SymmetricKey,
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<EncryptedData, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.key));
    
    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Prepare payload with optional AAD
    let payload = if let Some(aad) = associated_data {
        Payload {
            msg: plaintext,
            aad,
        }
    } else {
        Payload {
            msg: plaintext,
            aad: &[],
        }
    };
    
    // Encrypt
    let ciphertext_with_tag = cipher.encrypt(nonce, payload)
        .map_err(|_| "Encryption failed")?;
    
    // Split ciphertext and tag
    let tag_start = ciphertext_with_tag.len() - TAG_SIZE;
    let ciphertext = ciphertext_with_tag[..tag_start].to_vec();
    let tag: [u8; TAG_SIZE] = ciphertext_with_tag[tag_start..]
        .try_into()
        .map_err(|_| "Invalid tag size")?;
    
    Ok(EncryptedData {
        nonce: nonce_bytes,
        ciphertext,
        tag,
    })
}

/// Decrypt data with AES-256-GCM
pub fn decrypt(
    key: &SymmetricKey,
    encrypted: &EncryptedData,
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.key));
    let nonce = Nonce::from_slice(&encrypted.nonce);
    
    // Reconstruct ciphertext with tag
    let mut ciphertext_with_tag = encrypted.ciphertext.clone();
    ciphertext_with_tag.extend_from_slice(&encrypted.tag);
    
    // Prepare payload with optional AAD
    let payload = if let Some(aad) = associated_data {
        Payload {
            msg: &ciphertext_with_tag,
            aad,
        }
    } else {
        Payload {
            msg: &ciphertext_with_tag,
            aad: &[],
        }
    };
    
    // Decrypt
    let plaintext = cipher.decrypt(nonce, payload)
        .map_err(|_| "Decryption failed: authentication error")?;
    
    Ok(plaintext)
}

impl EncryptedData {
    /// Serialize to bytes: [nonce || ciphertext || tag]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(NONCE_SIZE + self.ciphertext.len() + TAG_SIZE);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes.extend_from_slice(&self.tag);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < NONCE_SIZE + TAG_SIZE {
            return Err("Invalid encrypted data: too short".to_string());
        }
        
        let nonce: [u8; NONCE_SIZE] = bytes[..NONCE_SIZE]
            .try_into()
            .map_err(|_| "Invalid nonce")?;
        
        let tag_start = bytes.len() - TAG_SIZE;
        let ciphertext = bytes[NONCE_SIZE..tag_start].to_vec();
        
        let tag: [u8; TAG_SIZE] = bytes[tag_start..]
            .try_into()
            .map_err(|_| "Invalid tag")?;
        
        Ok(Self {
            nonce,
            ciphertext,
            tag,
        })
    }
}

/// Simple AES-GCM encryption for key wrapping (used by TPM/StrongBox implementations)
/// Returns: (ciphertext_with_tag, nonce)
pub fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if key.len() != 32 {
        return Err("Key must be 32 bytes".to_string());
    }
    
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    
    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt (includes authentication tag)
    let ciphertext_with_tag = cipher.encrypt(nonce, plaintext)
        .map_err(|_| "Encryption failed")?;
    
    Ok((ciphertext_with_tag, nonce_bytes.to_vec()))
}

/// Simple AES-GCM decryption for key unwrapping (used by TPM/StrongBox implementations)
pub fn aes_gcm_decrypt(key: &[u8], ciphertext_with_tag: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("Key must be 32 bytes".to_string());
    }
    if nonce.len() != NONCE_SIZE {
        return Err(format!("Nonce must be {} bytes", NONCE_SIZE));
    }
    
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    
    // Decrypt and verify authentication tag
    let plaintext = cipher.decrypt(nonce, ciphertext_with_tag)
        .map_err(|_| "Decryption failed: authentication error")?;
    
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_encryption_roundtrip() {
        let key = SymmetricKey::generate();
        let plaintext = b"Hello, World! This is a test message.";
        
        // Encrypt
        let encrypted = encrypt(&key, plaintext, None).unwrap();
        
        // Decrypt
        let decrypted = decrypt(&key, &encrypted, None).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_symmetric_encryption_with_aad() {
        let key = SymmetricKey::generate();
        let plaintext = b"Secret data";
        let aad = b"metadata";
        
        // Encrypt with AAD
        let encrypted = encrypt(&key, plaintext, Some(aad)).unwrap();
        
        // Decrypt with correct AAD
        let decrypted = decrypt(&key, &encrypted, Some(aad)).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
        
        // Decrypt with wrong AAD should fail
        let wrong_aad = b"wrong";
        let result = decrypt(&key, &encrypted, Some(wrong_aad));
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let key = SymmetricKey::generate();
        let plaintext = b"Test data";
        
        let encrypted = encrypt(&key, plaintext, None).unwrap();
        let bytes = encrypted.to_bytes();
        let encrypted2 = EncryptedData::from_bytes(&bytes).unwrap();
        
        let decrypted = decrypt(&key, &encrypted2, None).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }
}
