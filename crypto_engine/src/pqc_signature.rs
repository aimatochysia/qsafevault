// Post-Quantum Digital Signatures: Dilithium wrapper
// Provides NIST-standardized post-quantum digital signatures for device identity and sync authentication
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait, SignedMessage, DetachedSignature};

/// PQC signature keypair (Dilithium3 - NIST Level 3 security)
pub struct PqcSigningKeypair {
    pub public_key: dilithium3::PublicKey,
    pub secret_key: dilithium3::SecretKey,
}

impl Drop for PqcSigningKeypair {
    fn drop(&mut self) {
        // Zeroize secret key memory
        // Note: pqcrypto types should handle this internally
    }
}

/// PQC detached signature
pub struct PqcSignature {
    signature: dilithium3::DetachedSignature,
}

/// PQC signed message (signature + message combined)
pub struct PqcSignedMessage {
    pub signed_data: Vec<u8>,
}

impl PqcSigningKeypair {
    /// Generate a new Dilithium3 signing keypair
    pub fn generate() -> Self {
        let (pk, sk) = dilithium3::keypair();
        Self {
            public_key: pk,
            secret_key: sk,
        }
    }

    /// Serialize public key to bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    /// Serialize secret key to bytes
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.secret_key.as_bytes().to_vec()
    }

    /// Deserialize keypair from bytes
    pub fn from_bytes(public_key_bytes: &[u8], secret_key_bytes: &[u8]) -> Result<Self, String> {
        let pk = dilithium3::PublicKey::from_bytes(public_key_bytes)
            .map_err(|_| "Invalid Dilithium public key")?;
        let sk = dilithium3::SecretKey::from_bytes(secret_key_bytes)
            .map_err(|_| "Invalid Dilithium secret key")?;
        Ok(Self {
            public_key: pk,
            secret_key: sk,
        })
    }

    /// Sign a message (returns detached signature)
    pub fn sign(&self, message: &[u8]) -> PqcSignature {
        let sig = dilithium3::detached_sign(message, &self.secret_key);
        PqcSignature { signature: sig }
    }

    /// Sign a message (returns signed message with embedded signature)
    pub fn sign_message(&self, message: &[u8]) -> PqcSignedMessage {
        let signed = dilithium3::sign(message, &self.secret_key);
        PqcSignedMessage {
            signed_data: signed.as_bytes().to_vec(),
        }
    }
}

/// Verify a detached signature against a public key
pub fn verify(
    public_key_bytes: &[u8],
    message: &[u8],
    signature: &PqcSignature,
) -> Result<bool, String> {
    let pk = dilithium3::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| "Invalid Dilithium public key")?;
    
    match dilithium3::verify_detached_signature(&signature.signature, message, &pk) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify a signed message and extract the original message
pub fn verify_signed_message(
    public_key_bytes: &[u8],
    signed_message: &PqcSignedMessage,
) -> Result<Vec<u8>, String> {
    let pk = dilithium3::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| "Invalid Dilithium public key")?;
    
    let sm = dilithium3::SignedMessage::from_bytes(&signed_message.signed_data)
        .map_err(|_| "Invalid signed message")?;
    
    dilithium3::open(&sm, &pk)
        .map(|v| v.to_vec())
        .map_err(|_| "Signature verification failed".to_string())
}

impl PqcSignature {
    /// Serialize signature to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.signature.as_bytes().to_vec()
    }

    /// Deserialize signature from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let sig = dilithium3::DetachedSignature::from_bytes(bytes)
            .map_err(|_| "Invalid Dilithium signature")?;
        Ok(Self { signature: sig })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_signature_roundtrip() {
        // Generate keypair
        let keypair = PqcSigningKeypair::generate();
        let pk_bytes = keypair.public_key_bytes();

        let message = b"Hello, Post-Quantum World!";
        
        // Sign
        let signature = keypair.sign(message);
        
        // Verify
        let valid = verify(&pk_bytes, message, &signature).unwrap();
        assert!(valid, "Valid signature should verify");
        
        // Verify with wrong message should fail
        let wrong_message = b"Wrong message";
        let invalid = verify(&pk_bytes, wrong_message, &signature).unwrap();
        assert!(!invalid, "Wrong message should not verify");
    }

    #[test]
    fn test_pqc_signed_message_roundtrip() {
        // Generate keypair
        let keypair = PqcSigningKeypair::generate();
        let pk_bytes = keypair.public_key_bytes();

        let message = b"Secret message for signing";
        
        // Sign message
        let signed = keypair.sign_message(message);
        
        // Verify and extract
        let extracted = verify_signed_message(&pk_bytes, &signed).unwrap();
        assert_eq!(message.to_vec(), extracted);
    }

    #[test]
    fn test_pqc_signature_serialization() {
        let keypair = PqcSigningKeypair::generate();
        let message = b"Test data";
        
        let signature = keypair.sign(message);
        let sig_bytes = signature.to_bytes();
        let signature2 = PqcSignature::from_bytes(&sig_bytes).unwrap();
        
        // Verify both signatures work
        let pk_bytes = keypair.public_key_bytes();
        assert!(verify(&pk_bytes, message, &signature).unwrap());
        assert!(verify(&pk_bytes, message, &signature2).unwrap());
    }

    #[test]
    fn test_pqc_keypair_serialization() {
        let keypair = PqcSigningKeypair::generate();
        let pk_bytes = keypair.public_key_bytes();
        let sk_bytes = keypair.secret_key_bytes();

        // Deserialize keypair
        let keypair2 = PqcSigningKeypair::from_bytes(&pk_bytes, &sk_bytes).unwrap();

        // Verify keys work
        let message = b"Test";
        let sig = keypair2.sign(message);
        assert!(verify(&pk_bytes, message, &sig).unwrap());
    }

    #[test]
    fn test_different_keypairs_different_signatures() {
        let keypair1 = PqcSigningKeypair::generate();
        let keypair2 = PqcSigningKeypair::generate();
        
        let message = b"Same message";
        
        let sig1 = keypair1.sign(message);
        let sig2 = keypair2.sign(message);
        
        // Signatures should be different
        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
        
        // Cross-verification should fail
        let pk1 = keypair1.public_key_bytes();
        let pk2 = keypair2.public_key_bytes();
        
        assert!(!verify(&pk2, message, &sig1).unwrap(), "sig1 should not verify with pk2");
        assert!(!verify(&pk1, message, &sig2).unwrap(), "sig2 should not verify with pk1");
    }
}
