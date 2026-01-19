// Stateless Hash-Based Digital Signatures: SLH-DSA wrapper (FIPS 205)
// FIPS 205 Stateless Hash-Based Digital Signature Algorithm (SPHINCS+)
// Using SLH-DSA-SHA2-128s (sphincssha2128ssimple) for balanced security/signature-size
// Provides stateless hash-based signatures as a conservative fallback option

use pqcrypto_sphincsplus::sphincssha2128ssimple;
use pqcrypto_traits::sign::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait, DetachedSignature};

/// SLH-DSA signature keypair (SLH-DSA-SHA2-128s - FIPS 205 certified)
/// Stateless hash-based signatures provide security based on hash function hardness only.
/// Unlike lattice-based schemes (ML-DSA), SLH-DSA does not rely on any structured mathematical
/// problems, making it a conservative choice for applications requiring maximum confidence.
pub struct SlhDsaSigningKeypair {
    pub public_key: sphincssha2128ssimple::PublicKey,
    pub secret_key: sphincssha2128ssimple::SecretKey,
}

/// SLH-DSA detached signature
pub struct SlhDsaSignature {
    signature: sphincssha2128ssimple::DetachedSignature,
}

impl SlhDsaSigningKeypair {
    /// Generate a new SLH-DSA-SHA2-128s signing keypair (FIPS 205)
    pub fn generate() -> Self {
        let (pk, sk) = sphincssha2128ssimple::keypair();
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
        let pk = sphincssha2128ssimple::PublicKey::from_bytes(public_key_bytes)
            .map_err(|_| "Invalid SLH-DSA public key")?;
        let sk = sphincssha2128ssimple::SecretKey::from_bytes(secret_key_bytes)
            .map_err(|_| "Invalid SLH-DSA secret key")?;
        Ok(Self {
            public_key: pk,
            secret_key: sk,
        })
    }

    /// Sign a message (returns detached signature)
    pub fn sign(&self, message: &[u8]) -> SlhDsaSignature {
        let sig = sphincssha2128ssimple::detached_sign(message, &self.secret_key);
        SlhDsaSignature { signature: sig }
    }
}

/// Verify a detached SLH-DSA signature against a public key
pub fn verify_slh_dsa(
    public_key_bytes: &[u8],
    message: &[u8],
    signature: &SlhDsaSignature,
) -> Result<bool, String> {
    let pk = sphincssha2128ssimple::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| "Invalid SLH-DSA public key")?;
    
    match sphincssha2128ssimple::verify_detached_signature(&signature.signature, message, &pk) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

impl SlhDsaSignature {
    /// Serialize signature to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.signature.as_bytes().to_vec()
    }

    /// Deserialize signature from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let sig = sphincssha2128ssimple::DetachedSignature::from_bytes(bytes)
            .map_err(|_| "Invalid SLH-DSA signature")?;
        Ok(Self { signature: sig })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slh_dsa_signature_roundtrip() {
        // Generate keypair
        let keypair = SlhDsaSigningKeypair::generate();
        let pk_bytes = keypair.public_key_bytes();

        let message = b"Hello, Hash-Based Signatures!";
        
        // Sign
        let signature = keypair.sign(message);
        
        // Verify
        let valid = verify_slh_dsa(&pk_bytes, message, &signature).unwrap();
        assert!(valid, "Valid signature should verify");
        
        // Verify with wrong message should fail
        let wrong_message = b"Wrong message";
        let invalid = verify_slh_dsa(&pk_bytes, wrong_message, &signature).unwrap();
        assert!(!invalid, "Wrong message should not verify");
    }

    #[test]
    fn test_slh_dsa_serialization() {
        let keypair = SlhDsaSigningKeypair::generate();
        let message = b"Test data";
        
        let signature = keypair.sign(message);
        let sig_bytes = signature.to_bytes();
        let signature2 = SlhDsaSignature::from_bytes(&sig_bytes).unwrap();
        
        // Verify both signatures work
        let pk_bytes = keypair.public_key_bytes();
        assert!(verify_slh_dsa(&pk_bytes, message, &signature).unwrap());
        assert!(verify_slh_dsa(&pk_bytes, message, &signature2).unwrap());
    }

    #[test]
    fn test_slh_dsa_keypair_serialization() {
        let keypair = SlhDsaSigningKeypair::generate();
        let pk_bytes = keypair.public_key_bytes();
        let sk_bytes = keypair.secret_key_bytes();

        // Deserialize keypair
        let keypair2 = SlhDsaSigningKeypair::from_bytes(&pk_bytes, &sk_bytes).unwrap();

        // Verify keys work
        let message = b"Test";
        let sig = keypair2.sign(message);
        assert!(verify_slh_dsa(&pk_bytes, message, &sig).unwrap());
    }

    #[test]
    fn test_different_keypairs_different_signatures() {
        let keypair1 = SlhDsaSigningKeypair::generate();
        let keypair2 = SlhDsaSigningKeypair::generate();
        
        let message = b"Same message";
        
        let sig1 = keypair1.sign(message);
        let sig2 = keypair2.sign(message);
        
        // Cross-verification should fail
        let pk1 = keypair1.public_key_bytes();
        let pk2 = keypair2.public_key_bytes();
        
        assert!(!verify_slh_dsa(&pk2, message, &sig1).unwrap(), "sig1 should not verify with pk2");
        assert!(!verify_slh_dsa(&pk1, message, &sig2).unwrap(), "sig2 should not verify with pk1");
    }
}
