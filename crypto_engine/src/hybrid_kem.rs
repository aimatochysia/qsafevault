// Hybrid KEM: Combines PQC (Kyber) + Classical (X25519) using HKDF-SHA3
use crate::pqc_kem::{PqcKeypair, PqcSharedSecret, PqcCiphertext, encapsulate as pqc_encapsulate};
use crate::classical_kem::{ClassicalKeypair, ClassicalSharedSecret};
use hkdf::Hkdf;
use sha3::Sha3_256;
use zeroize::{Zeroize, ZeroizeOnDrop};

const HYBRID_INFO: &[u8] = b"qsafevault-hybrid-kem-v1";

/// Hybrid keypair (PQC + Classical)
pub struct HybridKeypair {
    pub pqc: PqcKeypair,
    pub classical: ClassicalKeypair,
}

impl Drop for HybridKeypair {
    fn drop(&mut self) {
        // Drop will cascade to fields
    }
}

/// Hybrid ciphertext (contains both PQC and Classical components)
pub struct HybridCiphertext {
    pub pqc_ciphertext: Vec<u8>,
    pub classical_public_key: [u8; 32],
}

/// Hybrid shared secret derived from both KEM schemes
#[derive(Clone, ZeroizeOnDrop)]
pub struct HybridSharedSecret {
    pub secret: [u8; 32],
}

impl HybridKeypair {
    /// Generate a new hybrid keypair
    pub fn generate() -> Self {
        Self {
            pqc: PqcKeypair::generate(),
            classical: ClassicalKeypair::generate(),
        }
    }

    /// Serialize public keys to bytes
    pub fn public_keys_bytes(&self) -> (Vec<u8>, [u8; 32]) {
        (
            self.pqc.public_key_bytes(),
            self.classical.public_key_bytes(),
        )
    }

    /// Serialize secret keys to bytes
    pub fn secret_keys_bytes(&self) -> (Vec<u8>, [u8; 32]) {
        (
            self.pqc.secret_key_bytes(),
            self.classical.secret_key_bytes(),
        )
    }

    /// Deserialize keypair from bytes
    pub fn from_bytes(
        pqc_public: &[u8],
        pqc_secret: &[u8],
        classical_public: &[u8; 32],
        classical_secret: &[u8; 32],
    ) -> Result<Self, String> {
        Ok(Self {
            pqc: PqcKeypair::from_bytes(pqc_public, pqc_secret)?,
            classical: ClassicalKeypair::from_bytes(classical_public, classical_secret),
        })
    }

    /// Decapsulate hybrid ciphertext to get shared secret
    pub fn decapsulate(&self, ciphertext: &HybridCiphertext) -> Result<HybridSharedSecret, String> {
        // Deserialize PQC ciphertext
        let pqc_ct = PqcCiphertext::from_bytes(&ciphertext.pqc_ciphertext)?;
        
        // Decapsulate PQC
        let pqc_ss = self.pqc.decapsulate(&pqc_ct);
        
        // Perform classical ECDH
        let classical_ss = self.classical.diffie_hellman(&ciphertext.classical_public_key);
        
        // Combine using HKDF-SHA3
        let combined = combine_shared_secrets(&pqc_ss, &classical_ss);
        
        Ok(combined)
    }
}

/// Encapsulate to public keys to generate hybrid shared secret and ciphertext
pub fn encapsulate(
    pqc_public_key: &[u8],
    classical_public_key: &[u8; 32],
) -> Result<(HybridSharedSecret, HybridCiphertext), String> {
    // PQC encapsulation
    let (pqc_ss, pqc_ct) = pqc_encapsulate(pqc_public_key)?;
    
    // Classical ECDH: generate ephemeral key
    let ephemeral = ClassicalKeypair::generate();
    let classical_ss = ephemeral.diffie_hellman(classical_public_key);
    
    // Combine using HKDF-SHA3
    let combined = combine_shared_secrets(&pqc_ss, &classical_ss);
    
    let ciphertext = HybridCiphertext {
        pqc_ciphertext: pqc_ct.to_bytes(),
        classical_public_key: ephemeral.public_key_bytes(),
    };
    
    Ok((combined, ciphertext))
}

/// Combine PQC and Classical shared secrets using HKDF-SHA3
fn combine_shared_secrets(
    pqc_ss: &PqcSharedSecret,
    classical_ss: &ClassicalSharedSecret,
) -> HybridSharedSecret {
    // Concatenate both shared secrets as input key material
    let mut ikm = Vec::new();
    ikm.extend_from_slice(&pqc_ss.secret);
    ikm.extend_from_slice(&classical_ss.secret);
    
    // Use HKDF-SHA3 to derive final shared secret
    let hk = Hkdf::<Sha3_256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(HYBRID_INFO, &mut okm).expect("HKDF expand failed");
    
    // Zeroize IKM
    ikm.zeroize();
    
    HybridSharedSecret { secret: okm }
}

impl HybridCiphertext {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Length prefix for PQC ciphertext
        bytes.extend_from_slice(&(self.pqc_ciphertext.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.pqc_ciphertext);
        bytes.extend_from_slice(&self.classical_public_key);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 + 32 {
            return Err("Invalid hybrid ciphertext: too short".to_string());
        }
        
        let pqc_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if bytes.len() < 4 + pqc_len + 32 {
            return Err("Invalid hybrid ciphertext: incorrect length".to_string());
        }
        
        let pqc_ciphertext = bytes[4..4+pqc_len].to_vec();
        let classical_public_key = bytes[4+pqc_len..4+pqc_len+32].try_into()
            .map_err(|_| "Invalid classical public key")?;
        
        Ok(Self {
            pqc_ciphertext,
            classical_public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_roundtrip() {
        // Generate keypair
        let keypair = HybridKeypair::generate();
        let (pqc_pk, classical_pk) = keypair.public_keys_bytes();

        // Encapsulate
        let (ss1, ct) = encapsulate(&pqc_pk, &classical_pk).unwrap();
        
        // Decapsulate
        let ss2 = keypair.decapsulate(&ct).unwrap();

        // Check that shared secrets match
        assert_eq!(ss1.secret, ss2.secret);
    }

    #[test]
    fn test_hybrid_ciphertext_serialization() {
        let keypair = HybridKeypair::generate();
        let (pqc_pk, classical_pk) = keypair.public_keys_bytes();

        let (_, ct) = encapsulate(&pqc_pk, &classical_pk).unwrap();
        let ct_bytes = ct.to_bytes();
        let ct2 = HybridCiphertext::from_bytes(&ct_bytes).unwrap();

        assert_eq!(ct.pqc_ciphertext, ct2.pqc_ciphertext);
        assert_eq!(ct.classical_public_key, ct2.classical_public_key);
    }
}
