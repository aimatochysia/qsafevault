// Post-Quantum Cryptography: Kyber ML-KEM wrapper
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext as CiphertextTrait, PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait, SharedSecret as SharedSecretTrait};
use zeroize::ZeroizeOnDrop;

/// PQC keypair (Kyber ML-KEM 768)
pub struct PqcKeypair {
    pub public_key: mlkem768::PublicKey,
    pub secret_key: mlkem768::SecretKey,
}

impl Drop for PqcKeypair {
    fn drop(&mut self) {
        // Zeroize secret key memory
        // Note: pqcrypto types don't expose internal buffers for zeroization
        // They should handle this internally
    }
}

/// PQC ciphertext from encapsulation
pub struct PqcCiphertext {
    pub ciphertext: mlkem768::Ciphertext,
}

/// PQC shared secret
#[derive(Clone, ZeroizeOnDrop)]
pub struct PqcSharedSecret {
    pub secret: Vec<u8>,
}

impl PqcKeypair {
    /// Generate a new Kyber ML-KEM 768 keypair
    pub fn generate() -> Self {
        let (pk, sk) = mlkem768::keypair();
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
        let pk = mlkem768::PublicKey::from_bytes(public_key_bytes)
            .map_err(|_| "Invalid PQC public key")?;
        let sk = mlkem768::SecretKey::from_bytes(secret_key_bytes)
            .map_err(|_| "Invalid PQC secret key")?;
        Ok(Self {
            public_key: pk,
            secret_key: sk,
        })
    }

    /// Decapsulate ciphertext to get shared secret
    pub fn decapsulate(&self, ciphertext: &PqcCiphertext) -> PqcSharedSecret {
        let ss = mlkem768::decapsulate(&ciphertext.ciphertext, &self.secret_key);
        PqcSharedSecret {
            secret: ss.as_bytes().to_vec(),
        }
    }
}

/// Encapsulate to a public key to generate shared secret and ciphertext
pub fn encapsulate(public_key_bytes: &[u8]) -> Result<(PqcSharedSecret, PqcCiphertext), String> {
    let pk = mlkem768::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| "Invalid PQC public key")?;
    let (ss, ct) = mlkem768::encapsulate(&pk);
    Ok((
        PqcSharedSecret {
            secret: ss.as_bytes().to_vec(),
        },
        PqcCiphertext { ciphertext: ct },
    ))
}

impl PqcCiphertext {
    /// Serialize ciphertext to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.ciphertext.as_bytes().to_vec()
    }

    /// Deserialize ciphertext from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let ct = mlkem768::Ciphertext::from_bytes(bytes)
            .map_err(|_| "Invalid PQC ciphertext")?;
        Ok(Self { ciphertext: ct })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_kem_roundtrip() {
        // Generate keypair
        let keypair = PqcKeypair::generate();
        let pk_bytes = keypair.public_key_bytes();

        // Encapsulate
        let (ss1, ct) = encapsulate(&pk_bytes).unwrap();
        
        // Decapsulate
        let ss2 = keypair.decapsulate(&ct);

        // Check that shared secrets match
        assert_eq!(ss1.secret, ss2.secret);
    }

    #[test]
    fn test_pqc_serialization() {
        let keypair = PqcKeypair::generate();
        let pk_bytes = keypair.public_key_bytes();
        let sk_bytes = keypair.secret_key_bytes();

        // Deserialize keypair
        let keypair2 = PqcKeypair::from_bytes(&pk_bytes, &sk_bytes).unwrap();

        // Verify keys match
        assert_eq!(keypair.public_key_bytes(), keypair2.public_key_bytes());
    }
}
