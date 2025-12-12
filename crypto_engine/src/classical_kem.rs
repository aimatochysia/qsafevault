// Classical cryptography: X25519 ECDH wrapper
use x25519_dalek::{PublicKey, StaticSecret};
use rand_core::OsRng;
use zeroize::ZeroizeOnDrop;

/// Classical X25519 keypair
#[derive(ZeroizeOnDrop)]
pub struct ClassicalKeypair {
    #[zeroize(skip)]
    pub public_key: PublicKey,
    pub secret_key: StaticSecret,
}

/// Classical shared secret
#[derive(Clone, ZeroizeOnDrop)]
pub struct ClassicalSharedSecret {
    pub secret: [u8; 32],
}

impl ClassicalKeypair {
    /// Generate a new X25519 keypair
    pub fn generate() -> Self {
        let secret_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret_key);
        Self {
            public_key,
            secret_key,
        }
    }

    /// Serialize public key to bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    /// Serialize secret key to bytes
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.secret_key.to_bytes()
    }

    /// Deserialize keypair from bytes
    pub fn from_bytes(public_key_bytes: &[u8; 32], secret_key_bytes: &[u8; 32]) -> Self {
        let secret_key = StaticSecret::from(*secret_key_bytes);
        let public_key = PublicKey::from(*public_key_bytes);
        Self {
            public_key,
            secret_key,
        }
    }

    /// Perform ECDH key agreement
    pub fn diffie_hellman(&self, their_public: &[u8; 32]) -> ClassicalSharedSecret {
        let their_public_key = PublicKey::from(*their_public);
        let shared = self.secret_key.diffie_hellman(&their_public_key);
        ClassicalSharedSecret {
            secret: *shared.as_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classical_kem_roundtrip() {
        // Generate two keypairs
        let alice = ClassicalKeypair::generate();
        let bob = ClassicalKeypair::generate();

        // Perform key exchange
        let alice_shared = alice.diffie_hellman(&bob.public_key_bytes());
        let bob_shared = bob.diffie_hellman(&alice.public_key_bytes());

        // Check that shared secrets match
        assert_eq!(alice_shared.secret, bob_shared.secret);
    }

    #[test]
    fn test_classical_serialization() {
        let keypair = ClassicalKeypair::generate();
        let pk_bytes = keypair.public_key_bytes();
        let sk_bytes = keypair.secret_key_bytes();

        // Deserialize keypair
        let keypair2 = ClassicalKeypair::from_bytes(&pk_bytes, &sk_bytes);

        // Verify keys match
        assert_eq!(keypair.public_key_bytes(), keypair2.public_key_bytes());
    }
}
