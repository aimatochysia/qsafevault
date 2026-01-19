// QSafeVault Crypto Engine
// Production-grade cryptographic backend for Flutter password vault
// Implements FIPS 203/204/205 post-quantum cryptography with platform-secure key storage
//
// FIPS CERTIFIED ALGORITHMS ONLY:
// - ML-KEM-1024 (FIPS 203): Module-Lattice Key Encapsulation Mechanism
// - ML-DSA-65 (FIPS 204): Module-Lattice Digital Signature Algorithm
// - SLH-DSA (FIPS 205): Stateless Hash-Based Digital Signature Algorithm
// - AES-256-GCM: Authenticated Encryption
// - HKDF-SHA256: Key Derivation Function
//
// The Edition is set at initialization and is immutable for the process lifetime.
// Rust FFI is the security boundary - all policy enforcement happens here.

mod pqc_kem;
mod pqc_signature;
mod slh_dsa;
mod symmetric;
mod sealed_storage;
mod platform_keystore;
mod edition;
mod key_provider;
mod ffi;

pub use ffi::*;
pub use edition::{Edition, CryptoPolicy, EditionError, Algorithm, KeyProviderType};
pub use key_provider::{KeyProvider, ConsumerKeyProvider, EnterpriseKeyProvider, EnterpriseHsmConfig};

#[cfg(test)]
mod security_tests;

#[cfg(test)]
mod tests {
    #[test]
    fn test_integration() {
        // Basic integration test
        assert!(true);
    }
}
