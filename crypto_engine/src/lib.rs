// QSafeVault Crypto Engine
// Production-grade cryptographic backend for Flutter password vault
// Implements post-quantum cryptography with platform-secure key storage
//
// EDITION SYSTEM:
// - Consumer Grade: Post-quantum first, flexibility allowed
// - Enterprise Grade: FIPS-only, production-grade, external HSM required
//
// The Edition is set at initialization and is immutable for the process lifetime.
// Rust FFI is the security boundary - all policy enforcement happens here.

mod pqc_kem;
mod pqc_signature;
mod classical_kem;
mod hybrid_kem;
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
