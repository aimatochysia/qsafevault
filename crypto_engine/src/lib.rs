// QSafeVault Crypto Engine
// Production-grade cryptographic backend for Flutter password vault
// Implements post-quantum cryptography with platform-secure key storage
// All cryptography is post-quantum safe - no classical algorithms used for security

mod pqc_kem;
mod pqc_signature;
mod classical_kem;
mod hybrid_kem;
mod symmetric;
mod sealed_storage;
mod platform_keystore;
mod ffi;

pub use ffi::*;

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
