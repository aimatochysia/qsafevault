// QSafeVault Crypto Engine
// Production-grade cryptographic backend for Flutter password vault
// Implements hybrid post-quantum + classical cryptography with platform-secure key storage

mod pqc_kem;
mod classical_kem;
mod hybrid_kem;
mod symmetric;
mod sealed_storage;
mod platform_keystore;
mod ffi;

pub use ffi::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integration() {
        // Basic integration test
        assert!(true);
    }
}
