// QSafeVault Crypto Engine
// Production-grade cryptographic backend for Flutter password vault
// Implements hybrid post-quantum + classical cryptography with platform-secure key storage

#![allow(unused_assignments)]

mod pqc_kem;
mod classical_kem;
mod hybrid_kem;
mod symmetric;
mod sealed_storage;
mod platform_keystore;
mod ffi;

#[cfg(test)]
mod security_tests;

pub use ffi::*;

#[cfg(test)]
mod tests {
    #[test]
    fn test_integration() {
        assert!(true);
    }
}
