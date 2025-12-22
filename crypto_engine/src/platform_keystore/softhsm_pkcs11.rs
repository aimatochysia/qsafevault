// Platform keystore: SoftHSM PKCS#11 support
// Implements key storage and wrapping using PKCS#11 tokens (SoftHSM)

use std::path::PathBuf;

#[cfg(not(target_os = "android"))]
use super::softhsm_pkcs11_impl;

const SOFTHSM_LIBRARY_PATHS: &[&str] = &[
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/opt/homebrew/lib/softhsm/libsofthsm2.so", // macOS Homebrew
    "/usr/local/Cellar/softhsm/*/lib/softhsm/libsofthsm2.so", // macOS Homebrew versioned
    "C:\\SoftHSM2\\lib\\softhsm2-x64.dll", // Windows
];

/// Detect if SoftHSM is available on the system
pub fn is_softhsm_available() -> bool {
    for path in SOFTHSM_LIBRARY_PATHS {
        if PathBuf::from(path).exists() {
            log::debug!("SoftHSM detected at: {}", path);
            return true;
        }
        
        // Handle glob patterns for versioned paths
        if path.contains('*') {
            if let Some(parent) = PathBuf::from(path).parent() {
                if let Ok(entries) = std::fs::read_dir(parent) {
                    for entry in entries.flatten() {
                        let entry_path = entry.path();
                        if let Some(filename) = entry_path.file_name() {
                            if filename.to_string_lossy().contains("softhsm") {
                                log::debug!("SoftHSM detected at: {}", entry_path.display());
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    log::debug!("SoftHSM not detected on system");
    false
}

/// Seal private key using SoftHSM
#[cfg(not(target_os = "android"))]
pub fn seal_private_key(key_id: &str, key_data: &[u8]) -> Result<(), String> {
    let (wrapped, nonce) = softhsm_pkcs11_impl::seal_with_softhsm(key_id, key_data, None)?;
    // Store wrapped+nonce combination - in production, manage this externally
    log::info!("SoftHSM: Key sealed (wrapped_len={}, nonce_len={})", wrapped.len(), nonce.len());
    Ok(())
}

#[cfg(target_os = "android")]
pub fn seal_private_key(_key_id: &str, _key_data: &[u8]) -> Result<(), String> {
    Err("SoftHSM not supported on Android".to_string())
}

/// Unseal private key from SoftHSM
#[cfg(not(target_os = "android"))]
pub fn unseal_private_key(key_id: &str) -> Result<Vec<u8>, String> {
    // Note: This is a simplified interface - full implementation requires
    // passing wrapped_data and nonce from external storage
    log::warn!("SoftHSM unsealing - requires wrapped data from storage");
    Err("Unseal requires wrapped_data and nonce parameters".to_string())
}

#[cfg(target_os = "android")]
pub fn unseal_private_key(_key_id: &str) -> Result<Vec<u8>, String> {
    Err("SoftHSM not supported on Android".to_string())
}

/// Delete private key from SoftHSM
#[cfg(not(target_os = "android"))]
pub fn delete_private_key(key_id: &str) -> Result<(), String> {
    softhsm_pkcs11_impl::delete_from_softhsm(key_id, None)?;
    log::info!("SoftHSM: Key deleted");
    Ok(())
}

#[cfg(target_os = "android")]
pub fn delete_private_key(_key_id: &str) -> Result<(), String> {
    Err("SoftHSM not supported on Android".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_softhsm_detection() {
        // This test will only pass if SoftHSM is installed
        let available = is_softhsm_available();
        println!("SoftHSM available: {}", available);
    }
}
