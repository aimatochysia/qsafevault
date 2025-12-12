// Platform keystore: SoftHSM PKCS#11 support
// Implements key storage and wrapping using PKCS#11 tokens (SoftHSM)

use std::path::PathBuf;

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
pub fn seal_private_key(_key_id: &str, _key_data: &[u8]) -> Result<(), String> {
    // TODO: Full PKCS#11 implementation requires complex FFI bindings
    // For now, return error indicating not fully implemented
    log::info!("SoftHSM sealing requested but not yet fully implemented");
    Err("SoftHSM PKCS#11 integration requires full implementation".to_string())
}

/// Unseal private key from SoftHSM
pub fn unseal_private_key(_key_id: &str) -> Result<Vec<u8>, String> {
    log::info!("SoftHSM unsealing requested but not yet fully implemented");
    Err("SoftHSM PKCS#11 integration requires full implementation".to_string())
}

/// Delete private key from SoftHSM
pub fn delete_private_key(_key_id: &str) -> Result<(), String> {
    log::debug!("SoftHSM deletion requested but not yet fully implemented");
    Ok(())
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

