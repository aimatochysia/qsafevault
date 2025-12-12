// Platform keystore module
// Provides unified interface to platform-specific secure key storage with auto-detection

pub mod ios_secure_enclave;
pub mod macos_secure_enclave;
pub mod android_strongbox;
pub mod windows_tpm;
pub mod linux_tpm;
pub mod fallback_software;
pub mod softhsm_pkcs11;

use crate::sealed_storage::BackendType;

/// Backend availability status
#[derive(Debug, Clone, PartialEq)]
pub struct BackendStatus {
    pub tpm_available: bool,
    pub softhsm_available: bool,
    pub platform_secure_available: bool, // iOS/macOS/Android specific
}

/// Detect available backends on the current platform
pub fn detect_backends() -> BackendStatus {
    let tpm_available = is_tpm_available();
    let softhsm_available = softhsm_pkcs11::is_softhsm_available();
    let platform_secure_available = is_platform_secure_available();

    log::info!("Backend detection:");
    log::info!("  TPM2: {}", if tpm_available { "YES" } else { "NO" });
    log::info!("  SoftHSM: {}", if softhsm_available { "YES" } else { "NO" });
    log::info!("  Platform Secure: {}", if platform_secure_available { "YES" } else { "NO" });

    BackendStatus {
        tpm_available,
        softhsm_available,
        platform_secure_available,
    }
}

/// Check if TPM is available
fn is_tpm_available() -> bool {
    #[cfg(target_os = "windows")]
    {
        windows_tpm::is_tpm_available()
    }
    
    #[cfg(target_os = "linux")]
    {
        linux_tpm::is_tpm_available()
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        false
    }
}

/// Check if platform-specific secure storage is available
fn is_platform_secure_available() -> bool {
    #[cfg(target_os = "ios")]
    {
        true // iOS Keychain always available
    }
    
    #[cfg(target_os = "macos")]
    {
        true // macOS Keychain always available
    }
    
    #[cfg(target_os = "android")]
    {
        android_strongbox::is_strongbox_available()
    }
    
    #[cfg(not(any(target_os = "ios", target_os = "macos", target_os = "android")))]
    {
        false
    }
}

/// Determine the backend type based on availability
pub fn determine_backend_type() -> BackendType {
    let status = detect_backends();
    
    // Priority order:
    // 1. BOTH TPM2 + SoftHSM (dual-sealing)
    // 2. TPM2 only
    // 3. SoftHSM only
    // 4. Platform-specific (iOS/macOS/Android)
    // 5. Software fallback
    
    if status.tpm_available && status.softhsm_available {
        log::info!("Using BOTH TPM2 + SoftHSM (dual-sealing)");
        BackendType::TPMAndSoftHSM
    } else if status.tpm_available {
        log::info!("Using TPM2 only");
        BackendType::TPM
    } else if status.softhsm_available {
        log::info!("Using SoftHSM only");
        BackendType::SoftHSM
    } else if status.platform_secure_available {
        log::info!("Using platform-specific secure storage");
        // Return as fallback for now, could add Platform variant
        BackendType::Fallback
    } else {
        log::info!("Using software fallback (no secure hardware available)");
        BackendType::Fallback
    }
}

/// Unified platform keystore interface
pub struct PlatformKeystore;

impl PlatformKeystore {
    /// Seal a private key using the best available platform mechanism
    pub fn seal_key(key_id: &str, key_data: &[u8]) -> Result<BackendType, String> {
        let backend_type = determine_backend_type();
        
        match backend_type {
            BackendType::TPMAndSoftHSM => {
                // Dual-seal: wrap with both TPM and SoftHSM
                log::info!("Dual-sealing key with TPM2 + SoftHSM");
                
                // Seal with TPM
                let tpm_key_id = format!("{}_tpm", key_id);
                seal_with_tpm(&tpm_key_id, key_data)?;
                
                // Seal with SoftHSM
                let softhsm_key_id = format!("{}_softhsm", key_id);
                softhsm_pkcs11::seal_private_key(&softhsm_key_id, key_data)?;
                
                log::info!("Successfully dual-sealed key");
                Ok(BackendType::TPMAndSoftHSM)
            }
            BackendType::TPM => {
                log::info!("Sealing key with TPM2");
                seal_with_tpm(key_id, key_data)?;
                Ok(BackendType::TPM)
            }
            BackendType::SoftHSM => {
                log::info!("Sealing key with SoftHSM");
                softhsm_pkcs11::seal_private_key(key_id, key_data)?;
                Ok(BackendType::SoftHSM)
            }
            BackendType::Fallback => {
                // Try platform-specific first, then software fallback
                if let Ok(()) = seal_with_platform_secure(key_id, key_data) {
                    log::info!("Sealed key with platform-specific secure storage");
                    Ok(BackendType::Fallback)
                } else {
                    log::info!("Sealing key with software fallback");
                    fallback_software::seal_private_key(key_id, key_data)?;
                    Ok(BackendType::Fallback)
                }
            }
        }
    }
    
    /// Unseal a private key with auto-detection
    pub fn unseal_key(key_id: &str) -> Result<Vec<u8>, String> {
        let backend_type = determine_backend_type();
        
        match backend_type {
            BackendType::TPMAndSoftHSM => {
                // Try dual-unseal first
                log::info!("Attempting dual-unseal with TPM2 + SoftHSM");
                
                let tpm_key_id = format!("{}_tpm", key_id);
                let softhsm_key_id = format!("{}_softhsm", key_id);
                
                // Try TPM first
                if let Ok(data) = unseal_with_tpm(&tpm_key_id) {
                    log::info!("Successfully unsealed from TPM2");
                    return Ok(data);
                }
                
                // Try SoftHSM
                if let Ok(data) = softhsm_pkcs11::unseal_private_key(&softhsm_key_id) {
                    log::info!("Successfully unsealed from SoftHSM");
                    return Ok(data);
                }
                
                // Fall back to trying without suffixes
                unseal_with_fallback_chain(key_id)
            }
            BackendType::TPM => {
                log::info!("Attempting to unseal from TPM2");
                unseal_with_tpm(key_id)
                    .or_else(|_| unseal_with_fallback_chain(key_id))
            }
            BackendType::SoftHSM => {
                log::info!("Attempting to unseal from SoftHSM");
                softhsm_pkcs11::unseal_private_key(key_id)
                    .or_else(|_| unseal_with_fallback_chain(key_id))
            }
            BackendType::Fallback => {
                unseal_with_fallback_chain(key_id)
            }
        }
    }
    
    /// Delete a sealed key from all possible locations
    pub fn delete_key(key_id: &str) -> Result<(), String> {
        log::info!("Deleting key from all possible locations: {}", key_id);
        
        // Try all backends
        let _ = fallback_software::delete_private_key(key_id);
        
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        {
            let _ = delete_from_tpm(key_id);
            let tpm_key_id = format!("{}_tpm", key_id);
            let _ = delete_from_tpm(&tpm_key_id);
        }
        
        let _ = softhsm_pkcs11::delete_private_key(key_id);
        let softhsm_key_id = format!("{}_softhsm", key_id);
        let _ = softhsm_pkcs11::delete_private_key(&softhsm_key_id);
        
        #[cfg(target_os = "ios")]
        {
            let _ = ios_secure_enclave::delete_private_key(key_id);
        }
        
        #[cfg(target_os = "macos")]
        {
            let _ = macos_secure_enclave::delete_private_key(key_id);
        }
        
        #[cfg(target_os = "android")]
        {
            let _ = android_strongbox::delete_private_key(key_id);
        }
        
        log::info!("Key deletion completed");
        Ok(())
    }
}

/// Seal with TPM
fn seal_with_tpm(key_id: &str, key_data: &[u8]) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        windows_tpm::seal_private_key(key_id, key_data)
    }
    
    #[cfg(target_os = "linux")]
    {
        linux_tpm::seal_private_key(key_id, key_data)
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err("TPM not available on this platform".to_string())
    }
}

/// Unseal from TPM
fn unseal_with_tpm(key_id: &str) -> Result<Vec<u8>, String> {
    #[cfg(target_os = "windows")]
    {
        windows_tpm::unseal_private_key(key_id)
    }
    
    #[cfg(target_os = "linux")]
    {
        linux_tpm::unseal_private_key(key_id)
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err("TPM not available on this platform".to_string())
    }
}

/// Delete from TPM
fn delete_from_tpm(key_id: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        windows_tpm::delete_private_key(key_id)
    }
    
    #[cfg(target_os = "linux")]
    {
        linux_tpm::delete_private_key(key_id)
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Ok(())
    }
}

/// Seal with platform-specific secure storage
fn seal_with_platform_secure(_key_id: &str, _key_data: &[u8]) -> Result<(), String> {
    #[cfg(target_os = "ios")]
    {
        ios_secure_enclave::seal_private_key(_key_id, _key_data)
    }
    
    #[cfg(target_os = "macos")]
    {
        macos_secure_enclave::seal_private_key(_key_id, _key_data)
    }
    
    #[cfg(target_os = "android")]
    {
        android_strongbox::seal_private_key(_key_id, _key_data)
    }
    
    #[cfg(not(any(target_os = "ios", target_os = "macos", target_os = "android")))]
    {
        Err("Platform-specific secure storage not available".to_string())
    }
}

/// Unseal with fallback chain
fn unseal_with_fallback_chain(key_id: &str) -> Result<Vec<u8>, String> {
    // Try platform-specific first
    #[cfg(target_os = "ios")]
    {
        if let Ok(data) = ios_secure_enclave::unseal_private_key(key_id) {
            log::info!("Unsealed from iOS Secure Enclave");
            return Ok(data);
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        if let Ok(data) = macos_secure_enclave::unseal_private_key(key_id) {
            log::info!("Unsealed from macOS Keychain");
            return Ok(data);
        }
    }
    
    #[cfg(target_os = "android")]
    {
        if let Ok(data) = android_strongbox::unseal_private_key(key_id) {
            log::info!("Unsealed from Android StrongBox");
            return Ok(data);
        }
    }
    
    // Finally, try software fallback
    log::info!("Unsealing from software fallback");
    fallback_software::unseal_private_key(key_id)
}

