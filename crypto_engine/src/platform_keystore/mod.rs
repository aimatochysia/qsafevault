// Platform keystore module
// Provides unified interface to platform-specific secure key storage

pub mod ios_secure_enclave;
pub mod macos_secure_enclave;
pub mod android_strongbox;
pub mod windows_tpm;
pub mod linux_tpm;
pub mod fallback_software;

/// Unified platform keystore interface
pub struct PlatformKeystore;

impl PlatformKeystore {
    /// Seal a private key using the best available platform mechanism
    pub fn seal_key(key_id: &str, key_data: &[u8]) -> Result<(), String> {
        // Try platform-specific implementations first
        #[cfg(target_os = "ios")]
        {
            return ios_secure_enclave::seal_private_key(key_id, key_data)
                .or_else(|_| fallback_software::seal_private_key(key_id, key_data));
        }
        
        #[cfg(target_os = "macos")]
        {
            return macos_secure_enclave::seal_private_key(key_id, key_data)
                .or_else(|_| fallback_software::seal_private_key(key_id, key_data));
        }
        
        #[cfg(target_os = "android")]
        {
            return android_strongbox::seal_private_key(key_id, key_data)
                .or_else(|_| fallback_software::seal_private_key(key_id, key_data));
        }
        
        #[cfg(target_os = "windows")]
        {
            return windows_tpm::seal_private_key(key_id, key_data)
                .or_else(|_| fallback_software::seal_private_key(key_id, key_data));
        }
        
        #[cfg(target_os = "linux")]
        {
            return linux_tpm::seal_private_key(key_id, key_data)
                .or_else(|_| fallback_software::seal_private_key(key_id, key_data));
        }
        
        #[cfg(not(any(target_os = "ios", target_os = "macos", target_os = "android", target_os = "windows", target_os = "linux")))]
        {
            fallback_software::seal_private_key(key_id, key_data)
        }
    }
    
    /// Unseal a private key
    pub fn unseal_key(key_id: &str) -> Result<Vec<u8>, String> {
        // Try platform-specific implementations first
        #[cfg(target_os = "ios")]
        {
            return ios_secure_enclave::unseal_private_key(key_id)
                .or_else(|_| fallback_software::unseal_private_key(key_id));
        }
        
        #[cfg(target_os = "macos")]
        {
            return macos_secure_enclave::unseal_private_key(key_id)
                .or_else(|_| fallback_software::unseal_private_key(key_id));
        }
        
        #[cfg(target_os = "android")]
        {
            return android_strongbox::unseal_private_key(key_id)
                .or_else(|_| fallback_software::unseal_private_key(key_id));
        }
        
        #[cfg(target_os = "windows")]
        {
            return windows_tpm::unseal_private_key(key_id)
                .or_else(|_| fallback_software::unseal_private_key(key_id));
        }
        
        #[cfg(target_os = "linux")]
        {
            return linux_tpm::unseal_private_key(key_id)
                .or_else(|_| fallback_software::unseal_private_key(key_id));
        }
        
        #[cfg(not(any(target_os = "ios", target_os = "macos", target_os = "android", target_os = "windows", target_os = "linux")))]
        {
            fallback_software::unseal_private_key(key_id)
        }
    }
    
    /// Delete a sealed key
    pub fn delete_key(key_id: &str) -> Result<(), String> {
        // Try all possible locations
        let _ = fallback_software::delete_private_key(key_id);
        
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
        
        #[cfg(target_os = "windows")]
        {
            let _ = windows_tpm::delete_private_key(key_id);
        }
        
        #[cfg(target_os = "linux")]
        {
            let _ = linux_tpm::delete_private_key(key_id);
        }
        
        Ok(())
    }
}
