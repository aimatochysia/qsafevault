// Platform keystore: Linux TPM2 support via tpm2-tss
// Note: This requires system TPM2 libraries and tss-esapi crate

#[cfg(all(target_os = "linux", feature = "tpm"))]
use super::linux_tpm_impl;

/// Check if TPM2 is available on Linux
#[cfg(target_os = "linux")]
pub fn is_tpm_available() -> bool {
    // Check for TPM device nodes
    std::path::Path::new("/dev/tpm0").exists() || std::path::Path::new("/dev/tpmrm0").exists()
}

#[cfg(not(target_os = "linux"))]
pub fn is_tpm_available() -> bool {
    false
}

/// Store private key in Linux TPM2
#[cfg(target_os = "linux")]
pub fn seal_private_key(key_id: &str, key_data: &[u8]) -> Result<(), String> {
    #[cfg(feature = "tpm")]
    {
        // Use the full tss-esapi implementation
        log::info!("Linux TPM2: Using tss-esapi for sealing key '{}'", key_id);
        let (wrapped_data, nonce) = linux_tpm_impl::seal_with_linux_tpm(key_id, key_data)?;
        // Store nonce alongside the wrapped data for unsealing
        store_seal_metadata(key_id, &nonce)?;
        log::info!("Linux TPM2: Key sealed successfully");
        Ok(())
    }
    
    #[cfg(not(feature = "tpm"))]
    {
        log::warn!("Linux TPM2 support not compiled (enable 'tpm' feature)");
        Err(format!(
            "Linux TPM2 support not compiled - using fallback for: {}",
            key_id
        ))
    }
}

/// Retrieve private key from Linux TPM2
#[cfg(target_os = "linux")]
pub fn unseal_private_key(key_id: &str) -> Result<Vec<u8>, String> {
    #[cfg(feature = "tpm")]
    {
        // Use the full tss-esapi implementation
        log::info!("Linux TPM2: Using tss-esapi for unsealing key '{}'", key_id);
        
        // Load nonce from metadata
        let nonce = load_seal_metadata(key_id)?;
        
        // Load wrapped data from storage
        let storage_dir = get_tpm_storage_dir()?;
        let storage_path = storage_dir.join(format!("{}.tpm", key_id));
        let wrapped_data = std::fs::read(&storage_path)
            .map_err(|e| format!("Failed to read sealed data: {}", e))?;
        
        let key_data = linux_tpm_impl::unseal_with_linux_tpm(key_id, &wrapped_data, &nonce)?;
        log::info!("Linux TPM2: Key unsealed successfully");
        Ok(key_data)
    }
    
    #[cfg(not(feature = "tpm"))]
    {
        log::warn!("Linux TPM2 support not compiled (enable 'tpm' feature)");
        Err(format!(
            "Linux TPM2 support not compiled - using fallback for: {}",
            key_id
        ))
    }
}

/// Delete private key from Linux TPM2
#[cfg(target_os = "linux")]
pub fn delete_private_key(key_id: &str) -> Result<(), String> {
    #[cfg(feature = "tpm")]
    {
        // Use the full tss-esapi implementation
        linux_tpm_impl::delete_from_linux_tpm(key_id)?;
        // Also delete metadata
        let _ = delete_seal_metadata(key_id);
        log::info!("Linux TPM2: Key deleted successfully");
        Ok(())
    }
    
    #[cfg(not(feature = "tpm"))]
    {
        // No-op when TPM not compiled
        Ok(())
    }
}

// Helper functions for storing nonce/metadata
#[cfg(all(target_os = "linux", feature = "tpm"))]
fn get_tpm_storage_dir() -> Result<std::path::PathBuf, String> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| "Could not determine local data directory".to_string())?;
    
    let dir = base.join("QSafeVault").join("tpm_metadata");
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create TPM metadata directory: {}", e))?;
    
    Ok(dir)
}

#[cfg(all(target_os = "linux", feature = "tpm"))]
fn store_seal_metadata(key_id: &str, nonce: &[u8]) -> Result<(), String> {
    let dir = get_tpm_storage_dir()?;
    let path = dir.join(format!("{}.nonce", key_id));
    std::fs::write(&path, nonce)
        .map_err(|e| format!("Failed to write nonce: {}", e))
}

#[cfg(all(target_os = "linux", feature = "tpm"))]
fn load_seal_metadata(key_id: &str) -> Result<Vec<u8>, String> {
    let dir = get_tpm_storage_dir()?;
    let path = dir.join(format!("{}.nonce", key_id));
    std::fs::read(&path)
        .map_err(|e| format!("Failed to read nonce: {}", e))
}

#[cfg(all(target_os = "linux", feature = "tpm"))]
fn delete_seal_metadata(key_id: &str) -> Result<(), String> {
    let dir = get_tpm_storage_dir()?;
    let path = dir.join(format!("{}.nonce", key_id));
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("Failed to delete nonce: {}", e))?;
    }
    Ok(())
}

// Stub implementations for non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub fn seal_private_key(_key_id: &str, _key_data: &[u8]) -> Result<(), String> {
    Err("Linux TPM not available on this platform".to_string())
}

#[cfg(not(target_os = "linux"))]
pub fn unseal_private_key(_key_id: &str) -> Result<Vec<u8>, String> {
    Err("Linux TPM not available on this platform".to_string())
}

#[cfg(not(target_os = "linux"))]
pub fn delete_private_key(_key_id: &str) -> Result<(), String> {
    Err("Linux TPM not available on this platform".to_string())
}
