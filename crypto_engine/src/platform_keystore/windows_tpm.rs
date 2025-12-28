// Platform keystore: Windows TPM2 support via CNG/KSP
// Note: This requires Windows-specific APIs and TPM access

#[cfg(target_os = "windows")]
use super::windows_tpm_impl;

#[cfg(target_os = "windows")]
use windows::Win32::Security::Cryptography::{
    NCryptOpenStorageProvider,
    NCRYPT_PROV_HANDLE,
    MS_PLATFORM_CRYPTO_PROVIDER,
};

/// Check if TPM2 is available on Windows
#[cfg(target_os = "windows")]
pub fn is_tpm_available() -> bool {
    // Try to open the platform crypto provider (TPM)
    unsafe {
        let mut provider = NCRYPT_PROV_HANDLE::default();
        let result = NCryptOpenStorageProvider(
            &mut provider,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0,
        );
        result.is_ok()
    }
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn is_tpm_available() -> bool {
    false
}

/// Store private key using Windows TPM2
#[cfg(target_os = "windows")]
pub fn seal_private_key(key_id: &str, key_data: &[u8]) -> Result<(), String> {
    // Use the full Windows CNG/KSP implementation
    log::info!("Windows TPM2: Using CNG/KSP for sealing key '{}'", key_id);
    let (wrapped_data, nonce) = windows_tpm_impl::seal_with_windows_tpm(key_id, key_data)?;
    // Store nonce alongside the wrapped data for unsealing
    store_seal_metadata(key_id, &nonce)?;
    log::info!("Windows TPM2: Key sealed successfully");
    Ok(())
}

/// Retrieve private key from Windows TPM2
#[cfg(target_os = "windows")]
pub fn unseal_private_key(key_id: &str) -> Result<Vec<u8>, String> {
    // Use the full Windows CNG/KSP implementation
    log::info!("Windows TPM2: Using CNG/KSP for unsealing key '{}'", key_id);
    
    // Load nonce from metadata
    let nonce = load_seal_metadata(key_id)?;
    
    // Load wrapped data from storage
    let storage_dir = get_tpm_storage_dir()?;
    let storage_path = storage_dir.join(format!("{}.bin", key_id));
    let wrapped_data = std::fs::read(&storage_path)
        .map_err(|e| format!("Failed to read sealed data: {}", e))?;
    
    let key_data = windows_tpm_impl::unseal_with_windows_tpm(key_id, &wrapped_data, &nonce)?;
    log::info!("Windows TPM2: Key unsealed successfully");
    Ok(key_data)
}

/// Delete private key from Windows TPM2
#[cfg(target_os = "windows")]
pub fn delete_private_key(key_id: &str) -> Result<(), String> {
    // Use the full Windows CNG/KSP implementation
    windows_tpm_impl::delete_from_windows_tpm(key_id)?;
    // Also delete metadata
    let _ = delete_seal_metadata(key_id);
    log::info!("Windows TPM2: Key deleted successfully");
    Ok(())
}

// Helper functions for storing nonce/metadata
#[cfg(target_os = "windows")]
fn get_tpm_storage_dir() -> Result<std::path::PathBuf, String> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| "Could not determine local data directory".to_string())?;
    
    let dir = base.join("QSafeVault").join("tpm_metadata");
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create TPM metadata directory: {}", e))?;
    
    Ok(dir)
}

#[cfg(target_os = "windows")]
fn store_seal_metadata(key_id: &str, nonce: &[u8]) -> Result<(), String> {
    let dir = get_tpm_storage_dir()?;
    let path = dir.join(format!("{}.nonce", key_id));
    std::fs::write(&path, nonce)
        .map_err(|e| format!("Failed to write nonce: {}", e))
}

#[cfg(target_os = "windows")]
fn load_seal_metadata(key_id: &str) -> Result<Vec<u8>, String> {
    let dir = get_tpm_storage_dir()?;
    let path = dir.join(format!("{}.nonce", key_id));
    std::fs::read(&path)
        .map_err(|e| format!("Failed to read nonce: {}", e))
}

#[cfg(target_os = "windows")]
fn delete_seal_metadata(key_id: &str) -> Result<(), String> {
    let dir = get_tpm_storage_dir()?;
    let path = dir.join(format!("{}.nonce", key_id));
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("Failed to delete nonce: {}", e))?;
    }
    Ok(())
}

// Stub implementations for non-Windows platforms
#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn seal_private_key(_key_id: &str, _key_data: &[u8]) -> Result<(), String> {
    Err("Windows TPM not available on this platform".to_string())
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn unseal_private_key(_key_id: &str) -> Result<Vec<u8>, String> {
    Err("Windows TPM not available on this platform".to_string())
}

#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn delete_private_key(_key_id: &str) -> Result<(), String> {
    Err("Windows TPM not available on this platform".to_string())
}
