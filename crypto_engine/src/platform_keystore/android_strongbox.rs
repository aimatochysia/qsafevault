// Platform keystore: Android StrongBox Keystore support
// Full implementation with JNI bridge to Android Keystore

#[cfg(target_os = "android")]
use super::android_strongbox_impl;

/// Check if Android StrongBox is available
#[cfg(target_os = "android")]
pub fn is_strongbox_available() -> bool {
    // Use the full JNI implementation
    android_strongbox_impl::is_strongbox_available()
}

#[cfg(not(target_os = "android"))]
pub fn is_strongbox_available() -> bool {
    false
}

/// Store private key in Android StrongBox Keystore
#[cfg(target_os = "android")]
pub fn seal_private_key(key_id: &str, key_data: &[u8]) -> Result<(), String> {
    // Use the full JNI implementation
    log::info!("Android StrongBox: Using JNI for sealing key '{}'", key_id);
    let (wrapped_data, nonce) = android_strongbox_impl::seal_with_android_strongbox(key_id, key_data)?;
    // Store nonce alongside the wrapped data for unsealing
    store_seal_metadata(key_id, &nonce)?;
    // Store wrapped data
    store_wrapped_data(key_id, &wrapped_data)?;
    log::info!("Android StrongBox: Key sealed successfully");
    Ok(())
}

/// Retrieve private key from Android StrongBox Keystore
#[cfg(target_os = "android")]
pub fn unseal_private_key(key_id: &str) -> Result<Vec<u8>, String> {
    // Use the full JNI implementation
    log::info!("Android StrongBox: Using JNI for unsealing key '{}'", key_id);
    
    // Load nonce from metadata
    let nonce = load_seal_metadata(key_id)?;
    
    // Load wrapped data from storage
    let wrapped_data = load_wrapped_data(key_id)?;
    
    let key_data = android_strongbox_impl::unseal_with_android_strongbox(key_id, &wrapped_data, &nonce)?;
    log::info!("Android StrongBox: Key unsealed successfully");
    Ok(key_data)
}

/// Delete private key from Android StrongBox Keystore
#[cfg(target_os = "android")]
pub fn delete_private_key(key_id: &str) -> Result<(), String> {
    // Use the full JNI implementation
    android_strongbox_impl::delete_from_android_strongbox(key_id)?;
    // Also delete metadata and wrapped data
    let _ = delete_seal_metadata(key_id);
    let _ = delete_wrapped_data(key_id);
    log::info!("Android StrongBox: Key deleted successfully");
    Ok(())
}

// Helper functions for storing metadata and wrapped data
#[cfg(target_os = "android")]
fn get_strongbox_storage_dir() -> Result<std::path::PathBuf, String> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| "Could not determine local data directory".to_string())?;
    
    let dir = base.join("QSafeVault").join("strongbox_data");
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create StrongBox storage directory: {}", e))?;
    
    Ok(dir)
}

#[cfg(target_os = "android")]
fn store_seal_metadata(key_id: &str, nonce: &[u8]) -> Result<(), String> {
    let dir = get_strongbox_storage_dir()?;
    let path = dir.join(format!("{}.nonce", key_id));
    std::fs::write(&path, nonce)
        .map_err(|e| format!("Failed to write nonce: {}", e))
}

#[cfg(target_os = "android")]
fn load_seal_metadata(key_id: &str) -> Result<Vec<u8>, String> {
    let dir = get_strongbox_storage_dir()?;
    let path = dir.join(format!("{}.nonce", key_id));
    std::fs::read(&path)
        .map_err(|e| format!("Failed to read nonce: {}", e))
}

#[cfg(target_os = "android")]
fn delete_seal_metadata(key_id: &str) -> Result<(), String> {
    let dir = get_strongbox_storage_dir()?;
    let path = dir.join(format!("{}.nonce", key_id));
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("Failed to delete nonce: {}", e))?;
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn store_wrapped_data(key_id: &str, data: &[u8]) -> Result<(), String> {
    let dir = get_strongbox_storage_dir()?;
    let path = dir.join(format!("{}.wrapped", key_id));
    std::fs::write(&path, data)
        .map_err(|e| format!("Failed to write wrapped data: {}", e))
}

#[cfg(target_os = "android")]
fn load_wrapped_data(key_id: &str) -> Result<Vec<u8>, String> {
    let dir = get_strongbox_storage_dir()?;
    let path = dir.join(format!("{}.wrapped", key_id));
    std::fs::read(&path)
        .map_err(|e| format!("Failed to read wrapped data: {}", e))
}

#[cfg(target_os = "android")]
fn delete_wrapped_data(key_id: &str) -> Result<(), String> {
    let dir = get_strongbox_storage_dir()?;
    let path = dir.join(format!("{}.wrapped", key_id));
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("Failed to delete wrapped data: {}", e))?;
    }
    Ok(())
}

// Stub implementations for non-Android platforms
#[cfg(not(target_os = "android"))]
pub fn seal_private_key(_key_id: &str, _key_data: &[u8]) -> Result<(), String> {
    Err("Android StrongBox not available on this platform".to_string())
}

#[cfg(not(target_os = "android"))]
pub fn unseal_private_key(_key_id: &str) -> Result<Vec<u8>, String> {
    Err("Android StrongBox not available on this platform".to_string())
}

#[cfg(not(target_os = "android"))]
pub fn delete_private_key(_key_id: &str) -> Result<(), String> {
    Err("Android StrongBox not available on this platform".to_string())
}
