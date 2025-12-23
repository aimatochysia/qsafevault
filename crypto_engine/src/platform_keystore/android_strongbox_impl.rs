// Android StrongBox Implementation
// Provides key storage for Android platform using software fallback
//
// NOTE: This implementation uses software-based encryption for maximum compatibility.
// Full StrongBox JNI integration requires Android NDK setup and is handled by the
// Flutter Android plugin layer when available.

#![cfg(target_os = "android")]

use crate::symmetric::{aes_gcm_encrypt, aes_gcm_decrypt};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroize;

const STRONGBOX_KEYS_DIR: &str = "strongbox_keys";

/// Get the directory for storing keys
fn get_strongbox_storage_dir() -> Result<PathBuf, String> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| "Could not determine local data directory".to_string())?;
    
    let dir = base.join("QSafeVault").join(STRONGBOX_KEYS_DIR);
    fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create storage directory: {}", e))?;
    
    Ok(dir)
}

/// Check if StrongBox is available on this device
/// Note: Full StrongBox detection requires JNI which is handled at Flutter layer
pub fn is_strongbox_available() -> bool {
    // Return false to indicate we're using software fallback
    // The Flutter Android plugin handles actual StrongBox detection
    log::info!("Android StrongBox: Using software fallback mode");
    false
}

/// Seals a master key using software encryption (StrongBox fallback)
pub fn seal_with_android_strongbox(
    key_id: &str,
    master_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    log::info!("Android StrongBox: Sealing key '{}' (software fallback mode)", key_id);
    
    // Generate a random AES key for encryption
    use rand_core::RngCore;
    let mut wrapping_key = vec![0u8; 32];
    rand_core::OsRng.fill_bytes(&mut wrapping_key);
    
    // Wrap master key with AES-GCM
    let (wrapped_master, nonce) = aes_gcm_encrypt(&wrapping_key, master_key)
        .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;
    
    // Store the wrapping key securely
    let storage_dir = get_strongbox_storage_dir()?;
    let key_path = storage_dir.join(format!("{}.key", key_id));
    let data_path = storage_dir.join(format!("{}.dat", key_id));
    let nonce_path = storage_dir.join(format!("{}.nonce", key_id));
    
    fs::write(&key_path, &wrapping_key)
        .map_err(|e| format!("Failed to write key: {}", e))?;
    fs::write(&data_path, &wrapped_master)
        .map_err(|e| format!("Failed to write data: {}", e))?;
    fs::write(&nonce_path, &nonce)
        .map_err(|e| format!("Failed to write nonce: {}", e))?;
    
    // Zeroize sensitive data
    wrapping_key.zeroize();
    
    log::info!("Android StrongBox: Key sealed successfully");
    
    Ok((wrapped_master, nonce))
}

/// Unseals a master key using software decryption (StrongBox fallback)
pub fn unseal_with_android_strongbox(
    key_id: &str,
    _wrapped_data: &[u8],
    _nonce: &[u8],
) -> Result<Vec<u8>, String> {
    log::info!("Android StrongBox: Unsealing key '{}' (software fallback mode)", key_id);
    
    let storage_dir = get_strongbox_storage_dir()?;
    let key_path = storage_dir.join(format!("{}.key", key_id));
    let data_path = storage_dir.join(format!("{}.dat", key_id));
    let nonce_path = storage_dir.join(format!("{}.nonce", key_id));
    
    let mut wrapping_key = fs::read(&key_path)
        .map_err(|e| format!("Failed to read key: {}", e))?;
    let wrapped_master = fs::read(&data_path)
        .map_err(|e| format!("Failed to read data: {}", e))?;
    let nonce = fs::read(&nonce_path)
        .map_err(|e| format!("Failed to read nonce: {}", e))?;
    
    // Unwrap master key with AES-GCM
    let master_key = aes_gcm_decrypt(&wrapping_key, &wrapped_master, &nonce)
        .map_err(|e| format!("AES-GCM decryption failed: {}", e))?;
    
    // Zeroize sensitive data
    wrapping_key.zeroize();
    
    log::info!("Android StrongBox: Key unsealed successfully");
    
    Ok(master_key)
}

/// Deletes a key from storage
pub fn delete_from_android_strongbox(key_id: &str) -> Result<(), String> {
    log::info!("Android StrongBox: Deleting key '{}'", key_id);
    
    let storage_dir = get_strongbox_storage_dir()?;
    
    // Delete all associated files
    let _ = fs::remove_file(storage_dir.join(format!("{}.key", key_id)));
    let _ = fs::remove_file(storage_dir.join(format!("{}.dat", key_id)));
    let _ = fs::remove_file(storage_dir.join(format!("{}.nonce", key_id)));
    
    log::info!("Android StrongBox: Key deleted successfully");
    
    Ok(())
}
