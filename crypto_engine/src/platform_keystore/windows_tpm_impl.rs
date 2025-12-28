// Windows TPM2 CNG/KSP Full Implementation
// Provides hardware-backed key storage using Windows CNG and TPM Key Storage Provider

#![cfg(target_os = "windows")]

use crate::symmetric::{aes_gcm_encrypt, aes_gcm_decrypt};
use std::fs;
use std::path::PathBuf;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::{
    NCryptOpenStorageProvider, NCryptCreatePersistedKey, NCryptSetProperty,
    NCryptFinalizeKey, NCryptDeleteKey, NCryptOpenKey, NCryptFreeObject,
    NCryptEncrypt, NCryptDecrypt,
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_HANDLE,
    NCRYPT_MACHINE_KEY_FLAG, NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_SILENT_FLAG,
    NCRYPT_PAD_PKCS1_FLAG, NCRYPT_FLAGS,
    MS_PLATFORM_CRYPTO_PROVIDER, BCRYPT_RSA_ALGORITHM, NCRYPT_LENGTH_PROPERTY,
    CERT_KEY_SPEC,
};
use zeroize::Zeroize;

const TPM_WRAPPED_KEYS_DIR: &str = "tpm_wrapped_keys";

/// Get the directory for storing TPM-wrapped keys
fn get_tpm_storage_dir() -> Result<PathBuf, String> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| "Could not determine local data directory".to_string())?;
    
    let dir = base.join("QSafeVault").join(TPM_WRAPPED_KEYS_DIR);
    fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create TPM storage directory: {}", e))?;
    
    Ok(dir)
}

/// Seals a master key using Windows TPM2 via CNG
pub fn seal_with_windows_tpm(
    key_id: &str,
    master_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    log::info!("Windows TPM2: Sealing key '{}'", key_id);
    
    unsafe {
        // Open TPM storage provider
        let mut provider = NCRYPT_PROV_HANDLE::default();
        
        NCryptOpenStorageProvider(
            &mut provider,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0,
        ).map_err(|e| format!("Failed to open TPM provider: {:?}", e))?;
        
        log::info!("Windows TPM2: Provider opened successfully");
        
        // Generate TPM-backed RSA key for wrapping
        let tpm_key = create_tpm_key(provider, key_id)?;
        
        log::info!("Windows TPM2: TPM key created");
        
        // Wrap the master key using the TPM key
        let (wrapped_key, nonce) = wrap_with_tpm_key(tpm_key, master_key)?;
        
        log::info!("Windows TPM2: Key wrapped successfully");
        
        // Clean up handles
        let _ = NCryptFreeObject(NCRYPT_HANDLE(tpm_key.0));
        let _ = NCryptFreeObject(NCRYPT_HANDLE(provider.0));
        
        // Store wrapped key to filesystem
        let storage_path = get_tpm_storage_dir()?.join(format!("{}.bin", key_id));
        fs::write(&storage_path, &wrapped_key)
            .map_err(|e| format!("Failed to write wrapped key: {}", e))?;
        
        log::info!("Windows TPM2: Wrapped key stored at {:?}", storage_path);
        
        Ok((wrapped_key, nonce))
    }
}

/// Unseals a master key using Windows TPM2 via CNG
pub fn unseal_with_windows_tpm(
    key_id: &str,
    wrapped_key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, String> {
    log::info!("Windows TPM2: Unsealing key '{}'", key_id);
    
    unsafe {
        // Open TPM storage provider
        let mut provider = NCRYPT_PROV_HANDLE::default();
        
        NCryptOpenStorageProvider(
            &mut provider,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0,
        ).map_err(|e| format!("Failed to open TPM provider: {:?}", e))?;
        
        // Open existing TPM key
        let tpm_key = open_tpm_key(provider, key_id)?;
        
        log::info!("Windows TPM2: TPM key opened");
        
        // Unwrap the master key
        let master_key = unwrap_with_tpm_key(tpm_key, wrapped_key, nonce)?;
        
        log::info!("Windows TPM2: Key unwrapped successfully");
        
        // Clean up handles
        let _ = NCryptFreeObject(NCRYPT_HANDLE(tpm_key.0));
        let _ = NCryptFreeObject(NCRYPT_HANDLE(provider.0));
        
        Ok(master_key)
    }
}

/// Deletes a TPM-sealed key
pub fn delete_from_windows_tpm(key_id: &str) -> Result<(), String> {
    log::info!("Windows TPM2: Deleting key '{}'", key_id);
    
    unsafe {
        // Open TPM storage provider
        let mut provider = NCRYPT_PROV_HANDLE::default();
        
        NCryptOpenStorageProvider(
            &mut provider,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0,
        ).map_err(|e| format!("Failed to open TPM provider: {:?}", e))?;
        
        // Open and delete the key
        if let Ok(tpm_key) = open_tpm_key(provider, key_id) {
            let _ = NCryptDeleteKey(tpm_key, 0u32);
            log::info!("Windows TPM2: TPM key deleted");
        }
        
        // Delete wrapped key file
        let storage_path = get_tpm_storage_dir()?.join(format!("{}.bin", key_id));
        if storage_path.exists() {
            fs::remove_file(&storage_path)
                .map_err(|e| format!("Failed to delete wrapped key file: {}", e))?;
            log::info!("Windows TPM2: Wrapped key file deleted");
        }
        
        let _ = NCryptFreeObject(NCRYPT_HANDLE(provider.0));
        
        Ok(())
    }
}

// Helper functions

unsafe fn create_tpm_key(
    provider: NCRYPT_PROV_HANDLE,
    key_id: &str,
) -> Result<NCRYPT_KEY_HANDLE, String> {
    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    let key_name: Vec<u16> = format!("QSafeVault_{}\0", key_id).encode_utf16().collect();
    
    // Create persisted RSA key in TPM
    NCryptCreatePersistedKey(
        provider,
        &mut key_handle,
        BCRYPT_RSA_ALGORITHM,
        PCWSTR(key_name.as_ptr()),
        CERT_KEY_SPEC(0), // AT_KEYEXCHANGE not needed for NCrypt
        NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_MACHINE_KEY_FLAG,
    ).map_err(|e| format!("Failed to create persisted key: {:?}", e))?;
    
    // Set key length to 2048 bits
    let key_length: u32 = 2048;
    let key_length_bytes = key_length.to_le_bytes();
    
    NCryptSetProperty(
        NCRYPT_HANDLE(key_handle.0),
        NCRYPT_LENGTH_PROPERTY,
        &key_length_bytes,
        NCRYPT_FLAGS(0),
    ).map_err(|e| {
        let _ = NCryptFreeObject(NCRYPT_HANDLE(key_handle.0));
        format!("Failed to set key length: {:?}", e)
    })?;
    
    // Finalize key creation
    NCryptFinalizeKey(
        key_handle,
        NCRYPT_SILENT_FLAG,
    ).map_err(|e| {
        let _ = NCryptFreeObject(NCRYPT_HANDLE(key_handle.0));
        format!("Failed to finalize key: {:?}", e)
    })?;
    
    Ok(key_handle)
}

unsafe fn open_tpm_key(
    provider: NCRYPT_PROV_HANDLE,
    key_id: &str,
) -> Result<NCRYPT_KEY_HANDLE, String> {
    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    let key_name: Vec<u16> = format!("QSafeVault_{}\0", key_id).encode_utf16().collect();
    
    NCryptOpenKey(
        provider,
        &mut key_handle,
        PCWSTR(key_name.as_ptr()),
        CERT_KEY_SPEC(0),
        NCRYPT_FLAGS(0),
    ).map_err(|e| format!("Failed to open TPM key: {:?}", e))?;
    
    Ok(key_handle)
}

unsafe fn wrap_with_tpm_key(
    tpm_key: NCRYPT_KEY_HANDLE,
    master_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Generate a random AES key for actual encryption
    use rand_core::RngCore;
    let mut wrapping_key = vec![0u8; 32];
    rand_core::OsRng.fill_bytes(&mut wrapping_key);
    
    // First call to get required output size
    let mut encrypted_aes_key_len: u32 = 0;
    NCryptEncrypt(
        tpm_key,
        Some(&wrapping_key),
        None,
        None,
        &mut encrypted_aes_key_len,
        NCRYPT_PAD_PKCS1_FLAG,
    ).map_err(|e| {
        wrapping_key.zeroize();
        format!("Failed to get encrypted key length: {:?}", e)
    })?;
    
    // Allocate output buffer and encrypt
    let mut encrypted_aes_key = vec![0u8; encrypted_aes_key_len as usize];
    NCryptEncrypt(
        tpm_key,
        Some(&wrapping_key),
        None,
        Some(&mut encrypted_aes_key),
        &mut encrypted_aes_key_len,
        NCRYPT_PAD_PKCS1_FLAG,
    ).map_err(|e| {
        wrapping_key.zeroize();
        format!("Failed to encrypt AES key: {:?}", e)
    })?;
    
    encrypted_aes_key.truncate(encrypted_aes_key_len as usize);
    
    // Wrap master key with AES-GCM
    let (wrapped_master, nonce) = aes_gcm_encrypt(&wrapping_key, master_key)
        .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;
    
    // Combine: [encrypted_aes_key_len(4) | encrypted_aes_key | wrapped_master]
    let mut combined = Vec::with_capacity(4 + encrypted_aes_key.len() + wrapped_master.len());
    combined.extend_from_slice(&(encrypted_aes_key.len() as u32).to_le_bytes());
    combined.extend_from_slice(&encrypted_aes_key);
    combined.extend_from_slice(&wrapped_master);
    
    // Zeroize sensitive data
    wrapping_key.zeroize();
    
    Ok((combined, nonce))
}

unsafe fn unwrap_with_tpm_key(
    tpm_key: NCRYPT_KEY_HANDLE,
    wrapped_data: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, String> {
    // Parse combined data
    if wrapped_data.len() < 4 {
        return Err("Invalid wrapped data format".to_string());
    }
    
    let encrypted_aes_key_len = u32::from_le_bytes([
        wrapped_data[0],
        wrapped_data[1],
        wrapped_data[2],
        wrapped_data[3],
    ]) as usize;
    
    if wrapped_data.len() < 4 + encrypted_aes_key_len {
        return Err("Invalid wrapped data format".to_string());
    }
    
    let encrypted_aes_key = &wrapped_data[4..4 + encrypted_aes_key_len];
    let wrapped_master = &wrapped_data[4 + encrypted_aes_key_len..];
    
    // First call to get required output size
    let mut wrapping_key_len: u32 = 0;
    NCryptDecrypt(
        tpm_key,
        Some(encrypted_aes_key),
        None,
        None,
        &mut wrapping_key_len,
        NCRYPT_PAD_PKCS1_FLAG,
    ).map_err(|e| format!("Failed to get decrypted key length: {:?}", e))?;
    
    // Allocate output buffer and decrypt
    let mut wrapping_key = vec![0u8; wrapping_key_len as usize];
    NCryptDecrypt(
        tpm_key,
        Some(encrypted_aes_key),
        None,
        Some(&mut wrapping_key),
        &mut wrapping_key_len,
        NCRYPT_PAD_PKCS1_FLAG,
    ).map_err(|e| {
        wrapping_key.zeroize();
        format!("Failed to decrypt AES key: {:?}", e)
    })?;
    
    wrapping_key.truncate(wrapping_key_len as usize);
    
    // Unwrap master key with AES-GCM
    let master_key = aes_gcm_decrypt(&wrapping_key, wrapped_master, nonce)
        .map_err(|e| format!("AES-GCM decryption failed: {}", e))?;
    
    // Zeroize sensitive data
    wrapping_key.zeroize();
    
    Ok(master_key)
}
