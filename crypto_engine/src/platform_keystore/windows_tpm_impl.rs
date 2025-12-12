// Windows TPM2 CNG/KSP Full Implementation
// Provides hardware-backed key storage using Windows CNG and TPM Key Storage Provider

#![cfg(target_os = "windows")]

use crate::symmetric::{aes_gcm_encrypt, aes_gcm_decrypt};
use std::fs;
use std::path::PathBuf;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::{
    NCryptOpenStorageProvider, NCryptCreatePersistedKey, NCryptSetProperty,
    NCryptFinalizeKey, NCryptDeleteKey, NCryptOpenKey, NCryptExportKey,
    NCryptEncrypt, NCryptDecrypt, NCryptFreeObject,
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_MACHINE_KEY_FLAG,
    NCRYPT_OVERWRITE_KEY_FLAG, MS_PLATFORM_CRYPTO_PROVIDER,
    BCRYPT_RSA_ALGORITHM, NCRYPT_LENGTH_PROPERTY, NCRYPT_ALLOW_EXPORT_FLAG,
    NCRYPT_EXPORT_POLICY_PROPERTY, BCRYPT_PAD_PKCS1,
};
use windows::Win32::Foundation::{ERROR_SUCCESS, HRESULT};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
        let provider_name = encode_wide(MS_PLATFORM_CRYPTO_PROVIDER);
        
        let result = NCryptOpenStorageProvider(
            &mut provider,
            PCWSTR(provider_name.as_ptr()),
            0,
        );
        
        if result.is_err() {
            return Err(format!("Failed to open TPM provider: {:?}", result));
        }
        
        log::info!("Windows TPM2: Provider opened successfully");
        
        // Generate TPM-backed RSA key for wrapping
        let tpm_key = create_tpm_key(&provider, key_id)?;
        
        log::info!("Windows TPM2: TPM key created");
        
        // Wrap the master key using the TPM key
        let (wrapped_key, nonce) = wrap_with_tpm_key(tpm_key, master_key)?;
        
        log::info!("Windows TPM2: Key wrapped successfully");
        
        // Clean up
        let _ = NCryptFreeObject(tpm_key.0 as isize);
        let _ = NCryptFreeObject(provider.0 as isize);
        
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
        let provider_name = encode_wide(MS_PLATFORM_CRYPTO_PROVIDER);
        
        let result = NCryptOpenStorageProvider(
            &mut provider,
            PCWSTR(provider_name.as_ptr()),
            0,
        );
        
        if result.is_err() {
            return Err(format!("Failed to open TPM provider: {:?}", result));
        }
        
        // Open existing TPM key
        let tpm_key = open_tpm_key(&provider, key_id)?;
        
        log::info!("Windows TPM2: TPM key opened");
        
        // Unwrap the master key
        let master_key = unwrap_with_tpm_key(tpm_key, wrapped_key, nonce)?;
        
        log::info!("Windows TPM2: Key unwrapped successfully");
        
        // Clean up
        let _ = NCryptFreeObject(tpm_key.0 as isize);
        let _ = NCryptFreeObject(provider.0 as isize);
        
        Ok(master_key)
    }
}

/// Deletes a TPM-sealed key
pub fn delete_from_windows_tpm(key_id: &str) -> Result<(), String> {
    log::info!("Windows TPM2: Deleting key '{}'", key_id);
    
    unsafe {
        // Open TPM storage provider
        let mut provider = NCRYPT_PROV_HANDLE::default();
        let provider_name = encode_wide(MS_PLATFORM_CRYPTO_PROVIDER);
        
        let result = NCryptOpenStorageProvider(
            &mut provider,
            PCWSTR(provider_name.as_ptr()),
            0,
        );
        
        if result.is_err() {
            return Err(format!("Failed to open TPM provider: {:?}", result));
        }
        
        // Open and delete the key
        if let Ok(tpm_key) = open_tpm_key(&provider, key_id) {
            let _ = NCryptDeleteKey(tpm_key, 0);
            log::info!("Windows TPM2: TPM key deleted");
        }
        
        // Delete wrapped key file
        let storage_path = get_tpm_storage_dir()?.join(format!("{}.bin", key_id));
        if storage_path.exists() {
            fs::remove_file(&storage_path)
                .map_err(|e| format!("Failed to delete wrapped key file: {}", e))?;
            log::info!("Windows TPM2: Wrapped key file deleted");
        }
        
        let _ = NCryptFreeObject(provider.0 as isize);
        
        Ok(())
    }
}

// Helper functions

unsafe fn create_tpm_key(
    provider: &NCRYPT_PROV_HANDLE,
    key_id: &str,
) -> Result<NCRYPT_KEY_HANDLE, String> {
    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    let key_name = encode_wide(&format!("QSafeVault_{}", key_id));
    let algorithm = encode_wide(BCRYPT_RSA_ALGORITHM);
    
    // Create persisted key
    let result = NCryptCreatePersistedKey(
        *provider,
        &mut key_handle,
        PCWSTR(algorithm.as_ptr()),
        PCWSTR(key_name.as_ptr()),
        0,
        NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_MACHINE_KEY_FLAG,
    );
    
    if result.is_err() {
        return Err(format!("Failed to create persisted key: {:?}", result));
    }
    
    // Set key length to 2048 bits
    let key_length: u32 = 2048;
    let length_property = encode_wide(NCRYPT_LENGTH_PROPERTY);
    let result = NCryptSetProperty(
        key_handle,
        PCWSTR(length_property.as_ptr()),
        &key_length as *const u32 as *const u8,
        4,
        0,
    );
    
    if result.is_err() {
        let _ = NCryptFreeObject(key_handle.0 as isize);
        return Err(format!("Failed to set key length: {:?}", result));
    }
    
    // Allow export for wrapping operations
    let export_policy: u32 = NCRYPT_ALLOW_EXPORT_FLAG.0;
    let export_property = encode_wide(NCRYPT_EXPORT_POLICY_PROPERTY);
    let _ = NCryptSetProperty(
        key_handle,
        PCWSTR(export_property.as_ptr()),
        &export_policy as *const u32 as *const u8,
        4,
        0,
    );
    
    // Finalize key creation
    let result = NCryptFinalizeKey(key_handle, 0);
    
    if result.is_err() {
        let _ = NCryptFreeObject(key_handle.0 as isize);
        return Err(format!("Failed to finalize key: {:?}", result));
    }
    
    Ok(key_handle)
}

unsafe fn open_tpm_key(
    provider: &NCRYPT_PROV_HANDLE,
    key_id: &str,
) -> Result<NCRYPT_KEY_HANDLE, String> {
    let mut key_handle = NCRYPT_KEY_HANDLE::default();
    let key_name = encode_wide(&format!("QSafeVault_{}", key_id));
    
    let result = NCryptOpenKey(
        *provider,
        &mut key_handle,
        PCWSTR(key_name.as_ptr()),
        0,
        0,
    );
    
    if result.is_err() {
        return Err(format!("Failed to open TPM key: {:?}", result));
    }
    
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
    
    // Encrypt the AES key with TPM RSA key
    let mut encrypted_aes_key_len: u32 = 0;
    let result = NCryptEncrypt(
        tpm_key,
        wrapping_key.as_ptr(),
        wrapping_key.len() as u32,
        None,
        std::ptr::null_mut(),
        0,
        &mut encrypted_aes_key_len,
        BCRYPT_PAD_PKCS1,
    );
    
    if result.is_err() {
        wrapping_key.zeroize();
        return Err(format!("Failed to get encrypted key length: {:?}", result));
    }
    
    let mut encrypted_aes_key = vec![0u8; encrypted_aes_key_len as usize];
    let result = NCryptEncrypt(
        tpm_key,
        wrapping_key.as_ptr(),
        wrapping_key.len() as u32,
        None,
        encrypted_aes_key.as_mut_ptr(),
        encrypted_aes_key.len() as u32,
        &mut encrypted_aes_key_len,
        BCRYPT_PAD_PKCS1,
    );
    
    if result.is_err() {
        wrapping_key.zeroize();
        return Err(format!("Failed to encrypt AES key: {:?}", result));
    }
    
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
    
    // Decrypt AES key with TPM RSA key
    let mut wrapping_key_len: u32 = 0;
    let result = NCryptDecrypt(
        tpm_key,
        encrypted_aes_key.as_ptr(),
        encrypted_aes_key.len() as u32,
        None,
        std::ptr::null_mut(),
        0,
        &mut wrapping_key_len,
        BCRYPT_PAD_PKCS1,
    );
    
    if result.is_err() {
        return Err(format!("Failed to get decrypted key length: {:?}", result));
    }
    
    let mut wrapping_key = vec![0u8; wrapping_key_len as usize];
    let result = NCryptDecrypt(
        tpm_key,
        encrypted_aes_key.as_ptr(),
        encrypted_aes_key.len() as u32,
        None,
        wrapping_key.as_mut_ptr(),
        wrapping_key.len() as u32,
        &mut wrapping_key_len,
        BCRYPT_PAD_PKCS1,
    );
    
    if result.is_err() {
        wrapping_key.zeroize();
        return Err(format!("Failed to decrypt AES key: {:?}", result));
    }
    
    // Unwrap master key with AES-GCM
    let master_key = aes_gcm_decrypt(&wrapping_key[..32], wrapped_master, nonce)
        .map_err(|e| format!("AES-GCM decryption failed: {}", e))?;
    
    // Zeroize sensitive data
    wrapping_key.zeroize();
    
    Ok(master_key)
}

fn encode_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
