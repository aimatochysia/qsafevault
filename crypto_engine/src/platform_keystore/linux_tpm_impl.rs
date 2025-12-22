// Linux TPM2 Full Implementation using tss-esapi
// Provides hardware-backed key storage using TPM2 Software Stack

#![cfg(all(target_os = "linux", feature = "tpm"))]

use crate::symmetric::{aes_gcm_encrypt, aes_gcm_decrypt};
use std::fs;
use std::path::PathBuf;
use std::convert::TryFrom;
use tss_esapi::{
    Context, TctiNameConf,
    structures::{
        Auth, CreatePrimaryKeyResult, Data, Digest, MaxBuffer, Public, PublicBuilder,
        SensitiveData,
    },
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        resource_handles::Hierarchy,
    },
    attributes::ObjectAttributesBuilder,
    handles::KeyHandle,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

const TPM_SEALED_KEYS_DIR: &str = "tpm_sealed_keys";

/// Get the directory for storing TPM-sealed keys
fn get_tpm_storage_dir() -> Result<PathBuf, String> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| "Could not determine local data directory".to_string())?;
    
    let dir = base.join("QSafeVault").join(TPM_SEALED_KEYS_DIR);
    fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create TPM storage directory: {}", e))?;
    
    Ok(dir)
}

/// Seals a master key using Linux TPM2
pub fn seal_with_linux_tpm(
    key_id: &str,
    master_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    log::info!("Linux TPM2: Sealing key '{}'", key_id);
    
    // Initialize TPM context
    let mut context = create_tpm_context()?;
    
    log::info!("Linux TPM2: Context created");
    
    // Create Storage Root Key (SRK) in endorsement hierarchy
    let srk = create_srk(&mut context)?;
    
    log::info!("Linux TPM2: SRK created");
    
    // Generate a random AES wrapping key
    use rand_core::RngCore;
    let mut wrapping_key = vec![0u8; 32];
    rand_core::OsRng.fill_bytes(&mut wrapping_key);
    
    // Seal the wrapping key to TPM
    let sealed_blob = seal_to_tpm(&mut context, srk, &wrapping_key)?;
    
    log::info!("Linux TPM2: Wrapping key sealed to TPM");
    
    // Wrap master key with AES-GCM
    let (wrapped_master, nonce) = aes_gcm_encrypt(&wrapping_key, master_key)
        .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;
    
    // Combine: [sealed_blob_len(4) | sealed_blob | wrapped_master]
    let mut combined = Vec::with_capacity(4 + sealed_blob.len() + wrapped_master.len());
    combined.extend_from_slice(&(sealed_blob.len() as u32).to_le_bytes());
    combined.extend_from_slice(&sealed_blob);
    combined.extend_from_slice(&wrapped_master);
    
    // Store to filesystem
    let storage_path = get_tpm_storage_dir()?.join(format!("{}.tpm", key_id));
    fs::write(&storage_path, &combined)
        .map_err(|e| format!("Failed to write sealed blob: {}", e))?;
    
    log::info!("Linux TPM2: Sealed blob stored at {:?}", storage_path);
    
    // Clean up
    wrapping_key.zeroize();
    let _ = context.flush_context(srk.into());
    
    Ok((combined, nonce))
}

/// Unseals a master key using Linux TPM2
pub fn unseal_with_linux_tpm(
    key_id: &str,
    wrapped_data: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, String> {
    log::info!("Linux TPM2: Unsealing key '{}'", key_id);
    
    // Parse combined data
    if wrapped_data.len() < 4 {
        return Err("Invalid wrapped data format".to_string());
    }
    
    let sealed_blob_len = u32::from_le_bytes([
        wrapped_data[0],
        wrapped_data[1],
        wrapped_data[2],
        wrapped_data[3],
    ]) as usize;
    
    if wrapped_data.len() < 4 + sealed_blob_len {
        return Err("Invalid wrapped data format".to_string());
    }
    
    let sealed_blob = &wrapped_data[4..4 + sealed_blob_len];
    let wrapped_master = &wrapped_data[4 + sealed_blob_len..];
    
    // Initialize TPM context
    let mut context = create_tpm_context()?;
    
    // Create SRK
    let srk = create_srk(&mut context)?;
    
    log::info!("Linux TPM2: SRK created");
    
    // Unseal wrapping key from TPM
    let mut wrapping_key = unseal_from_tpm(&mut context, srk, sealed_blob)?;
    
    log::info!("Linux TPM2: Wrapping key unsealed from TPM");
    
    // Unwrap master key with AES-GCM
    let master_key = aes_gcm_decrypt(&wrapping_key, wrapped_master, nonce)
        .map_err(|e| format!("AES-GCM decryption failed: {}", e))?;
    
    // Clean up
    wrapping_key.zeroize();
    let _ = context.flush_context(srk.into());
    
    log::info!("Linux TPM2: Key unsealed successfully");
    
    Ok(master_key)
}

/// Deletes a TPM-sealed key
pub fn delete_from_linux_tpm(key_id: &str) -> Result<(), String> {
    log::info!("Linux TPM2: Deleting key '{}'", key_id);
    
    // Delete sealed blob file
    let storage_path = get_tpm_storage_dir()?.join(format!("{}.tpm", key_id));
    if storage_path.exists() {
        fs::remove_file(&storage_path)
            .map_err(|e| format!("Failed to delete sealed blob: {}", e))?;
        log::info!("Linux TPM2: Sealed blob deleted");
    }
    
    Ok(())
}

// Helper functions

fn create_tpm_context() -> Result<Context, String> {
    // Try different TCTI configurations
    let tcti_configs = vec![
        "device:/dev/tpmrm0",
        "device:/dev/tpm0",
        "tabrmd:",
        "mssim:",
    ];
    
    for config_str in tcti_configs {
        if let Ok(tcti_conf) = TctiNameConf::from_str(config_str) {
            if let Ok(context) = Context::new(tcti_conf) {
                log::info!("Linux TPM2: Connected via {}", config_str);
                return Ok(context);
            }
        }
    }
    
    Err("Failed to connect to TPM2 device".to_string())
}

fn create_srk(context: &mut Context) -> Result<KeyHandle, String> {
    // Build SRK public area
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(true)
        .build()
        .map_err(|e| format!("Failed to build object attributes: {}", e))?;
    
    let primary_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(
            tss_esapi::structures::SymmetricDefinitionObject::Aes128Cfb,
            tss_esapi::structures::RsaScheme::Null,
            tss_esapi::structures::RsaKeyBits::Rsa2048,
            tss_esapi::structures::RsaExponent::default(),
        )
        .with_rsa_unique_identifier(tss_esapi::structures::PublicKeyRsa::default())
        .build()
        .map_err(|e| format!("Failed to build SRK public: {}", e))?;
    
    // Create primary key in owner hierarchy
    let result = context
        .create_primary(
            Hierarchy::Owner,
            primary_pub,
            None,
            None,
            None,
            None,
        )
        .map_err(|e| format!("Failed to create primary key: {}", e))?;
    
    Ok(result.key_handle)
}

fn seal_to_tpm(
    context: &mut Context,
    parent_handle: KeyHandle,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    // Build sealed object public area
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        .build()
        .map_err(|e| format!("Failed to build sealed object attributes: {}", e))?;
    
    let sealed_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_keyed_hash_parameters(
            tss_esapi::structures::KeyedHashScheme::Null,
        )
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(|e| format!("Failed to build sealed object public: {}", e))?;
    
    // Create sensitive data
    let sensitive_data = SensitiveData::try_from(data.to_vec())
        .map_err(|e| format!("Failed to create sensitive data: {}", e))?;
    
    // Create sealed object
    let result = context
        .create(
            parent_handle,
            sealed_pub,
            None,
            Some(sensitive_data),
            None,
            None,
        )
        .map_err(|e| format!("Failed to create sealed object: {}", e))?;
    
    // Serialize the private and public parts
    let private_bytes = result.out_private.as_ref();
    let public_bytes = result.out_public.marshall()
        .map_err(|e| format!("Failed to marshall public: {}", e))?;
    
    // Combine: [public_len(4) | public | private]
    let mut sealed_blob = Vec::with_capacity(4 + public_bytes.len() + private_bytes.len());
    sealed_blob.extend_from_slice(&(public_bytes.len() as u32).to_le_bytes());
    sealed_blob.extend_from_slice(&public_bytes);
    sealed_blob.extend_from_slice(private_bytes);
    
    Ok(sealed_blob)
}

fn unseal_from_tpm(
    context: &mut Context,
    parent_handle: KeyHandle,
    sealed_blob: &[u8],
) -> Result<Vec<u8>, String> {
    // Parse sealed blob
    if sealed_blob.len() < 4 {
        return Err("Invalid sealed blob format".to_string());
    }
    
    let public_len = u32::from_le_bytes([
        sealed_blob[0],
        sealed_blob[1],
        sealed_blob[2],
        sealed_blob[3],
    ]) as usize;
    
    if sealed_blob.len() < 4 + public_len {
        return Err("Invalid sealed blob format".to_string());
    }
    
    let public_bytes = &sealed_blob[4..4 + public_len];
    let private_bytes = &sealed_blob[4 + public_len..];
    
    // Unmarshal public
    let public = Public::unmarshall(public_bytes)
        .map_err(|e| format!("Failed to unmarshall public: {}", e))?;
    
    // Create TPM2B_PRIVATE from bytes
    let private = tss_esapi::structures::Private::try_from(private_bytes.to_vec())
        .map_err(|e| format!("Failed to create private: {}", e))?;
    
    // Load the sealed object
    let loaded_handle = context
        .load(parent_handle, private, public)
        .map_err(|e| format!("Failed to load sealed object: {}", e))?;
    
    // Unseal the data
    let unsealed = context
        .unseal(loaded_handle.into())
        .map_err(|e| format!("Failed to unseal: {}", e))?;
    
    // Clean up
    let _ = context.flush_context(loaded_handle.into());
    
    Ok(unsealed.as_ref().to_vec())
}
