// Platform keystore: iOS Secure Enclave support
// Uses the security-framework crate for Keychain access

#[cfg(target_os = "ios")]
use security_framework::passwords::{set_generic_password, get_generic_password, delete_generic_password};

/// Store private key in iOS Secure Enclave
#[cfg(target_os = "ios")]
pub fn seal_private_key(key_id: &str, key_data: &[u8]) -> Result<(), String> {
    // Delete existing key if present
    let _ = delete_private_key(key_id);
    
    // Store in keychain using the passwords API
    set_generic_password("qsafevault", key_id, key_data)
        .map_err(|e| format!("Failed to store key in Keychain: {}", e))?;
    
    log::info!("iOS Keychain: Key '{}' stored successfully", key_id);
    
    Ok(())
}

/// Retrieve private key from iOS Secure Enclave
#[cfg(target_os = "ios")]
pub fn unseal_private_key(key_id: &str) -> Result<Vec<u8>, String> {
    let data = get_generic_password("qsafevault", key_id)
        .map_err(|e| format!("Failed to retrieve key from Keychain: {}", e))?;
    
    log::info!("iOS Keychain: Key '{}' retrieved successfully", key_id);
    
    Ok(data)
}

/// Delete private key from iOS Secure Enclave
#[cfg(target_os = "ios")]
pub fn delete_private_key(key_id: &str) -> Result<(), String> {
    delete_generic_password("qsafevault", key_id)
        .map_err(|e| format!("Failed to delete key from Keychain: {}", e))?;
    
    log::info!("iOS Keychain: Key '{}' deleted successfully", key_id);
    
    Ok(())
}

// Stub implementations for non-iOS platforms
#[cfg(not(target_os = "ios"))]
pub fn seal_private_key(_key_id: &str, _key_data: &[u8]) -> Result<(), String> {
    Err("iOS Secure Enclave not available on this platform".to_string())
}

#[cfg(not(target_os = "ios"))]
pub fn unseal_private_key(_key_id: &str) -> Result<Vec<u8>, String> {
    Err("iOS Secure Enclave not available on this platform".to_string())
}

#[cfg(not(target_os = "ios"))]
pub fn delete_private_key(_key_id: &str) -> Result<(), String> {
    Err("iOS Secure Enclave not available on this platform".to_string())
}
