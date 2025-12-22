// Platform keystore: macOS Secure Enclave support
#[cfg(target_os = "macos")]
use security_framework::item::{ItemClass, ItemSearchOptions, Limit};

/// Store private key in macOS Keychain (with T2/Secure Enclave if available)
#[cfg(target_os = "macos")]
pub fn seal_private_key(key_id: &str, key_data: &[u8]) -> Result<(), String> {
    use security_framework::item::{ItemAddOptions, ItemSearchOptions};
    
    // Delete existing key if present
    let _ = unseal_private_key(key_id);
    let _ = delete_private_key(key_id);
    
    // Store in keychain
    let mut add_opts = ItemAddOptions::new(ItemClass::generic_password());
    add_opts.set_service(key_id);
    add_opts.set_account("qsafevault");
    add_opts.set_value_data(key_data);
    add_opts.set_accessible(security_framework::item::Accessible::WhenUnlockedThisDeviceOnly);
    
    add_opts.add().map_err(|e| format!("Failed to store key: {}", e))?;
    
    Ok(())
}

/// Retrieve private key from macOS Keychain
#[cfg(target_os = "macos")]
pub fn unseal_private_key(key_id: &str) -> Result<Vec<u8>, String> {
    let mut search = ItemSearchOptions::new();
    search.class(ItemClass::generic_password());
    search.service(key_id);
    search.account("qsafevault");
    search.limit(Limit::One);
    search.load_data(true);
    
    let results = search.search().map_err(|e| format!("Failed to retrieve key: {}", e))?;
    
    if results.is_empty() {
        return Err("Key not found".to_string());
    }
    
    let item = &results[0];
    let data = item.data().ok_or("No data in keychain item")?;
    
    Ok(data.to_vec())
}

/// Delete private key from macOS Keychain
#[cfg(target_os = "macos")]
pub fn delete_private_key(key_id: &str) -> Result<(), String> {
    let mut search = ItemSearchOptions::new();
    search.class(ItemClass::generic_password());
    search.service(key_id);
    search.account("qsafevault");
    
    search.delete().map_err(|e| format!("Failed to delete key: {}", e))?;
    
    Ok(())
}

// Stub implementations for non-macOS platforms
#[cfg(not(target_os = "macos"))]
pub fn seal_private_key(_key_id: &str, _key_data: &[u8]) -> Result<(), String> {
    Err("macOS Keychain not available on this platform".to_string())
}

#[cfg(not(target_os = "macos"))]
pub fn unseal_private_key(_key_id: &str) -> Result<Vec<u8>, String> {
    Err("macOS Keychain not available on this platform".to_string())
}

#[cfg(not(target_os = "macos"))]
pub fn delete_private_key(_key_id: &str) -> Result<(), String> {
    Err("macOS Keychain not available on this platform".to_string())
}
