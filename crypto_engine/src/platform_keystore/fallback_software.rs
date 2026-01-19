// Platform keystore: Software fallback for platforms without secure hardware
use std::fs;
use std::path::PathBuf;

/// Get the storage path for software-based keystore
fn get_keystore_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;
    let keystore_dir = home.join(".qsafevault").join("keystore");
    fs::create_dir_all(&keystore_dir)
        .map_err(|e| format!("Failed to create keystore directory: {}", e))?;
    Ok(keystore_dir)
}

/// Generate file path for a specific key
fn get_key_path(key_id: &str) -> Result<PathBuf, String> {
    let keystore_dir = get_keystore_path()?;
    // Use a hash of the key_id to avoid filesystem issues
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(key_id.as_bytes());
    let hash = hasher.finalize();
    let filename = format!("{:x}.key", hash);
    Ok(keystore_dir.join(filename))
}

/// Store private key in software keystore (fallback)
/// WARNING: This is not hardware-backed and should only be used as a fallback
pub fn seal_private_key(key_id: &str, key_data: &[u8]) -> Result<(), String> {
    let key_path = get_key_path(key_id)?;
    
    // Write key to file with restricted permissions
    fs::write(&key_path, key_data)
        .map_err(|e| format!("Failed to write key: {}", e))?;
    
    // Set permissions to 600 (owner read/write only) on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&key_path, perms)
            .map_err(|e| format!("Failed to set permissions: {}", e))?;
    }
    
    Ok(())
}

/// Retrieve private key from software keystore
pub fn unseal_private_key(key_id: &str) -> Result<Vec<u8>, String> {
    let key_path = get_key_path(key_id)?;
    
    if !key_path.exists() {
        return Err("Key not found".to_string());
    }
    
    fs::read(&key_path)
        .map_err(|e| format!("Failed to read key: {}", e))
}

/// Delete private key from software keystore
pub fn delete_private_key(key_id: &str) -> Result<(), String> {
    let key_path = get_key_path(key_id)?;
    
    if !key_path.exists() {
        return Ok(()); // Already deleted
    }
    
    // Securely wipe file contents before deletion
    if let Ok(metadata) = fs::metadata(&key_path) {
        let size = metadata.len() as usize;
        let zeros = vec![0u8; size];
        let _ = fs::write(&key_path, zeros);
    }
    
    fs::remove_file(&key_path)
        .map_err(|e| format!("Failed to delete key: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_keystore_roundtrip() {
        let key_id = "test_key_123";
        let key_data = b"test_secret_key_data";

        // Seal
        seal_private_key(key_id, key_data).unwrap();

        // Unseal
        let retrieved = unseal_private_key(key_id).unwrap();
        assert_eq!(key_data, retrieved.as_slice());

        // Delete
        delete_private_key(key_id).unwrap();

        // Verify deleted
        let result = unseal_private_key(key_id);
        assert!(result.is_err());
    }
}
