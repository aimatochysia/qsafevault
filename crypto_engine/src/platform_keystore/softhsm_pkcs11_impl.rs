// SoftHSM PKCS#11 Full Implementation
// Provides PKCS#11-based key wrapping/unwrapping using SoftHSM tokens
//
// Uses the pkcs11 crate for PKCS#11 interface
// Keys are stored securely within the HSM token and never extracted

#![cfg(not(target_os = "android"))]
#![allow(static_mut_refs)]

use std::path::PathBuf;
use std::sync::Once;
use std::fs;
use pkcs11::Ctx;
use pkcs11::types::*;

static INIT: Once = Once::new();
static mut PKCS11_CTX: Option<Ctx> = None;

/// PKCS#11 library paths for different platforms
fn get_softhsm_paths() -> Vec<PathBuf> {
    vec![
        // Linux
        PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
        PathBuf::from("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"),
        PathBuf::from("/usr/lib64/pkcs11/libsofthsm2.so"),
        PathBuf::from("/usr/local/lib/softhsm/libsofthsm2.so"),
        
        // macOS
        PathBuf::from("/usr/local/lib/softhsm/libsofthsm2.so"),
        PathBuf::from("/opt/homebrew/lib/softhsm/libsofthsm2.so"),
        PathBuf::from("/usr/local/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so"),
        
        // Windows
        PathBuf::from("C:\\SoftHSM2\\lib\\softhsm2-x64.dll"),
        PathBuf::from("C:\\Program Files\\SoftHSM2\\lib\\softhsm2-x64.dll"),
        PathBuf::from("C:\\Program Files (x86)\\SoftHSM2\\lib\\softhsm2.dll"),
    ]
}

/// Get storage directory for SoftHSM encrypted data (not keys)
fn get_softhsm_storage_dir() -> Result<PathBuf, String> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| "Could not determine local data directory".to_string())?;
    
    let dir = base.join("QSafeVault").join("softhsm_data");
    fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create SoftHSM storage directory: {}", e))?;
    
    Ok(dir)
}

/// Find SoftHSM library path
fn find_softhsm_library() -> Option<PathBuf> {
    get_softhsm_paths()
        .into_iter()
        .find(|p| p.exists())
}

/// Initialize PKCS#11 context (called once)
fn init_pkcs11() -> Result<&'static Ctx, String> {
    unsafe {
        INIT.call_once(|| {
            if let Some(lib_path) = find_softhsm_library() {
                log::info!("SoftHSM: Loading library from {:?}", lib_path);
                match Ctx::new(lib_path) {
                    Ok(mut ctx) => {
                        // Initialize PKCS#11
                        if let Err(e) = ctx.initialize(None) {
                            log::error!("SoftHSM: Failed to initialize: {:?}", e);
                            return;
                        }
                        log::info!("SoftHSM: PKCS#11 initialized successfully");
                        PKCS11_CTX = Some(ctx);
                    }
                    Err(e) => {
                        log::error!("SoftHSM: Failed to load library: {:?}", e);
                    }
                }
            } else {
                log::warn!("SoftHSM: Library not found");
            }
        });
        
        PKCS11_CTX.as_ref().ok_or_else(|| "PKCS#11 context not initialized".to_string())
    }
}

/// Get first available slot with a token
fn get_token_slot(ctx: &Ctx) -> Result<CK_SLOT_ID, String> {
    let slots = ctx.get_slot_list(true)
        .map_err(|e| format!("Failed to get slot list: {:?}", e))?;
    
    slots.first()
        .cloned()
        .ok_or_else(|| "No token slots available".to_string())
}

/// Wraps a master key using PKCS#11 SoftHSM with hardware-protected encryption
/// The wrapping key remains in the HSM and is never extracted
/// Returns: (encrypted_data, iv) or error
pub fn seal_with_softhsm(
    key_id: &str,
    master_key: &[u8],
    pin: Option<&str>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    log::info!("SoftHSM: Sealing key '{}' using HSM-backed encryption", key_id);
    
    let ctx = init_pkcs11()?;
    let slot = get_token_slot(ctx)?;
    
    // Open session
    let session = ctx.open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)
        .map_err(|e| format!("Failed to open session: {:?}", e))?;
    
    log::info!("SoftHSM: Session opened");
    
    // Login with PIN
    let user_pin = pin.unwrap_or("1234");
    ctx.login(session, CKU_USER, Some(user_pin))
        .map_err(|e| format!("Failed to login: {:?}", e))?;
    
    log::info!("SoftHSM: Logged in");
    
    // Generate AES-256 key in the HSM token (non-extractable, sensitive)
    let key_label = format!("QSV_WK_{}", key_id);
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    
    let key_len: CK_ULONG = 32;
    let key_template = vec![
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&CKO_SECRET_KEY),
        CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&CKK_AES),
        CK_ATTRIBUTE::new(CKA_VALUE_LEN).with_ck_ulong(&key_len),
        CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&CK_TRUE),
        CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&CK_TRUE),
        CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&CK_TRUE),      // Key is sensitive
        CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&CK_FALSE),   // Cannot be extracted
        CK_ATTRIBUTE::new(CKA_ENCRYPT).with_bool(&CK_TRUE),
        CK_ATTRIBUTE::new(CKA_DECRYPT).with_bool(&CK_TRUE),
        CK_ATTRIBUTE::new(CKA_LABEL).with_bytes(key_label.as_bytes()),
    ];
    
    let wrapping_key_handle = ctx.generate_key(session, &mechanism, &key_template)
        .map_err(|e| format!("Failed to generate wrapping key in HSM: {:?}", e))?;
    
    log::info!("SoftHSM: Wrapping key generated in HSM token (non-extractable)");
    
    // Generate random IV for AES-CBC
    use rand_core::RngCore;
    let mut iv = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut iv);
    
    // Use AES-CBC encryption within the HSM
    let encrypt_mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        pParameter: iv.as_ptr() as *mut _,
        ulParameterLen: 16,
    };
    
    // Initialize encryption
    ctx.encrypt_init(session, &encrypt_mechanism, wrapping_key_handle)
        .map_err(|e| format!("Failed to init encryption: {:?}", e))?;
    
    // Encrypt the master key
    let encrypted_data = ctx.encrypt(session, master_key)
        .map_err(|e| format!("Failed to encrypt: {:?}", e))?;
    
    log::info!("SoftHSM: Master key encrypted using HSM");
    
    // Store encrypted data and IV to filesystem (keys stay in HSM)
    let storage_dir = get_softhsm_storage_dir()?;
    let data_path = storage_dir.join(format!("{}.enc", key_id));
    let iv_path = storage_dir.join(format!("{}.iv", key_id));
    
    fs::write(&data_path, &encrypted_data)
        .map_err(|e| format!("Failed to write encrypted data: {}", e))?;
    fs::write(&iv_path, &iv)
        .map_err(|e| format!("Failed to write IV: {}", e))?;
    
    // Logout and close session
    let _ = ctx.logout(session);
    let _ = ctx.close_session(session);
    
    log::info!("SoftHSM: Key sealed successfully (key remains in HSM)");
    
    Ok((encrypted_data, iv.to_vec()))
}

/// Unwraps a master key using PKCS#11 SoftHSM
#[allow(dead_code)]
pub fn unseal_with_softhsm(
    key_id: &str,
    _wrapped_key: &[u8],
    _nonce: &[u8],
    pin: Option<&str>,
) -> Result<Vec<u8>, String> {
    log::info!("SoftHSM: Unsealing key '{}' using HSM-backed decryption", key_id);
    
    let ctx = init_pkcs11()?;
    let slot = get_token_slot(ctx)?;
    
    // Open session
    let session = ctx.open_session(slot, CKF_SERIAL_SESSION, None, None)
        .map_err(|e| format!("Failed to open session: {:?}", e))?;
    
    log::info!("SoftHSM: Session opened");
    
    // Login with PIN
    let user_pin = pin.unwrap_or("1234");
    ctx.login(session, CKU_USER, Some(user_pin))
        .map_err(|e| format!("Failed to login: {:?}", e))?;
    
    log::info!("SoftHSM: Logged in");
    
    // Find wrapping key by label in the HSM
    let key_label = format!("QSV_WK_{}", key_id);
    let find_template = vec![
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&CKO_SECRET_KEY),
        CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&CKK_AES),
        CK_ATTRIBUTE::new(CKA_LABEL).with_bytes(key_label.as_bytes()),
    ];
    
    ctx.find_objects_init(session, &find_template)
        .map_err(|e| format!("Failed to init find: {:?}", e))?;
    
    let objects = ctx.find_objects(session, 1)
        .map_err(|e| format!("Failed to find objects: {:?}", e))?;
    
    ctx.find_objects_final(session)
        .map_err(|e| format!("Failed to finalize find: {:?}", e))?;
    
    if objects.is_empty() {
        let _ = ctx.logout(session);
        let _ = ctx.close_session(session);
        return Err(format!("Wrapping key not found in SoftHSM for: {}", key_id));
    }
    
    let wrapping_key_handle = objects[0];
    
    log::info!("SoftHSM: Wrapping key found in HSM");
    
    // Load encrypted data and IV from filesystem
    let storage_dir = get_softhsm_storage_dir()?;
    let data_path = storage_dir.join(format!("{}.enc", key_id));
    let iv_path = storage_dir.join(format!("{}.iv", key_id));
    
    let encrypted_data = fs::read(&data_path)
        .map_err(|e| format!("Failed to read encrypted data: {}", e))?;
    let iv = fs::read(&iv_path)
        .map_err(|e| format!("Failed to read IV: {}", e))?;
    
    // Use AES-CBC decryption within the HSM
    let decrypt_mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        pParameter: iv.as_ptr() as *mut _,
        ulParameterLen: iv.len() as CK_ULONG,
    };
    
    // Initialize decryption
    ctx.decrypt_init(session, &decrypt_mechanism, wrapping_key_handle)
        .map_err(|e| format!("Failed to init decryption: {:?}", e))?;
    
    // Decrypt the master key
    let master_key = ctx.decrypt(session, &encrypted_data)
        .map_err(|e| format!("Failed to decrypt: {:?}", e))?;
    
    log::info!("SoftHSM: Master key decrypted using HSM");
    
    // Logout and close session
    let _ = ctx.logout(session);
    let _ = ctx.close_session(session);
    
    log::info!("SoftHSM: Key unsealed successfully");
    
    Ok(master_key)
}

/// Deletes a key from SoftHSM
#[allow(dead_code)]
pub fn delete_from_softhsm(key_id: &str, pin: Option<&str>) -> Result<(), String> {
    log::info!("SoftHSM: Deleting key '{}'", key_id);
    
    let ctx = init_pkcs11()?;
    let slot = get_token_slot(ctx)?;
    
    // Open session
    let session = ctx.open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)
        .map_err(|e| format!("Failed to open session: {:?}", e))?;
    
    // Login with PIN
    let user_pin = pin.unwrap_or("1234");
    ctx.login(session, CKU_USER, Some(user_pin))
        .map_err(|e| format!("Failed to login: {:?}", e))?;
    
    // Find wrapping key by label
    let key_label = format!("QSV_WK_{}", key_id);
    let find_template = vec![
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&CKO_SECRET_KEY),
        CK_ATTRIBUTE::new(CKA_LABEL).with_bytes(key_label.as_bytes()),
    ];
    
    ctx.find_objects_init(session, &find_template)
        .map_err(|e| format!("Failed to init find: {:?}", e))?;
    
    let objects = ctx.find_objects(session, 1)
        .map_err(|e| format!("Failed to find objects: {:?}", e))?;
    
    ctx.find_objects_final(session)
        .map_err(|e| format!("Failed to finalize find: {:?}", e))?;
    
    // Delete key from HSM if found
    for obj in objects {
        ctx.destroy_object(session, obj)
            .map_err(|e| format!("Failed to destroy object: {:?}", e))?;
        log::info!("SoftHSM: Key object deleted from token");
    }
    
    // Delete encrypted data files from storage
    let storage_dir = get_softhsm_storage_dir()?;
    let _ = fs::remove_file(storage_dir.join(format!("{}.enc", key_id)));
    let _ = fs::remove_file(storage_dir.join(format!("{}.iv", key_id)));
    
    // Logout and close session
    let _ = ctx.logout(session);
    let _ = ctx.close_session(session);
    
    log::info!("SoftHSM: Key deletion completed");
    
    Ok(())
}
