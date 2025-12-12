// FFI layer: C ABI for Flutter integration
// All functions return status codes and use out-parameters for data

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::slice;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::hybrid_kem::{HybridKeypair, HybridCiphertext, encapsulate as hybrid_encapsulate};
use crate::symmetric::{SymmetricKey, EncryptedData, encrypt, decrypt};
use crate::sealed_storage::{SealedBlob, AlgorithmId};
use crate::platform_keystore::PlatformKeystore;

// Status codes
pub const STATUS_OK: c_int = 0;
pub const STATUS_ERROR: c_int = -1;
pub const STATUS_INVALID_PARAM: c_int = -2;
pub const STATUS_NOT_FOUND: c_int = -3;

// Global handle storage
lazy_static::lazy_static! {
    static ref KEYPAIR_HANDLES: Mutex<HashMap<u64, HybridKeypair>> = Mutex::new(HashMap::new());
    static ref KEY_HANDLES: Mutex<HashMap<u64, SymmetricKey>> = Mutex::new(HashMap::new());
}

static mut NEXT_HANDLE: u64 = 1;

fn next_handle() -> u64 {
    unsafe {
        let handle = NEXT_HANDLE;
        NEXT_HANDLE += 1;
        handle
    }
}

/// Generate a new hybrid keypair (PQC + Classical)
/// Returns handle to keypair, public keys written to out parameters
#[no_mangle]
pub extern "C" fn pqcrypto_generate_hybrid_keypair(
    keypair_handle_out: *mut u64,
    pqc_public_key_out: *mut *mut u8,
    pqc_public_key_len_out: *mut usize,
    classical_public_key_out: *mut u8, // 32 bytes fixed
    error_msg_out: *mut *mut c_char,
) -> c_int {
    if keypair_handle_out.is_null() || pqc_public_key_out.is_null() 
        || pqc_public_key_len_out.is_null() || classical_public_key_out.is_null() {
        return STATUS_INVALID_PARAM;
    }

    match std::panic::catch_unwind(|| {
        // Generate keypair
        let keypair = HybridKeypair::generate();
        let (pqc_pk, classical_pk) = keypair.public_keys_bytes();
        
        // Allocate and copy PQC public key
        let pqc_pk_len = pqc_pk.len();
        let pqc_pk_ptr = unsafe {
            let ptr = libc::malloc(pqc_pk_len) as *mut u8;
            if ptr.is_null() {
                return Err("Memory allocation failed".to_string());
            }
            std::ptr::copy_nonoverlapping(pqc_pk.as_ptr(), ptr, pqc_pk_len);
            ptr
        };
        
        // Copy classical public key (32 bytes fixed)
        unsafe {
            std::ptr::copy_nonoverlapping(classical_pk.as_ptr(), classical_public_key_out, 32);
        }
        
        // Store keypair and return handle
        let handle = next_handle();
        KEYPAIR_HANDLES.lock().unwrap().insert(handle, keypair);
        
        unsafe {
            *keypair_handle_out = handle;
            *pqc_public_key_out = pqc_pk_ptr;
            *pqc_public_key_len_out = pqc_pk_len;
        }
        
        Ok(())
    }) {
        Ok(Ok(())) => STATUS_OK,
        Ok(Err(e)) => {
            if !error_msg_out.is_null() {
                if let Ok(c_str) = CString::new(e) {
                    unsafe { *error_msg_out = c_str.into_raw(); }
                }
            }
            STATUS_ERROR
        }
        Err(_) => STATUS_ERROR,
    }
}

/// Hybrid encrypt a master key
/// Encapsulates to public keys, then wraps the master key with the shared secret
#[no_mangle]
pub extern "C" fn pqcrypto_hybrid_encrypt_master_key(
    pqc_public_key: *const u8,
    pqc_public_key_len: usize,
    classical_public_key: *const u8, // 32 bytes
    master_key: *const u8, // 32 bytes
    sealed_blob_out: *mut *mut u8,
    sealed_blob_len_out: *mut usize,
    error_msg_out: *mut *mut c_char,
) -> c_int {
    if pqc_public_key.is_null() || classical_public_key.is_null() 
        || master_key.is_null() || sealed_blob_out.is_null() 
        || sealed_blob_len_out.is_null() {
        return STATUS_INVALID_PARAM;
    }

    match std::panic::catch_unwind(|| {
        let pqc_pk = unsafe { slice::from_raw_parts(pqc_public_key, pqc_public_key_len) };
        let classical_pk: &[u8; 32] = unsafe { &*(classical_public_key as *const [u8; 32]) };
        let master_key_bytes: &[u8; 32] = unsafe { &*(master_key as *const [u8; 32]) };
        
        // Perform hybrid encapsulation
        let (shared_secret, hybrid_ct) = hybrid_encapsulate(pqc_pk, classical_pk)
            .map_err(|e| format!("Hybrid encapsulation failed: {}", e))?;
        
        // Use shared secret to encrypt master key
        let sym_key = SymmetricKey::from_bytes(shared_secret.secret);
        let encrypted = encrypt(&sym_key, master_key_bytes, None)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Create sealed blob
        let mut blob_data = Vec::new();
        blob_data.extend_from_slice(&hybrid_ct.to_bytes());
        blob_data.push(0xFF); // Separator
        blob_data.extend_from_slice(&encrypted.to_bytes());
        
        let sealed_blob = SealedBlob::new(AlgorithmId::HybridKemAes256Gcm, blob_data, None);
        let sealed_bytes = sealed_blob.to_bytes()
            .map_err(|e| format!("Serialization failed: {}", e))?;
        
        // Allocate and copy sealed blob
        let sealed_len = sealed_bytes.len();
        let sealed_ptr = unsafe {
            let ptr = libc::malloc(sealed_len) as *mut u8;
            if ptr.is_null() {
                return Err("Memory allocation failed".to_string());
            }
            std::ptr::copy_nonoverlapping(sealed_bytes.as_ptr(), ptr, sealed_len);
            ptr
        };
        
        unsafe {
            *sealed_blob_out = sealed_ptr;
            *sealed_blob_len_out = sealed_len;
        }
        
        Ok(())
    }) {
        Ok(Ok(())) => STATUS_OK,
        Ok(Err(e)) => {
            if !error_msg_out.is_null() {
                if let Ok(c_str) = CString::new(e) {
                    unsafe { *error_msg_out = c_str.into_raw(); }
                }
            }
            STATUS_ERROR
        }
        Err(_) => STATUS_ERROR,
    }
}

/// Hybrid decrypt a master key
/// Decapsulates ciphertext with keypair, then unwraps the master key
#[no_mangle]
pub extern "C" fn pqcrypto_hybrid_decrypt_master_key(
    keypair_handle: u64,
    sealed_blob: *const u8,
    sealed_blob_len: usize,
    master_key_out: *mut u8, // 32 bytes
    error_msg_out: *mut *mut c_char,
) -> c_int {
    if sealed_blob.is_null() || master_key_out.is_null() {
        return STATUS_INVALID_PARAM;
    }

    match std::panic::catch_unwind(|| {
        let sealed_bytes = unsafe { slice::from_raw_parts(sealed_blob, sealed_blob_len) };
        
        // Deserialize sealed blob
        let blob = SealedBlob::from_bytes(sealed_bytes)
            .map_err(|e| format!("Deserialization failed: {}", e))?;
        blob.validate()
            .map_err(|e| format!("Validation failed: {}", e))?;
        
        // Find separator
        let separator_pos = blob.ciphertext.iter().position(|&b| b == 0xFF)
            .ok_or("Invalid blob format: separator not found")?;
        
        let hybrid_ct_bytes = &blob.ciphertext[..separator_pos];
        let encrypted_bytes = &blob.ciphertext[separator_pos+1..];
        
        // Deserialize components
        let hybrid_ct = HybridCiphertext::from_bytes(hybrid_ct_bytes)
            .map_err(|e| format!("Invalid hybrid ciphertext: {}", e))?;
        let encrypted = EncryptedData::from_bytes(encrypted_bytes)
            .map_err(|e| format!("Invalid encrypted data: {}", e))?;
        
        // Get keypair
        let keypairs = KEYPAIR_HANDLES.lock().unwrap();
        let keypair = keypairs.get(&keypair_handle)
            .ok_or("Invalid keypair handle")?;
        
        // Decapsulate to get shared secret
        let shared_secret = keypair.decapsulate(&hybrid_ct)
            .map_err(|e| format!("Decapsulation failed: {}", e))?;
        
        // Decrypt master key
        let sym_key = SymmetricKey::from_bytes(shared_secret.secret);
        let master_key_bytes = decrypt(&sym_key, &encrypted, None)
            .map_err(|e| format!("Decryption failed: {}", e))?;
        
        if master_key_bytes.len() != 32 {
            return Err("Invalid master key length".to_string());
        }
        
        // Copy master key to output
        unsafe {
            std::ptr::copy_nonoverlapping(master_key_bytes.as_ptr(), master_key_out, 32);
        }
        
        Ok(())
    }) {
        Ok(Ok(())) => STATUS_OK,
        Ok(Err(e)) => {
            if !error_msg_out.is_null() {
                if let Ok(c_str) = CString::new(e) {
                    unsafe { *error_msg_out = c_str.into_raw(); }
                }
            }
            STATUS_ERROR
        }
        Err(_) => STATUS_ERROR,
    }
}

/// Seal private key with platform keystore
#[no_mangle]
pub extern "C" fn pqcrypto_seal_private_key_with_platform_keystore(
    keypair_handle: u64,
    key_id: *const c_char,
    error_msg_out: *mut *mut c_char,
) -> c_int {
    if key_id.is_null() {
        return STATUS_INVALID_PARAM;
    }

    match std::panic::catch_unwind(|| -> Result<(), String> {
        let key_id_str = unsafe { CStr::from_ptr(key_id).to_str() }
            .map_err(|_| "Invalid key ID".to_string())?;
        
        // Get keypair
        let keypairs = KEYPAIR_HANDLES.lock().unwrap();
        let keypair = keypairs.get(&keypair_handle)
            .ok_or("Invalid keypair handle")?;
        
        // Serialize secret keys
        let (pqc_sk, classical_sk) = keypair.secret_keys_bytes();
        
        // Combine both secret keys
        let mut combined_sk = Vec::new();
        combined_sk.extend_from_slice(&(pqc_sk.len() as u32).to_le_bytes());
        combined_sk.extend_from_slice(&pqc_sk);
        combined_sk.extend_from_slice(&classical_sk);
        
        // Seal with platform keystore
        PlatformKeystore::seal_key(key_id_str, &combined_sk)
            .map_err(|e| format!("Failed to seal key: {}", e))?;
        
        Ok(())
    }) {
        Ok(Ok(())) => STATUS_OK,
        Ok(Err(e)) => {
            if !error_msg_out.is_null() {
                if let Ok(c_str) = CString::new(e) {
                    unsafe { *error_msg_out = c_str.into_raw(); }
                }
            }
            STATUS_ERROR
        }
        Err(_) => STATUS_ERROR,
    }
}

/// Unseal private key from platform keystore
#[no_mangle]
pub extern "C" fn pqcrypto_unseal_private_key_from_platform_keystore(
    key_id: *const c_char,
    pqc_public_key: *const u8,
    pqc_public_key_len: usize,
    classical_public_key: *const u8, // 32 bytes
    keypair_handle_out: *mut u64,
    error_msg_out: *mut *mut c_char,
) -> c_int {
    if key_id.is_null() || pqc_public_key.is_null() 
        || classical_public_key.is_null() || keypair_handle_out.is_null() {
        return STATUS_INVALID_PARAM;
    }

    match std::panic::catch_unwind(|| -> Result<(), String> {
        let key_id_str = unsafe { CStr::from_ptr(key_id).to_str() }
            .map_err(|_| "Invalid key ID".to_string())?;
        
        // Unseal from platform keystore
        let combined_sk = PlatformKeystore::unseal_key(key_id_str)
            .map_err(|e| format!("Failed to unseal key: {}", e))?;
        
        // Parse combined secret keys
        if combined_sk.len() < 4 {
            return Err("Invalid sealed key format".to_string());
        }
        
        let pqc_sk_len = u32::from_le_bytes([
            combined_sk[0], combined_sk[1], combined_sk[2], combined_sk[3]
        ]) as usize;
        
        if combined_sk.len() < 4 + pqc_sk_len + 32 {
            return Err("Invalid sealed key length".to_string());
        }
        
        let pqc_sk = &combined_sk[4..4+pqc_sk_len];
        let classical_sk_bytes: [u8; 32] = combined_sk[4+pqc_sk_len..4+pqc_sk_len+32]
            .try_into()
            .map_err(|_| "Invalid classical secret key")?;
        
        // Reconstruct keypair
        let pqc_pk = unsafe { slice::from_raw_parts(pqc_public_key, pqc_public_key_len) };
        let classical_pk: &[u8; 32] = unsafe { &*(classical_public_key as *const [u8; 32]) };
        
        let keypair = HybridKeypair::from_bytes(pqc_pk, pqc_sk, classical_pk, &classical_sk_bytes)
            .map_err(|e| format!("Failed to reconstruct keypair: {}", e))?;
        
        // Store keypair and return handle
        let handle = next_handle();
        KEYPAIR_HANDLES.lock().unwrap().insert(handle, keypair);
        
        unsafe {
            *keypair_handle_out = handle;
        }
        
        Ok(())
    }) {
        Ok(Ok(())) => STATUS_OK,
        Ok(Err(e)) => {
            if !error_msg_out.is_null() {
                if let Ok(c_str) = CString::new(e) {
                    unsafe { *error_msg_out = c_str.into_raw(); }
                }
            }
            STATUS_ERROR
        }
        Err(_) => STATUS_ERROR,
    }
}

/// Encrypt vault data with AES-256-GCM
#[no_mangle]
pub extern "C" fn pqcrypto_encrypt_vault(
    master_key: *const u8, // 32 bytes
    plaintext: *const u8,
    plaintext_len: usize,
    sealed_blob_out: *mut *mut u8,
    sealed_blob_len_out: *mut usize,
    error_msg_out: *mut *mut c_char,
) -> c_int {
    if master_key.is_null() || plaintext.is_null() 
        || sealed_blob_out.is_null() || sealed_blob_len_out.is_null() {
        return STATUS_INVALID_PARAM;
    }

    match std::panic::catch_unwind(|| {
        let master_key_bytes: &[u8; 32] = unsafe { &*(master_key as *const [u8; 32]) };
        let plaintext_bytes = unsafe { slice::from_raw_parts(plaintext, plaintext_len) };
        
        // Encrypt
        let sym_key = SymmetricKey::from_bytes(*master_key_bytes);
        let encrypted = encrypt(&sym_key, plaintext_bytes, None)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Create sealed blob
        let sealed_blob = SealedBlob::new(
            AlgorithmId::Aes256Gcm,
            encrypted.to_bytes(),
            None
        );
        let sealed_bytes = sealed_blob.to_bytes()
            .map_err(|e| format!("Serialization failed: {}", e))?;
        
        // Allocate and copy
        let sealed_len = sealed_bytes.len();
        let sealed_ptr = unsafe {
            let ptr = libc::malloc(sealed_len) as *mut u8;
            if ptr.is_null() {
                return Err("Memory allocation failed".to_string());
            }
            std::ptr::copy_nonoverlapping(sealed_bytes.as_ptr(), ptr, sealed_len);
            ptr
        };
        
        unsafe {
            *sealed_blob_out = sealed_ptr;
            *sealed_blob_len_out = sealed_len;
        }
        
        Ok(())
    }) {
        Ok(Ok(())) => STATUS_OK,
        Ok(Err(e)) => {
            if !error_msg_out.is_null() {
                if let Ok(c_str) = CString::new(e) {
                    unsafe { *error_msg_out = c_str.into_raw(); }
                }
            }
            STATUS_ERROR
        }
        Err(_) => STATUS_ERROR,
    }
}

/// Decrypt vault data with AES-256-GCM
#[no_mangle]
pub extern "C" fn pqcrypto_decrypt_vault(
    master_key: *const u8, // 32 bytes
    sealed_blob: *const u8,
    sealed_blob_len: usize,
    plaintext_out: *mut *mut u8,
    plaintext_len_out: *mut usize,
    error_msg_out: *mut *mut c_char,
) -> c_int {
    if master_key.is_null() || sealed_blob.is_null() 
        || plaintext_out.is_null() || plaintext_len_out.is_null() {
        return STATUS_INVALID_PARAM;
    }

    match std::panic::catch_unwind(|| {
        let master_key_bytes: &[u8; 32] = unsafe { &*(master_key as *const [u8; 32]) };
        let sealed_bytes = unsafe { slice::from_raw_parts(sealed_blob, sealed_blob_len) };
        
        // Deserialize sealed blob
        let blob = SealedBlob::from_bytes(sealed_bytes)
            .map_err(|e| format!("Deserialization failed: {}", e))?;
        blob.validate()
            .map_err(|e| format!("Validation failed: {}", e))?;
        
        // Decrypt
        let encrypted = EncryptedData::from_bytes(&blob.ciphertext)
            .map_err(|e| format!("Invalid encrypted data: {}", e))?;
        
        let sym_key = SymmetricKey::from_bytes(*master_key_bytes);
        let plaintext_bytes = decrypt(&sym_key, &encrypted, None)
            .map_err(|e| format!("Decryption failed: {}", e))?;
        
        // Allocate and copy
        let plaintext_len = plaintext_bytes.len();
        let plaintext_ptr = unsafe {
            let ptr = libc::malloc(plaintext_len) as *mut u8;
            if ptr.is_null() {
                return Err("Memory allocation failed".to_string());
            }
            std::ptr::copy_nonoverlapping(plaintext_bytes.as_ptr(), ptr, plaintext_len);
            ptr
        };
        
        unsafe {
            *plaintext_out = plaintext_ptr;
            *plaintext_len_out = plaintext_len;
        }
        
        Ok(())
    }) {
        Ok(Ok(())) => STATUS_OK,
        Ok(Err(e)) => {
            if !error_msg_out.is_null() {
                if let Ok(c_str) = CString::new(e) {
                    unsafe { *error_msg_out = c_str.into_raw(); }
                }
            }
            STATUS_ERROR
        }
        Err(_) => STATUS_ERROR,
    }
}

/// Free a handle (keypair or key)
#[no_mangle]
pub extern "C" fn pqcrypto_free_handle(handle: u64) -> c_int {
    KEYPAIR_HANDLES.lock().unwrap().remove(&handle);
    KEY_HANDLES.lock().unwrap().remove(&handle);
    STATUS_OK
}

/// Free memory allocated by Rust
#[no_mangle]
pub extern "C" fn pqcrypto_free_memory(ptr: *mut u8) {
    if !ptr.is_null() {
        unsafe {
            libc::free(ptr as *mut c_void);
        }
    }
}

/// Free error message string
#[no_mangle]
pub extern "C" fn pqcrypto_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}
