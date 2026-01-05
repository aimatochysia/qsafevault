// FFI layer: C ABI for Flutter integration
// All functions return status codes and use out-parameters for data
//
// EDITION SYSTEM:
// Edition MUST be initialized before any cryptographic operations.
// The Edition determines the CryptoPolicy (PQAllowed vs FipsOnly).
// Enterprise mode enforces FIPS-only algorithms and requires external HSM.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::slice;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::hybrid_kem::{HybridKeypair, HybridCiphertext, encapsulate as hybrid_encapsulate};
use crate::symmetric::{SymmetricKey, EncryptedData, encrypt, decrypt};
use crate::sealed_storage::{SealedBlob, AlgorithmId};
use crate::platform_keystore::PlatformKeystore;
use crate::edition::{Edition, Algorithm, EditionError, get_edition, initialize_edition, is_initialized, enforce_algorithm};

// Status codes
pub const STATUS_OK: c_int = 0;
pub const STATUS_ERROR: c_int = -1;
pub const STATUS_INVALID_PARAM: c_int = -2;
pub const STATUS_NOT_FOUND: c_int = -3;
// Edition-specific status codes
pub const STATUS_EDITION_NOT_INITIALIZED: c_int = -10;
pub const STATUS_EDITION_ALREADY_INITIALIZED: c_int = -11;
pub const STATUS_FIPS_VIOLATION: c_int = -20;
pub const STATUS_PQ_DISABLED: c_int = -21;
pub const STATUS_HSM_REQUIRED: c_int = -22;
pub const STATUS_SOFTHSM_PROHIBITED: c_int = -23;
pub const STATUS_SERVER_EDITION_MISMATCH: c_int = -30;

// Global handle storage
lazy_static::lazy_static! {
    static ref KEYPAIR_HANDLES: Mutex<HashMap<u64, HybridKeypair>> = Mutex::new(HashMap::new());
    static ref KEY_HANDLES: Mutex<HashMap<u64, SymmetricKey>> = Mutex::new(HashMap::new());
}

// Thread-safe handle counter
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

fn next_handle() -> u64 {
    NEXT_HANDLE.fetch_add(1, Ordering::SeqCst)
}

// =============================================================================
// Edition System FFI Functions
// =============================================================================

/// Convert EditionError to status code
fn edition_error_to_status(error: &EditionError) -> c_int {
    match error {
        EditionError::AlreadyInitialized => STATUS_EDITION_ALREADY_INITIALIZED,
        EditionError::NotInitialized => STATUS_EDITION_NOT_INITIALIZED,
        EditionError::NonFipsAlgorithmProhibited(_) => STATUS_FIPS_VIOLATION,
        EditionError::PostQuantumDisabled => STATUS_PQ_DISABLED,
        EditionError::SoftHsmProhibited => STATUS_SOFTHSM_PROHIBITED,
        EditionError::LocalKeyGenerationProhibited => STATUS_HSM_REQUIRED,
        EditionError::ExternalHsmRequired => STATUS_HSM_REQUIRED,
        EditionError::HsmNotFipsValidated => STATUS_FIPS_VIOLATION,
        EditionError::ServerEditionMismatch { .. } => STATUS_SERVER_EDITION_MISMATCH,
        EditionError::ServerMissingEnterpriseFeatures(_) => STATUS_SERVER_EDITION_MISMATCH,
        EditionError::ConfigurationError(_) => STATUS_ERROR,
    }
}

/// Initialize the crypto engine with a specific Edition
/// This MUST be called before any cryptographic operations
/// Edition values: 0 = Consumer, 1 = Enterprise
/// 
/// ENTERPRISE MODE REQUIREMENTS:
/// - FIPS-only algorithms will be enforced
/// - Post-quantum algorithms are DISABLED
/// - External HSM is REQUIRED for root key operations
/// - SoftHSM is PROHIBITED
///
/// Returns: STATUS_OK on success, STATUS_EDITION_ALREADY_INITIALIZED if called twice
#[no_mangle]
pub extern "C" fn pqcrypto_initialize_edition(
    edition: c_int,
    error_msg_out: *mut *mut c_char,
) -> c_int {
    let ed = match edition {
        0 => Edition::Consumer,
        1 => Edition::Enterprise,
        _ => {
            if !error_msg_out.is_null() {
                if let Ok(c_str) = CString::new("Invalid edition value. Use 0 for Consumer, 1 for Enterprise.") {
                    unsafe { *error_msg_out = c_str.into_raw(); }
                }
            }
            return STATUS_INVALID_PARAM;
        }
    };

    match initialize_edition(ed) {
        Ok(()) => STATUS_OK,
        Err(e) => {
            let status = edition_error_to_status(&e);
            if !error_msg_out.is_null() {
                if let Ok(c_str) = CString::new(e.to_string()) {
                    unsafe { *error_msg_out = c_str.into_raw(); }
                }
            }
            status
        }
    }
}

/// Get the current Edition
/// Returns: 0 = Consumer, 1 = Enterprise, -10 = Not initialized
#[no_mangle]
pub extern "C" fn pqcrypto_get_edition(
    edition_out: *mut c_int,
    error_msg_out: *mut *mut c_char,
) -> c_int {
    if edition_out.is_null() {
        return STATUS_INVALID_PARAM;
    }

    match get_edition() {
        Ok(ed) => {
            unsafe {
                *edition_out = match ed {
                    Edition::Consumer => 0,
                    Edition::Enterprise => 1,
                };
            }
            STATUS_OK
        }
        Err(e) => {
            let status = edition_error_to_status(&e);
            if !error_msg_out.is_null() {
                if let Ok(c_str) = CString::new(e.to_string()) {
                    unsafe { *error_msg_out = c_str.into_raw(); }
                }
            }
            status
        }
    }
}

/// Check if the Edition has been initialized
/// Returns: 1 if initialized, 0 if not
#[no_mangle]
pub extern "C" fn pqcrypto_is_edition_initialized() -> c_int {
    if is_initialized() { 1 } else { 0 }
}

/// Get Edition information as JSON string
/// Returns JSON with: edition, crypto_policy, is_enterprise, pq_allowed, fips_only
#[no_mangle]
pub extern "C" fn pqcrypto_get_edition_info(
    info_out: *mut *mut c_char,
    error_msg_out: *mut *mut c_char,
) -> c_int {
    if info_out.is_null() {
        return STATUS_INVALID_PARAM;
    }

    match get_edition() {
        Ok(ed) => {
            let policy = ed.crypto_policy();
            let info = format!(
                r#"{{"edition":"{}","crypto_policy":"{}","is_enterprise":{},"pq_allowed":{},"fips_only":{}}}"#,
                match ed {
                    Edition::Consumer => "Consumer",
                    Edition::Enterprise => "Enterprise",
                },
                match policy {
                    crate::edition::CryptoPolicy::PQAllowed => "PQAllowed",
                    crate::edition::CryptoPolicy::FipsOnly => "FipsOnly",
                },
                ed == Edition::Enterprise,
                policy == crate::edition::CryptoPolicy::PQAllowed,
                policy == crate::edition::CryptoPolicy::FipsOnly,
            );

            if let Ok(c_str) = CString::new(info) {
                unsafe { *info_out = c_str.into_raw(); }
                STATUS_OK
            } else {
                STATUS_ERROR
            }
        }
        Err(e) => {
            let status = edition_error_to_status(&e);
            if !error_msg_out.is_null() {
                if let Ok(c_str) = CString::new(e.to_string()) {
                    unsafe { *error_msg_out = c_str.into_raw(); }
                }
            }
            status
        }
    }
}

/// Verify that an algorithm is permitted under the current Edition policy
/// Algorithm IDs:
///   FIPS: 0=AES256GCM, 1=SHA256, 2=SHA384, 3=HKDF_SHA256, 4=PBKDF2_HMAC_SHA256
///   Non-FIPS: 10=ML_KEM_768, 11=DILITHIUM3, 12=X25519, 13=SHA3_256, 14=HKDF_SHA3_256, 15=ARGON2ID
#[no_mangle]
pub extern "C" fn pqcrypto_verify_algorithm_permitted(
    algorithm_id: c_int,
    error_msg_out: *mut *mut c_char,
) -> c_int {
    let algorithm = match algorithm_id {
        // FIPS-approved
        0 => Algorithm::Aes256Gcm,
        1 => Algorithm::Sha256,
        2 => Algorithm::Sha384,
        3 => Algorithm::HkdfSha256,
        4 => Algorithm::Pbkdf2HmacSha256,
        5 => Algorithm::EcdsaP256,
        6 => Algorithm::EcdsaP384,
        7 => Algorithm::RsaOaep,
        8 => Algorithm::EcdhP256,
        9 => Algorithm::EcdhP384,
        // Non-FIPS (Consumer only)
        10 => Algorithm::MlKem768,
        11 => Algorithm::Dilithium3,
        12 => Algorithm::X25519,
        13 => Algorithm::Sha3_256,
        14 => Algorithm::HkdfSha3_256,
        15 => Algorithm::Argon2id,
        _ => {
            if !error_msg_out.is_null() {
                if let Ok(c_str) = CString::new("Unknown algorithm ID") {
                    unsafe { *error_msg_out = c_str.into_raw(); }
                }
            }
            return STATUS_INVALID_PARAM;
        }
    };

    match enforce_algorithm(algorithm) {
        Ok(()) => STATUS_OK,
        Err(e) => {
            let status = edition_error_to_status(&e);
            if !error_msg_out.is_null() {
                if let Ok(c_str) = CString::new(e.to_string()) {
                    unsafe { *error_msg_out = c_str.into_raw(); }
                }
            }
            status
        }
    }
}

/// Verify server Edition compatibility
/// Client edition: 0 = Consumer, 1 = Enterprise
/// Server edition: 0 = Consumer, 1 = Enterprise
/// Returns STATUS_OK if compatible, STATUS_SERVER_EDITION_MISMATCH if not
#[no_mangle]
pub extern "C" fn pqcrypto_verify_server_edition(
    client_edition: c_int,
    server_edition: c_int,
    error_msg_out: *mut *mut c_char,
) -> c_int {
    let client = match client_edition {
        0 => Edition::Consumer,
        1 => Edition::Enterprise,
        _ => {
            if !error_msg_out.is_null() {
                if let Ok(c_str) = CString::new("Invalid client edition value") {
                    unsafe { *error_msg_out = c_str.into_raw(); }
                }
            }
            return STATUS_INVALID_PARAM;
        }
    };

    let server = match server_edition {
        0 => Edition::Consumer,
        1 => Edition::Enterprise,
        _ => {
            if !error_msg_out.is_null() {
                if let Ok(c_str) = CString::new("Invalid server edition value") {
                    unsafe { *error_msg_out = c_str.into_raw(); }
                }
            }
            return STATUS_INVALID_PARAM;
        }
    };

    match client.verify_server_edition(server) {
        Ok(()) => STATUS_OK,
        Err(e) => {
            let status = edition_error_to_status(&e);
            if !error_msg_out.is_null() {
                if let Ok(c_str) = CString::new(e.to_string()) {
                    unsafe { *error_msg_out = c_str.into_raw(); }
                }
            }
            status
        }
    }
}

// =============================================================================
// Edition-Aware Helper Functions
// =============================================================================

/// Check edition and enforce ML-KEM 768 algorithm policy before hybrid operations
/// This verifies that the ML-KEM 768 (Kyber) post-quantum KEM algorithm is permitted.
/// Used by hybrid encryption/decryption and keypair generation functions.
fn require_hybrid_pq_algorithms() -> Result<(), String> {
    // Hybrid operations use ML-KEM 768 + X25519
    // Both are non-FIPS, but we check ML-KEM as the primary PQ algorithm
    // X25519 would also fail in Enterprise mode via the same policy
    match enforce_algorithm(Algorithm::MlKem768) {
        Ok(()) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Generate a new hybrid keypair (PQC + Classical)
/// Returns handle to keypair, public keys written to out parameters
/// 
/// NOTE: This function uses post-quantum algorithms (ML-KEM 768, X25519)
/// It is PROHIBITED in Enterprise mode and will return STATUS_PQ_DISABLED
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

    // Enforce edition policy - PQ algorithms required
    if let Err(e) = require_hybrid_pq_algorithms() {
        if !error_msg_out.is_null() {
            if let Ok(c_str) = CString::new(e) {
                unsafe { *error_msg_out = c_str.into_raw(); }
            }
        }
        return STATUS_PQ_DISABLED;
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
/// 
/// NOTE: This function uses post-quantum algorithms (ML-KEM 768, X25519)
/// It is PROHIBITED in Enterprise mode and will return STATUS_PQ_DISABLED
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

    // Enforce edition policy - PQ algorithms required
    if let Err(e) = require_hybrid_pq_algorithms() {
        if !error_msg_out.is_null() {
            if let Ok(c_str) = CString::new(e) {
                unsafe { *error_msg_out = c_str.into_raw(); }
            }
        }
        return STATUS_PQ_DISABLED;
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
/// 
/// NOTE: This function uses post-quantum algorithms (ML-KEM 768, X25519)
/// It is PROHIBITED in Enterprise mode and will return STATUS_PQ_DISABLED
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

    // Enforce edition policy - PQ algorithms required
    if let Err(e) = require_hybrid_pq_algorithms() {
        if !error_msg_out.is_null() {
            if let Ok(c_str) = CString::new(e) {
                unsafe { *error_msg_out = c_str.into_raw(); }
            }
        }
        return STATUS_PQ_DISABLED;
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
        let backend_type = PlatformKeystore::seal_key(key_id_str, &combined_sk)
            .map_err(|e| format!("Failed to seal key: {}", e))?;
        
        log::info!("Sealed key with backend: {:?}", backend_type);
        
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

/// Get backend detection information
/// Returns a JSON string with backend status
#[no_mangle]
pub extern "C" fn pqcrypto_get_backend_info(
    info_out: *mut *mut c_char,
    error_msg_out: *mut *mut c_char,
) -> c_int {
    if info_out.is_null() {
        return STATUS_INVALID_PARAM;
    }

    match std::panic::catch_unwind(|| -> Result<String, String> {
        use crate::platform_keystore::detect_backends;
        
        let status = detect_backends();
        let backend_type = crate::platform_keystore::determine_backend_type();
        
        let info = format!(
            r#"{{"tpm_available":{}, "softhsm_available":{}, "platform_secure_available":{}, "backend_type":"{}"}}"#,
            status.tpm_available,
            status.softhsm_available,
            status.platform_secure_available,
            format!("{:?}", backend_type)
        );
        
        Ok(info)
    }) {
        Ok(Ok(info)) => {
            if let Ok(c_str) = CString::new(info) {
                unsafe { *info_out = c_str.into_raw(); }
                STATUS_OK
            } else {
                STATUS_ERROR
            }
        }
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

/// Initialize logging (debug builds only)
/// level: 0=Error, 1=Warn, 2=Info, 3=Debug, 4=Trace
#[no_mangle]
pub extern "C" fn pqcrypto_init_logging(level: c_int) -> c_int {
    use log::LevelFilter;
    
    let log_level = match level {
        0 => LevelFilter::Error,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        4 => LevelFilter::Trace,
        _ => LevelFilter::Info,
    };
    
    // Initialize simple logger (ignore error if already initialized)
    let _ = simple_logger::SimpleLogger::new()
        .with_level(log_level)
        .init();
    
    log::info!("QSafeVault crypto engine logging initialized at level: {:?}", log_level);
    log::info!("PQC Implementation: Kyber ML-KEM 768");
    log::info!("Classical KEM: X25519");
    log::info!("Hybrid KDF: HKDF-SHA3-256");
    log::info!("Symmetric Encryption: AES-256-GCM");
    
    STATUS_OK
}

/// Generate secure random bytes
/// Uses the OS cryptographically secure random number generator
#[no_mangle]
pub extern "C" fn pqcrypto_generate_random_bytes(
    length: usize,
    bytes_out: *mut *mut u8,
    error_msg_out: *mut *mut c_char,
) -> c_int {
    if bytes_out.is_null() || length == 0 {
        return STATUS_INVALID_PARAM;
    }

    match std::panic::catch_unwind(|| {
        use rand_core::{OsRng, RngCore};
        use zeroize::Zeroize;
        
        let mut bytes = vec![0u8; length];
        OsRng.fill_bytes(&mut bytes);
        
        // Allocate and copy
        let bytes_ptr = unsafe {
            let ptr = libc::malloc(length) as *mut u8;
            if ptr.is_null() {
                bytes.zeroize(); // Clear sensitive data before returning error
                return Err("Memory allocation failed".to_string());
            }
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, length);
            ptr
        };
        
        // Zeroize the local buffer after copying
        bytes.zeroize();
        
        unsafe {
            *bytes_out = bytes_ptr;
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

/// Derive a key using HKDF-SHA3-256
/// Used for key derivation from shared secrets
#[no_mangle]
pub extern "C" fn pqcrypto_derive_key_hkdf(
    input_key_material: *const u8,
    ikm_len: usize,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    output_key_len: usize,
    output_key_out: *mut *mut u8,
    error_msg_out: *mut *mut c_char,
) -> c_int {
    if input_key_material.is_null() || output_key_out.is_null() || output_key_len == 0 {
        return STATUS_INVALID_PARAM;
    }

    match std::panic::catch_unwind(|| {
        use hkdf::Hkdf;
        use sha3::Sha3_256;
        use zeroize::Zeroize;
        
        let ikm = unsafe { slice::from_raw_parts(input_key_material, ikm_len) };
        let salt_slice = if !salt.is_null() && salt_len > 0 {
            Some(unsafe { slice::from_raw_parts(salt, salt_len) })
        } else {
            None
        };
        let info_slice = if !info.is_null() && info_len > 0 {
            unsafe { slice::from_raw_parts(info, info_len) }
        } else {
            &[]
        };
        
        let hk = Hkdf::<Sha3_256>::new(salt_slice, ikm);
        let mut okm = vec![0u8; output_key_len];
        hk.expand(info_slice, &mut okm)
            .map_err(|_| "HKDF expansion failed")?;
        
        // Allocate and copy
        let output_ptr = unsafe {
            let ptr = libc::malloc(output_key_len) as *mut u8;
            if ptr.is_null() {
                okm.zeroize(); // Clear sensitive key material before returning error
                return Err("Memory allocation failed".to_string());
            }
            std::ptr::copy_nonoverlapping(okm.as_ptr(), ptr, output_key_len);
            ptr
        };
        
        // Zeroize the output key material buffer after copying
        okm.zeroize();
        
        unsafe {
            *output_key_out = output_ptr;
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

/// Get version information about the crypto engine
#[no_mangle]
pub extern "C" fn pqcrypto_get_version(
    version_out: *mut *mut c_char,
) -> c_int {
    if version_out.is_null() {
        return STATUS_INVALID_PARAM;
    }

    let version = format!(
        r#"{{"version":"{}","algorithms":{{"kem":"ML-KEM-768 (Kyber)","signature":"Dilithium3","kdf":"HKDF-SHA3-256","cipher":"AES-256-GCM","hash":"SHA3-256"}},"fips_compatible":true,"post_quantum":true,"classical_fallback":false}}"#,
        env!("CARGO_PKG_VERSION")
    );
    
    if let Ok(c_str) = CString::new(version) {
        unsafe { *version_out = c_str.into_raw(); }
        STATUS_OK
    } else {
        STATUS_ERROR
    }
}

// =============================================================================
// Post-Quantum Digital Signatures (Dilithium3)
// =============================================================================

use crate::pqc_signature::{PqcSigningKeypair, PqcSignature, verify as pqc_verify};

// Global storage for signing keypairs
lazy_static::lazy_static! {
    static ref SIGNING_KEYPAIR_HANDLES: Mutex<HashMap<u64, PqcSigningKeypair>> = Mutex::new(HashMap::new());
}

/// Helper to enforce Dilithium3 algorithm policy
fn require_dilithium() -> Result<(), String> {
    match enforce_algorithm(Algorithm::Dilithium3) {
        Ok(()) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Generate a new Dilithium3 signing keypair
/// Returns handle to keypair, public key written to out parameter
/// 
/// NOTE: This function uses post-quantum algorithm (Dilithium3)
/// It is PROHIBITED in Enterprise mode and will return STATUS_PQ_DISABLED
#[no_mangle]
pub extern "C" fn pqcrypto_generate_signing_keypair(
    keypair_handle_out: *mut u64,
    public_key_out: *mut *mut u8,
    public_key_len_out: *mut usize,
    error_msg_out: *mut *mut c_char,
) -> c_int {
    if keypair_handle_out.is_null() || public_key_out.is_null() || public_key_len_out.is_null() {
        return STATUS_INVALID_PARAM;
    }

    // Enforce edition policy - Dilithium3 is a PQ algorithm
    if let Err(e) = require_dilithium() {
        if !error_msg_out.is_null() {
            if let Ok(c_str) = CString::new(e) {
                unsafe { *error_msg_out = c_str.into_raw(); }
            }
        }
        return STATUS_PQ_DISABLED;
    }

    match std::panic::catch_unwind(|| {
        // Generate keypair
        let keypair = PqcSigningKeypair::generate();
        let pk_bytes = keypair.public_key_bytes();
        
        // Allocate and copy public key
        let pk_len = pk_bytes.len();
        let pk_ptr = unsafe {
            let ptr = libc::malloc(pk_len) as *mut u8;
            if ptr.is_null() {
                return Err("Memory allocation failed".to_string());
            }
            std::ptr::copy_nonoverlapping(pk_bytes.as_ptr(), ptr, pk_len);
            ptr
        };
        
        // Store keypair and return handle
        let handle = next_handle();
        SIGNING_KEYPAIR_HANDLES.lock().unwrap().insert(handle, keypair);
        
        unsafe {
            *keypair_handle_out = handle;
            *public_key_out = pk_ptr;
            *public_key_len_out = pk_len;
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

/// Sign a message using Dilithium3
/// Returns detached signature
/// 
/// NOTE: This function uses post-quantum algorithm (Dilithium3)
/// It is PROHIBITED in Enterprise mode and will return STATUS_PQ_DISABLED
#[no_mangle]
pub extern "C" fn pqcrypto_sign_message(
    keypair_handle: u64,
    message: *const u8,
    message_len: usize,
    signature_out: *mut *mut u8,
    signature_len_out: *mut usize,
    error_msg_out: *mut *mut c_char,
) -> c_int {
    if message.is_null() || signature_out.is_null() || signature_len_out.is_null() {
        return STATUS_INVALID_PARAM;
    }

    // Enforce edition policy - Dilithium3 is a PQ algorithm
    if let Err(e) = require_dilithium() {
        if !error_msg_out.is_null() {
            if let Ok(c_str) = CString::new(e) {
                unsafe { *error_msg_out = c_str.into_raw(); }
            }
        }
        return STATUS_PQ_DISABLED;
    }

    match std::panic::catch_unwind(|| {
        let message_bytes = unsafe { slice::from_raw_parts(message, message_len) };
        
        // Get keypair
        let keypairs = SIGNING_KEYPAIR_HANDLES.lock().unwrap();
        let keypair = keypairs.get(&keypair_handle)
            .ok_or("Invalid signing keypair handle")?;
        
        // Sign
        let signature = keypair.sign(message_bytes);
        let sig_bytes = signature.to_bytes();
        
        // Allocate and copy signature
        let sig_len = sig_bytes.len();
        let sig_ptr = unsafe {
            let ptr = libc::malloc(sig_len) as *mut u8;
            if ptr.is_null() {
                return Err("Memory allocation failed".to_string());
            }
            std::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), ptr, sig_len);
            ptr
        };
        
        unsafe {
            *signature_out = sig_ptr;
            *signature_len_out = sig_len;
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

/// Verify a Dilithium3 signature
/// Returns STATUS_OK if valid, STATUS_ERROR if invalid
/// 
/// NOTE: This function uses post-quantum algorithm (Dilithium3)
/// It is PROHIBITED in Enterprise mode and will return STATUS_PQ_DISABLED
#[no_mangle]
pub extern "C" fn pqcrypto_verify_signature(
    public_key: *const u8,
    public_key_len: usize,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
    valid_out: *mut c_int,
    error_msg_out: *mut *mut c_char,
) -> c_int {
    if public_key.is_null() || message.is_null() || signature.is_null() || valid_out.is_null() {
        return STATUS_INVALID_PARAM;
    }

    // Enforce edition policy - Dilithium3 is a PQ algorithm
    if let Err(e) = require_dilithium() {
        if !error_msg_out.is_null() {
            if let Ok(c_str) = CString::new(e) {
                unsafe { *error_msg_out = c_str.into_raw(); }
            }
        }
        return STATUS_PQ_DISABLED;
    }

    match std::panic::catch_unwind(|| -> Result<(), String> {
        let pk_bytes = unsafe { slice::from_raw_parts(public_key, public_key_len) };
        let message_bytes = unsafe { slice::from_raw_parts(message, message_len) };
        let sig_bytes = unsafe { slice::from_raw_parts(signature, signature_len) };
        
        // Deserialize signature
        let sig = PqcSignature::from_bytes(sig_bytes)
            .map_err(|e| format!("Invalid signature: {}", e))?;
        
        // Verify
        let valid = pqc_verify(pk_bytes, message_bytes, &sig)
            .map_err(|e| format!("Verification error: {}", e))?;
        
        unsafe {
            *valid_out = if valid { 1 } else { 0 };
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

/// Free a signing keypair handle
#[no_mangle]
pub extern "C" fn pqcrypto_free_signing_keypair(handle: u64) -> c_int {
    SIGNING_KEYPAIR_HANDLES.lock().unwrap().remove(&handle);
    STATUS_OK
}

/// Get signing keypair public key bytes
#[no_mangle]
pub extern "C" fn pqcrypto_get_signing_public_key(
    keypair_handle: u64,
    public_key_out: *mut *mut u8,
    public_key_len_out: *mut usize,
    error_msg_out: *mut *mut c_char,
) -> c_int {
    if public_key_out.is_null() || public_key_len_out.is_null() {
        return STATUS_INVALID_PARAM;
    }

    match std::panic::catch_unwind(|| {
        // Get keypair
        let keypairs = SIGNING_KEYPAIR_HANDLES.lock().unwrap();
        let keypair = keypairs.get(&keypair_handle)
            .ok_or("Invalid signing keypair handle")?;
        
        let pk_bytes = keypair.public_key_bytes();
        
        // Allocate and copy public key
        let pk_len = pk_bytes.len();
        let pk_ptr = unsafe {
            let ptr = libc::malloc(pk_len) as *mut u8;
            if ptr.is_null() {
                return Err("Memory allocation failed".to_string());
            }
            std::ptr::copy_nonoverlapping(pk_bytes.as_ptr(), ptr, pk_len);
            ptr
        };
        
        unsafe {
            *public_key_out = pk_ptr;
            *public_key_len_out = pk_len;
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
