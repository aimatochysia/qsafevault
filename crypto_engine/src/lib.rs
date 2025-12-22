//! QSafeVault Crypto Engine - Rust FFI Library
//!
//! This library provides cryptographic primitives for the QSafeVault password manager:
//! - AES-256-GCM authenticated encryption
//! - HKDF-SHA3-256 key derivation
//! - X25519 key exchange
//! - ML-KEM-768 (post-quantum) key encapsulation
//! - Secure memory zeroization

use std::ptr;
use std::slice;

use aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use rand::RngCore;
use sha3::Sha3_256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

// ============================================================================
// Constants
// ============================================================================

/// AES-256-GCM nonce size in bytes
pub const AES_GCM_NONCE_SIZE: usize = 12;
/// AES-256-GCM tag size in bytes
pub const AES_GCM_TAG_SIZE: usize = 16;
/// AES-256 key size in bytes
pub const AES_KEY_SIZE: usize = 32;
/// X25519 public key size in bytes
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;
/// X25519 secret key size in bytes
pub const X25519_SECRET_KEY_SIZE: usize = 32;
/// X25519 shared secret size in bytes
pub const X25519_SHARED_SECRET_SIZE: usize = 32;
/// ML-KEM-768 public key size in bytes
pub const MLKEM_PUBLIC_KEY_SIZE: usize = 1184;
/// ML-KEM-768 secret key size in bytes
pub const MLKEM_SECRET_KEY_SIZE: usize = 2400;
/// ML-KEM-768 ciphertext size in bytes
pub const MLKEM_CIPHERTEXT_SIZE: usize = 1088;
/// ML-KEM-768 shared secret size in bytes
pub const MLKEM_SHARED_SECRET_SIZE: usize = 32;

// ============================================================================
// Error codes
// ============================================================================

pub const CRYPTO_SUCCESS: i32 = 0;
pub const CRYPTO_ERROR_NULL_POINTER: i32 = -1;
pub const CRYPTO_ERROR_INVALID_LENGTH: i32 = -2;
pub const CRYPTO_ERROR_ENCRYPTION_FAILED: i32 = -3;
pub const CRYPTO_ERROR_DECRYPTION_FAILED: i32 = -4;
pub const CRYPTO_ERROR_KEY_DERIVATION_FAILED: i32 = -5;
pub const CRYPTO_ERROR_KEY_EXCHANGE_FAILED: i32 = -6;
pub const CRYPTO_ERROR_KEM_FAILED: i32 = -7;
pub const CRYPTO_ERROR_BUFFER_TOO_SMALL: i32 = -8;

// ============================================================================
// Helper functions
// ============================================================================

/// Securely zeroize a byte slice
fn secure_zero(data: &mut [u8]) {
    data.zeroize();
}

/// Generate cryptographically secure random bytes
fn generate_random_bytes(dest: &mut [u8]) -> bool {
    let mut rng = rand::thread_rng();
    rng.fill_bytes(dest);
    true
}

// ============================================================================
// FFI Exports - Memory Management
// ============================================================================

/// Securely zeroize a buffer
///
/// # Safety
/// - `buffer` must be a valid pointer to `len` bytes of allocated memory
#[no_mangle]
pub unsafe extern "C" fn crypto_secure_zero(buffer: *mut u8, len: usize) -> i32 {
    if buffer.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }
    let slice = slice::from_raw_parts_mut(buffer, len);
    secure_zero(slice);
    CRYPTO_SUCCESS
}

/// Generate random bytes
///
/// # Safety
/// - `dest` must be a valid pointer to `len` bytes of allocated memory
#[no_mangle]
pub unsafe extern "C" fn crypto_random_bytes(dest: *mut u8, len: usize) -> i32 {
    if dest.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }
    let slice = slice::from_raw_parts_mut(dest, len);
    if generate_random_bytes(slice) {
        CRYPTO_SUCCESS
    } else {
        CRYPTO_ERROR_ENCRYPTION_FAILED
    }
}

// ============================================================================
// FFI Exports - AES-256-GCM Encryption
// ============================================================================

/// Encrypt data using AES-256-GCM
///
/// Output format: nonce (12 bytes) || ciphertext || tag (16 bytes)
///
/// # Safety
/// - All pointers must be valid and point to allocated memory of the specified sizes
/// - `key` must point to exactly 32 bytes
/// - `nonce` must point to exactly 12 bytes
/// - `output` must have space for plaintext_len + 16 (tag) bytes
#[no_mangle]
pub unsafe extern "C" fn crypto_aes_gcm_encrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
    // Validate pointers
    if key.is_null() || nonce.is_null() || plaintext.is_null() || output.is_null() || output_len.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    // Validate lengths
    if key_len != AES_KEY_SIZE {
        return CRYPTO_ERROR_INVALID_LENGTH;
    }
    if nonce_len != AES_GCM_NONCE_SIZE {
        return CRYPTO_ERROR_INVALID_LENGTH;
    }

    let required_output_size = plaintext_len + AES_GCM_TAG_SIZE;
    if output_capacity < required_output_size {
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }

    // Create slices
    let key_slice = slice::from_raw_parts(key, key_len);
    let nonce_slice = slice::from_raw_parts(nonce, nonce_len);
    let plaintext_slice = slice::from_raw_parts(plaintext, plaintext_len);

    // Create cipher
    let cipher = match Aes256Gcm::new_from_slice(key_slice) {
        Ok(c) => c,
        Err(_) => return CRYPTO_ERROR_ENCRYPTION_FAILED,
    };

    let nonce_obj = Nonce::from_slice(nonce_slice);

    // Encrypt
    match cipher.encrypt(nonce_obj, plaintext_slice) {
        Ok(ciphertext) => {
            let output_slice = slice::from_raw_parts_mut(output, ciphertext.len());
            output_slice.copy_from_slice(&ciphertext);
            *output_len = ciphertext.len();
            CRYPTO_SUCCESS
        }
        Err(_) => CRYPTO_ERROR_ENCRYPTION_FAILED,
    }
}

/// Decrypt data using AES-256-GCM
///
/// Input format: ciphertext || tag (16 bytes)
///
/// # Safety
/// - All pointers must be valid and point to allocated memory of the specified sizes
/// - `key` must point to exactly 32 bytes
/// - `nonce` must point to exactly 12 bytes
/// - `ciphertext` must include the 16-byte tag at the end
/// - `output` must have space for ciphertext_len - 16 bytes
#[no_mangle]
pub unsafe extern "C" fn crypto_aes_gcm_decrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
    // Validate pointers
    if key.is_null() || nonce.is_null() || ciphertext.is_null() || output.is_null() || output_len.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    // Validate lengths
    if key_len != AES_KEY_SIZE {
        return CRYPTO_ERROR_INVALID_LENGTH;
    }
    if nonce_len != AES_GCM_NONCE_SIZE {
        return CRYPTO_ERROR_INVALID_LENGTH;
    }
    if ciphertext_len < AES_GCM_TAG_SIZE {
        return CRYPTO_ERROR_INVALID_LENGTH;
    }

    let expected_plaintext_size = ciphertext_len - AES_GCM_TAG_SIZE;
    if output_capacity < expected_plaintext_size {
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }

    // Create slices
    let key_slice = slice::from_raw_parts(key, key_len);
    let nonce_slice = slice::from_raw_parts(nonce, nonce_len);
    let ciphertext_slice = slice::from_raw_parts(ciphertext, ciphertext_len);

    // Create cipher
    let cipher = match Aes256Gcm::new_from_slice(key_slice) {
        Ok(c) => c,
        Err(_) => return CRYPTO_ERROR_DECRYPTION_FAILED,
    };

    let nonce_obj = Nonce::from_slice(nonce_slice);

    // Decrypt
    match cipher.decrypt(nonce_obj, ciphertext_slice) {
        Ok(plaintext) => {
            let output_slice = slice::from_raw_parts_mut(output, plaintext.len());
            output_slice.copy_from_slice(&plaintext);
            *output_len = plaintext.len();
            CRYPTO_SUCCESS
        }
        Err(_) => CRYPTO_ERROR_DECRYPTION_FAILED,
    }
}

// ============================================================================
// FFI Exports - HKDF-SHA3-256 Key Derivation
// ============================================================================

/// Derive a key using HKDF-SHA3-256
///
/// # Safety
/// - All pointers must be valid and point to allocated memory of the specified sizes
/// - `output_key` must have space for `output_key_len` bytes
#[no_mangle]
pub unsafe extern "C" fn crypto_hkdf_sha3_derive(
    input_key_material: *const u8,
    ikm_len: usize,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    output_key: *mut u8,
    output_key_len: usize,
) -> i32 {
    // Validate pointers
    if input_key_material.is_null() || output_key.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    // Create slices
    let ikm_slice = slice::from_raw_parts(input_key_material, ikm_len);
    
    let salt_slice = if salt.is_null() || salt_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(salt, salt_len)
    };

    let info_slice = if info.is_null() || info_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(info, info_len)
    };

    // Perform HKDF
    let hk = Hkdf::<Sha3_256>::new(Some(salt_slice), ikm_slice);
    
    let output_slice = slice::from_raw_parts_mut(output_key, output_key_len);
    
    match hk.expand(info_slice, output_slice) {
        Ok(()) => CRYPTO_SUCCESS,
        Err(_) => CRYPTO_ERROR_KEY_DERIVATION_FAILED,
    }
}

// ============================================================================
// FFI Exports - X25519 Key Exchange
// ============================================================================

/// Generate an X25519 key pair
///
/// # Safety
/// - `public_key` must point to 32 bytes of allocated memory
/// - `secret_key` must point to 32 bytes of allocated memory
#[no_mangle]
pub unsafe extern "C" fn crypto_x25519_keypair(
    public_key: *mut u8,
    secret_key: *mut u8,
) -> i32 {
    if public_key.is_null() || secret_key.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    let mut rng = rand::thread_rng();
    let secret = StaticSecret::random_from_rng(&mut rng);
    let public = X25519PublicKey::from(&secret);

    let public_slice = slice::from_raw_parts_mut(public_key, X25519_PUBLIC_KEY_SIZE);
    let secret_slice = slice::from_raw_parts_mut(secret_key, X25519_SECRET_KEY_SIZE);

    public_slice.copy_from_slice(public.as_bytes());
    secret_slice.copy_from_slice(secret.as_bytes());

    CRYPTO_SUCCESS
}

/// Perform X25519 key exchange
///
/// # Safety
/// - `my_secret_key` must point to 32 bytes
/// - `their_public_key` must point to 32 bytes
/// - `shared_secret` must point to 32 bytes of allocated memory
#[no_mangle]
pub unsafe extern "C" fn crypto_x25519_exchange(
    my_secret_key: *const u8,
    their_public_key: *const u8,
    shared_secret: *mut u8,
) -> i32 {
    if my_secret_key.is_null() || their_public_key.is_null() || shared_secret.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    let secret_slice = slice::from_raw_parts(my_secret_key, X25519_SECRET_KEY_SIZE);
    let public_slice = slice::from_raw_parts(their_public_key, X25519_PUBLIC_KEY_SIZE);

    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(secret_slice);
    let secret = StaticSecret::from(secret_bytes);

    let mut public_bytes = [0u8; 32];
    public_bytes.copy_from_slice(public_slice);
    let public = X25519PublicKey::from(public_bytes);

    let shared = secret.diffie_hellman(&public);

    let shared_slice = slice::from_raw_parts_mut(shared_secret, X25519_SHARED_SECRET_SIZE);
    shared_slice.copy_from_slice(shared.as_bytes());

    // Zeroize local copies
    secret_bytes.zeroize();

    CRYPTO_SUCCESS
}

// ============================================================================
// FFI Exports - ML-KEM-768 (Post-Quantum Key Encapsulation)
// ============================================================================

/// Generate an ML-KEM-768 key pair
///
/// # Safety
/// - `public_key` must point to MLKEM_PUBLIC_KEY_SIZE bytes of allocated memory
/// - `secret_key` must point to MLKEM_SECRET_KEY_SIZE bytes of allocated memory
#[no_mangle]
pub unsafe extern "C" fn crypto_mlkem_keypair(
    public_key: *mut u8,
    secret_key: *mut u8,
) -> i32 {
    if public_key.is_null() || secret_key.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    let (pk, sk) = mlkem768::keypair();

    let pk_bytes = pk.as_bytes();
    let sk_bytes = sk.as_bytes();

    if pk_bytes.len() != MLKEM_PUBLIC_KEY_SIZE || sk_bytes.len() != MLKEM_SECRET_KEY_SIZE {
        return CRYPTO_ERROR_KEM_FAILED;
    }

    let public_slice = slice::from_raw_parts_mut(public_key, MLKEM_PUBLIC_KEY_SIZE);
    let secret_slice = slice::from_raw_parts_mut(secret_key, MLKEM_SECRET_KEY_SIZE);

    public_slice.copy_from_slice(pk_bytes);
    secret_slice.copy_from_slice(sk_bytes);

    CRYPTO_SUCCESS
}

/// Encapsulate a shared secret using ML-KEM-768
///
/// # Safety
/// - `public_key` must point to MLKEM_PUBLIC_KEY_SIZE bytes
/// - `ciphertext` must point to MLKEM_CIPHERTEXT_SIZE bytes of allocated memory
/// - `shared_secret` must point to MLKEM_SHARED_SECRET_SIZE bytes of allocated memory
#[no_mangle]
pub unsafe extern "C" fn crypto_mlkem_encapsulate(
    public_key: *const u8,
    ciphertext: *mut u8,
    shared_secret: *mut u8,
) -> i32 {
    if public_key.is_null() || ciphertext.is_null() || shared_secret.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    let pk_slice = slice::from_raw_parts(public_key, MLKEM_PUBLIC_KEY_SIZE);

    let pk = match mlkem768::PublicKey::from_bytes(pk_slice) {
        Ok(pk) => pk,
        Err(_) => return CRYPTO_ERROR_KEM_FAILED,
    };

    let (ss, ct) = mlkem768::encapsulate(&pk);

    let ct_bytes = ct.as_bytes();
    let ss_bytes = ss.as_bytes();

    if ct_bytes.len() != MLKEM_CIPHERTEXT_SIZE || ss_bytes.len() != MLKEM_SHARED_SECRET_SIZE {
        return CRYPTO_ERROR_KEM_FAILED;
    }

    let ciphertext_slice = slice::from_raw_parts_mut(ciphertext, MLKEM_CIPHERTEXT_SIZE);
    let shared_slice = slice::from_raw_parts_mut(shared_secret, MLKEM_SHARED_SECRET_SIZE);

    ciphertext_slice.copy_from_slice(ct_bytes);
    shared_slice.copy_from_slice(ss_bytes);

    CRYPTO_SUCCESS
}

/// Decapsulate a shared secret using ML-KEM-768
///
/// # Safety
/// - `secret_key` must point to MLKEM_SECRET_KEY_SIZE bytes
/// - `ciphertext` must point to MLKEM_CIPHERTEXT_SIZE bytes
/// - `shared_secret` must point to MLKEM_SHARED_SECRET_SIZE bytes of allocated memory
#[no_mangle]
pub unsafe extern "C" fn crypto_mlkem_decapsulate(
    secret_key: *const u8,
    ciphertext: *const u8,
    shared_secret: *mut u8,
) -> i32 {
    if secret_key.is_null() || ciphertext.is_null() || shared_secret.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    let sk_slice = slice::from_raw_parts(secret_key, MLKEM_SECRET_KEY_SIZE);
    let ct_slice = slice::from_raw_parts(ciphertext, MLKEM_CIPHERTEXT_SIZE);

    let sk = match mlkem768::SecretKey::from_bytes(sk_slice) {
        Ok(sk) => sk,
        Err(_) => return CRYPTO_ERROR_KEM_FAILED,
    };

    let ct = match mlkem768::Ciphertext::from_bytes(ct_slice) {
        Ok(ct) => ct,
        Err(_) => return CRYPTO_ERROR_KEM_FAILED,
    };

    let ss = mlkem768::decapsulate(&ct, &sk);
    let ss_bytes = ss.as_bytes();

    if ss_bytes.len() != MLKEM_SHARED_SECRET_SIZE {
        return CRYPTO_ERROR_KEM_FAILED;
    }

    let shared_slice = slice::from_raw_parts_mut(shared_secret, MLKEM_SHARED_SECRET_SIZE);
    shared_slice.copy_from_slice(ss_bytes);

    CRYPTO_SUCCESS
}

// ============================================================================
// FFI Exports - Hybrid Key Exchange (X25519 + ML-KEM)
// ============================================================================

/// Size of hybrid public key (X25519 + ML-KEM)
pub const HYBRID_PUBLIC_KEY_SIZE: usize = X25519_PUBLIC_KEY_SIZE + MLKEM_PUBLIC_KEY_SIZE;
/// Size of hybrid secret key (X25519 + ML-KEM)
pub const HYBRID_SECRET_KEY_SIZE: usize = X25519_SECRET_KEY_SIZE + MLKEM_SECRET_KEY_SIZE;
/// Size of hybrid ciphertext (X25519 public key + ML-KEM ciphertext)
pub const HYBRID_CIPHERTEXT_SIZE: usize = X25519_PUBLIC_KEY_SIZE + MLKEM_CIPHERTEXT_SIZE;
/// Size of hybrid shared secret (combined and derived)
pub const HYBRID_SHARED_SECRET_SIZE: usize = 32;

/// Generate a hybrid key pair (X25519 + ML-KEM-768)
///
/// # Safety
/// - `public_key` must point to HYBRID_PUBLIC_KEY_SIZE bytes of allocated memory
/// - `secret_key` must point to HYBRID_SECRET_KEY_SIZE bytes of allocated memory
#[no_mangle]
pub unsafe extern "C" fn crypto_hybrid_keypair(
    public_key: *mut u8,
    secret_key: *mut u8,
) -> i32 {
    if public_key.is_null() || secret_key.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    // Generate X25519 keypair
    let x25519_pk = public_key;
    let x25519_sk = secret_key;
    let result = crypto_x25519_keypair(x25519_pk, x25519_sk);
    if result != CRYPTO_SUCCESS {
        return result;
    }

    // Generate ML-KEM keypair
    let mlkem_pk = public_key.add(X25519_PUBLIC_KEY_SIZE);
    let mlkem_sk = secret_key.add(X25519_SECRET_KEY_SIZE);
    let result = crypto_mlkem_keypair(mlkem_pk, mlkem_sk);
    if result != CRYPTO_SUCCESS {
        return result;
    }

    CRYPTO_SUCCESS
}

/// Encapsulate using hybrid scheme (X25519 + ML-KEM-768)
///
/// This performs both X25519 key exchange and ML-KEM encapsulation,
/// then derives a combined shared secret using HKDF.
///
/// # Safety
/// - `their_public_key` must point to HYBRID_PUBLIC_KEY_SIZE bytes
/// - `ciphertext` must point to HYBRID_CIPHERTEXT_SIZE bytes of allocated memory
/// - `shared_secret` must point to HYBRID_SHARED_SECRET_SIZE bytes of allocated memory
#[no_mangle]
pub unsafe extern "C" fn crypto_hybrid_encapsulate(
    their_public_key: *const u8,
    ciphertext: *mut u8,
    shared_secret: *mut u8,
) -> i32 {
    if their_public_key.is_null() || ciphertext.is_null() || shared_secret.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    // Generate ephemeral X25519 keypair
    let mut x25519_ephemeral_pk = [0u8; X25519_PUBLIC_KEY_SIZE];
    let mut x25519_ephemeral_sk = [0u8; X25519_SECRET_KEY_SIZE];
    let result = crypto_x25519_keypair(x25519_ephemeral_pk.as_mut_ptr(), x25519_ephemeral_sk.as_mut_ptr());
    if result != CRYPTO_SUCCESS {
        return result;
    }

    // Perform X25519 key exchange
    let mut x25519_shared = [0u8; X25519_SHARED_SECRET_SIZE];
    let result = crypto_x25519_exchange(
        x25519_ephemeral_sk.as_ptr(),
        their_public_key,
        x25519_shared.as_mut_ptr(),
    );
    if result != CRYPTO_SUCCESS {
        x25519_ephemeral_sk.zeroize();
        return result;
    }

    // Perform ML-KEM encapsulation
    let mlkem_pk = their_public_key.add(X25519_PUBLIC_KEY_SIZE);
    let mlkem_ct = ciphertext.add(X25519_PUBLIC_KEY_SIZE);
    let mut mlkem_shared = [0u8; MLKEM_SHARED_SECRET_SIZE];
    let result = crypto_mlkem_encapsulate(mlkem_pk, mlkem_ct, mlkem_shared.as_mut_ptr());
    if result != CRYPTO_SUCCESS {
        x25519_ephemeral_sk.zeroize();
        x25519_shared.zeroize();
        return result;
    }

    // Copy ephemeral X25519 public key to ciphertext
    let ct_slice = slice::from_raw_parts_mut(ciphertext, X25519_PUBLIC_KEY_SIZE);
    ct_slice.copy_from_slice(&x25519_ephemeral_pk);

    // Combine shared secrets using HKDF
    let mut combined = [0u8; X25519_SHARED_SECRET_SIZE + MLKEM_SHARED_SECRET_SIZE];
    combined[..X25519_SHARED_SECRET_SIZE].copy_from_slice(&x25519_shared);
    combined[X25519_SHARED_SECRET_SIZE..].copy_from_slice(&mlkem_shared);

    let info = b"qsv-hybrid-shared-secret-v1";
    let result = crypto_hkdf_sha3_derive(
        combined.as_ptr(),
        combined.len(),
        ptr::null(),
        0,
        info.as_ptr(),
        info.len(),
        shared_secret,
        HYBRID_SHARED_SECRET_SIZE,
    );

    // Zeroize sensitive data
    x25519_ephemeral_sk.zeroize();
    x25519_shared.zeroize();
    mlkem_shared.zeroize();
    combined.zeroize();

    result
}

/// Decapsulate using hybrid scheme (X25519 + ML-KEM-768)
///
/// # Safety
/// - `my_secret_key` must point to HYBRID_SECRET_KEY_SIZE bytes
/// - `ciphertext` must point to HYBRID_CIPHERTEXT_SIZE bytes
/// - `shared_secret` must point to HYBRID_SHARED_SECRET_SIZE bytes of allocated memory
#[no_mangle]
pub unsafe extern "C" fn crypto_hybrid_decapsulate(
    my_secret_key: *const u8,
    ciphertext: *const u8,
    shared_secret: *mut u8,
) -> i32 {
    if my_secret_key.is_null() || ciphertext.is_null() || shared_secret.is_null() {
        return CRYPTO_ERROR_NULL_POINTER;
    }

    // Perform X25519 key exchange
    let x25519_sk = my_secret_key;
    let x25519_their_pk = ciphertext; // Ephemeral public key from sender
    let mut x25519_shared = [0u8; X25519_SHARED_SECRET_SIZE];
    let result = crypto_x25519_exchange(x25519_sk, x25519_their_pk, x25519_shared.as_mut_ptr());
    if result != CRYPTO_SUCCESS {
        return result;
    }

    // Perform ML-KEM decapsulation
    let mlkem_sk = my_secret_key.add(X25519_SECRET_KEY_SIZE);
    let mlkem_ct = ciphertext.add(X25519_PUBLIC_KEY_SIZE);
    let mut mlkem_shared = [0u8; MLKEM_SHARED_SECRET_SIZE];
    let result = crypto_mlkem_decapsulate(mlkem_sk, mlkem_ct, mlkem_shared.as_mut_ptr());
    if result != CRYPTO_SUCCESS {
        x25519_shared.zeroize();
        return result;
    }

    // Combine shared secrets using HKDF
    let mut combined = [0u8; X25519_SHARED_SECRET_SIZE + MLKEM_SHARED_SECRET_SIZE];
    combined[..X25519_SHARED_SECRET_SIZE].copy_from_slice(&x25519_shared);
    combined[X25519_SHARED_SECRET_SIZE..].copy_from_slice(&mlkem_shared);

    let info = b"qsv-hybrid-shared-secret-v1";
    let result = crypto_hkdf_sha3_derive(
        combined.as_ptr(),
        combined.len(),
        ptr::null(),
        0,
        info.as_ptr(),
        info.len(),
        shared_secret,
        HYBRID_SHARED_SECRET_SIZE,
    );

    // Zeroize sensitive data
    x25519_shared.zeroize();
    mlkem_shared.zeroize();
    combined.zeroize();

    result
}

// ============================================================================
// FFI Exports - Constants Getters
// ============================================================================

#[no_mangle]
pub extern "C" fn crypto_get_aes_key_size() -> usize {
    AES_KEY_SIZE
}

#[no_mangle]
pub extern "C" fn crypto_get_aes_nonce_size() -> usize {
    AES_GCM_NONCE_SIZE
}

#[no_mangle]
pub extern "C" fn crypto_get_aes_tag_size() -> usize {
    AES_GCM_TAG_SIZE
}

#[no_mangle]
pub extern "C" fn crypto_get_x25519_public_key_size() -> usize {
    X25519_PUBLIC_KEY_SIZE
}

#[no_mangle]
pub extern "C" fn crypto_get_x25519_secret_key_size() -> usize {
    X25519_SECRET_KEY_SIZE
}

#[no_mangle]
pub extern "C" fn crypto_get_x25519_shared_secret_size() -> usize {
    X25519_SHARED_SECRET_SIZE
}

#[no_mangle]
pub extern "C" fn crypto_get_mlkem_public_key_size() -> usize {
    MLKEM_PUBLIC_KEY_SIZE
}

#[no_mangle]
pub extern "C" fn crypto_get_mlkem_secret_key_size() -> usize {
    MLKEM_SECRET_KEY_SIZE
}

#[no_mangle]
pub extern "C" fn crypto_get_mlkem_ciphertext_size() -> usize {
    MLKEM_CIPHERTEXT_SIZE
}

#[no_mangle]
pub extern "C" fn crypto_get_mlkem_shared_secret_size() -> usize {
    MLKEM_SHARED_SECRET_SIZE
}

#[no_mangle]
pub extern "C" fn crypto_get_hybrid_public_key_size() -> usize {
    HYBRID_PUBLIC_KEY_SIZE
}

#[no_mangle]
pub extern "C" fn crypto_get_hybrid_secret_key_size() -> usize {
    HYBRID_SECRET_KEY_SIZE
}

#[no_mangle]
pub extern "C" fn crypto_get_hybrid_ciphertext_size() -> usize {
    HYBRID_CIPHERTEXT_SIZE
}

#[no_mangle]
pub extern "C" fn crypto_get_hybrid_shared_secret_size() -> usize {
    HYBRID_SHARED_SECRET_SIZE
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        
        unsafe {
            assert_eq!(crypto_random_bytes(buf1.as_mut_ptr(), buf1.len()), CRYPTO_SUCCESS);
            assert_eq!(crypto_random_bytes(buf2.as_mut_ptr(), buf2.len()), CRYPTO_SUCCESS);
        }
        
        // Buffers should be different (with overwhelming probability)
        assert_ne!(buf1, buf2);
        // Buffers should not be all zeros
        assert_ne!(buf1, [0u8; 32]);
    }

    #[test]
    fn test_secure_zero() {
        let mut buf = [0xFFu8; 32];
        
        unsafe {
            assert_eq!(crypto_secure_zero(buf.as_mut_ptr(), buf.len()), CRYPTO_SUCCESS);
        }
        
        assert_eq!(buf, [0u8; 32]);
    }

    #[test]
    fn test_aes_gcm_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let plaintext = b"Hello, QSafeVault!";
        
        let mut ciphertext = vec![0u8; plaintext.len() + AES_GCM_TAG_SIZE];
        let mut ciphertext_len = 0usize;
        
        unsafe {
            let result = crypto_aes_gcm_encrypt(
                key.as_ptr(),
                key.len(),
                nonce.as_ptr(),
                nonce.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                ciphertext.as_mut_ptr(),
                ciphertext.len(),
                &mut ciphertext_len,
            );
            assert_eq!(result, CRYPTO_SUCCESS);
            assert_eq!(ciphertext_len, plaintext.len() + AES_GCM_TAG_SIZE);
        }
        
        let mut decrypted = vec![0u8; plaintext.len()];
        let mut decrypted_len = 0usize;
        
        unsafe {
            let result = crypto_aes_gcm_decrypt(
                key.as_ptr(),
                key.len(),
                nonce.as_ptr(),
                nonce.len(),
                ciphertext.as_ptr(),
                ciphertext_len,
                decrypted.as_mut_ptr(),
                decrypted.len(),
                &mut decrypted_len,
            );
            assert_eq!(result, CRYPTO_SUCCESS);
            assert_eq!(decrypted_len, plaintext.len());
        }
        
        assert_eq!(&decrypted[..decrypted_len], plaintext);
    }

    #[test]
    fn test_aes_gcm_tampered_ciphertext() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let plaintext = b"Hello, QSafeVault!";
        
        let mut ciphertext = vec![0u8; plaintext.len() + AES_GCM_TAG_SIZE];
        let mut ciphertext_len = 0usize;
        
        unsafe {
            crypto_aes_gcm_encrypt(
                key.as_ptr(),
                key.len(),
                nonce.as_ptr(),
                nonce.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                ciphertext.as_mut_ptr(),
                ciphertext.len(),
                &mut ciphertext_len,
            );
        }
        
        // Tamper with ciphertext
        ciphertext[0] ^= 0xFF;
        
        let mut decrypted = vec![0u8; plaintext.len()];
        let mut decrypted_len = 0usize;
        
        unsafe {
            let result = crypto_aes_gcm_decrypt(
                key.as_ptr(),
                key.len(),
                nonce.as_ptr(),
                nonce.len(),
                ciphertext.as_ptr(),
                ciphertext_len,
                decrypted.as_mut_ptr(),
                decrypted.len(),
                &mut decrypted_len,
            );
            assert_eq!(result, CRYPTO_ERROR_DECRYPTION_FAILED);
        }
    }

    #[test]
    fn test_hkdf_sha3_derive() {
        let ikm = b"input key material";
        let salt = b"random salt";
        let info = b"context info";
        let mut output = [0u8; 32];
        
        unsafe {
            let result = crypto_hkdf_sha3_derive(
                ikm.as_ptr(),
                ikm.len(),
                salt.as_ptr(),
                salt.len(),
                info.as_ptr(),
                info.len(),
                output.as_mut_ptr(),
                output.len(),
            );
            assert_eq!(result, CRYPTO_SUCCESS);
        }
        
        // Output should not be all zeros
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_x25519_keypair_and_exchange() {
        let mut alice_pk = [0u8; X25519_PUBLIC_KEY_SIZE];
        let mut alice_sk = [0u8; X25519_SECRET_KEY_SIZE];
        let mut bob_pk = [0u8; X25519_PUBLIC_KEY_SIZE];
        let mut bob_sk = [0u8; X25519_SECRET_KEY_SIZE];
        
        unsafe {
            assert_eq!(crypto_x25519_keypair(alice_pk.as_mut_ptr(), alice_sk.as_mut_ptr()), CRYPTO_SUCCESS);
            assert_eq!(crypto_x25519_keypair(bob_pk.as_mut_ptr(), bob_sk.as_mut_ptr()), CRYPTO_SUCCESS);
        }
        
        let mut alice_shared = [0u8; X25519_SHARED_SECRET_SIZE];
        let mut bob_shared = [0u8; X25519_SHARED_SECRET_SIZE];
        
        unsafe {
            assert_eq!(crypto_x25519_exchange(alice_sk.as_ptr(), bob_pk.as_ptr(), alice_shared.as_mut_ptr()), CRYPTO_SUCCESS);
            assert_eq!(crypto_x25519_exchange(bob_sk.as_ptr(), alice_pk.as_ptr(), bob_shared.as_mut_ptr()), CRYPTO_SUCCESS);
        }
        
        // Both should derive the same shared secret
        assert_eq!(alice_shared, bob_shared);
        // Shared secret should not be all zeros
        assert_ne!(alice_shared, [0u8; X25519_SHARED_SECRET_SIZE]);
    }

    #[test]
    fn test_mlkem_keypair_and_encapsulate() {
        let mut pk = vec![0u8; MLKEM_PUBLIC_KEY_SIZE];
        let mut sk = vec![0u8; MLKEM_SECRET_KEY_SIZE];
        
        unsafe {
            assert_eq!(crypto_mlkem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()), CRYPTO_SUCCESS);
        }
        
        let mut ciphertext = vec![0u8; MLKEM_CIPHERTEXT_SIZE];
        let mut encap_shared = [0u8; MLKEM_SHARED_SECRET_SIZE];
        
        unsafe {
            assert_eq!(crypto_mlkem_encapsulate(pk.as_ptr(), ciphertext.as_mut_ptr(), encap_shared.as_mut_ptr()), CRYPTO_SUCCESS);
        }
        
        let mut decap_shared = [0u8; MLKEM_SHARED_SECRET_SIZE];
        
        unsafe {
            assert_eq!(crypto_mlkem_decapsulate(sk.as_ptr(), ciphertext.as_ptr(), decap_shared.as_mut_ptr()), CRYPTO_SUCCESS);
        }
        
        // Both should derive the same shared secret
        assert_eq!(encap_shared, decap_shared);
        // Shared secret should not be all zeros
        assert_ne!(encap_shared, [0u8; MLKEM_SHARED_SECRET_SIZE]);
    }

    #[test]
    fn test_hybrid_keypair_and_exchange() {
        let mut alice_pk = vec![0u8; HYBRID_PUBLIC_KEY_SIZE];
        let mut alice_sk = vec![0u8; HYBRID_SECRET_KEY_SIZE];
        
        unsafe {
            assert_eq!(crypto_hybrid_keypair(alice_pk.as_mut_ptr(), alice_sk.as_mut_ptr()), CRYPTO_SUCCESS);
        }
        
        let mut ciphertext = vec![0u8; HYBRID_CIPHERTEXT_SIZE];
        let mut bob_shared = [0u8; HYBRID_SHARED_SECRET_SIZE];
        
        unsafe {
            assert_eq!(crypto_hybrid_encapsulate(alice_pk.as_ptr(), ciphertext.as_mut_ptr(), bob_shared.as_mut_ptr()), CRYPTO_SUCCESS);
        }
        
        let mut alice_shared = [0u8; HYBRID_SHARED_SECRET_SIZE];
        
        unsafe {
            assert_eq!(crypto_hybrid_decapsulate(alice_sk.as_ptr(), ciphertext.as_ptr(), alice_shared.as_mut_ptr()), CRYPTO_SUCCESS);
        }
        
        // Both should derive the same shared secret
        assert_eq!(alice_shared, bob_shared);
        // Shared secret should not be all zeros
        assert_ne!(alice_shared, [0u8; HYBRID_SHARED_SECRET_SIZE]);
    }

    #[test]
    fn test_constant_getters() {
        assert_eq!(crypto_get_aes_key_size(), 32);
        assert_eq!(crypto_get_aes_nonce_size(), 12);
        assert_eq!(crypto_get_aes_tag_size(), 16);
        assert_eq!(crypto_get_x25519_public_key_size(), 32);
        assert_eq!(crypto_get_x25519_secret_key_size(), 32);
        assert_eq!(crypto_get_x25519_shared_secret_size(), 32);
        assert_eq!(crypto_get_mlkem_public_key_size(), 1184);
        assert_eq!(crypto_get_mlkem_secret_key_size(), 2400);
        assert_eq!(crypto_get_mlkem_ciphertext_size(), 1088);
        assert_eq!(crypto_get_mlkem_shared_secret_size(), 32);
    }
}
