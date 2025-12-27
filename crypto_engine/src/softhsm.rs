//! SoftHSM2 / PKCS#11 Support Module
//!
//! This module provides Hardware Security Module (HSM) functionality using SoftHSM2
//! through the PKCS#11 interface. It enables secure key storage and cryptographic
//! operations within an HSM environment.
//!
//! ## Supported Platforms
//! - Linux (x86_64, aarch64)
//! - macOS (x86_64, aarch64)
//! - Windows (x86_64)
//!
//! ## Not Supported
//! - Android (no native PKCS#11)
//! - iOS (no native PKCS#11)
//! - WebAssembly (no native library access)
//!
//! ## Features
//! - Token initialization and management
//! - AES-256-GCM key generation and operations
//! - RSA key generation (2048, 4096 bits)
//! - ECDSA key generation (P-256, P-384)
//! - Secure key storage with PIN protection
//! - Digital signatures and verification

#![cfg(not(any(target_os = "android", target_os = "ios", target_arch = "wasm32")))]

use std::path::Path;
use std::slice;
use std::sync::Mutex;

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::{AuthPin, Ulong};

// ============================================================================
// Error Codes for HSM Operations
// ============================================================================

pub const HSM_SUCCESS: i32 = 0;
pub const HSM_ERROR_NOT_INITIALIZED: i32 = -100;
pub const HSM_ERROR_ALREADY_INITIALIZED: i32 = -101;
pub const HSM_ERROR_LIBRARY_LOAD_FAILED: i32 = -102;
pub const HSM_ERROR_NO_SLOT_AVAILABLE: i32 = -103;
pub const HSM_ERROR_TOKEN_NOT_PRESENT: i32 = -104;
pub const HSM_ERROR_PIN_INCORRECT: i32 = -105;
pub const HSM_ERROR_PIN_LOCKED: i32 = -106;
pub const HSM_ERROR_SESSION_FAILED: i32 = -107;
pub const HSM_ERROR_KEY_GENERATION_FAILED: i32 = -108;
pub const HSM_ERROR_KEY_NOT_FOUND: i32 = -109;
pub const HSM_ERROR_ENCRYPTION_FAILED: i32 = -110;
pub const HSM_ERROR_DECRYPTION_FAILED: i32 = -111;
pub const HSM_ERROR_SIGNATURE_FAILED: i32 = -112;
pub const HSM_ERROR_VERIFICATION_FAILED: i32 = -113;
pub const HSM_ERROR_INVALID_PARAMETER: i32 = -114;
pub const HSM_ERROR_BUFFER_TOO_SMALL: i32 = -115;
pub const HSM_ERROR_NULL_POINTER: i32 = -116;
pub const HSM_ERROR_OPERATION_FAILED: i32 = -117;
pub const HSM_ERROR_TOKEN_INIT_FAILED: i32 = -118;
pub const HSM_ERROR_UNSUPPORTED_PLATFORM: i32 = -119;

// ============================================================================
// Key Types
// ============================================================================

pub const HSM_KEY_TYPE_AES_256: u32 = 1;
pub const HSM_KEY_TYPE_RSA_2048: u32 = 2;
pub const HSM_KEY_TYPE_RSA_4096: u32 = 3;
pub const HSM_KEY_TYPE_EC_P256: u32 = 4;
pub const HSM_KEY_TYPE_EC_P384: u32 = 5;

// ============================================================================
// Global HSM Context
// ============================================================================

struct HsmContext {
    pkcs11: Option<Pkcs11>,
    session: Option<Session>,
    slot: Option<Slot>,
}

impl HsmContext {
    const fn new() -> Self {
        HsmContext {
            pkcs11: None,
            session: None,
            slot: None,
        }
    }
}

static HSM_CONTEXT: Mutex<HsmContext> = Mutex::new(HsmContext::new());

// ============================================================================
// Helper Functions
// ============================================================================

/// Get the default SoftHSM2 library path for the current platform
fn get_default_softhsm_path() -> Option<&'static str> {
    #[cfg(target_os = "linux")]
    {
        // Common locations for SoftHSM2 on Linux
        let paths = [
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/lib64/softhsm/libsofthsm2.so",
            "/usr/local/lib/softhsm/libsofthsm2.so",
        ];
        for path in paths {
            if Path::new(path).exists() {
                return Some(path);
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    {
        let paths = [
            "/usr/local/lib/softhsm/libsofthsm2.so",
            "/opt/homebrew/lib/softhsm/libsofthsm2.so",
            "/usr/local/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so",
        ];
        for path in paths {
            if Path::new(path).exists() {
                return Some(path);
            }
        }
        None
    }

    #[cfg(target_os = "windows")]
    {
        let paths = [
            "C:\\SoftHSM2\\lib\\softhsm2.dll",
            "C:\\Program Files\\SoftHSM2\\lib\\softhsm2.dll",
            "C:\\Program Files (x86)\\SoftHSM2\\lib\\softhsm2.dll",
        ];
        for path in paths {
            if Path::new(path).exists() {
                return Some(path);
            }
        }
        None
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// Convert ObjectHandle to u64 for FFI
///
/// # Safety Note
/// ObjectHandle is a newtype wrapper around CK_OBJECT_HANDLE (typically `unsigned long`).
/// The cryptoki library does not provide a direct conversion API, so we use transmute.
/// This is safe because:
/// 1. ObjectHandle is #[repr(transparent)] wrapping CK_OBJECT_HANDLE
/// 2. CK_OBJECT_HANDLE is an alias for c_ulong
/// 3. We perform size validation at compile time
fn handle_to_u64(handle: ObjectHandle) -> u64 {
    // Compile-time size assertion to ensure safety
    const _: () = assert!(
        std::mem::size_of::<ObjectHandle>() == std::mem::size_of::<cryptoki_sys::CK_OBJECT_HANDLE>(),
        "ObjectHandle size mismatch"
    );
    
    // SAFETY: ObjectHandle is a transparent wrapper around CK_OBJECT_HANDLE
    let raw: cryptoki_sys::CK_OBJECT_HANDLE = unsafe { std::mem::transmute(handle) };
    raw as u64
}

/// Convert u64 to ObjectHandle for FFI
///
/// # Safety Note
/// See `handle_to_u64` for safety rationale.
fn u64_to_handle(value: u64) -> ObjectHandle {
    // Compile-time size assertion to ensure safety
    const _: () = assert!(
        std::mem::size_of::<ObjectHandle>() == std::mem::size_of::<cryptoki_sys::CK_OBJECT_HANDLE>(),
        "ObjectHandle size mismatch"
    );
    
    let raw = value as cryptoki_sys::CK_OBJECT_HANDLE;
    // SAFETY: ObjectHandle is a transparent wrapper around CK_OBJECT_HANDLE
    unsafe { std::mem::transmute(raw) }
}

// ============================================================================
// FFI Exports - HSM Initialization
// ============================================================================

/// Initialize the HSM with the SoftHSM2 library
///
/// # Safety
/// - `library_path` can be NULL to use the default path
/// - If provided, `library_path` must be a valid null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn hsm_initialize(
    library_path: *const libc::c_char,
    library_path_len: usize,
) -> i32 {
    let mut ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    if ctx.pkcs11.is_some() {
        return HSM_ERROR_ALREADY_INITIALIZED;
    }

    // Determine library path
    let path = if library_path.is_null() || library_path_len == 0 {
        match get_default_softhsm_path() {
            Some(p) => p.to_string(),
            None => return HSM_ERROR_LIBRARY_LOAD_FAILED,
        }
    } else {
        let path_slice = slice::from_raw_parts(library_path as *const u8, library_path_len);
        match std::str::from_utf8(path_slice) {
            Ok(s) => s.to_string(),
            Err(_) => return HSM_ERROR_INVALID_PARAMETER,
        }
    };

    // Load the PKCS#11 library
    let pkcs11 = match Pkcs11::new(&path) {
        Ok(p) => p,
        Err(_) => return HSM_ERROR_LIBRARY_LOAD_FAILED,
    };

    // Initialize the library
    if let Err(_) = pkcs11.initialize(CInitializeArgs::OsThreads) {
        return HSM_ERROR_LIBRARY_LOAD_FAILED;
    }

    ctx.pkcs11 = Some(pkcs11);
    HSM_SUCCESS
}

/// Finalize and cleanup the HSM context
#[no_mangle]
pub extern "C" fn hsm_finalize() -> i32 {
    let mut ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    // Drop the session first
    ctx.session = None;
    ctx.slot = None;

    // Finalize will be called when pkcs11 is dropped
    ctx.pkcs11 = None;

    HSM_SUCCESS
}

/// Check if SoftHSM2 is available on this platform
#[no_mangle]
pub extern "C" fn hsm_is_available() -> i32 {
    if get_default_softhsm_path().is_some() {
        1
    } else {
        0
    }
}

/// Get the number of available slots
#[no_mangle]
pub extern "C" fn hsm_get_slot_count() -> i32 {
    let ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return -1,
    };

    let pkcs11 = match &ctx.pkcs11 {
        Some(p) => p,
        None => return -1,
    };

    match pkcs11.get_slots_with_initialized_token() {
        Ok(slots) => slots.len() as i32,
        Err(_) => -1,
    }
}

// ============================================================================
// FFI Exports - Token Management
// ============================================================================

/// Initialize a token in the specified slot
///
/// # Safety
/// - `so_pin` must be a valid pointer to `so_pin_len` bytes
/// - `label` must be a valid pointer to `label_len` bytes (max 32 chars)
#[no_mangle]
pub unsafe extern "C" fn hsm_init_token(
    slot_index: u32,
    so_pin: *const u8,
    so_pin_len: usize,
    label: *const u8,
    label_len: usize,
) -> i32 {
    if so_pin.is_null() || label.is_null() {
        return HSM_ERROR_NULL_POINTER;
    }

    let ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    let pkcs11 = match &ctx.pkcs11 {
        Some(p) => p,
        None => return HSM_ERROR_NOT_INITIALIZED,
    };

    // Get all slots
    let slots = match pkcs11.get_all_slots() {
        Ok(s) => s,
        Err(_) => return HSM_ERROR_NO_SLOT_AVAILABLE,
    };

    if slot_index as usize >= slots.len() {
        return HSM_ERROR_NO_SLOT_AVAILABLE;
    }

    let slot = slots[slot_index as usize];

    // Prepare SO PIN and label
    let so_pin_slice = slice::from_raw_parts(so_pin, so_pin_len);
    let so_pin_str = match std::str::from_utf8(so_pin_slice) {
        Ok(s) => s,
        Err(_) => return HSM_ERROR_INVALID_PARAMETER,
    };

    let label_slice = slice::from_raw_parts(label, label_len);
    let label_str = match std::str::from_utf8(label_slice) {
        Ok(s) => s,
        Err(_) => return HSM_ERROR_INVALID_PARAMETER,
    };

    // Initialize the token
    match pkcs11.init_token(slot, &AuthPin::new(so_pin_str.to_string()), label_str) {
        Ok(_) => HSM_SUCCESS,
        Err(_) => HSM_ERROR_TOKEN_INIT_FAILED,
    }
}

/// Open a session on the specified slot
///
/// # Safety
/// - `user_pin` must be a valid pointer to `user_pin_len` bytes
#[no_mangle]
pub unsafe extern "C" fn hsm_open_session(
    slot_index: u32,
    user_pin: *const u8,
    user_pin_len: usize,
) -> i32 {
    if user_pin.is_null() {
        return HSM_ERROR_NULL_POINTER;
    }

    let mut ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    let pkcs11 = match &ctx.pkcs11 {
        Some(p) => p,
        None => return HSM_ERROR_NOT_INITIALIZED,
    };

    // Get slots with initialized tokens
    let slots = match pkcs11.get_slots_with_initialized_token() {
        Ok(s) => s,
        Err(_) => return HSM_ERROR_NO_SLOT_AVAILABLE,
    };

    if slot_index as usize >= slots.len() {
        return HSM_ERROR_NO_SLOT_AVAILABLE;
    }

    let slot = slots[slot_index as usize];

    // Open a read/write session
    let session = match pkcs11.open_rw_session(slot) {
        Ok(s) => s,
        Err(_) => return HSM_ERROR_SESSION_FAILED,
    };

    // Prepare user PIN
    let user_pin_slice = slice::from_raw_parts(user_pin, user_pin_len);
    let user_pin_str = match std::str::from_utf8(user_pin_slice) {
        Ok(s) => s,
        Err(_) => return HSM_ERROR_INVALID_PARAMETER,
    };

    // Login as user
    match session.login(UserType::User, Some(&AuthPin::new(user_pin_str.to_string()))) {
        Ok(_) => {}
        Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::PinIncorrect, _)) => {
            return HSM_ERROR_PIN_INCORRECT;
        }
        Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::PinLocked, _)) => {
            return HSM_ERROR_PIN_LOCKED;
        }
        Err(_) => return HSM_ERROR_SESSION_FAILED,
    }

    ctx.session = Some(session);
    ctx.slot = Some(slot);

    HSM_SUCCESS
}

/// Close the current session
#[no_mangle]
pub extern "C" fn hsm_close_session() -> i32 {
    let mut ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    if let Some(session) = ctx.session.take() {
        let _ = session.logout();
        // Session is dropped here
    }

    ctx.slot = None;

    HSM_SUCCESS
}

/// Set the user PIN for the current token
///
/// # Safety
/// - `so_pin` must be a valid pointer to `so_pin_len` bytes
/// - `user_pin` must be a valid pointer to `user_pin_len` bytes
#[no_mangle]
pub unsafe extern "C" fn hsm_set_user_pin(
    slot_index: u32,
    so_pin: *const u8,
    so_pin_len: usize,
    user_pin: *const u8,
    user_pin_len: usize,
) -> i32 {
    if so_pin.is_null() || user_pin.is_null() {
        return HSM_ERROR_NULL_POINTER;
    }

    let ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    let pkcs11 = match &ctx.pkcs11 {
        Some(p) => p,
        None => return HSM_ERROR_NOT_INITIALIZED,
    };

    // Get slots
    let slots = match pkcs11.get_slots_with_initialized_token() {
        Ok(s) => s,
        Err(_) => return HSM_ERROR_NO_SLOT_AVAILABLE,
    };

    if slot_index as usize >= slots.len() {
        return HSM_ERROR_NO_SLOT_AVAILABLE;
    }

    let slot = slots[slot_index as usize];

    // Open a session and login as SO
    let session = match pkcs11.open_rw_session(slot) {
        Ok(s) => s,
        Err(_) => return HSM_ERROR_SESSION_FAILED,
    };

    let so_pin_slice = slice::from_raw_parts(so_pin, so_pin_len);
    let so_pin_str = match std::str::from_utf8(so_pin_slice) {
        Ok(s) => s,
        Err(_) => return HSM_ERROR_INVALID_PARAMETER,
    };

    // Login as Security Officer
    match session.login(UserType::So, Some(&AuthPin::new(so_pin_str.to_string()))) {
        Ok(_) => {}
        Err(_) => return HSM_ERROR_PIN_INCORRECT,
    }

    let user_pin_slice = slice::from_raw_parts(user_pin, user_pin_len);
    let user_pin_str = match std::str::from_utf8(user_pin_slice) {
        Ok(s) => s,
        Err(_) => return HSM_ERROR_INVALID_PARAMETER,
    };

    // Initialize the user PIN
    match session.init_pin(&AuthPin::new(user_pin_str.to_string())) {
        Ok(_) => HSM_SUCCESS,
        Err(_) => HSM_ERROR_OPERATION_FAILED,
    }
}

// ============================================================================
// FFI Exports - Key Generation
// ============================================================================

/// Generate a symmetric AES-256 key
///
/// # Safety
/// - `key_label` must be a valid pointer to `key_label_len` bytes
/// - `key_id` must be a valid pointer to `key_id_len` bytes
/// - `key_handle` must be a valid pointer to store the key handle
#[no_mangle]
pub unsafe extern "C" fn hsm_generate_aes_key(
    key_label: *const u8,
    key_label_len: usize,
    key_id: *const u8,
    key_id_len: usize,
    extractable: bool,
    key_handle: *mut u64,
) -> i32 {
    if key_label.is_null() || key_id.is_null() || key_handle.is_null() {
        return HSM_ERROR_NULL_POINTER;
    }

    let ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    let session = match &ctx.session {
        Some(s) => s,
        None => return HSM_ERROR_NOT_INITIALIZED,
    };

    let label_slice = slice::from_raw_parts(key_label, key_label_len);
    let id_slice = slice::from_raw_parts(key_id, key_id_len);

    // Key attributes
    let key_template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(Ulong::from(32u64)), // 256 bits
        Attribute::Label(label_slice.to_vec()),
        Attribute::Id(id_slice.to_vec()),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(!extractable),
        Attribute::Extractable(extractable),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Wrap(true),
        Attribute::Unwrap(true),
    ];

    // Generate the key
    match session.generate_key(&Mechanism::AesKeyGen, &key_template) {
        Ok(handle) => {
            *key_handle = handle_to_u64(handle);
            HSM_SUCCESS
        }
        Err(_) => HSM_ERROR_KEY_GENERATION_FAILED,
    }
}

/// Generate an RSA key pair
///
/// # Safety
/// - `key_label` must be a valid pointer to `key_label_len` bytes
/// - `key_id` must be a valid pointer to `key_id_len` bytes
/// - `public_key_handle` and `private_key_handle` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn hsm_generate_rsa_keypair(
    key_bits: u32,
    key_label: *const u8,
    key_label_len: usize,
    key_id: *const u8,
    key_id_len: usize,
    public_key_handle: *mut u64,
    private_key_handle: *mut u64,
) -> i32 {
    if key_label.is_null() || key_id.is_null() || public_key_handle.is_null() || private_key_handle.is_null() {
        return HSM_ERROR_NULL_POINTER;
    }

    if key_bits != 2048 && key_bits != 4096 {
        return HSM_ERROR_INVALID_PARAMETER;
    }

    let ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    let session = match &ctx.session {
        Some(s) => s,
        None => return HSM_ERROR_NOT_INITIALIZED,
    };

    let label_slice = slice::from_raw_parts(key_label, key_label_len);
    let id_slice = slice::from_raw_parts(key_id, key_id_len);

    // Public key attributes
    let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01]; // 65537
    let public_template = vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::RSA),
        Attribute::ModulusBits(Ulong::from(key_bits as u64)),
        Attribute::PublicExponent(public_exponent),
        Attribute::Label(label_slice.to_vec()),
        Attribute::Id(id_slice.to_vec()),
        Attribute::Token(true),
        Attribute::Encrypt(true),
        Attribute::Verify(true),
        Attribute::Wrap(true),
    ];

    // Private key attributes
    let private_template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Label(label_slice.to_vec()),
        Attribute::Id(id_slice.to_vec()),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Decrypt(true),
        Attribute::Sign(true),
        Attribute::Unwrap(true),
    ];

    // Generate the key pair
    match session.generate_key_pair(
        &Mechanism::RsaPkcsKeyPairGen,
        &public_template,
        &private_template,
    ) {
        Ok((pub_handle, priv_handle)) => {
            *public_key_handle = handle_to_u64(pub_handle);
            *private_key_handle = handle_to_u64(priv_handle);
            HSM_SUCCESS
        }
        Err(_) => HSM_ERROR_KEY_GENERATION_FAILED,
    }
}

/// Generate an ECDSA key pair
///
/// # Safety
/// - `key_label` must be a valid pointer to `key_label_len` bytes
/// - `key_id` must be a valid pointer to `key_id_len` bytes
/// - `public_key_handle` and `private_key_handle` must be valid pointers
#[no_mangle]
pub unsafe extern "C" fn hsm_generate_ec_keypair(
    curve: u32, // HSM_KEY_TYPE_EC_P256 or HSM_KEY_TYPE_EC_P384
    key_label: *const u8,
    key_label_len: usize,
    key_id: *const u8,
    key_id_len: usize,
    public_key_handle: *mut u64,
    private_key_handle: *mut u64,
) -> i32 {
    if key_label.is_null() || key_id.is_null() || public_key_handle.is_null() || private_key_handle.is_null() {
        return HSM_ERROR_NULL_POINTER;
    }

    // OID for the EC curve
    let ec_params = match curve {
        4 => vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07], // P-256
        5 => vec![0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22], // P-384
        _ => return HSM_ERROR_INVALID_PARAMETER,
    };

    let ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    let session = match &ctx.session {
        Some(s) => s,
        None => return HSM_ERROR_NOT_INITIALIZED,
    };

    let label_slice = slice::from_raw_parts(key_label, key_label_len);
    let id_slice = slice::from_raw_parts(key_id, key_id_len);

    // Public key attributes
    let public_template = vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::EcParams(ec_params.clone()),
        Attribute::Label(label_slice.to_vec()),
        Attribute::Id(id_slice.to_vec()),
        Attribute::Token(true),
        Attribute::Verify(true),
    ];

    // Private key attributes
    let private_template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Label(label_slice.to_vec()),
        Attribute::Id(id_slice.to_vec()),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Sign(true),
    ];

    // Generate the key pair
    match session.generate_key_pair(
        &Mechanism::EccKeyPairGen,
        &public_template,
        &private_template,
    ) {
        Ok((pub_handle, priv_handle)) => {
            *public_key_handle = handle_to_u64(pub_handle);
            *private_key_handle = handle_to_u64(priv_handle);
            HSM_SUCCESS
        }
        Err(_) => HSM_ERROR_KEY_GENERATION_FAILED,
    }
}

// ============================================================================
// FFI Exports - Key Management
// ============================================================================

/// Find a key by label
///
/// # Safety
/// - `key_label` must be a valid pointer to `key_label_len` bytes
/// - `key_handle` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn hsm_find_key(
    key_label: *const u8,
    key_label_len: usize,
    key_handle: *mut u64,
) -> i32 {
    if key_label.is_null() || key_handle.is_null() {
        return HSM_ERROR_NULL_POINTER;
    }

    let ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    let session = match &ctx.session {
        Some(s) => s,
        None => return HSM_ERROR_NOT_INITIALIZED,
    };

    let label_slice = slice::from_raw_parts(key_label, key_label_len);

    let search_template = vec![
        Attribute::Label(label_slice.to_vec()),
    ];

    match session.find_objects(&search_template) {
        Ok(handles) => {
            if handles.is_empty() {
                HSM_ERROR_KEY_NOT_FOUND
            } else {
                *key_handle = handle_to_u64(handles[0]);
                HSM_SUCCESS
            }
        }
        Err(_) => HSM_ERROR_OPERATION_FAILED,
    }
}

/// Delete a key by handle
#[no_mangle]
pub extern "C" fn hsm_delete_key(key_handle: u64) -> i32 {
    let ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    let session = match &ctx.session {
        Some(s) => s,
        None => return HSM_ERROR_NOT_INITIALIZED,
    };

    let handle = u64_to_handle(key_handle);

    match session.destroy_object(handle) {
        Ok(_) => HSM_SUCCESS,
        Err(_) => HSM_ERROR_OPERATION_FAILED,
    }
}

// ============================================================================
// FFI Exports - Cryptographic Operations
// ============================================================================

/// Encrypt data using AES-GCM with a key stored in the HSM
///
/// # Safety
/// - All pointers must be valid
/// - `iv` must point to 12 bytes
/// - `output` must have sufficient capacity
#[no_mangle]
pub unsafe extern "C" fn hsm_aes_gcm_encrypt(
    key_handle: u64,
    iv: *const u8,
    iv_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
    if iv.is_null() || plaintext.is_null() || output.is_null() || output_len.is_null() {
        return HSM_ERROR_NULL_POINTER;
    }

    if iv_len != 12 {
        return HSM_ERROR_INVALID_PARAMETER;
    }

    let required_size = plaintext_len + 16; // ciphertext + tag
    if output_capacity < required_size {
        return HSM_ERROR_BUFFER_TOO_SMALL;
    }

    let ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    let session = match &ctx.session {
        Some(s) => s,
        None => return HSM_ERROR_NOT_INITIALIZED,
    };

    let handle = u64_to_handle(key_handle);
    let iv_slice = slice::from_raw_parts(iv, iv_len);
    let plaintext_slice = slice::from_raw_parts(plaintext, plaintext_len);

    let aad_slice = if aad.is_null() || aad_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(aad, aad_len)
    };

    // Create GCM parameters
    let gcm_params = cryptoki::mechanism::aead::GcmParams::new(
        iv_slice,
        aad_slice,
        Ulong::from(128u64), // 128-bit tag
    );

    let mechanism = Mechanism::AesGcm(gcm_params);

    match session.encrypt(&mechanism, handle, plaintext_slice) {
        Ok(ciphertext) => {
            if ciphertext.len() > output_capacity {
                return HSM_ERROR_BUFFER_TOO_SMALL;
            }
            let output_slice = slice::from_raw_parts_mut(output, ciphertext.len());
            output_slice.copy_from_slice(&ciphertext);
            *output_len = ciphertext.len();
            HSM_SUCCESS
        }
        Err(_) => HSM_ERROR_ENCRYPTION_FAILED,
    }
}

/// Decrypt data using AES-GCM with a key stored in the HSM
///
/// # Safety
/// - All pointers must be valid
/// - `iv` must point to 12 bytes
/// - `output` must have sufficient capacity
#[no_mangle]
pub unsafe extern "C" fn hsm_aes_gcm_decrypt(
    key_handle: u64,
    iv: *const u8,
    iv_len: usize,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
    if iv.is_null() || ciphertext.is_null() || output.is_null() || output_len.is_null() {
        return HSM_ERROR_NULL_POINTER;
    }

    if iv_len != 12 {
        return HSM_ERROR_INVALID_PARAMETER;
    }

    if ciphertext_len < 16 {
        return HSM_ERROR_INVALID_PARAMETER;
    }

    let ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    let session = match &ctx.session {
        Some(s) => s,
        None => return HSM_ERROR_NOT_INITIALIZED,
    };

    let handle = u64_to_handle(key_handle);
    let iv_slice = slice::from_raw_parts(iv, iv_len);
    let ciphertext_slice = slice::from_raw_parts(ciphertext, ciphertext_len);

    let aad_slice = if aad.is_null() || aad_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(aad, aad_len)
    };

    // Create GCM parameters
    let gcm_params = cryptoki::mechanism::aead::GcmParams::new(
        iv_slice,
        aad_slice,
        Ulong::from(128u64), // 128-bit tag
    );

    let mechanism = Mechanism::AesGcm(gcm_params);

    match session.decrypt(&mechanism, handle, ciphertext_slice) {
        Ok(plaintext) => {
            if plaintext.len() > output_capacity {
                return HSM_ERROR_BUFFER_TOO_SMALL;
            }
            let output_slice = slice::from_raw_parts_mut(output, plaintext.len());
            output_slice.copy_from_slice(&plaintext);
            *output_len = plaintext.len();
            HSM_SUCCESS
        }
        Err(_) => HSM_ERROR_DECRYPTION_FAILED,
    }
}

/// Sign data using RSA-PKCS#1 v1.5 with SHA-256
///
/// # Safety
/// - All pointers must be valid
/// - `signature` must have sufficient capacity (256 bytes for RSA-2048, 512 for RSA-4096)
#[no_mangle]
pub unsafe extern "C" fn hsm_rsa_sign_sha256(
    private_key_handle: u64,
    data: *const u8,
    data_len: usize,
    signature: *mut u8,
    signature_capacity: usize,
    signature_len: *mut usize,
) -> i32 {
    if data.is_null() || signature.is_null() || signature_len.is_null() {
        return HSM_ERROR_NULL_POINTER;
    }

    let ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    let session = match &ctx.session {
        Some(s) => s,
        None => return HSM_ERROR_NOT_INITIALIZED,
    };

    let handle = u64_to_handle(private_key_handle);
    let data_slice = slice::from_raw_parts(data, data_len);

    let mechanism = Mechanism::Sha256RsaPkcs;

    match session.sign(&mechanism, handle, data_slice) {
        Ok(sig) => {
            if sig.len() > signature_capacity {
                return HSM_ERROR_BUFFER_TOO_SMALL;
            }
            let sig_slice = slice::from_raw_parts_mut(signature, sig.len());
            sig_slice.copy_from_slice(&sig);
            *signature_len = sig.len();
            HSM_SUCCESS
        }
        Err(_) => HSM_ERROR_SIGNATURE_FAILED,
    }
}

/// Verify an RSA-PKCS#1 v1.5 signature with SHA-256
///
/// # Safety
/// - All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn hsm_rsa_verify_sha256(
    public_key_handle: u64,
    data: *const u8,
    data_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> i32 {
    if data.is_null() || signature.is_null() {
        return HSM_ERROR_NULL_POINTER;
    }

    let ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    let session = match &ctx.session {
        Some(s) => s,
        None => return HSM_ERROR_NOT_INITIALIZED,
    };

    let handle = u64_to_handle(public_key_handle);
    let data_slice = slice::from_raw_parts(data, data_len);
    let sig_slice = slice::from_raw_parts(signature, signature_len);

    let mechanism = Mechanism::Sha256RsaPkcs;

    match session.verify(&mechanism, handle, data_slice, sig_slice) {
        Ok(()) => HSM_SUCCESS,
        Err(_) => HSM_ERROR_VERIFICATION_FAILED,
    }
}

/// Sign data using ECDSA with SHA-256
///
/// # Safety
/// - All pointers must be valid
/// - `signature` must have sufficient capacity
#[no_mangle]
pub unsafe extern "C" fn hsm_ecdsa_sign_sha256(
    private_key_handle: u64,
    data: *const u8,
    data_len: usize,
    signature: *mut u8,
    signature_capacity: usize,
    signature_len: *mut usize,
) -> i32 {
    if data.is_null() || signature.is_null() || signature_len.is_null() {
        return HSM_ERROR_NULL_POINTER;
    }

    let ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    let session = match &ctx.session {
        Some(s) => s,
        None => return HSM_ERROR_NOT_INITIALIZED,
    };

    let handle = u64_to_handle(private_key_handle);
    let data_slice = slice::from_raw_parts(data, data_len);

    let mechanism = Mechanism::Ecdsa;

    // Hash the data first (ECDSA expects pre-hashed data)
    use sha3::{Digest, Sha3_256};
    let hash = Sha3_256::digest(data_slice);

    match session.sign(&mechanism, handle, &hash) {
        Ok(sig) => {
            if sig.len() > signature_capacity {
                return HSM_ERROR_BUFFER_TOO_SMALL;
            }
            let sig_slice = slice::from_raw_parts_mut(signature, sig.len());
            sig_slice.copy_from_slice(&sig);
            *signature_len = sig.len();
            HSM_SUCCESS
        }
        Err(_) => HSM_ERROR_SIGNATURE_FAILED,
    }
}

/// Verify an ECDSA signature with SHA-256
///
/// # Safety
/// - All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn hsm_ecdsa_verify_sha256(
    public_key_handle: u64,
    data: *const u8,
    data_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> i32 {
    if data.is_null() || signature.is_null() {
        return HSM_ERROR_NULL_POINTER;
    }

    let ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    let session = match &ctx.session {
        Some(s) => s,
        None => return HSM_ERROR_NOT_INITIALIZED,
    };

    let handle = u64_to_handle(public_key_handle);
    let data_slice = slice::from_raw_parts(data, data_len);
    let sig_slice = slice::from_raw_parts(signature, signature_len);

    let mechanism = Mechanism::Ecdsa;

    // Hash the data first
    use sha3::{Digest, Sha3_256};
    let hash = Sha3_256::digest(data_slice);

    match session.verify(&mechanism, handle, &hash, sig_slice) {
        Ok(()) => HSM_SUCCESS,
        Err(_) => HSM_ERROR_VERIFICATION_FAILED,
    }
}

// ============================================================================
// FFI Exports - Random Number Generation
// ============================================================================

/// Generate random bytes using the HSM's hardware RNG
///
/// # Safety
/// - `output` must be a valid pointer to `output_len` bytes
#[no_mangle]
pub unsafe extern "C" fn hsm_generate_random(
    output: *mut u8,
    output_len: usize,
) -> i32 {
    if output.is_null() {
        return HSM_ERROR_NULL_POINTER;
    }

    let ctx = match HSM_CONTEXT.lock() {
        Ok(c) => c,
        Err(_) => return HSM_ERROR_OPERATION_FAILED,
    };

    let session = match &ctx.session {
        Some(s) => s,
        None => return HSM_ERROR_NOT_INITIALIZED,
    };

    match session.generate_random_vec(output_len as u32) {
        Ok(random_bytes) => {
            let output_slice = slice::from_raw_parts_mut(output, output_len);
            output_slice.copy_from_slice(&random_bytes);
            HSM_SUCCESS
        }
        Err(_) => HSM_ERROR_OPERATION_FAILED,
    }
}

// ============================================================================
// FFI Exports - Utility Functions
// ============================================================================

/// Get the error message for an HSM error code
#[no_mangle]
pub extern "C" fn hsm_get_error_message(error_code: i32) -> *const libc::c_char {
    let msg = match error_code {
        HSM_SUCCESS => "Success\0",
        HSM_ERROR_NOT_INITIALIZED => "HSM not initialized\0",
        HSM_ERROR_ALREADY_INITIALIZED => "HSM already initialized\0",
        HSM_ERROR_LIBRARY_LOAD_FAILED => "Failed to load PKCS#11 library\0",
        HSM_ERROR_NO_SLOT_AVAILABLE => "No slot available\0",
        HSM_ERROR_TOKEN_NOT_PRESENT => "Token not present\0",
        HSM_ERROR_PIN_INCORRECT => "Incorrect PIN\0",
        HSM_ERROR_PIN_LOCKED => "PIN is locked\0",
        HSM_ERROR_SESSION_FAILED => "Session operation failed\0",
        HSM_ERROR_KEY_GENERATION_FAILED => "Key generation failed\0",
        HSM_ERROR_KEY_NOT_FOUND => "Key not found\0",
        HSM_ERROR_ENCRYPTION_FAILED => "Encryption failed\0",
        HSM_ERROR_DECRYPTION_FAILED => "Decryption failed\0",
        HSM_ERROR_SIGNATURE_FAILED => "Signature failed\0",
        HSM_ERROR_VERIFICATION_FAILED => "Verification failed\0",
        HSM_ERROR_INVALID_PARAMETER => "Invalid parameter\0",
        HSM_ERROR_BUFFER_TOO_SMALL => "Buffer too small\0",
        HSM_ERROR_NULL_POINTER => "Null pointer\0",
        HSM_ERROR_OPERATION_FAILED => "Operation failed\0",
        HSM_ERROR_TOKEN_INIT_FAILED => "Token initialization failed\0",
        HSM_ERROR_UNSUPPORTED_PLATFORM => "Unsupported platform\0",
        _ => "Unknown error\0",
    };
    msg.as_ptr() as *const libc::c_char
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hsm_is_available() {
        // This test just checks the function runs without crashing
        let result = hsm_is_available();
        // Result depends on whether SoftHSM2 is installed
        assert!(result == 0 || result == 1);
    }

    #[test]
    fn test_error_messages() {
        let msg = hsm_get_error_message(HSM_SUCCESS);
        assert!(!msg.is_null());

        let msg = hsm_get_error_message(HSM_ERROR_PIN_INCORRECT);
        assert!(!msg.is_null());
    }
}
