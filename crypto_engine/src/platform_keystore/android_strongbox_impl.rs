// Android StrongBox Full Implementation using JNI
// Provides hardware-backed key storage using Android Keystore with StrongBox
//
// This implementation uses the `jni` crate to access Android KeyStore APIs.
// The Rust library is loaded by Flutter and provides native functions for
// encryption/decryption using StrongBox-backed keys.

#![cfg(target_os = "android")]

use crate::symmetric::{aes_gcm_encrypt, aes_gcm_decrypt};
use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString, JValue, GlobalRef};
use jni::sys::jbyteArray;
use std::sync::Mutex;
use zeroize::Zeroize;

// Global JVM reference for accessing Java/Android APIs from Rust
lazy_static::lazy_static! {
    static ref JVM: Mutex<Option<jni::JavaVM>> = Mutex::new(None);
}

/// Initialize JNI - must be called from Java/Kotlin before using StrongBox
/// This is typically called from the Flutter plugin's native initialization
#[no_mangle]
pub extern "system" fn Java_com_qsafevault_crypto_CryptoEngine_initNative<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) {
    let jvm = env.get_java_vm().expect("Failed to get JavaVM");
    let mut jvm_guard = JVM.lock().unwrap();
    *jvm_guard = Some(jvm);
    log::info!("Android StrongBox: JNI initialized successfully");
}

/// Get the stored JNIEnv
fn with_jni_env<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce(&mut JNIEnv) -> Result<R, String>,
{
    let jvm_guard = JVM.lock().map_err(|e| format!("Failed to lock JVM: {:?}", e))?;
    let jvm = jvm_guard.as_ref().ok_or("JNI not initialized")?;
    let mut env = jvm.attach_current_thread()
        .map_err(|e| format!("Failed to attach thread: {:?}", e))?;
    f(&mut env)
}

/// Check if StrongBox is available on this device
pub fn is_strongbox_available() -> bool {
    with_jni_env(|env| {
        check_strongbox_support_internal(env)
    }).unwrap_or(false)
}

fn check_strongbox_support_internal(env: &mut JNIEnv) -> Result<bool, String> {
    // Use reflection to check for StrongBox support
    // This checks PackageManager.hasSystemFeature("android.hardware.strongbox_keystore")
    
    let activity_thread_class = env.find_class("android/app/ActivityThread")
        .map_err(|e| format!("Failed to find ActivityThread: {:?}", e))?;
    
    let current_app = env.call_static_method(
        activity_thread_class,
        "currentApplication",
        "()Landroid/app/Application;",
        &[],
    ).map_err(|e| format!("Failed to get current application: {:?}", e))?
        .l().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    let pm = env.call_method(
        &current_app,
        "getPackageManager",
        "()Landroid/content/pm/PackageManager;",
        &[],
    ).map_err(|e| format!("Failed to get PackageManager: {:?}", e))?
        .l().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    let feature = env.new_string("android.hardware.strongbox_keystore")
        .map_err(|e| format!("Failed to create string: {:?}", e))?;
    
    let has_feature = env.call_method(
        &pm,
        "hasSystemFeature",
        "(Ljava/lang/String;)Z",
        &[JValue::Object(&feature.into())],
    ).map_err(|e| format!("Failed to check feature: {:?}", e))?
        .z().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    log::info!("Android StrongBox: Available = {}", has_feature);
    Ok(has_feature)
}

/// Seals a master key using Android StrongBox Keystore
pub fn seal_with_android_strongbox(
    key_id: &str,
    master_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    log::info!("Android StrongBox: Sealing key '{}'", key_id);
    
    with_jni_env(|env| {
        seal_with_strongbox_internal(env, key_id, master_key)
    })
}

fn seal_with_strongbox_internal(
    env: &mut JNIEnv,
    key_id: &str,
    master_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Generate or get StrongBox-backed AES key
    let key_alias = format!("QSafeVault_{}", key_id);
    generate_strongbox_key_if_needed(env, &key_alias)?;
    
    log::info!("Android StrongBox: StrongBox key ready");
    
    // Encrypt the master key directly with the StrongBox key
    let encrypted = encrypt_with_strongbox(env, &key_alias, master_key)?;
    
    log::info!("Android StrongBox: Key sealed successfully");
    
    // Return encrypted data and empty nonce (StrongBox uses internal IV)
    Ok((encrypted, vec![]))
}

/// Unseals a master key using Android StrongBox Keystore
pub fn unseal_with_android_strongbox(
    key_id: &str,
    wrapped_data: &[u8],
    _nonce: &[u8],
) -> Result<Vec<u8>, String> {
    log::info!("Android StrongBox: Unsealing key '{}'", key_id);
    
    with_jni_env(|env| {
        let key_alias = format!("QSafeVault_{}", key_id);
        decrypt_with_strongbox(env, &key_alias, wrapped_data)
    })
}

/// Deletes a key from Android StrongBox Keystore
pub fn delete_from_android_strongbox(key_id: &str) -> Result<(), String> {
    log::info!("Android StrongBox: Deleting key '{}'", key_id);
    
    with_jni_env(|env| {
        let key_alias = format!("QSafeVault_{}", key_id);
        delete_strongbox_key(env, &key_alias)
    })
}

// Internal helper functions

fn generate_strongbox_key_if_needed(env: &mut JNIEnv, key_alias: &str) -> Result<(), String> {
    // Get KeyStore instance
    let keystore_class = env.find_class("java/security/KeyStore")
        .map_err(|e| format!("Failed to find KeyStore class: {:?}", e))?;
    
    let provider_str = env.new_string("AndroidKeyStore")
        .map_err(|e| format!("Failed to create string: {:?}", e))?;
    
    let keystore = env.call_static_method(
        keystore_class,
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/KeyStore;",
        &[JValue::Object(&provider_str.into())],
    ).map_err(|e| format!("Failed to get KeyStore: {:?}", e))?
        .l().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Load keystore
    env.call_method(&keystore, "load", "(Ljava/security/KeyStore$LoadStoreParameter;)V", &[JValue::Object(&JObject::null())])
        .map_err(|e| format!("Failed to load keystore: {:?}", e))?;
    
    // Check if key already exists
    let key_alias_str = env.new_string(key_alias)
        .map_err(|e| format!("Failed to create key alias string: {:?}", e))?;
    
    let contains_alias = env.call_method(
        &keystore,
        "containsAlias",
        "(Ljava/lang/String;)Z",
        &[JValue::Object(&key_alias_str.into())],
    ).map_err(|e| format!("Failed to check alias: {:?}", e))?
        .z().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    if contains_alias {
        log::info!("Android StrongBox: Key already exists");
        return Ok(());
    }
    
    // Generate new StrongBox-backed key
    let key_gen_class = env.find_class("javax/crypto/KeyGenerator")
        .map_err(|e| format!("Failed to find KeyGenerator: {:?}", e))?;
    
    let aes_str = env.new_string("AES")
        .map_err(|e| format!("Failed to create string: {:?}", e))?;
    
    let key_gen = env.call_static_method(
        key_gen_class,
        "getInstance",
        "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
        &[JValue::Object(&aes_str.into()), JValue::Object(&provider_str.into())],
    ).map_err(|e| format!("Failed to get KeyGenerator: {:?}", e))?
        .l().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Build KeyGenParameterSpec with StrongBox
    let spec = build_key_gen_parameter_spec(env, key_alias)?;
    
    // Initialize and generate key
    env.call_method(&key_gen, "init", "(Ljava/security/spec/AlgorithmParameterSpec;)V", &[JValue::Object(&spec)])
        .map_err(|e| format!("Failed to init KeyGenerator: {:?}", e))?;
    
    env.call_method(&key_gen, "generateKey", "()Ljavax/crypto/SecretKey;", &[])
        .map_err(|e| format!("Failed to generate key: {:?}", e))?;
    
    log::info!("Android StrongBox: Key generated successfully");
    Ok(())
}

fn build_key_gen_parameter_spec<'local>(
    env: &mut JNIEnv<'local>,
    key_alias: &str,
) -> Result<JObject<'local>, String> {
    let builder_class = env.find_class("android/security/keystore/KeyGenParameterSpec$Builder")
        .map_err(|e| format!("Failed to find Builder class: {:?}", e))?;
    
    let key_alias_str = env.new_string(key_alias)
        .map_err(|e| format!("Failed to create string: {:?}", e))?;
    
    // KeyProperties.PURPOSE_ENCRYPT | PURPOSE_DECRYPT = 3
    let purposes = 3i32;
    
    let builder = env.new_object(
        builder_class,
        "(Ljava/lang/String;I)V",
        &[JValue::Object(&key_alias_str.into()), JValue::Int(purposes)],
    ).map_err(|e| format!("Failed to create Builder: {:?}", e))?;
    
    // Set block modes
    let gcm_str = env.new_string("GCM")
        .map_err(|e| format!("Failed to create string: {:?}", e))?;
    let string_class = env.find_class("java/lang/String")
        .map_err(|e| format!("Failed to find String class: {:?}", e))?;
    let block_modes = env.new_object_array(1, string_class, &gcm_str)
        .map_err(|e| format!("Failed to create array: {:?}", e))?;
    
    let builder = env.call_method(
        &builder,
        "setBlockModes",
        "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Object(&block_modes.into())],
    ).map_err(|e| format!("Failed to set block modes: {:?}", e))?
        .l().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Set encryption paddings
    let no_padding_str = env.new_string("NoPadding")
        .map_err(|e| format!("Failed to create string: {:?}", e))?;
    let paddings = env.new_object_array(1, string_class, &no_padding_str)
        .map_err(|e| format!("Failed to create array: {:?}", e))?;
    
    let builder = env.call_method(
        &builder,
        "setEncryptionPaddings",
        "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Object(&paddings.into())],
    ).map_err(|e| format!("Failed to set paddings: {:?}", e))?
        .l().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Set key size
    let builder = env.call_method(
        &builder,
        "setKeySize",
        "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Int(256)],
    ).map_err(|e| format!("Failed to set key size: {:?}", e))?
        .l().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Enable StrongBox
    let builder = env.call_method(
        &builder,
        "setIsStrongBoxBacked",
        "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Bool(1)],
    ).map_err(|e| format!("Failed to set StrongBox: {:?}", e))?
        .l().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Build the spec
    let spec = env.call_method(
        &builder,
        "build",
        "()Landroid/security/keystore/KeyGenParameterSpec;",
        &[],
    ).map_err(|e| format!("Failed to build spec: {:?}", e))?
        .l().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    Ok(spec)
}

fn encrypt_with_strongbox(
    env: &mut JNIEnv,
    key_alias: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    // Get the key from KeyStore
    let key = get_key_from_keystore(env, key_alias)?;
    
    // Get Cipher instance
    let cipher_class = env.find_class("javax/crypto/Cipher")
        .map_err(|e| format!("Failed to find Cipher: {:?}", e))?;
    
    let transformation = env.new_string("AES/GCM/NoPadding")
        .map_err(|e| format!("Failed to create string: {:?}", e))?;
    
    let cipher = env.call_static_method(
        cipher_class,
        "getInstance",
        "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
        &[JValue::Object(&transformation.into())],
    ).map_err(|e| format!("Failed to get Cipher: {:?}", e))?
        .l().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Initialize for encryption (mode 1 = ENCRYPT_MODE)
    env.call_method(
        &cipher,
        "init",
        "(ILjava/security/Key;)V",
        &[JValue::Int(1), JValue::Object(&key)],
    ).map_err(|e| format!("Failed to init cipher: {:?}", e))?;
    
    // Get IV
    let iv = env.call_method(&cipher, "getIV", "()[B", &[])
        .map_err(|e| format!("Failed to get IV: {:?}", e))?
        .l().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Convert plaintext to Java byte array
    let plaintext_arr = env.byte_array_from_slice(plaintext)
        .map_err(|e| format!("Failed to create byte array: {:?}", e))?;
    
    // Encrypt
    let ciphertext = env.call_method(
        &cipher,
        "doFinal",
        "([B)[B",
        &[JValue::Object(&plaintext_arr.into())],
    ).map_err(|e| format!("Failed to encrypt: {:?}", e))?
        .l().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Convert results to Rust
    let iv_bytes = env.convert_byte_array(iv.as_raw().cast())
        .map_err(|e| format!("Failed to convert IV: {:?}", e))?;
    let ciphertext_bytes = env.convert_byte_array(ciphertext.as_raw().cast())
        .map_err(|e| format!("Failed to convert ciphertext: {:?}", e))?;
    
    // Combine IV + ciphertext
    let mut result = Vec::with_capacity(iv_bytes.len() + ciphertext_bytes.len() + 4);
    result.extend_from_slice(&(iv_bytes.len() as u32).to_le_bytes());
    result.extend_from_slice(&iv_bytes);
    result.extend_from_slice(&ciphertext_bytes);
    
    Ok(result)
}

fn decrypt_with_strongbox(
    env: &mut JNIEnv,
    key_alias: &str,
    encrypted: &[u8],
) -> Result<Vec<u8>, String> {
    // Parse IV and ciphertext
    if encrypted.len() < 4 {
        return Err("Invalid encrypted data".to_string());
    }
    
    let iv_len = u32::from_le_bytes([encrypted[0], encrypted[1], encrypted[2], encrypted[3]]) as usize;
    if encrypted.len() < 4 + iv_len {
        return Err("Invalid encrypted data".to_string());
    }
    
    let iv = &encrypted[4..4 + iv_len];
    let ciphertext = &encrypted[4 + iv_len..];
    
    // Get the key from KeyStore
    let key = get_key_from_keystore(env, key_alias)?;
    
    // Get Cipher instance
    let cipher_class = env.find_class("javax/crypto/Cipher")
        .map_err(|e| format!("Failed to find Cipher: {:?}", e))?;
    
    let transformation = env.new_string("AES/GCM/NoPadding")
        .map_err(|e| format!("Failed to create string: {:?}", e))?;
    
    let cipher = env.call_static_method(
        cipher_class,
        "getInstance",
        "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
        &[JValue::Object(&transformation.into())],
    ).map_err(|e| format!("Failed to get Cipher: {:?}", e))?
        .l().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Create GCMParameterSpec
    let gcm_spec_class = env.find_class("javax/crypto/spec/GCMParameterSpec")
        .map_err(|e| format!("Failed to find GCMParameterSpec: {:?}", e))?;
    
    let iv_arr = env.byte_array_from_slice(iv)
        .map_err(|e| format!("Failed to create IV array: {:?}", e))?;
    
    let gcm_spec = env.new_object(
        gcm_spec_class,
        "(I[B)V",
        &[JValue::Int(128), JValue::Object(&iv_arr.into())],
    ).map_err(|e| format!("Failed to create GCMParameterSpec: {:?}", e))?;
    
    // Initialize for decryption (mode 2 = DECRYPT_MODE)
    env.call_method(
        &cipher,
        "init",
        "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[JValue::Int(2), JValue::Object(&key), JValue::Object(&gcm_spec)],
    ).map_err(|e| format!("Failed to init cipher: {:?}", e))?;
    
    // Convert ciphertext to Java byte array
    let ciphertext_arr = env.byte_array_from_slice(ciphertext)
        .map_err(|e| format!("Failed to create byte array: {:?}", e))?;
    
    // Decrypt
    let plaintext = env.call_method(
        &cipher,
        "doFinal",
        "([B)[B",
        &[JValue::Object(&ciphertext_arr.into())],
    ).map_err(|e| format!("Failed to decrypt: {:?}", e))?
        .l().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Convert to Rust
    let plaintext_bytes = env.convert_byte_array(plaintext.as_raw().cast())
        .map_err(|e| format!("Failed to convert plaintext: {:?}", e))?;
    
    Ok(plaintext_bytes)
}

fn get_key_from_keystore<'local>(
    env: &mut JNIEnv<'local>,
    key_alias: &str,
) -> Result<JObject<'local>, String> {
    let keystore_class = env.find_class("java/security/KeyStore")
        .map_err(|e| format!("Failed to find KeyStore: {:?}", e))?;
    
    let provider_str = env.new_string("AndroidKeyStore")
        .map_err(|e| format!("Failed to create string: {:?}", e))?;
    
    let keystore = env.call_static_method(
        keystore_class,
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/KeyStore;",
        &[JValue::Object(&provider_str.into())],
    ).map_err(|e| format!("Failed to get KeyStore: {:?}", e))?
        .l().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    env.call_method(&keystore, "load", "(Ljava/security/KeyStore$LoadStoreParameter;)V", &[JValue::Object(&JObject::null())])
        .map_err(|e| format!("Failed to load keystore: {:?}", e))?;
    
    let key_alias_str = env.new_string(key_alias)
        .map_err(|e| format!("Failed to create string: {:?}", e))?;
    
    let key = env.call_method(
        &keystore,
        "getKey",
        "(Ljava/lang/String;[C)Ljava/security/Key;",
        &[JValue::Object(&key_alias_str.into()), JValue::Object(&JObject::null())],
    ).map_err(|e| format!("Failed to get key: {:?}", e))?
        .l().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    Ok(key)
}

fn delete_strongbox_key(env: &mut JNIEnv, key_alias: &str) -> Result<(), String> {
    let keystore_class = env.find_class("java/security/KeyStore")
        .map_err(|e| format!("Failed to find KeyStore: {:?}", e))?;
    
    let provider_str = env.new_string("AndroidKeyStore")
        .map_err(|e| format!("Failed to create string: {:?}", e))?;
    
    let keystore = env.call_static_method(
        keystore_class,
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/KeyStore;",
        &[JValue::Object(&provider_str.into())],
    ).map_err(|e| format!("Failed to get KeyStore: {:?}", e))?
        .l().map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    env.call_method(&keystore, "load", "(Ljava/security/KeyStore$LoadStoreParameter;)V", &[JValue::Object(&JObject::null())])
        .map_err(|e| format!("Failed to load keystore: {:?}", e))?;
    
    let key_alias_str = env.new_string(key_alias)
        .map_err(|e| format!("Failed to create string: {:?}", e))?;
    
    env.call_method(
        &keystore,
        "deleteEntry",
        "(Ljava/lang/String;)V",
        &[JValue::Object(&key_alias_str.into())],
    ).map_err(|e| format!("Failed to delete key: {:?}", e))?;
    
    log::info!("Android StrongBox: Key deleted");
    Ok(())
}
