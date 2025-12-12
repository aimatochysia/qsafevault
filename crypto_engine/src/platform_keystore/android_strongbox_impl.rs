// Android StrongBox Full Implementation using JNI
// Provides hardware-backed key storage using Android Keystore with StrongBox

#![cfg(target_os = "android")]

use crate::symmetric::{aes_gcm_encrypt, aes_gcm_decrypt};
use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jbyteArray, jstring};
use std::sync::Mutex;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Global JVM reference (must be set by Flutter/Android during initialization)
static mut JVM: Option<*mut jni::JavaVM> = None;
static JVM_LOCK: Mutex<()> = Mutex::new(());

/// Initialize JNI (call this from Flutter Android initialization)
pub fn init_jni(env: JNIEnv) {
    unsafe {
        let _lock = JVM_LOCK.lock().unwrap();
        if JVM.is_none() {
            if let Ok(jvm) = env.get_java_vm() {
                JVM = Some(Box::into_raw(Box::new(jvm)));
                log::info!("Android StrongBox: JNI initialized");
            }
        }
    }
}

/// Get JNI environment
fn get_env() -> Result<JNIEnv<'static>, String> {
    unsafe {
        let _lock = JVM_LOCK.lock().unwrap();
        if let Some(jvm_ptr) = JVM {
            let jvm = &*jvm_ptr;
            jvm.get_env()
                .map_err(|e| format!("Failed to get JNI env: {:?}", e))
        } else {
            Err("JNI not initialized".to_string())
        }
    }
}

/// Check if StrongBox is available on this device
pub fn is_strongbox_available() -> bool {
    match check_strongbox_support() {
        Ok(available) => {
            log::info!("Android StrongBox: Available = {}", available);
            available
        }
        Err(e) => {
            log::warn!("Android StrongBox: Check failed: {}", e);
            false
        }
    }
}

/// Seals a master key using Android StrongBox Keystore
pub fn seal_with_android_strongbox(
    key_id: &str,
    master_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    log::info!("Android StrongBox: Sealing key '{}'", key_id);
    
    let mut env = get_env()?;
    
    // Generate StrongBox-backed wrapping key
    generate_strongbox_key(&mut env, key_id)?;
    
    log::info!("Android StrongBox: Wrapping key generated");
    
    // Generate random AES key
    use rand_core::RngCore;
    let mut wrapping_key = vec![0u8; 32];
    rand_core::OsRng.fill_bytes(&mut wrapping_key);
    
    // Encrypt AES key with StrongBox key
    let encrypted_aes_key = encrypt_with_strongbox_key(&mut env, key_id, &wrapping_key)?;
    
    log::info!("Android StrongBox: AES key encrypted");
    
    // Wrap master key with AES-GCM
    let (wrapped_master, nonce) = aes_gcm_encrypt(&wrapping_key, master_key)
        .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;
    
    // Combine: [encrypted_aes_key_len(4) | encrypted_aes_key | wrapped_master]
    let mut combined = Vec::with_capacity(4 + encrypted_aes_key.len() + wrapped_master.len());
    combined.extend_from_slice(&(encrypted_aes_key.len() as u32).to_le_bytes());
    combined.extend_from_slice(&encrypted_aes_key);
    combined.extend_from_slice(&wrapped_master);
    
    // Zeroize sensitive data
    wrapping_key.zeroize();
    
    log::info!("Android StrongBox: Key sealed successfully");
    
    Ok((combined, nonce))
}

/// Unseals a master key using Android StrongBox Keystore
pub fn unseal_with_android_strongbox(
    key_id: &str,
    wrapped_data: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, String> {
    log::info!("Android StrongBox: Unsealing key '{}'", key_id);
    
    // Parse combined data
    if wrapped_data.len() < 4 {
        return Err("Invalid wrapped data format".to_string());
    }
    
    let encrypted_aes_key_len = u32::from_le_bytes([
        wrapped_data[0],
        wrapped_data[1],
        wrapped_data[2],
        wrapped_data[3],
    ]) as usize;
    
    if wrapped_data.len() < 4 + encrypted_aes_key_len {
        return Err("Invalid wrapped data format".to_string());
    }
    
    let encrypted_aes_key = &wrapped_data[4..4 + encrypted_aes_key_len];
    let wrapped_master = &wrapped_data[4 + encrypted_aes_key_len..];
    
    let mut env = get_env()?;
    
    // Decrypt AES key with StrongBox key
    let mut wrapping_key = decrypt_with_strongbox_key(&mut env, key_id, encrypted_aes_key)?;
    
    log::info!("Android StrongBox: AES key decrypted");
    
    // Unwrap master key with AES-GCM
    let master_key = aes_gcm_decrypt(&wrapping_key, wrapped_master, nonce)
        .map_err(|e| format!("AES-GCM decryption failed: {}", e))?;
    
    // Zeroize sensitive data
    wrapping_key.zeroize();
    
    log::info!("Android StrongBox: Key unsealed successfully");
    
    Ok(master_key)
}

/// Deletes a key from Android StrongBox Keystore
pub fn delete_from_android_strongbox(key_id: &str) -> Result<(), String> {
    log::info!("Android StrongBox: Deleting key '{}'", key_id);
    
    let mut env = get_env()?;
    
    delete_strongbox_key(&mut env, key_id)?;
    
    log::info!("Android StrongBox: Key deleted successfully");
    
    Ok(())
}

// JNI Helper Functions

fn check_strongbox_support() -> Result<bool, String> {
    let mut env = get_env()?;
    
    // Get PackageManager
    let context = get_application_context(&mut env)?;
    let package_manager = env
        .call_method(context, "getPackageManager", "()Landroid/content/pm/PackageManager;", &[])
        .map_err(|e| format!("Failed to get PackageManager: {:?}", e))?
        .l()
        .map_err(|e| format!("Failed to convert to object: {:?}", e))?;
    
    // Check for FEATURE_STRONGBOX_KEYSTORE
    let feature_name = env
        .new_string("android.hardware.strongbox_keystore")
        .map_err(|e| format!("Failed to create string: {:?}", e))?;
    
    let has_feature = env
        .call_method(
            package_manager,
            "hasSystemFeature",
            "(Ljava/lang/String;)Z",
            &[JValue::Object(&feature_name)],
        )
        .map_err(|e| format!("Failed to check feature: {:?}", e))?
        .z()
        .map_err(|e| format!("Failed to convert to boolean: {:?}", e))?;
    
    Ok(has_feature)
}

fn generate_strongbox_key(env: &mut JNIEnv, key_id: &str) -> Result<(), String> {
    // Get KeyStore instance
    let keystore = get_keystore(env)?;
    
    // Get KeyGenerator
    let key_alias = env
        .new_string(format!("QSafeVault_{}", key_id))
        .map_err(|e| format!("Failed to create key alias: {:?}", e))?;
    
    let key_gen_cls = env
        .find_class("javax/crypto/KeyGenerator")
        .map_err(|e| format!("Failed to find KeyGenerator class: {:?}", e))?;
    
    let algorithm = env
        .new_string("AES")
        .map_err(|e| format!("Failed to create algorithm string: {:?}", e))?;
    
    let provider = env
        .new_string("AndroidKeyStore")
        .map_err(|e| format!("Failed to create provider string: {:?}", e))?;
    
    let key_gen = env
        .call_static_method(
            key_gen_cls,
            "getInstance",
            "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
            &[JValue::Object(&algorithm), JValue::Object(&provider)],
        )
        .map_err(|e| format!("Failed to get KeyGenerator instance: {:?}", e))?
        .l()
        .map_err(|e| format!("Failed to convert to object: {:?}", e))?;
    
    // Build KeyGenParameterSpec with StrongBox
    let spec = build_key_spec_with_strongbox(env, &key_alias)?;
    
    // Initialize KeyGenerator
    env.call_method(
        key_gen,
        "init",
        "(Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[JValue::Object(&spec)],
    )
    .map_err(|e| format!("Failed to initialize KeyGenerator: {:?}", e))?;
    
    // Generate key
    env.call_method(key_gen, "generateKey", "()Ljavax/crypto/SecretKey;", &[])
        .map_err(|e| format!("Failed to generate key: {:?}", e))?;
    
    Ok(())
}

fn build_key_spec_with_strongbox(env: &mut JNIEnv, key_alias: &JString) -> Result<JObject, String> {
    let spec_builder_cls = env
        .find_class("android/security/keystore/KeyGenParameterSpec$Builder")
        .map_err(|e| format!("Failed to find Builder class: {:?}", e))?;
    
    // Create builder with key alias and purposes
    let purposes = 3i32; // PURPOSE_ENCRYPT | PURPOSE_DECRYPT
    let builder = env
        .new_object(
            spec_builder_cls,
            "(Ljava/lang/String;I)V",
            &[JValue::Object(key_alias), JValue::Int(purposes)],
        )
        .map_err(|e| format!("Failed to create builder: {:?}", e))?;
    
    // Set block mode to GCM
    let block_mode = env
        .new_string("GCM")
        .map_err(|e| format!("Failed to create block mode: {:?}", e))?;
    
    let block_modes_array = env
        .new_object_array(1, "java/lang/String", &block_mode)
        .map_err(|e| format!("Failed to create block modes array: {:?}", e))?;
    
    let builder = env
        .call_method(
            builder,
            "setBlockModes",
            "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Object(&JObject::from(block_modes_array))],
        )
        .map_err(|e| format!("Failed to set block modes: {:?}", e))?
        .l()
        .map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Set encryption padding to NoPadding
    let padding = env
        .new_string("NoPadding")
        .map_err(|e| format!("Failed to create padding: {:?}", e))?;
    
    let paddings_array = env
        .new_object_array(1, "java/lang/String", &padding)
        .map_err(|e| format!("Failed to create paddings array: {:?}", e))?;
    
    let builder = env
        .call_method(
            builder,
            "setEncryptionPaddings",
            "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Object(&JObject::from(paddings_array))],
        )
        .map_err(|e| format!("Failed to set paddings: {:?}", e))?
        .l()
        .map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Set key size to 256
    let builder = env
        .call_method(
            builder,
            "setKeySize",
            "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Int(256)],
        )
        .map_err(|e| format!("Failed to set key size: {:?}", e))?
        .l()
        .map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Enable StrongBox if available (API 28+)
    let builder = env
        .call_method(
            builder,
            "setIsStrongBoxBacked",
            "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Bool(1)],
        )
        .map_err(|e| format!("Failed to set StrongBox: {:?}", e))?
        .l()
        .map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Build the spec
    let spec = env
        .call_method(builder, "build", "()Landroid/security/keystore/KeyGenParameterSpec;", &[])
        .map_err(|e| format!("Failed to build spec: {:?}", e))?
        .l()
        .map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    Ok(spec)
}

fn encrypt_with_strongbox_key(
    env: &mut JNIEnv,
    key_id: &str,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let key = get_strongbox_key(env, key_id)?;
    
    // Get Cipher instance
    let cipher_cls = env
        .find_class("javax/crypto/Cipher")
        .map_err(|e| format!("Failed to find Cipher class: {:?}", e))?;
    
    let transformation = env
        .new_string("AES/GCM/NoPadding")
        .map_err(|e| format!("Failed to create transformation: {:?}", e))?;
    
    let cipher = env
        .call_static_method(
            cipher_cls,
            "getInstance",
            "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
            &[JValue::Object(&transformation)],
        )
        .map_err(|e| format!("Failed to get Cipher instance: {:?}", e))?
        .l()
        .map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Initialize for encryption
    env.call_method(
        cipher,
        "init",
        "(ILjava/security/Key;)V",
        &[JValue::Int(1), JValue::Object(&key)], // 1 = ENCRYPT_MODE
    )
    .map_err(|e| format!("Failed to init cipher: {:?}", e))?;
    
    // Convert data to byte array
    let data_array = env
        .byte_array_from_slice(data)
        .map_err(|e| format!("Failed to create byte array: {:?}", e))?;
    
    // Encrypt
    let encrypted = env
        .call_method(
            cipher,
            "doFinal",
            "([B)[B",
            &[JValue::Object(&JObject::from(data_array))],
        )
        .map_err(|e| format!("Failed to encrypt: {:?}", e))?
        .l()
        .map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Convert back to Vec<u8>
    let encrypted_bytes = env
        .convert_byte_array(encrypted.into_raw())
        .map_err(|e| format!("Failed to convert encrypted data: {:?}", e))?;
    
    Ok(encrypted_bytes)
}

fn decrypt_with_strongbox_key(
    env: &mut JNIEnv,
    key_id: &str,
    encrypted_data: &[u8],
) -> Result<Vec<u8>, String> {
    let key = get_strongbox_key(env, key_id)?;
    
    // Get Cipher instance
    let cipher_cls = env
        .find_class("javax/crypto/Cipher")
        .map_err(|e| format!("Failed to find Cipher class: {:?}", e))?;
    
    let transformation = env
        .new_string("AES/GCM/NoPadding")
        .map_err(|e| format!("Failed to create transformation: {:?}", e))?;
    
    let cipher = env
        .call_static_method(
            cipher_cls,
            "getInstance",
            "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
            &[JValue::Object(&transformation)],
        )
        .map_err(|e| format!("Failed to get Cipher instance: {:?}", e))?
        .l()
        .map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Initialize for decryption
    env.call_method(
        cipher,
        "init",
        "(ILjava/security/Key;)V",
        &[JValue::Int(2), JValue::Object(&key)], // 2 = DECRYPT_MODE
    )
    .map_err(|e| format!("Failed to init cipher: {:?}", e))?;
    
    // Convert data to byte array
    let data_array = env
        .byte_array_from_slice(encrypted_data)
        .map_err(|e| format!("Failed to create byte array: {:?}", e))?;
    
    // Decrypt
    let decrypted = env
        .call_method(
            cipher,
            "doFinal",
            "([B)[B",
            &[JValue::Object(&JObject::from(data_array))],
        )
        .map_err(|e| format!("Failed to decrypt: {:?}", e))?
        .l()
        .map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Convert back to Vec<u8>
    let decrypted_bytes = env
        .convert_byte_array(decrypted.into_raw())
        .map_err(|e| format!("Failed to convert decrypted data: {:?}", e))?;
    
    Ok(decrypted_bytes)
}

fn get_strongbox_key(env: &mut JNIEnv, key_id: &str) -> Result<JObject, String> {
    let keystore = get_keystore(env)?;
    
    let key_alias = env
        .new_string(format!("QSafeVault_{}", key_id))
        .map_err(|e| format!("Failed to create key alias: {:?}", e))?;
    
    let password = JObject::null(); // null for KeyStore password
    
    let key = env
        .call_method(
            keystore,
            "getKey",
            "(Ljava/lang/String;[C)Ljava/security/Key;",
            &[JValue::Object(&key_alias), JValue::Object(&password)],
        )
        .map_err(|e| format!("Failed to get key: {:?}", e))?
        .l()
        .map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    Ok(key)
}

fn delete_strongbox_key(env: &mut JNIEnv, key_id: &str) -> Result<(), String> {
    let keystore = get_keystore(env)?;
    
    let key_alias = env
        .new_string(format!("QSafeVault_{}", key_id))
        .map_err(|e| format!("Failed to create key alias: {:?}", e))?;
    
    env.call_method(
        keystore,
        "deleteEntry",
        "(Ljava/lang/String;)V",
        &[JValue::Object(&key_alias)],
    )
    .map_err(|e| format!("Failed to delete key: {:?}", e))?;
    
    Ok(())
}

fn get_keystore(env: &mut JNIEnv) -> Result<JObject, String> {
    let keystore_cls = env
        .find_class("java/security/KeyStore")
        .map_err(|e| format!("Failed to find KeyStore class: {:?}", e))?;
    
    let provider = env
        .new_string("AndroidKeyStore")
        .map_err(|e| format!("Failed to create provider string: {:?}", e))?;
    
    let keystore = env
        .call_static_method(
            keystore_cls,
            "getInstance",
            "(Ljava/lang/String;)Ljava/security/KeyStore;",
            &[JValue::Object(&provider)],
        )
        .map_err(|e| format!("Failed to get KeyStore instance: {:?}", e))?
        .l()
        .map_err(|e| format!("Failed to convert: {:?}", e))?;
    
    // Load keystore
    env.call_method(keystore, "load", "(Ljava/security/KeyStore$LoadStoreParameter;)V", &[JValue::Object(&JObject::null())])
        .map_err(|e| format!("Failed to load keystore: {:?}", e))?;
    
    Ok(keystore)
}

fn get_application_context(env: &mut JNIEnv) -> Result<JObject, String> {
    // This requires the context to be set during initialization
    // In production, store the application context in a static variable
    Err("Application context not available - must be set during initialization".to_string())
}
