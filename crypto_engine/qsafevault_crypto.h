/* QSafeVault Crypto Engine C API Header
 * 
 * This header provides the FFI interface to the Rust cryptographic backend.
 * All cryptographic operations should go through these functions.
 * 
 * Flutter/Dart code must never handle raw key material directly.
 */

#ifndef QSAFEVAULT_CRYPTO_ENGINE_H
#define QSAFEVAULT_CRYPTO_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes */
#define PQCRYPTO_STATUS_OK 0
#define PQCRYPTO_STATUS_ERROR -1
#define PQCRYPTO_STATUS_INVALID_PARAM -2
#define PQCRYPTO_STATUS_NOT_FOUND -3

/* Type definitions */
typedef uint64_t pqcrypto_handle_t;

/**
 * Generate a new hybrid keypair (PQC + Classical)
 * 
 * @param keypair_handle_out Output: handle to the generated keypair
 * @param pqc_public_key_out Output: pointer to PQC public key (caller must free)
 * @param pqc_public_key_len_out Output: length of PQC public key
 * @param classical_public_key_out Output: 32-byte classical public key
 * @param error_msg_out Output: error message if failed (caller must free)
 * @return Status code
 */
int32_t pqcrypto_generate_hybrid_keypair(
    pqcrypto_handle_t *keypair_handle_out,
    uint8_t **pqc_public_key_out,
    size_t *pqc_public_key_len_out,
    uint8_t *classical_public_key_out,
    char **error_msg_out
);

/**
 * Hybrid encrypt a master key
 * Encapsulates to public keys, then wraps the master key with the shared secret
 * 
 * @param pqc_public_key PQC public key
 * @param pqc_public_key_len Length of PQC public key
 * @param classical_public_key 32-byte classical public key
 * @param master_key 32-byte master key to encrypt
 * @param sealed_blob_out Output: sealed blob (caller must free)
 * @param sealed_blob_len_out Output: length of sealed blob
 * @param error_msg_out Output: error message if failed (caller must free)
 * @return Status code
 */
int32_t pqcrypto_hybrid_encrypt_master_key(
    const uint8_t *pqc_public_key,
    size_t pqc_public_key_len,
    const uint8_t *classical_public_key,
    const uint8_t *master_key,
    uint8_t **sealed_blob_out,
    size_t *sealed_blob_len_out,
    char **error_msg_out
);

/**
 * Hybrid decrypt a master key
 * Decapsulates ciphertext with keypair, then unwraps the master key
 * 
 * @param keypair_handle Handle to the keypair
 * @param sealed_blob Sealed blob containing encrypted master key
 * @param sealed_blob_len Length of sealed blob
 * @param master_key_out Output: 32-byte master key
 * @param error_msg_out Output: error message if failed (caller must free)
 * @return Status code
 */
int32_t pqcrypto_hybrid_decrypt_master_key(
    pqcrypto_handle_t keypair_handle,
    const uint8_t *sealed_blob,
    size_t sealed_blob_len,
    uint8_t *master_key_out,
    char **error_msg_out
);

/**
 * Seal private key with platform keystore
 * Stores the private key using platform-specific secure storage
 * 
 * @param keypair_handle Handle to the keypair
 * @param key_id Identifier for the key in platform keystore
 * @param error_msg_out Output: error message if failed (caller must free)
 * @return Status code
 */
int32_t pqcrypto_seal_private_key_with_platform_keystore(
    pqcrypto_handle_t keypair_handle,
    const char *key_id,
    char **error_msg_out
);

/**
 * Unseal private key from platform keystore
 * Retrieves the private key from platform-specific secure storage
 * 
 * @param key_id Identifier for the key in platform keystore
 * @param pqc_public_key PQC public key
 * @param pqc_public_key_len Length of PQC public key
 * @param classical_public_key 32-byte classical public key
 * @param keypair_handle_out Output: handle to the unsealed keypair
 * @param error_msg_out Output: error message if failed (caller must free)
 * @return Status code
 */
int32_t pqcrypto_unseal_private_key_from_platform_keystore(
    const char *key_id,
    const uint8_t *pqc_public_key,
    size_t pqc_public_key_len,
    const uint8_t *classical_public_key,
    pqcrypto_handle_t *keypair_handle_out,
    char **error_msg_out
);

/**
 * Encrypt vault data with AES-256-GCM
 * 
 * @param master_key 32-byte master key
 * @param plaintext Plaintext data to encrypt
 * @param plaintext_len Length of plaintext
 * @param sealed_blob_out Output: sealed blob (caller must free)
 * @param sealed_blob_len_out Output: length of sealed blob
 * @param error_msg_out Output: error message if failed (caller must free)
 * @return Status code
 */
int32_t pqcrypto_encrypt_vault(
    const uint8_t *master_key,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t **sealed_blob_out,
    size_t *sealed_blob_len_out,
    char **error_msg_out
);

/**
 * Decrypt vault data with AES-256-GCM
 * 
 * @param master_key 32-byte master key
 * @param sealed_blob Sealed blob containing encrypted data
 * @param sealed_blob_len Length of sealed blob
 * @param plaintext_out Output: decrypted plaintext (caller must free)
 * @param plaintext_len_out Output: length of plaintext
 * @param error_msg_out Output: error message if failed (caller must free)
 * @return Status code
 */
int32_t pqcrypto_decrypt_vault(
    const uint8_t *master_key,
    const uint8_t *sealed_blob,
    size_t sealed_blob_len,
    uint8_t **plaintext_out,
    size_t *plaintext_len_out,
    char **error_msg_out
);

/**
 * Free a handle (keypair or key)
 * 
 * @param handle Handle to free
 * @return Status code
 */
int32_t pqcrypto_free_handle(pqcrypto_handle_t handle);

/**
 * Free memory allocated by Rust
 * 
 * @param ptr Pointer to memory to free
 */
void pqcrypto_free_memory(uint8_t *ptr);

/**
 * Free error message string
 * 
 * @param ptr Pointer to string to free
 */
void pqcrypto_free_string(char *ptr);

/**
 * Get backend detection information
 * Returns a JSON string with available backends and active backend type
 * 
 * @param info_out Output: JSON string with backend info (caller must free with pqcrypto_free_string)
 * @param error_msg_out Output: error message if failed (caller must free with pqcrypto_free_string)
 * @return Status code
 * 
 * Example output:
 * {
 *   "tpm_available": true,
 *   "softhsm_available": true,
 *   "platform_secure_available": false,
 *   "backend_type": "TPMAndSoftHSM"
 * }
 */
int32_t pqcrypto_get_backend_info(
    char **info_out,
    char **error_msg_out
);

/**
 * Initialize logging system
 * Call this before other functions to enable debug logging
 * 
 * @param level Log level: 0=Error, 1=Warn, 2=Info, 3=Debug, 4=Trace
 * @return Status code
 * 
 * Logs include:
 * - Backend detection results
 * - Algorithm identifiers
 * - Operation types
 * - Success/failure status
 * 
 * Never logs:
 * - Raw cryptographic keys
 * - Shared secrets
 * - Plaintext data
 * - Internal entropy
 */
int32_t pqcrypto_init_logging(int32_t level);

/**
 * Generate secure random bytes
 * Uses the OS cryptographically secure random number generator
 * 
 * @param length Number of random bytes to generate
 * @param bytes_out Output: pointer to random bytes (caller must free with pqcrypto_free_memory)
 * @param error_msg_out Output: error message if failed (caller must free with pqcrypto_free_string)
 * @return Status code
 */
int32_t pqcrypto_generate_random_bytes(
    size_t length,
    uint8_t **bytes_out,
    char **error_msg_out
);

/**
 * Derive a key using HKDF-SHA3-256
 * Used for key derivation from shared secrets
 * 
 * @param input_key_material Input key material
 * @param ikm_len Length of input key material
 * @param salt Optional salt (can be NULL)
 * @param salt_len Length of salt (0 if no salt)
 * @param info Optional context/application-specific information (can be NULL)
 * @param info_len Length of info (0 if no info)
 * @param output_key_len Desired length of output key
 * @param output_key_out Output: derived key (caller must free with pqcrypto_free_memory)
 * @param error_msg_out Output: error message if failed (caller must free with pqcrypto_free_string)
 * @return Status code
 */
int32_t pqcrypto_derive_key_hkdf(
    const uint8_t *input_key_material,
    size_t ikm_len,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *info,
    size_t info_len,
    size_t output_key_len,
    uint8_t **output_key_out,
    char **error_msg_out
);

/**
 * Get version and algorithm information
 * Returns a JSON string with version and supported algorithms
 * 
 * @param version_out Output: JSON string with version info (caller must free with pqcrypto_free_string)
 * @return Status code
 * 
 * Example output:
 * {
 *   "version": "0.1.0",
 *   "algorithms": {
 *     "kem": "ML-KEM-768 (Kyber)",
 *     "classical": "X25519",
 *     "kdf": "HKDF-SHA3-256",
 *     "cipher": "AES-256-GCM",
 *     "hash": "SHA3-256"
 *   },
 *   "fips_compatible": true,
 *   "post_quantum": true
 * }
 */
int32_t pqcrypto_get_version(char **version_out);

#ifdef __cplusplus
}
#endif

#endif /* QSAFEVAULT_CRYPTO_ENGINE_H */
