import 'dart:typed_data';
import 'package:qsafevault/ffi/rust_crypto_service.dart';

/// Example usage of the Rust crypto service
void main() async {
  final crypto = RustCryptoService();
  
  print('=== QSafeVault Rust Crypto Engine Example ===\n');
  
  // Example 1: Generate a hybrid keypair
  print('1. Generating hybrid keypair (PQC + Classical)...');
  final keypair = crypto.generateHybridKeypair();
  print('   Keypair handle: ${keypair.handle}');
  print('   PQC public key size: ${keypair.pqcPublicKey.length} bytes');
  print('   Classical public key size: ${keypair.classicalPublicKey.length} bytes\n');
  
  // Example 2: Encrypt and decrypt a master key
  print('2. Master key encryption/decryption with hybrid KEM...');
  final masterKey = Uint8List.fromList(List.generate(32, (i) => i + 1)); // Example key
  print('   Original master key: ${masterKey.sublist(0, 8)}...');
  
  final encryptedMasterKey = crypto.hybridEncryptMasterKey(
    keypair.pqcPublicKey,
    keypair.classicalPublicKey,
    masterKey,
  );
  print('   Encrypted master key size: ${encryptedMasterKey.length} bytes');
  
  final decryptedMasterKey = crypto.hybridDecryptMasterKey(
    keypair.handle,
    encryptedMasterKey,
  );
  print('   Decrypted master key: ${decryptedMasterKey.sublist(0, 8)}...');
  print('   Match: ${_bytesEqual(masterKey, decryptedMasterKey)}\n');
  
  // Example 3: Seal and unseal private key
  print('3. Sealing private key to platform keystore...');
  try {
    crypto.sealPrivateKey(keypair.handle, 'test_key_id_123');
    print('   Private key sealed successfully');
    
    final unsealedHandle = crypto.unsealPrivateKey(
      'test_key_id_123',
      keypair.pqcPublicKey,
      keypair.classicalPublicKey,
    );
    print('   Private key unsealed, new handle: $unsealedHandle');
    
    // Test that unsealed key works
    final testEncrypted = crypto.hybridEncryptMasterKey(
      keypair.pqcPublicKey,
      keypair.classicalPublicKey,
      masterKey,
    );
    final testDecrypted = crypto.hybridDecryptMasterKey(
      unsealedHandle,
      testEncrypted,
    );
    print('   Unsealed key works: ${_bytesEqual(masterKey, testDecrypted)}');
    
    crypto.freeHandle(unsealedHandle);
  } catch (e) {
    print('   Platform keystore not available (expected in some environments): $e');
  }
  print('');
  
  // Example 4: Encrypt and decrypt vault data
  print('4. Vault data encryption/decryption with AES-256-GCM...');
  final vaultData = 'This is secret vault data containing passwords!';
  final vaultBytes = Uint8List.fromList(vaultData.codeUnits);
  print('   Original vault data: "$vaultData"');
  
  final encryptedVault = crypto.encryptVault(masterKey, vaultBytes);
  print('   Encrypted vault size: ${encryptedVault.length} bytes');
  
  final decryptedVault = crypto.decryptVault(masterKey, encryptedVault);
  final decryptedText = String.fromCharCodes(decryptedVault);
  print('   Decrypted vault data: "$decryptedText"');
  print('   Match: ${vaultData == decryptedText}\n');
  
  // Example 5: Complete workflow
  print('5. Complete workflow example...');
  print('   a. Generate Alice\'s keypair');
  final aliceKeypair = crypto.generateHybridKeypair();
  
  print('   b. Generate Bob\'s keypair');
  final bobKeypair = crypto.generateHybridKeypair();
  
  print('   c. Alice encrypts master key for Bob');
  final aliceToBoB = crypto.hybridEncryptMasterKey(
    bobKeypair.pqcPublicKey,
    bobKeypair.classicalPublicKey,
    masterKey,
  );
  
  print('   d. Bob decrypts master key from Alice');
  final bobReceivedKey = crypto.hybridDecryptMasterKey(
    bobKeypair.handle,
    aliceToBoB,
  );
  
  print('   e. Bob uses received key to decrypt vault');
  final bobDecryptedVault = crypto.decryptVault(bobReceivedKey, encryptedVault);
  final bobDecryptedText = String.fromCharCodes(bobDecryptedVault);
  
  print('   Bob successfully decrypted: "$bobDecryptedText"');
  print('   Match: ${vaultData == bobDecryptedText}\n');
  
  // Cleanup
  print('6. Cleaning up handles...');
  crypto.freeHandle(keypair.handle);
  crypto.freeHandle(aliceKeypair.handle);
  crypto.freeHandle(bobKeypair.handle);
  print('   All handles freed\n');
  
  print('=== Example Complete ===');
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
