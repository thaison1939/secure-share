import sodium from 'libsodium-wrappers-sumo';
/**
 * Password-based file encryption using libsodium's ChaCha20-Poly1305 (IETF variant)
 * and Argon2id for password hashing/key derivation.
 */

// EncryptionResult interface matches the data sent to the server.
export interface EncryptionResult {
  encryptedData: Uint8Array;
  passwordHashBase64: string;
  nonceBase64: string;
  pwhashSaltBase64: string;
}

// DecryptionInput interface matches data received from the server + user password.
export interface DecryptionInput {
  encryptedData: Uint8Array;
  nonceBase64: string;
  pwhashSaltBase64: string;
  password: string;
  expectedPasswordHashBase64: string;
}

// ✅ CRITICAL FIX: Initialize constants immediately after sodium.ready
let isInitialized = false;
let PWHASH_OPSLIMIT: number;
let PWHASH_MEMLIMIT: number;
let PWHASH_ALG: number;
let PWHASH_SALT_BYTES: number;
let CHACHA_KEY_BYTES: number;
let CHACHA_NONCE_BYTES: number;
let CHACHA_TAG_BYTES: number;

// --- Helper functions for Base64 conversion ---
function uint8ArrayToBase64(buffer: Uint8Array): string {
  return sodium.to_base64(buffer, sodium.base64_variants.URLSAFE_NO_PADDING);
}

function base64ToUint8Array(base64: string): Uint8Array {
  return sodium.from_base64(base64, sodium.base64_variants.URLSAFE_NO_PADDING);
}

/**
 * ✅ FIXED: Ensure sodium is ready and constants are properly initialized
 */
async function ensureSodiumReady(): Promise<void> {
  if (isInitialized) {
    return; // Already initialized
  }

  await sodium.ready;
  
  console.log('libsodium-sumo initialized successfully');
  console.log('libsodium version:', sodium.sodium_version_string());

  // ✅ CRITICAL FIX: Use correct algorithm constant name
  PWHASH_OPSLIMIT = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
  PWHASH_MEMLIMIT = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;
  PWHASH_ALG = sodium.crypto_pwhash_ALG_ARGON2ID13; // ✅ FIXED: Was ALG_ARGON2ID, should be ALG_ARGON2ID13
  PWHASH_SALT_BYTES = sodium.crypto_pwhash_SALTBYTES;
  CHACHA_KEY_BYTES = sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES;
  CHACHA_NONCE_BYTES = sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
  CHACHA_TAG_BYTES = sodium.crypto_aead_chacha20poly1305_ietf_ABYTES;

  // ✅ DEBUG: Log what we actually get from sodium
  console.log('Raw sodium algorithm constants:', {
    ALG_ARGON2ID: sodium.crypto_pwhash_ALG_ARGON2ID,
    ALG_ARGON2ID13: sodium.crypto_pwhash_ALG_ARGON2ID13,
    ALG_ARGON2I: sodium.crypto_pwhash_ALG_ARGON2I,
    ALG_SCRYPTSALSA208SHA256: sodium.crypto_pwhash_ALG_SCRYPTSALSA208SHA256
  });

  // ✅ VALIDATION: Ensure constants were properly set
  if (!PWHASH_SALT_BYTES || !CHACHA_NONCE_BYTES || !CHACHA_KEY_BYTES || !PWHASH_ALG) {
    console.error('Critical constants not initialized:', {
      PWHASH_SALT_BYTES,
      CHACHA_NONCE_BYTES,
      CHACHA_KEY_BYTES,
      PWHASH_ALG
    });
    throw new Error('Failed to initialize libsodium constants');
  }

  console.log('Constants initialized successfully:', {
    PWHASH_SALT_BYTES,
    CHACHA_KEY_BYTES,
    CHACHA_NONCE_BYTES,
    CHACHA_TAG_BYTES,
    PWHASH_OPSLIMIT,
    PWHASH_MEMLIMIT,
    PWHASH_ALG // ✅ This should now show a number
  });

  // ✅ TEST: Verify key functions are available
  if (typeof sodium.crypto_pwhash !== 'function') {
    throw new Error('crypto_pwhash function not available');
  }
  if (typeof sodium.crypto_aead_chacha20poly1305_ietf_encrypt !== 'function') {
    throw new Error('crypto_aead_chacha20poly1305_ietf_encrypt function not available');
  }
  
  isInitialized = true;
  console.log('libsodium-sumo fully ready for use');
}

/**
 * ✅ FIXED: Derive encryption key with proper validation
 */
async function deriveEncryptionKeyFromPassword(password: string, pwhashSalt: Uint8Array): Promise<Uint8Array> {
  await ensureSodiumReady();
  
  console.log('Deriving encryption key with Argon2id...');
  console.log('Password length:', password.length);
  console.log('PwhashSalt length:', pwhashSalt.length, '(expected:', PWHASH_SALT_BYTES, ')');
  
  if (pwhashSalt.length !== PWHASH_SALT_BYTES) {
    throw new Error(`Invalid pwhash salt length: ${pwhashSalt.length}, expected: ${PWHASH_SALT_BYTES}`);
  }

  try {
    const key = sodium.crypto_pwhash(
      CHACHA_KEY_BYTES,
      password,
      pwhashSalt,
      PWHASH_OPSLIMIT,
      PWHASH_MEMLIMIT,
      PWHASH_ALG
    );
    
    console.log('Encryption key derived, length:', key.length);
    return key;
  } catch (error) {
    console.error('Encryption key derivation failed:', error);
    throw new Error('Failed to derive encryption key');
  }
}

/**
 * ✅ FIXED: Derive password hash with proper validation
 */
export async function derivePasswordHash(password: string, pwhashSalt: Uint8Array): Promise<Uint8Array> {
  await ensureSodiumReady();
  
  console.log('Deriving password hash with Argon2id...');
  console.log('Password length:', password.length);
  console.log('PwhashSalt length:', pwhashSalt.length, '(expected:', PWHASH_SALT_BYTES, ')');
  
  if (pwhashSalt.length !== PWHASH_SALT_BYTES) {
    throw new Error(`Invalid pwhash salt length: ${pwhashSalt.length}, expected: ${PWHASH_SALT_BYTES}`);
  }

  try {
    const hash = sodium.crypto_pwhash(
      CHACHA_KEY_BYTES, // Same length as key for consistency
      password,
      pwhashSalt,
      PWHASH_OPSLIMIT,
      PWHASH_MEMLIMIT,
      PWHASH_ALG
    );
    
    console.log('Password hash derived, length:', hash.length);
    return hash;
  } catch (error) {
    console.error('Password hash derivation failed:', error);
    throw new Error('Failed to derive password hash');
  }
}

/**
 * ✅ FIXED: Encrypt file with improved error handling
 */
export async function encryptFile(file: File, password: string): Promise<EncryptionResult> {
  await ensureSodiumReady(); // ✅ This MUST complete before accessing constants
  
  try {
    console.log('Starting file encryption...');
    console.log('File size:', file.size, 'bytes');
    console.log('Password length:', password.length, 'characters');
    
    // ✅ VALIDATION: Ensure constants are available before using them
    console.log('Constants check before generation:', {
      CHACHA_NONCE_BYTES,
      PWHASH_SALT_BYTES,
      isInitialized
    });
    
    if (!CHACHA_NONCE_BYTES || !PWHASH_SALT_BYTES) {
      throw new Error('Libsodium constants not properly initialized');
    }

    // Generate separate nonce for ChaCha20-Poly1305 (12 bytes)
    console.log('Generating nonce with CHACHA_NONCE_BYTES:', CHACHA_NONCE_BYTES);
    const nonce = sodium.randombytes_buf(CHACHA_NONCE_BYTES);
    console.log('Generated nonce length:', nonce.length, 'bytes');

    // ✅ FIXED: Generate dedicated salt for Argon2id (16 bytes)
    console.log('Generating pwhash salt with PWHASH_SALT_BYTES:', PWHASH_SALT_BYTES);
    const pwhashSalt = sodium.randombytes_buf(PWHASH_SALT_BYTES);
    console.log('Generated pwhash salt length:', pwhashSalt.length, 'bytes');

    // Read file data
    const fileBuffer = await file.arrayBuffer();
    const fileData = new Uint8Array(fileBuffer);
    console.log('File data loaded, length:', fileData.length, 'bytes');

    // Derive encryption key using pwhash salt
    console.log('Deriving encryption key...');
    const encryptionKey = await deriveEncryptionKeyFromPassword(password, pwhashSalt);

    // Derive password hash using pwhash salt
    console.log('Deriving password hash...');
    const passwordHash = await derivePasswordHash(password, pwhashSalt);

    // Encrypt file data
    console.log('Encrypting with ChaCha20-Poly1305...');
    const encryptedData = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      fileData,           // message
      null,               // additional_data
      null,               // secret_nonce (not used in IETF variant)
      nonce,              // public_nonce
      encryptionKey       // key
    );
    
    console.log('File encrypted successfully, encrypted length:', encryptedData.length, 'bytes');

    const result = {
      encryptedData,
      passwordHashBase64: uint8ArrayToBase64(passwordHash),
      nonceBase64: uint8ArrayToBase64(nonce),
      pwhashSaltBase64: uint8ArrayToBase64(pwhashSalt),
    };
    
    console.log('Encryption result prepared:', {
      encryptedDataLength: result.encryptedData.length,
      passwordHashBase64Length: result.passwordHashBase64.length,
      nonceBase64Length: result.nonceBase64.length,
      pwhashSaltBase64Length: result.pwhashSaltBase64.length
    });
    
    return result;
    
  } catch (error) {
    console.error('File encryption failed:', error);
    throw new Error(`Failed to encrypt file: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * ✅ UPDATED: Verify password using pwhash salt
 */
export async function verifyPassword(
  password: string,
  pwhashSaltBase64: string,
  expectedPasswordHashBase64: string
): Promise<boolean> {
  await ensureSodiumReady();
  
  try {
    const pwhashSalt = base64ToUint8Array(pwhashSaltBase64);
    const expectedHash = base64ToUint8Array(expectedPasswordHashBase64);
    
    const derivedHash = await derivePasswordHash(password, pwhashSalt);
    
    return sodium.compare(derivedHash, expectedHash) === 0;
  } catch (error) {
    console.error('Password verification failed:', error);
    return false;
  }
}

/**
 * ✅ UPDATED: Decrypt file using separate salts
 */
export async function decryptFile(input: DecryptionInput): Promise<Uint8Array> {
  await ensureSodiumReady();
  
  try {
    console.log('Starting file decryption...');
    
    // Verify password using pwhash salt
    const passwordValid = await verifyPassword(
      input.password,
      input.pwhashSaltBase64,
      input.expectedPasswordHashBase64
    );
    
    if (!passwordValid) {
      throw new Error('Incorrect password provided.');
    }
    
    // Convert base64 to Uint8Array
    const nonce = base64ToUint8Array(input.nonceBase64);
    const pwhashSalt = base64ToUint8Array(input.pwhashSaltBase64);
    
    // Re-derive encryption key using pwhash salt
    const decryptionKey = await deriveEncryptionKeyFromPassword(input.password, pwhashSalt);
    
    // Decrypt using nonce
    const decryptedData = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
      null,
      input.encryptedData,
      null,
      nonce,
      decryptionKey
    );

    console.log('File decrypted successfully');
    return decryptedData;
    
  } catch (error) {
    console.error('File decryption failed:', error);
    if (error instanceof Error && error.message === 'Incorrect password provided.') {
      throw error;
    }
    throw new Error('Failed to decrypt file - corrupted data or general decryption error');
  }
}
