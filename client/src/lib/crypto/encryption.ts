/**
 * Password-based file encryption using ChaCha20-Poly1305
 * Uses PBKDF2 to derive encryption keys from user passwords
 */

export interface EncryptionResult {
  encryptedData: Uint8Array;
  nonceBase64: string;
  passwordHashBase64: string; // Changed from keyBase64
}

export interface DecryptionInput {
  encryptedData: Uint8Array;
  nonceBase64: string;
  password: string; // Added password parameter
}

// PBKDF2 configuration
const PBKDF2_ITERATIONS = 200000;
const KEY_LENGTH = 32; // 256 bits for ChaCha20
const HASH_LENGTH = 32; // 256 bits for password hash

/**
 * Derives both encryption key and password hash from password and nonce
 */
async function deriveKeysFromPassword(
  password: string, 
  nonce: Uint8Array
): Promise<{ encryptionKey: CryptoKey; passwordHash: Uint8Array }> {
  const encoder = new TextEncoder();
  const passwordKey = await window.crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey', 'deriveBits']
  );

  const derivedBits = await window.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: nonce,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    passwordKey,
    (KEY_LENGTH + HASH_LENGTH) * 8
  );

  const derivedBytes = new Uint8Array(derivedBits);
  const encryptionKeyBytes = derivedBytes.slice(0, KEY_LENGTH);
  const passwordHash = derivedBytes.slice(KEY_LENGTH);

  const encryptionKey = await window.crypto.subtle.importKey(
    'raw',
    encryptionKeyBytes,
    { name: 'ChaCha20-Poly1305' },
    false,
    ['encrypt', 'decrypt']
  );

  return { encryptionKey, passwordHash };
}

/**
 * Encrypt file with password-based key derivation
 */
export async function encryptFile(file: File, password: string): Promise<EncryptionResult> {
  if (typeof window === 'undefined') {
    throw new Error('Encryption must be performed client-side');
  }

  if (!window.crypto || !window.crypto.subtle) {
    throw new Error('Web Crypto API not supported in this browser');
  }

  try {
    // Generate cryptographically secure nonce
    const nonce = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit nonce for ChaCha20-Poly1305

    // Derive encryption key and password hash
    const { encryptionKey, passwordHash } = await deriveKeysFromPassword(password, nonce);

    // Read file content
    const fileBuffer = await file.arrayBuffer();
    const fileData = new Uint8Array(fileBuffer);

    // Encrypt the file
    const encryptedBuffer = await window.crypto.subtle.encrypt(
      {
        name: 'ChaCha20-Poly1305',
        iv: nonce,
      },
      encryptionKey,
      fileData
    );

    const encryptedData = new Uint8Array(encryptedBuffer);

    // Convert nonce and password hash to base64 for URL embedding
    const nonceBase64 = btoa(String.fromCharCode(...nonce));
    const passwordHashBase64 = btoa(String.fromCharCode(...passwordHash));

    return {
      encryptedData,
      nonceBase64,
      passwordHashBase64,
    };
  } catch (error) {
    console.error('Encryption failed:', error);
    throw new Error('Failed to encrypt file');
  }
}

/**
 * Decrypt file with password-based key derivation
 */
export async function decryptFile(input: DecryptionInput): Promise<Uint8Array> {
  if (typeof window === 'undefined') {
    throw new Error('Decryption must be performed client-side');
  }

  if (!window.crypto || !window.crypto.subtle) {
    throw new Error('Web Crypto API not supported in this browser');
  }

  try {
    // Convert base64 back to Uint8Array
    const nonce = new Uint8Array(
      atob(input.nonceBase64).split('').map(char => char.charCodeAt(0))
    );

    // Derive encryption key from password and nonce
    const { encryptionKey } = await deriveKeysFromPassword(input.password, nonce);

    // Decrypt the data
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: 'ChaCha20-Poly1305',
        iv: nonce,
      },
      encryptionKey,
      input.encryptedData
    );

    return new Uint8Array(decryptedBuffer);
  } catch (error) {
    console.error('Decryption failed:', error);
    throw new Error('Failed to decrypt file - invalid password or corrupted data');
  }
}

/**
 * Verify password against stored hash (client-side verification)
 */
export async function verifyPassword(
  password: string, 
  nonceBase64: string, 
  expectedPasswordHashBase64: string
): Promise<boolean> {
  const nonce = new Uint8Array(
    atob(nonceBase64).split('').map(char => char.charCodeAt(0))
  );
  const expectedPasswordHash = new Uint8Array(
    atob(expectedPasswordHashBase64).split('').map(char => char.charCodeAt(0))
  );

  const { passwordHash } = await deriveKeysFromPassword(password, nonce);

  return passwordHash.length === expectedPasswordHash.length &&
    passwordHash.every((byte, i) => byte === expectedPasswordHash[i]);
}
