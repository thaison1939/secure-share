/**
 * Cryptographically secure UUID generation for file identifiers
 */

/**
 * Generate a cryptographically secure UUID v4
 * Uses the browser's native crypto.randomUUID() for maximum security
 */
export function generateSecureUUID(): string {
  if (typeof window === 'undefined' || !window.crypto?.randomUUID) {
    throw new Error('Secure UUID generation not supported in this environment');
  }
  
  return window.crypto.randomUUID();
}

/**
 * Validate UUID v4 format
 */
export function isValidUUID(uuid: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}
