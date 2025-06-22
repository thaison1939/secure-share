/**
 * URL fragment utilities for password-protected file sharing
 * No longer embeds encryption keys in URL fragments for security
 */

export interface ExtractedKeys {
  uuid: string;
  // Note: In password-protected mode, we don't extract keys from URL
  // The nonce is retrieved from server, and key is derived from password
}

export interface ShareLinkParams {
  baseUrl: string;
  uuid: string;
}

/**
 * Generate a clean share link with only UUID (no fragments)
 * Password-protected mode - no sensitive data in URL
 */
export function generateShareLink(params: ShareLinkParams): string {
  const { baseUrl, uuid } = params;
  // Clean URL with no fragment - password protection doesn't need keys in URL
  return `${baseUrl}/download/${uuid}`;
}

/**
 * Extract keys from URL fragment (for password-protected mode)
 * Returns minimal info since we don't store keys in URL anymore
 */
export function extractKeysFromUrl(): ExtractedKeys | null {
  try {
    // In password-protected mode, we only get UUID from the URL path
    // This function is kept for compatibility but doesn't extract from fragment
    const pathParts = window.location.pathname.split('/');
    const uuid = pathParts[pathParts.length - 1];
    
    if (!uuid || uuid.length === 0) {
      return null;
    }

    return {
      uuid,
    };
  } catch (error) {
    console.error('Failed to extract keys from URL:', error);
    return null;
  }
}

/**
 * Clear any sensitive data from URL fragment (cleanup function)
 */
export function clearUrlFragment(): void {
  if (window.location.hash) {
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
  }
}

export function sanitizeUrl(): void {
  if (typeof window !== 'undefined' && window.location.hash) {
    // Replace the current URL in history, removing the fragment
    window.history.replaceState({}, document.title, window.location.pathname + window.location.search);
  }
}
