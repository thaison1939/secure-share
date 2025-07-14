import { DownloadResponse } from "@/lib/api/download";

// client/src/lib/api/download.ts
export async function downloadEncryptedFile(uuid: string): Promise<DownloadResponse> {
  try {
    // Use the dynamic route instead of query parameters
    const response = await fetch(`/api/download/${uuid}`, {
      method: 'GET',
    });

    if (!response.ok) {
      if (response.status === 404) {
        return {
          success: false,
          error: 'File not found or has expired',
        };
      }
      
      if (response.status === 403) {
        return {
          success: false,
          error: 'Download limit exceeded',
        };
      }

      if (response.status === 429) {
        const errorData = await response.json().catch(() => ({ error: 'Too many attempts' }));
        return {
          success: false,
          error: errorData.error || 'Too many password attempts',
        };
      }

      throw new Error(`Download failed: ${response.status}`);
    }

    // Get metadata from headers
    const filename = response.headers.get('X-Original-Filename') || 'downloaded-file';
    const remainingDownloads = response.headers.get('X-Remaining-Downloads');
    const passwordHashBase64 = response.headers.get('X-Password-Hash-Base64');
    const nonceBase64 = response.headers.get('X-Nonce-Base64');
    const pwhashSaltBase64 = response.headers.get('X-Pwhash-Salt-Base64');

    // Get encrypted file data
    const arrayBuffer = await response.arrayBuffer();
    const data = new Uint8Array(arrayBuffer);

    return {
      success: true,
      data,
      filename,
      remainingDownloads: remainingDownloads ? parseInt(remainingDownloads) : undefined,
      passwordHashBase64: passwordHashBase64 || undefined,
      nonceBase64: nonceBase64 || undefined,
      pwhashSaltBase64: pwhashSaltBase64 || undefined,
    };

  } catch (error) {
    console.error('Download request failed:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Download failed',
    };
  }
}