/**
 * Upload API client functions with libsodium-wrappers encryption
 */

export interface UploadRequest {
  encryptedFile: Uint8Array;
  uuid: string;
  originalFilename: string;
  downloadLimit: number;
  fileSize: number;
  passwordHashBase64: string;    // Derived using pwhashSalt
  nonceBase64: string;           // For ChaCha20-Poly1305
  pwhashSaltBase64: string;      // ✅ NEW: For Argon2id operations
}

export interface UploadResponse {
  success: boolean;
  uuid?: string;
  message?: string;
  error?: string;
}

/**
 * Upload encrypted file with progress tracking
 */
export async function uploadWithProgress(
  request: UploadRequest,
  onProgress?: (loaded: number, total: number) => void
): Promise<UploadResponse> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    
    // Progress tracking
    if (onProgress) {
      xhr.upload.addEventListener('progress', (event) => {
        if (event.lengthComputable) {
          onProgress(event.loaded, event.total);
        }
      });
    }

    // Response handling
    xhr.addEventListener('load', () => {
      try {
        if (xhr.status >= 200 && xhr.status < 300) {
          const response = JSON.parse(xhr.responseText);
          resolve(response);
        } else {
          const errorResponse = JSON.parse(xhr.responseText);
          resolve({
            success: false,
            uuid: request.uuid,
            error: errorResponse.error || `HTTP ${xhr.status}`
          });
        }
      } catch (error) {
        resolve({
          success: false,
          uuid: request.uuid,
          error: 'Invalid server response'
        });
      }
    });

    xhr.addEventListener('error', () => {
      resolve({
        success: false,
        uuid: request.uuid,
        error: 'Upload failed - network error'
      });
    });

    xhr.addEventListener('timeout', () => {
      resolve({
        success: false,
        uuid: request.uuid,
        error: 'Upload failed - timeout'
      });
    });

    // Prepare form data
    const formData = new FormData();
    
    // Create blob from encrypted data
    const encryptedBlob = new Blob([request.encryptedFile], { 
      type: 'application/octet-stream' 
    });
    
    formData.append('file', encryptedBlob);
    formData.append('uuid', request.uuid);
    formData.append('originalFilename', request.originalFilename);
    formData.append('downloadLimit', request.downloadLimit.toString());
    formData.append('fileSize', request.fileSize.toString());
    
    // ✅ UPDATED: Send all three base64 fields
    formData.append('passwordHashBase64', request.passwordHashBase64);
    formData.append('nonceBase64', request.nonceBase64);
    formData.append('pwhashSaltBase64', request.pwhashSaltBase64); // NEW FIELD

    // Configure request
    xhr.open('POST', '/api/upload');
    xhr.timeout = 300000; // 5 minute timeout
    
    // Add client auth header (will be verified by Next.js proxy)
    xhr.setRequestHeader('X-Client-Auth', `Bearer ${process.env.NEXT_PUBLIC_UPLOAD_AUTH_SECRET || 'dev-secret'}`);
    
    // Send request
    xhr.send(formData);
  });
}

/**
 * Simple upload without progress tracking
 */
export async function uploadEncryptedFile(request: UploadRequest): Promise<UploadResponse> {
  return uploadWithProgress(request);
}
