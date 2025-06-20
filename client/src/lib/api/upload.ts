export interface UploadRequest {
  encryptedFile: Uint8Array;
  uuid: string;
  originalFilename: string;
  clickLimit: number;
  fileSize: number;
}

export interface UploadResponse {
  success: boolean;
  uuid: string;
  message?: string;
  error?: string;
}

export async function uploadEncryptedFile(request: UploadRequest): Promise<UploadResponse> {
  try {
    const formData = new FormData();
    formData.append('file', new Blob([request.encryptedFile]), 'encrypted-file');
    formData.append('uuid', request.uuid);
    formData.append('originalFilename', request.originalFilename);
    formData.append('clickLimit', request.clickLimit.toString());
    formData.append('fileSize', request.fileSize.toString());

    const response = await fetch('/api/upload', {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ error: 'Upload failed' }));
      throw new Error(errorData.error || `HTTP ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Upload request failed:', error);
    return {
      success: false,
      uuid: request.uuid,
      error: error instanceof Error ? error.message : 'Upload failed',
    };
  }
}
