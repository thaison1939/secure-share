/**
 * Client-side File Validation
 * Provides user experience validation before upload
 * Note: Server-side validation is still required for security
 */

interface ValidationResult {
  isValid: boolean;
  errors: string[];
}

interface FileValidationOptions {
  maxSizeMB?: number;
  allowedExtensions?: string[];
}

export function validateFile(file: File, options?: FileValidationOptions): ValidationResult {
  const errors: string[] = [];
  
  // Get config from environment or use defaults
  const maxSizeMB = options?.maxSizeMB || parseInt(process.env.NEXT_PUBLIC_MAX_FILE_SIZE_MB || '100');
  const allowedExtensions = options?.allowedExtensions || 
    (process.env.NEXT_PUBLIC_SUPPORTED_FILE_TYPES || '').split(',').filter(Boolean);

  // Validate file size
  const maxSizeBytes = maxSizeMB * 1024 * 1024;
  if (file.size > maxSizeBytes) {
    errors.push(`File size must be less than ${maxSizeMB}MB`);
  }

  // Validate file extension (if configured)
  if (allowedExtensions.length > 0) {
    const fileName = file.name.toLowerCase();
    const hasValidExtension = allowedExtensions.some(ext => 
      fileName.endsWith(ext.toLowerCase())
    );
    
    if (!hasValidExtension) {
      errors.push(`File type not supported. Allowed types: ${allowedExtensions.join(', ')}`);
    }
  }

  // Basic file name validation
  if (!file.name || file.name.trim().length === 0) {
    errors.push('File must have a valid name');
  }

  if (file.name.length > 255) {
    errors.push('File name too long (max 255 characters)');
  }

  return {
    isValid: errors.length === 0,
    errors,
  };
}

export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
