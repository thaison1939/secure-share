/**
 * File validation utilities for secure share.
 * These functions help validate file properties (size, type, extension) client-side
 * before upload, providing immediate user feedback.
 */

export interface FileConfig {
  maxFileSizeMB: number;
  allowedTypes: string[]; // MIME types (e.g., 'image/png', 'application/pdf') or file extensions (e.g., '.txt')
}

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
}

/**
 * Retrieves file validation configuration from client-side environment variables.
 * @returns An object conforming to FileConfig.
 */
export function getFileConfigFromEnv(): FileConfig {
  // Parse max file size from environment variable, defaulting to 100MB
  const maxFileSizeMB = parseInt(process.env.NEXT_PUBLIC_MAX_FILE_SIZE_MB || '100', 10); // Ensure radix 10

  // Parse allowed types from a comma-separated string, trimming whitespace
  const allowedTypesStr = process.env.NEXT_PUBLIC_SUPPORTED_FILE_TYPES || '';
  const allowedTypes = allowedTypesStr
    .split(',')
    .map(t => t.trim().toLowerCase()) // Normalize to lowercase for consistent comparison
    .filter(t => t !== ''); // Remove any empty strings from splitting

  return {
    maxFileSizeMB,
    allowedTypes
  };
}

/**
 * Validates a given File object against a provided FileConfig.
 * Checks for size, blocked extensions, and allowed types.
 * @param file The File object to validate.
 * @param config The FileConfig object containing validation rules.
 * @returns A ValidationResult indicating if the file is valid and a list of errors if any.
 */
export function validateFile(file: File, config: FileConfig): ValidationResult {
  const errors: string[] = [];

  // 1. Check file size
  const fileSizeMB = file.size / (1024 * 1024);
  if (fileSizeMB > config.maxFileSizeMB) {
    errors.push(`File size (${fileSizeMB.toFixed(1)}MB) exceeds maximum allowed size (${config.maxFileSizeMB}MB).`);
  }

  const fileExtension = '.' + (file.name.split('.').pop()?.toLowerCase() || ''); // Ensure lowercase and handle no extension

  // 3. Check allowed types (if specified in config)
  if (config.allowedTypes.length > 0) {
    const isAllowedType = config.allowedTypes.some(typeRule => {
      if (typeRule.includes('/')) {
        // MIME type check (e.g., 'image/jpeg', 'application/pdf', 'image/*')
        const [majorType, subType] = typeRule.split('/');
        if (subType === '*') { // Wildcard match (e.g., 'image/*')
          return file.type.startsWith(`${majorType}/`);
        }
        return file.type.toLowerCase() === typeRule; // Exact MIME type match
      } else if (typeRule.startsWith('.')) {
        // Extension check (e.g., '.txt')
        return fileExtension === typeRule;
      } else {
        // Fallback: treat as extension if no '/' or '.'
        return fileExtension === `.${typeRule}`;
      }
    });

    if (!isAllowedType) {
      errors.push(`File type not allowed. Allowed types include: ${config.allowedTypes.join(', ')}.`);
    }
  }

  return {
    isValid: errors.length === 0,
    errors
  };
}

/**
 * Formats file size into a human-readable string (e.g., "1.23 MB").
 * @param bytes The file size in bytes.
 * @param decimals The number of decimal places to include (default: 2).
 * @returns A formatted string representing the file size.
 */
export function formatFileSize(bytes: number, decimals = 2): string {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];

  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}
