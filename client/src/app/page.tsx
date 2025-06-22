"use client";

import React, { useState, useRef, ChangeEvent, FormEvent } from 'react';
import { generateSecureUUID } from '../lib/crypto/uuid';
import { encryptFile, type EncryptionResult } from '../lib/crypto/encryption'; 
import { generateShareLink } from '../lib/crypto/url-fragment';
import { uploadWithProgress, type UploadResponse } from '../lib/api/upload'; 
import { getFileConfigFromEnv, validateFile, formatFileSize } from '../lib/file-validation';
import { useToast } from '@/components/ui/use-toast'; 
import { cn } from '../lib/utils'; 

// Get file validation configuration from environment variables
const FILE_CONFIG = getFileConfigFromEnv();
const MAX_FILE_SIZE_MB = parseInt(process.env.NEXT_PUBLIC_MAX_FILE_SIZE_MB || '100');
const DEFAULT_CLICK_LIMIT = parseInt(process.env.NEXT_PUBLIC_DEFAULT_CLICK_LIMIT || '1');
// API_BASE_URL should point to your Next.js frontend base URL for generating the share link.
// For Vercel/Cloudflare Pages deployments, this would often be the root domain.
const API_BASE_URL = process.env.NEXT_PUBLIC_VERCEL_URL ? `https://${process.env.NEXT_PUBLIC_VERCEL_URL}` : 'http://localhost:3000';


export default function HomePage() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [password, setPassword] = useState<string>(''); // Added password state
  const [clickLimit, setClickLimit] = useState<number>(DEFAULT_CLICK_LIMIT);
  const [shareLink, setShareLink] = useState<string | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number>(0); // 0-100
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const { toast } = useToast(); 

  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    setUploadError(null);
    setShareLink(null);
    setUploadProgress(0);
    if (event.target.files && event.target.files[0]) {
      const file = event.target.files[0];
      const validation = validateFile(file, FILE_CONFIG);
      if (!validation.isValid) {
        setUploadError(validation.errors.join('\n'));
        setSelectedFile(null);
        toast({
          title: "File Validation Error",
          description: validation.errors.join(', '),
          variant: "destructive",
          duration: 5000,
        });
      } else {
        setSelectedFile(file);
      }
    } else {
      setSelectedFile(null);
    }
  };

  const handleUpload = async (event: FormEvent) => {
    event.preventDefault();
    if (!selectedFile) {
      setUploadError("Please select a file to upload.");
      toast({
        title: "No File Selected",
        description: "Please choose a file before uploading.",
        variant: "destructive",
      });
      return;
    }
    if (!password) { 
      setUploadError("Please enter a password for encryption.");
      toast({
        title: "Password Required",
        description: "Please set a password for your file.",
        variant: "destructive",
      });
      return;
    }

    setIsUploading(true);
    setUploadError(null);
    setShareLink(null);
    setUploadProgress(0);

    try {
      // 1. Generate UUID
      const uuid = generateSecureUUID();
      console.log('Generated UUID:', uuid);

      // 2. Encrypt file client-side using libsodium
      const encryptionToast = toast({
        title: "Encrypting File...",
        description: "Your file is being encrypted securely in your browser. Please do not close this page.",
        variant: "default",
        duration: 1000000, // Long duration for ongoing process
      });
      
      const encryptionResult: EncryptionResult = await encryptFile(selectedFile, password);
      console.log('File encrypted client-side.');
      encryptionToast.dismiss(); // Dismiss the encryption toast on success

      // ✅ UPDATED: Prepare upload request with all three base64 fields
      const uploadRequest = {
        encryptedFile: encryptionResult.encryptedData,
        uuid: uuid,
        originalFilename: selectedFile.name,
        clickLimit: clickLimit,
        fileSize: selectedFile.size, 
        passwordHashBase64: encryptionResult.passwordHashBase64,
        nonceBase64: encryptionResult.nonceBase64,
        pwhashSaltBase64: encryptionResult.pwhashSaltBase64, // ✅ NEW FIELD
      };

      // 4. Upload encrypted file with progress
      const uploadToast = toast({
        title: "Uploading Encrypted File...",
        description: "Transferring your encrypted file to the server.",
        variant: "default",
        duration: 1000000,
      });

      const uploadResponse: UploadResponse = await uploadWithProgress(uploadRequest, (loaded, total) => {
        const percent = Math.round((loaded / total) * 100);
        setUploadProgress(percent);
      });

      if (uploadResponse.success) {
        uploadToast.dismiss(); // Dismiss upload toast on success
        // 5. Generate shareable link (no sensitive data in fragment, only UUID)
        const generatedLink = generateShareLink({
          baseUrl: API_BASE_URL,
          uuid: uuid,
        });
        setShareLink(generatedLink);
        toast({
          title: "Upload Successful!",
          description: "Your file is securely shared. Copy the link below.",
          variant: "default",
          duration: 8000,
        });
        // Clear selected file and password after successful upload
        setSelectedFile(null);
        setPassword('');
        if (fileInputRef.current) {
          fileInputRef.current.value = ''; // Clear file input
        }

      } else {
        uploadToast.dismiss(); // Dismiss upload toast on error
        const userFriendlyError = uploadResponse.error || "An unknown error occurred during upload. Please try again.";
        setUploadError(userFriendlyError);
        toast({
          title: "Upload Failed",
          description: userFriendlyError,
          variant: "destructive",
          duration: 5000,
        });
      }
    } catch (error: any) {
      // Handle errors...
      console.error('Full upload process failed:', error);
      let userFriendlyError = "An unexpected error occurred during the upload process.";

      // Map specific errors to user-friendly messages
      if (error.message.includes('File too large')) {
        userFriendlyError = `The selected file is too large. Max size: ${MAX_FILE_SIZE_MB}MB.`;
      } else if (error.message.includes('Failed to encrypt file')) {
        userFriendlyError = "Failed to encrypt the file. Please try again or with a different file.";
      } else if (error.message.includes('Failed to initialize cryptographic library')) {
        userFriendlyError = "Cryptographic library initialization failed. Please refresh and try again.";
      }
      
      setUploadError(userFriendlyError);
      toast({
        title: "Upload Error",
        description: userFriendlyError,
        variant: "destructive",
        duration: 8000,
      });
    } finally {
      setIsUploading(false);
      setUploadProgress(0); // Reset progress on completion/error
    }
  };

  const handleCopyLink = () => {
    if (shareLink) {
      // Use document.execCommand('copy') for better compatibility in iframes
      const textarea = document.createElement('textarea');
      textarea.value = shareLink;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy'); 
      document.body.removeChild(textarea);
      toast({
        title: "Link Copied!",
        description: "The shareable link has been copied to your clipboard.",
        variant: "success",
      });
    }
  };

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-6 bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      <div className="w-full max-w-lg p-8 space-y-6 bg-white dark:bg-gray-800 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
        <h1 className="text-3xl font-bold text-center text-blue-600 dark:text-blue-400">Secure Share</h1>
        <p className="text-center text-gray-600 dark:text-gray-300">
          Share files anonymously and privately. Files auto-delete after 1 hour or N clicks.
          The server never sees your content unencrypted.
        </p>

        <form onSubmit={handleUpload} className="space-y-4">
          <div>
            <label htmlFor="file-upload" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Select File (Max {MAX_FILE_SIZE_MB}MB)
            </label>
            <input
              id="file-upload"
              ref={fileInputRef}
              type="file"
              onChange={handleFileChange}
              className="block w-full text-sm text-gray-500
                file:mr-4 file:py-2 file:px-4
                file:rounded-full file:border-0
                file:text-sm file:font-semibold
                file:bg-blue-50 file:text-blue-700
                hover:file:bg-blue-100 dark:file:bg-blue-900 dark:file:text-blue-300 dark:hover:file:bg-blue-800
                cursor-pointer"
              disabled={isUploading}
            />
            {selectedFile && (
              <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
                Selected: {selectedFile.name} ({formatFileSize(selectedFile.size)})
              </p>
            )}
            {uploadError && (
              <p className="mt-2 text-sm text-red-600 dark:text-red-400">{uploadError}</p>
            )}
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Set Password for File
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm
                         focus:outline-none focus:ring-blue-500 focus:border-blue-500
                         dark:bg-gray-700 dark:border-gray-600 dark:text-gray-100"
              placeholder="Enter a strong password"
              disabled={isUploading}
              autoComplete="new-password"
            />
          </div>

          <div>
            <label htmlFor="click-limit" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Max Download Clicks (N)
            </label>
            <input
              id="click-limit"
              type="number"
              min="1"
              max="999" // A reasonable upper limit
              value={clickLimit}
              onChange={(e) => setClickLimit(parseInt(e.target.value) || 1)}
              className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm
                         focus:outline-none focus:ring-blue-500 focus:border-blue-500
                         dark:bg-gray-700 dark:border-gray-600 dark:text-gray-100"
              disabled={isUploading}
            />
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
              File will auto-delete after 1 hour or this many downloads, whichever comes first.
            </p>
          </div>

          <button
            type="submit"
            className={cn(
              "w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white",
              isUploading || !selectedFile || !password ? "bg-blue-400 cursor-not-allowed" : "bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500",
              "transition duration-150 ease-in-out"
            )}
            disabled={isUploading || !selectedFile || !password}
          >
            {isUploading ? (
              <>
                Uploading... ({uploadProgress}%)
                <div className="ml-2 w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
              </>
            ) : (
              'Upload & Get Share Link'
            )}
          </button>

          {isUploading && (
            <div className="w-full bg-gray-200 rounded-full h-2.5 dark:bg-gray-700 mt-4">
              <div
                className="bg-blue-600 h-2.5 rounded-full"
                style={{ width: `${uploadProgress}%` }}
              ></div>
            </div>
          )}
        </form>

        {shareLink && (
          <div className="mt-6 p-4 bg-gray-100 dark:bg-gray-700 border border-dashed border-gray-300 dark:border-gray-600 rounded-md space-y-3">
            <h3 className="text-lg font-semibold text-gray-800 dark:text-gray-200">Your Share Link:</h3>
            <p className="break-all font-mono text-sm text-blue-600 dark:text-blue-400">
              {shareLink}
            </p>
            <button
              onClick={handleCopyLink}
              className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 transition duration-150 ease-in-out"
            >
              Copy Link
            </button>
            <p className="text-xs text-center text-gray-500 dark:text-gray-400 mt-2">
              **IMPORTANT:** This link leads to your encrypted file. Share it only with trusted recipients!
            </p>
          </div>
        )}

        <div className="mt-8 text-center text-gray-500 dark:text-gray-400 text-sm">
          <p>
            Files are encrypted in your browser and auto-deleted from the server after 1 hour or N downloads.
            We never see your plaintext content.
          </p>
          <p className="mt-2 text-red-500 dark:text-red-300 font-semibold">
            **Warning:** We cannot scan for malicious content. Download at your own risk.
          </p>
        </div>
      </div>
    </main>
  );
}
