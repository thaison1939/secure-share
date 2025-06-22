"use client";

import React, { useEffect, useState } from 'react';
import { clearUrlFragment } from '../../../lib/crypto/url-fragment';
// Import DecryptionInput from the libsodium-wrappers version of encryption.ts
import { decryptFile, /* verifyPassword, */ type DecryptionInput } from '../../../lib/crypto/encryption';
import { downloadEncryptedFile, type DownloadResponse } from '../../../lib/api/download';
import { isValidUUID } from '../../../lib/crypto/uuid';
import { useToast } from '@/components/ui/use-toast';
import { cn } from '../../../lib/utils';

interface DownloadPageProps {
  params: {
    uuid: string;
  };
}

export default function DownloadPage({ params }: DownloadPageProps) {
  const { uuid } = params;
  const [downloadStatus, setDownloadStatus] = useState<'idle' | 'downloading' | 'decrypting' | 'success' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [originalFilename, setOriginalFilename] = useState<string | null>(null);
  const [remainingClicks, setRemainingClicks] = useState<number | undefined>(undefined);
  const [password, setPassword] = useState<string>('');

  // ✅ UPDATED: Store server metadata including new pwhashSaltBase64
  const [serverMetadata, setServerMetadata] = useState<{
    passwordHashBase64: string;
    nonceBase64: string;
    pwhashSaltBase64: string;    // ✅ NEW FIELD
    encryptedData: Uint8Array;
  } | null>(null);

  const { toast } = useToast();

  useEffect(() => {
    // ✅ FIXED: Validate UUID from URL path, not fragment
    if (!isValidUUID(uuid)) {
      setErrorMessage("Invalid file ID format in URL.");
      setDownloadStatus('error');
      toast({
        title: "Link Error",
        description: "Invalid file ID format in the URL.",
        variant: "destructive", // Use destructive variant for errors
        duration: 5000,
      });
      return;
    }

    // ✅ FIXED: Clear any URL fragment for security (no sensitive data expected)
    clearUrlFragment();

    // Auto-fetch file metadata when component loads
    handleInitialDownload();

  }, [uuid, toast]); // `toast` is stable, so it's safe to include.

  const handleInitialDownload = async () => {
    setDownloadStatus('downloading');
    setErrorMessage(null);

    toast({
      title: "Fetching File...",
      description: "Retrieving encrypted file and metadata from server.",
      duration: 3000,
    });

    try {
      const downloadResponse: DownloadResponse = await downloadEncryptedFile(uuid);

      if (!downloadResponse.success || !downloadResponse.data) {
        setErrorMessage(downloadResponse.error || "Failed to download encrypted file.");
        setDownloadStatus('error');
        toast({
          title: "Download Failed",
          description: downloadResponse.error || "Could not retrieve the file.",
          variant: "destructive",
          duration: 5000,
        });
        return;
      }

      // ✅ UPDATED: Extract all three metadata fields from server headers
      if (!downloadResponse.passwordHashBase64 || !downloadResponse.nonceBase64 || !downloadResponse.pwhashSaltBase64) {
        setErrorMessage("Missing password verification data from server. This file might be corrupted or an invalid format.");
        setDownloadStatus('error');
        toast({
          title: "Server Data Error",
          description: "Missing critical password verification data from the server. File might be corrupted.",
          variant: "destructive",
          duration: 7000,
        });
        return;
      }

      // ✅ UPDATED: Store all metadata including pwhash salt
      setServerMetadata({
        passwordHashBase64: downloadResponse.passwordHashBase64,
        nonceBase64: downloadResponse.nonceBase64,
        pwhashSaltBase64: downloadResponse.pwhashSaltBase64, // ✅ NEW FIELD
        encryptedData: downloadResponse.data,
      });

      // Update UI info from server response
      setOriginalFilename(downloadResponse.filename || `file-${uuid}`);
      setRemainingClicks(downloadResponse.remainingClicks);

      // Ready for password input
      setDownloadStatus('idle');
      toast({
        title: "Ready for Password",
        description: "Please enter the password to decrypt the file.",
        duration: 3000,
      });

    } catch (error: any) {
      console.error('Initial download failed:', error);
      const errorMessageText = error.message || 'Failed to fetch file from server.';
      setErrorMessage(errorMessageText);
      setDownloadStatus('error');
      toast({
        title: "Fetch Failed",
        description: errorMessageText,
        variant: "destructive",
        duration: 5000,
      });
    }
  };

  const handlePasswordAndDecrypt = async () => {
    if (!serverMetadata || !password) {
      setErrorMessage("Please enter the password to proceed with decryption.");
      toast({
        title: "Password Required",
        description: "Please enter the password to decrypt the file.",
        variant: "destructive",
        duration: 3000,
      });
      return;
    }

    setDownloadStatus('decrypting');
    setErrorMessage(null);

    toast({
      title: "Verifying Password & Decrypting...",
      description: "Checking password and decrypting file securely in your browser. This may take a moment...",
      duration: 1000000,
    });

    try {
      // ✅ UPDATED: Pass all required fields to decryptFile including pwhashSaltBase64
      const decryptionInput: DecryptionInput = {
        encryptedData: serverMetadata.encryptedData,
        nonceBase64: serverMetadata.nonceBase64,
        password: password,
        expectedPasswordHashBase64: serverMetadata.passwordHashBase64,
        pwhashSaltBase64: serverMetadata.pwhashSaltBase64, // ✅ NEW FIELD
      };

      const decryptedData: Uint8Array = await decryptFile(decryptionInput);
      console.log('File decrypted client-side successfully.');

      // Offer file for download
      const blob = new Blob([decryptedData], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = originalFilename || `downloaded-secure-share-file-${uuid}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setDownloadStatus('success');
      toast({
        title: "Download Complete!",
        description: `File '${originalFilename || 'downloaded-file'}' has been downloaded and decrypted.`,
        variant: "default", // Use default instead of success
        duration: 8000,
      });

    } catch (error: any) {
      console.error('Password verification or decryption failed:', error);

      let errorMessageText: string;
      if (error.message === 'Incorrect password provided.') {
        errorMessageText = 'Incorrect password. Please try again.';
        setDownloadStatus('idle'); // Allow retry
      } else {
        errorMessageText = `File could not be decrypted. It may be corrupted or an unexpected error occurred. Details: ${error.message}`;
        setDownloadStatus('error');
      }

      setErrorMessage(errorMessageText);
      toast({
        title: "Decryption Failed",
        description: errorMessageText,
        variant: "destructive",
        duration: 5000,
      });
    }
  };

  // ✅ FIXED: Handle Enter key press correctly
  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    // Only trigger decryption if Enter is pressed, not currently processing, password is not empty, and metadata is loaded.
    if (e.key === 'Enter' && !isProcessing && password && serverMetadata) {
      handlePasswordAndDecrypt();
    }
  };

  const isProcessing = downloadStatus === 'downloading' || downloadStatus === 'decrypting';

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-6 bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      <div className="w-full max-w-lg p-8 space-y-6 bg-white dark:bg-gray-800 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
        <h1 className="text-3xl font-bold text-center text-blue-600 dark:text-blue-400">Secure Share</h1>
        <p className="text-center text-gray-600 dark:text-gray-300">
          File ID: <span className="font-mono break-all">{uuid}</span>
        </p>

        {/* Password input section - only show when ready */}
        {serverMetadata && downloadStatus === 'idle' && (
          <div className="space-y-4">
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Enter Password to Decrypt
              </label>
              <input
                type="password"
                id="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition duration-150 ease-in-out text-gray-900 dark:bg-gray-700 dark:border-gray-600 dark:text-gray-100"
                placeholder="••••••••"
                disabled={isProcessing}
                onKeyPress={handleKeyPress}
                autoComplete="current-password"
                autoFocus
              />
            </div>
          </div>
        )}

        {/* Ready state: File downloaded, waiting for password */}
        {serverMetadata && downloadStatus === 'idle' && (
          <div className="text-center">
            <p className="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-4">
              Enter password to decrypt your secure file.
            </p>
            {originalFilename && (
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                File: <span className="font-mono">{originalFilename}</span>
              </p>
            )}
            <button
              onClick={handlePasswordAndDecrypt}
              className={cn(
                "w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white",
                "bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500",
                "transition duration-150 ease-in-out",
                !password ? "opacity-50 cursor-not-allowed" : "" // Visual feedback for disabled button
              )}
              disabled={!password} // Disable button if no password is typed
            >
              Decrypt & Download File
            </button>
            <p className="mt-4 text-sm text-gray-500 dark:text-gray-400">
              **Important:** Decryption happens securely in your browser.
              The server never sees the plaintext.
            </p>
          </div>
        )}

        {/* Processing state: Downloading or Decrypting */}
        {isProcessing && (
          <div className="text-center p-4">
            {/* Corrected className for consistency */}
            <p className="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-2">
              {downloadStatus === 'downloading' ? 'Fetching Encrypted File...' : 'Verifying Password & Decrypting...'}
            </p>
            <div className="w-full bg-gray-200 rounded-full h-2.5 dark:bg-gray-700 mt-4">
              <div className="bg-blue-600 h-2.5 rounded-full animate-pulse" style={{ width: '100%' }}></div>
            </div>
            <p className="mt-4 text-sm text-gray-500 dark:text-gray-400">
              Please wait, this may take a moment.
            </p>
          </div>
        )}

        {/* Success state */}
        {downloadStatus === 'success' && (
          <div className="text-center p-4 bg-green-50 dark:bg-green-900/20 rounded-md">
            <p className="text-lg font-semibold text-green-700 dark:text-green-400">
              File downloaded and decrypted successfully!
            </p>
            {originalFilename && (
              <p className="mt-2 text-sm text-gray-700 dark:text-gray-300">
                Original Filename: <span className="font-mono">{originalFilename}</span>
              </p>
            )}
            {typeof remainingClicks === 'number' && (
              <p className="mt-2 text-sm text-gray-700 dark:text-gray-300">
                Remaining Downloads: <span className="font-bold">{remainingClicks}</span>
              </p>
            )}
            <p className="mt-4 text-sm text-gray-500 dark:text-gray-400">
              The file should have automatically downloaded to your device.
            </p>
            <button
              onClick={() => window.location.reload()}
              className={cn(
                "mt-6 py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white",
                "bg-gray-600 hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500",
                "transition duration-150 ease-in-out"
              )}
            >
              Try Another Download (if available)
            </button>
          </div>
        )}

        {/* Error state */}
        {downloadStatus === 'error' && errorMessage && (
          <div className="text-center p-4 bg-red-50 dark:bg-red-900/20 rounded-md">
            <p className="text-lg font-semibold text-red-700 dark:text-red-400">
              Error!
            </p>
            <p className="mt-2 text-sm text-red-600 dark:text-red-400">{errorMessage}</p>
            <button
              onClick={() => window.location.reload()}
              className={cn(
                "mt-4 py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white",
                "bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500",
                "transition duration-150 ease-in-out"
              )}
            >
              Try Again
            </button>
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
