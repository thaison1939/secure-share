"use client";

import React, { useEffect, useState } from 'react';
import { clearUrlFragment } from '../../../lib/crypto/url-fragment';
import { decryptFile, type DecryptionInput } from '../../../lib/crypto/encryption';
import { downloadEncryptedFile, type DownloadResponse } from '../../../lib/api/download';
import { isValidUUID } from '../../../lib/crypto/uuid';
import { useToast } from '@/components/ui/use-toast';
import { formatFileSize } from '../../../lib/file-validation';

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
  const [fileSize, setFileSize] = useState<number | null>(null);
  const [remainingClicks, setRemainingClicks] = useState<number | undefined>(undefined);
  const [password, setPassword] = useState<string>('');

  const [serverMetadata, setServerMetadata] = useState<{
    passwordHashBase64: string;
    nonceBase64: string;
    pwhashSaltBase64: string;
    encryptedData: Uint8Array;
  } | null>(null);

  const { toast } = useToast();

  useEffect(() => {
    if (!isValidUUID(uuid)) {
      setErrorMessage("Invalid file ID format in URL.");
      setDownloadStatus('error');
      toast({
        title: "Link Error",
        description: "Invalid file ID format in the URL.",
        variant: "destructive",
        duration: 5000,
      });
      return;
    }

    clearUrlFragment();
    handleInitialDownload();
  }, [uuid, toast]);

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

      setServerMetadata({
        passwordHashBase64: downloadResponse.passwordHashBase64,
        nonceBase64: downloadResponse.nonceBase64,
        pwhashSaltBase64: downloadResponse.pwhashSaltBase64,
        encryptedData: downloadResponse.data,
      });

      setOriginalFilename(downloadResponse.filename || `file-${uuid}`);
      setRemainingClicks(downloadResponse.remainingDownloads);
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
      const decryptionInput: DecryptionInput = {
        encryptedData: serverMetadata.encryptedData,
        nonceBase64: serverMetadata.nonceBase64,
        password: password,
        expectedPasswordHashBase64: serverMetadata.passwordHashBase64,
        pwhashSaltBase64: serverMetadata.pwhashSaltBase64,
      };

      const decryptedData: Uint8Array = await decryptFile(decryptionInput);
      console.log('File decrypted client-side successfully.');

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
        variant: "default",
        duration: 8000,
      });

    } catch (error: any) {
      console.error('Password verification or decryption failed:', error);

      let errorMessageText: string;
      if (error.message === 'Incorrect password provided.') {
        errorMessageText = 'Incorrect password. Please try again.';
        setDownloadStatus('idle');
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

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !isProcessing && password && serverMetadata) {
      handlePasswordAndDecrypt();
    }
  };

  const isProcessing = downloadStatus === 'downloading' || downloadStatus === 'decrypting';

  return (
    <div className="wrapper">
      <div className="container">
        <h1>Download Secure File</h1>
        
        {/* File info when loaded */}
        {serverMetadata && originalFilename && (
          <div className="upload-container" style={{marginBottom: '10px'}}>
            <div className="border-container success">
              <div className="selected-file">
                <i className="fas fa-file selected-file-icon" style={{color: '#22c55e'}}></i>
                <p className="selected-file-name">{originalFilename}</p>
                {fileSize && (
                  <p className="selected-file-size">
                    {formatFileSize(fileSize)}
                  </p>
                )}
                {typeof remainingClicks === 'number' && (
                  <p style={{margin: '5px 0', fontSize: '0.95em', color: '#666'}}>
                    Downloads remaining: <strong>{remainingClicks}</strong>
                    {downloadStatus === 'idle' && errorMessage === 'Incorrect password. Please try again.' && (
                      <span style={{color: '#dc2626', fontWeight: 'bold', marginLeft: '10px'}}>
                        - Wrong password
                      </span>
                    )}
                  </p>
                )}                    
                </div>
              </div>
          </div>
        )}

        {/* Password input */}
        {serverMetadata && downloadStatus === 'idle' && (
          <div className="form-section">
            <label className="form-label">
              <i className="fas fa-lock lock-icon"></i>
              Enter Password to Decrypt File
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="form-input"
              placeholder="Enter the file password"
              disabled={isProcessing}
              onKeyPress={handleKeyPress}
              autoComplete="current-password"
              autoFocus
            />
          </div>
        )}

        {/* Download button */}
        {serverMetadata && downloadStatus === 'idle' && (
          <button
            onClick={async () => {
              // Increment counter on server (regardless of password success)
              try {
                const response = await fetch(`/api/download/${uuid}/increment`, {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                  },
                });
                
                if (response.ok) {
                  const data = await response.json();
                  if (data.fileDeleted) {
                    // File was deleted due to limit reached
                    setErrorMessage("Download limit reached. File has been deleted.");
                    setDownloadStatus('error');
                    return;
                  }
                  // Update remaining count using new field name
                  setRemainingClicks(data.remainingDownloads);
                } else {
                  const errorData = await response.json();
                  setErrorMessage(errorData.error || "Failed to track download.");
                  return;
                }
              } catch (error) {
                console.error('Failed to increment download count:', error);
                setErrorMessage("Service temporarily unavailable. Please try again later.");
                return;
              }
              
              // Proceed with password verification and decryption
              handlePasswordAndDecrypt();
            }}
            className="upload-btn"
            disabled={!password || (typeof remainingClicks === 'number' && remainingClicks <= 0)}
          >
            <i className="fas fa-download" style={{marginRight: '8px'}}></i>
            Decrypt & Download File ({remainingClicks || 0} left)
          </button>
        )}

        {/* Show remaining downloads warning */}
        {typeof remainingClicks === 'number' && remainingClicks <= 0 && (
          <div className="share-container" style={{backgroundColor: '#fef2f2', borderColor: 'rgba(220, 38, 38, 0.3)'}}>
            <h3 className="share-title" style={{color: '#dc2626'}}>
              <i className="fas fa-exclamation-triangle" style={{marginRight: '8px'}}></i>
              Download Limit Reached
            </h3>
            <p style={{margin: '10px 0', color: '#dc2626', fontSize: '0.9em'}}>
              This file has reached its maximum download limit and is no longer available.
            </p>
          </div>
        )}

        {/* Processing state */}
        {isProcessing && (
          <>
            <div className="upload-container">
              <div className="border-container" style={{textAlign: 'center', padding: '30px'}}>
                <div style={{fontSize: '3rem', color: '#95afc0', marginBottom: '20px'}}>
                  <i className="fas fa-spinner fa-spin"></i>
                </div>
                <p style={{margin: '0', fontSize: '1.1em', fontWeight: '600'}}>
                  {downloadStatus === 'downloading' ? 'Fetching Encrypted File...' : 'Verifying Password & Decrypting...'}
                </p>
              </div>
            </div>
            
            <div className="progress-container">
              <div className="progress-bar" style={{ width: '100%', animation: 'pulse 2s infinite' }}></div>
            </div>
          </>
        )}

        {/* Success state */}
        {downloadStatus === 'success' && (
          <div className="share-container" style={{backgroundColor: '#e8f5e8', borderColor: 'rgba(34, 197, 94, 0.3)'}}>
            <h3 className="share-title" style={{color: '#16a34a'}}>
              <i className="fas fa-check-circle" style={{marginRight: '8px'}}></i>
              Download Complete!
            </h3>
            <p style={{margin: '10px 0', color: '#15803d'}}>
              File '{originalFilename || 'downloaded-file'}' has been downloaded and decrypted.
            </p>
            <button 
              onClick={() => window.location.reload()}
              className="copy-btn"
              style={{backgroundColor: '#16a34a'}}
            >
              <i className="fas fa-redo" style={{marginRight: '8px'}}></i>
              Try Another Download
            </button>
            <div className="important-text">
              The file should have automatically downloaded to your device.
            </div>
          </div>
        )}

        {/* Error state */}
        {downloadStatus === 'error' && errorMessage && (
          <div className="share-container" style={{backgroundColor: '#fef2f2', borderColor: 'rgba(220, 38, 38, 0.3)'}}>
            <h3 className="share-title" style={{color: '#dc2626'}}>
              <i className="fas fa-exclamation-triangle" style={{marginRight: '8px'}}></i>
              Error!
            </h3>
            <p style={{margin: '10px 0', color: '#dc2626', fontSize: '0.9em'}}>
              {errorMessage}
            </p>
            <button 
              onClick={() => window.location.reload()}
              className="copy-btn"
              style={{backgroundColor: '#dc2626'}}
            >
              <i className="fas fa-redo" style={{marginRight: '8px'}}></i>
              Try Again
            </button>
          </div>
        )}

        <div className="disclaimer">
          <p>
            File is encrypted <i>before</i> it reaches our servers, making it inaccessible to everyone, including us, without the specific link and the password you've chosen.
          </p>
          <p className="disclaimer-warning">
            **Warning:** We cannot scan for malicious content. Download at your own risk.
          </p>
        </div>
      </div>
    </div>
  );
}
