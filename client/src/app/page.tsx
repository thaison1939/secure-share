"use client";

import React, { useState, useRef, ChangeEvent, FormEvent, DragEvent } from 'react';
import { generateSecureUUID } from '../lib/crypto/uuid';
import { encryptFile, type EncryptionResult } from '../lib/crypto/encryption'; 
import { generateShareLink } from '../lib/crypto/url-fragment';
import { uploadWithProgress, type UploadResponse } from '../lib/api/upload'; 
import { getFileConfigFromEnv, validateFile, formatFileSize } from '../lib/file-validation';
import { useToast } from '@/components/ui/use-toast'; 

const FILE_CONFIG = getFileConfigFromEnv();
const MAX_FILE_SIZE_MB = parseInt(process.env.NEXT_PUBLIC_MAX_FILE_SIZE_MB || '100');
const DEFAULT_DOWNLOAD_LIMIT = 5;
const API_BASE_URL = process.env.NEXT_PUBLIC_VERCEL_URL ? `https://${process.env.NEXT_PUBLIC_VERCEL_URL}` : `http://localhost:3001`;

export default function HomePage() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [password, setPassword] = useState<string>('');
  const [downloadLimit, setdownloadLimit] = useState<number>(DEFAULT_DOWNLOAD_LIMIT);
  const [showAdvanced, setShowAdvanced] = useState<boolean>(false);
  const [shareLink, setShareLink] = useState<string | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number>(0);
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [isDragOver, setIsDragOver] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const { toast } = useToast(); 

  const handleFileSelection = (file: File) => {
    setUploadError(null);
    setShareLink(null);
    setUploadProgress(0);
    
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
  };

  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files[0]) {
      handleFileSelection(event.target.files[0]);
    } else {
      setSelectedFile(null);
    }
  };

  const handleDragEnter = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);

    const files = e.dataTransfer.files;
    if (files && files[0]) {
      handleFileSelection(files[0]);
    }
  };

  const handleBrowseClick = () => {
    fileInputRef.current.click();
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
      const uuid = generateSecureUUID();

      const encryptionToast = toast({
        title: "Encrypting File...",
        description: "Your file is being encrypted securely in your browser. Please do not close this page.",
        variant: "default",
        duration: 1000000,
      });
      
      const encryptionResult: EncryptionResult = await encryptFile(selectedFile, password);
      console.log('File encrypted client-side.');
      encryptionToast.dismiss();

      const uploadRequest = {
        encryptedFile: encryptionResult.encryptedData,
        uuid: uuid,
        originalFilename: selectedFile.name,
        downloadLimit: downloadLimit,
        fileSize: selectedFile.size, 
        passwordHashBase64: encryptionResult.passwordHashBase64,
        nonceBase64: encryptionResult.nonceBase64,
        pwhashSaltBase64: encryptionResult.pwhashSaltBase64, 
      };

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
        uploadToast.dismiss();
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
        setSelectedFile(null);
        setPassword('');
        if (fileInputRef.current) {
          fileInputRef.current.value = '';
        }
      } else {
        uploadToast.dismiss();
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
      console.error('Full upload process failed:', error);
      let userFriendlyError = "An unexpected error occurred during the upload process.";

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
      setUploadProgress(0);
    }
  };

  const handleCopyLink = () => {
    if (shareLink) {
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
    <div className="wrapper">
      <div className="container">
        <h1>Upload a file</h1>
        
        <form onSubmit={handleUpload}>
          <div className="upload-container">
            <div 
              className={`border-container ${isDragOver ? 'drag-over' : ''} ${uploadError ? 'error' : ''} ${selectedFile && !uploadError ? 'success' : ''}`}
              onDragEnter={handleDragEnter}
              onDragLeave={handleDragLeave}
              onDragOver={handleDragOver}
              onDrop={handleDrop}
              onClick={handleBrowseClick}
              style={{cursor: 'pointer'}}
            >
              {selectedFile ? (
                <div className="selected-file">
                  <i className="fas fa-check-circle selected-file-icon"></i>
                  <p className="selected-file-name">{selectedFile.name}</p>
                  <p className="selected-file-size">
                    {formatFileSize(selectedFile.size)}
                  </p>
                </div>
              ) : (
                <>
                  <div className="upload-icon">
                    <i className="fa-solid fa-upload"></i>
                  </div>
                  <p>Drag and drop files here, or <a 
                    href="#" 
                    id="file-browser" 
                  >browse</a> your computer.</p>
                </>
              )}
              
              <input
                ref={fileInputRef}
                type="file"
                onChange={handleFileChange}
                style={{display: 'none'}}
                disabled={isUploading}
                formEncType='multipart/form-data'
              />
            </div>
          </div>

          {uploadError && (
            <div className="error-message">{uploadError}</div>
          )}

          <button
            type="submit"
            className="upload-btn"
            disabled={isUploading || !selectedFile || !password}
          >
            {isUploading ? (
              <>
                <i className="fas fa-spinner fa-spin spinner-icon"></i>
                Uploading... ({uploadProgress}%)
              </>
            ) : (
              <>
                <i className="fas fa-shield-alt shield-icon"></i>
                Upload and Encrypt
              </>
            )}
          </button>

          {isUploading && (
            <div className="progress-container">
              <div className="progress-bar" style={{ width: `${uploadProgress}%` }}></div>
            </div>
          )}

          <div className="form-section">
            <label className="form-label">
              <i className="fas fa-lock lock-icon"></i>
              Set Password for File
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="form-input"
              placeholder="Enter a strong password"
              disabled={isUploading}
              autoComplete="new-password"
            />
          </div>

          <div className="checkbox-section">
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={showAdvanced}
                onChange={(e) => setShowAdvanced(e.target.checked)}
                className="checkbox-input"
              />
              <span className="checkbox-text">Advanced Settings</span>
            </label>
          </div>

          {showAdvanced && (
            <div className="form-section">
              <label className="form-label">
                <i className="fas fa-download download-icon"></i>
                Maximum Downloads (1-10)
              </label>
              <input
                type="number"
                min="1"
                max="10"
                value={downloadLimit}
                onChange={(e) => {
                  const value = parseInt(e.target.value) || 1;
                  setdownloadLimit(Math.max(1, Math.min(10, value)));
                }}
                className="form-input"
                disabled={isUploading}
              />
              <div className="helper-text">
                File will auto-delete after 1 hour or this many downloads on the link, whichever comes first.
              </div>
            </div>
          )}
        </form>

        {shareLink && (
          <div className="share-container">
            <h3 className="share-title">
              <i className="fas fa-share-alt share-icon"></i>
              Your Share Link:
            </h3>
            <div className="share-link">{shareLink}</div>
            <button onClick={handleCopyLink} className="copy-btn">
              <i className="fas fa-copy copy-btn-icon"></i>
              Copy Link
            </button>
            <div className="important-text">
              <strong>IMPORTANT:</strong> This link leads to your encrypted file. Share it only with trusted recipients!
            </div>
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