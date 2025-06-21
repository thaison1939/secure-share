'use client';

import { useState } from 'react';
import { encryptFile } from '../lib/crypto/encryption';
import { generateSecureUUID } from '../lib/crypto/uuid';
import { uploadEncryptedFile } from '../lib/api/upload';
import { validateFile } from '../lib/file-validation';

export default function UploadPage() {
  const [password, setPassword] = useState('');
  const [isUploading, setIsUploading] = useState(false);
  const [shareLink, setShareLink] = useState('');

  const handleUpload = async (file: File) => {
    if (!file) return;
    
    if (!password) {
      alert('Please enter a password');
      return;
    }

    try {
      setIsUploading(true);
      
      const validation = validateFile(file);
      if (!validation.isValid) {
        console.error(validation.errors.join(', '));
        alert('File validation failed: ' + validation.errors.join(', '));
        return;
      }

      const uuid = generateSecureUUID();
      const { encryptedData, passwordHashBase64, nonceBase64 } = await encryptFile(file, password);

      const uploadResponse = await uploadEncryptedFile({
        encryptedFile: encryptedData,
        uuid,
        originalFilename: file.name,
        clickLimit: 1,
        fileSize: file.size,
        passwordHashBase64,
        nonceBase64,
      });

      if (uploadResponse.success) {
        const link = `${window.location.origin}/download/${uuid}`;
        setShareLink(link);
        alert(`File uploaded successfully! Share link: ${link}`);
      } else {
        console.error('Upload failed:', uploadResponse.error);
        alert('File upload failed: ' + (uploadResponse.error || 'Unknown error'));
      }
    } catch (error) {
      console.error('Upload error:', error);
      alert('An error occurred during file upload. Please try again.');
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="max-w-md mx-auto mt-8 p-6 border rounded-lg">
      <h1 className="text-2xl font-bold mb-4">Upload File</h1>
      
      <div className="space-y-4">
        <div>
          <label htmlFor="password" className="block text-sm font-medium mb-2">
            Password (required)
          </label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-2 border rounded-md"
            placeholder="Enter password for file protection"
            disabled={isUploading}
          />
        </div>
        
        <div>
          <label htmlFor="file" className="block text-sm font-medium mb-2">
            Select File
          </label>
          <input
            type="file"
            id="file"
            onChange={(e) => e.target.files?.[0] && handleUpload(e.target.files[0])}
            className="w-full px-3 py-2 border rounded-md"
            disabled={isUploading}
          />
        </div>
        
        {isUploading && <p className="text-blue-600">Uploading...</p>}
        
        {shareLink && (
          <div className="mt-4 p-3 bg-green-50 border border-green-200 rounded-md">
            <p className="text-sm font-medium text-green-800">Share Link:</p>
            <input
              type="text"
              value={shareLink}
              readOnly
              className="w-full mt-1 px-2 py-1 text-sm border rounded"
              onClick={(e) => e.currentTarget.select()}
            />
          </div>
        )}
      </div>
    </div>
  );
}
