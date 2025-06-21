'use client';

import { useState } from 'react';
import { downloadEncryptedFile } from '../../../lib/api/download';
import { decryptFile, verifyPassword } from '../../../lib/crypto/encryption';

export default function DownloadPage() {
  const [password, setPassword] = useState('');
  const [status, setStatus] = useState<'ready' | 'downloading' | 'verifying' | 'decrypting' | 'error'>('ready');
  const [error, setError] = useState<string>('');

  const handleDownload = async () => {
    if (!password) {
      alert('Please enter the password');
      return;
    }

    try {
      setStatus('downloading');
      setError('');
      
      // Extract UUID from URL
      const uuid = window.location.pathname.split('/download/')[1];
      if (!uuid) {
        throw new Error('Invalid download URL');
      }

      // Download encrypted file and metadata
      const downloadResponse = await downloadEncryptedFile(uuid);
      if (!downloadResponse.success || !downloadResponse.data) {
        throw new Error(downloadResponse.error || 'Download failed');
      }

      if (!downloadResponse.passwordHash || !downloadResponse.nonceBase64) {
        throw new Error('Missing password verification data');
      }

      setStatus('verifying');

      // Verify password client-side
      const isPasswordValid = await verifyPassword(
        password, 
        downloadResponse.nonceBase64, 
        downloadResponse.passwordHash
      );

      if (!isPasswordValid) {
        throw new Error('Incorrect password');
      }

      setStatus('decrypting');

      // Decrypt file with password
      const decryptedData = await decryptFile({
        encryptedData: downloadResponse.data,
        nonceBase64: downloadResponse.nonceBase64,
        password: password,
      });

      // Trigger download
      const blob = new Blob([decryptedData]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = downloadResponse.filename || 'downloaded-file';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setStatus('ready');
      alert(`File "${downloadResponse.filename}" downloaded successfully!`);
      
    } catch (error) {
      console.error('Download error:', error);
      setError(error instanceof Error ? error.message : 'Download failed');
      setStatus('error');
    }
  };

  return (
    <div className="max-w-md mx-auto mt-8 p-6 border rounded-lg">
      <h1 className="text-2xl font-bold mb-4">Download File</h1>
      
      <div className="space-y-4">
        <div>
          <label htmlFor="password" className="block text-sm font-medium mb-2">
            Password
          </label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-2 border rounded-md"
            placeholder="Enter file password"
            disabled={status !== 'ready'}
            onKeyPress={(e) => e.key === 'Enter' && handleDownload()}
          />
        </div>
        
        <button
          onClick={handleDownload}
          disabled={status !== 'ready' || !password}
          className="w-full px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:bg-gray-400"
        >
          {status === 'ready' && 'Download File'}
          {status === 'downloading' && 'Downloading...'}
          {status === 'verifying' && 'Verifying Password...'}
          {status === 'decrypting' && 'Decrypting...'}
          {status === 'error' && 'Try Again'}
        </button>
        
        {error && (
          <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md">
            <p className="text-sm text-red-800">{error}</p>
          </div>
        )}
      </div>
    </div>
  );
}
