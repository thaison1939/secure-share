'use client';

import { useEffect, useState } from 'react';
import { extractKeysFromUrl } from '@/lib/crypto/url-fragment';
import { downloadEncryptedFile } from '@/lib/api/download';
import { decryptFile } from '@/lib/crypto/encryption';

export default function DownloadPage() {
  const [status, setStatus] = useState<'loading' | 'ready' | 'downloading' | 'decrypting' | 'error'>('loading');
  const [error, setError] = useState<string>('');
  const [filename, setFilename] = useState<string>('');

  const handleDownload = async () => {
    try {
      setStatus('downloading');
      
      const keys = extractKeysFromUrl();
      if (!keys) {
        throw new Error('Invalid download link');
      }

      const downloadResponse = await downloadEncryptedFile(keys.uuid);
      if (!downloadResponse.success || !downloadResponse.data) {
        throw new Error(downloadResponse.error || 'Download failed');
      }

      setStatus('decrypting');

      const decryptedData = await decryptFile({
        encryptedData: downloadResponse.data,
        keyBase64: keys.keyBase64,
        nonceBase64: keys.nonceBase64,
      });

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
    } catch (error) {
      console.error('Download error:', error);
      setError(error instanceof Error ? error.message : 'Download failed');
      setStatus('error');
    }
  };

  useEffect(() => {
    setStatus('ready');
  }, []);

  return (
    <div>
      <h1>Download File</h1>
      {status === 'loading' && <p>Preparing download...</p>}
      {status === 'ready' && <button onClick={handleDownload}>Download File</button>}
      {status === 'downloading' && <p>Downloading encrypted file...</p>}
      {status === 'decrypting' && <p>Decrypting file...</p>}
      {status === 'error' && <p>Error: {error}</p>}
    </div>
  );
}
