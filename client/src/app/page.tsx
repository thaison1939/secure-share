import { encryptFile } from '@/lib/crypto/encryption';
import { generateSecureUUID } from '@/lib/crypto/uuid';
import { uploadEncryptedFile } from '@/lib/api/upload';
import { validateFile } from '@/lib/validation/file-validation';

export default function UploadPage() {
  const handleUpload = async (file: File) => {
    try {
      const validation = validateFile(file);
      if (!validation.isValid) {
        console.error(validation.errors.join(', '));
        alert('File validation failed. Please check the console for details.');
        return;
      }

      const uuid = generateSecureUUID();
      const { encryptedData, keyBase64, nonceBase64 } = await encryptFile(file);

      const uploadResponse = await uploadEncryptedFile({
        encryptedFile: encryptedData,
        uuid,
        originalFilename: file.name,
        clickLimit: 1,
        fileSize: file.size,
      });

      if (uploadResponse.success) {
        const shareLink = `${window.location.origin}/download/${uuid}#key=${keyBase64}&nonce=${nonceBase64}`;
        alert(`File uploaded successfully! Share link: ${shareLink}`);
      } else {
        console.error('Upload failed:', uploadResponse.error);
        alert('File upload failed. Please try again.');
      }
    } catch (error) {
      console.error('Upload error:', error);
      alert('An error occurred during file upload. Please try again.');
    }
  };

  return (
    <div>
      <input type="file" onChange={(e) => handleUpload(e.target.files[0])} />
    </div>
  );
}
