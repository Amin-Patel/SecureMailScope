/**
 * Format bytes into a human-readable string.
 * @param {number} bytes
 * @param {number} decimals
 * @returns {string}
 */
export function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];

  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Validate a file primarily based on its extension.
 * Supports case-insensitive extensions (.pcap, .pcapng).
 * @param {File} file
 * @returns {{valid: boolean, error?: string}}
 */
export function validateFile(file) {
  if (!file) {
    return { valid: false, error: 'No file selected.' };
  }

  const allowedExtensions = ['.pcap', '.pcapng', '.cap'];
  const fileName = file.name.toLowerCase();
  
  const isValidExt = allowedExtensions.some(ext => fileName.endsWith(ext));
  
  if (!isValidExt) {
    return { valid: false, error: 'Please select a valid PCAP or PCAPNG file.' };
  }

  // Example size limit: 500MB (can be adjusted)
  const MAX_SIZE_MB = 500;
  if (file.size > MAX_SIZE_MB * 1024 * 1024) {
    return { valid: false, error: `File size exceeds the ${MAX_SIZE_MB}MB limit.` };
  }

  return { valid: true };
}
