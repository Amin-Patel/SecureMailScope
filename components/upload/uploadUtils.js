// components/upload/uploadUtils.js

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
    return { valid: false, error: 'A PCAP file is required.' };
  }

  const name = file.name || '';
  const dotIndex = name.lastIndexOf('.');
  if (dotIndex === -1) {
    return { valid: false, error: 'This file type is not supported. Please upload a .pcap or .pcapng file.' };
  }

  const ext = name.slice(dotIndex).toLowerCase();
  if (ext !== '.pcap' && ext !== '.pcapng') {
    return { valid: false, error: 'This file type is not supported. Please upload a .pcap or .pcapng file.' };
  }

  return { valid: true };
}
