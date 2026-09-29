// src/utils/api.js
// Real API service layer for SecureMailScope frontend.
// Uses Axios to communicate with the FastAPI backend via configurable base URL
// Automatically attaches Supabase Auth JWT Bearer token to all outgoing requests.

import axios from 'axios';
import { supabase } from '../lib/supabase';

// Base API configuration from Vite environment variable
export const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL || 'http://localhost:8001'
).replace(/\/+$/, '');

export const API_URL = API_BASE_URL.endsWith('/api')
  ? API_BASE_URL
  : `${API_BASE_URL}/api`;

// Create a reusable Axios instance with the required base URL.
const apiClient = axios.create({
  baseURL: API_URL,
  timeout: 30000, // 30 seconds timeout
});

// Request Interceptor: Attach Supabase JWT Token
apiClient.interceptors.request.use(async (config) => {
  try {
    const { data: { session } } = await supabase.auth.getSession();
    if (session?.access_token) {
      config.headers.Authorization = `Bearer ${session.access_token}`;
    }
  } catch (err) {
    console.warn('[API Client] Could not attach Supabase session token:', err);
  }
  return config;
}, (error) => {
  return Promise.reject(error);
});

/**
 * Helper to extract a user‑friendly error message from an Axios error.
 * @param {any} error The error thrown by Axios
 * @returns {string} Human readable message
 */
function parseError(error) {
  if (error.response) {
    // Server responded with a status outside the 2xx range
    const msg = error.response.data?.detail || error.response.data?.message;
    return msg || `Server returned status ${error.response.status}`;
  }
  if (error.request) {
    // No response received – likely a network problem
    return 'Unable to connect to the SecureMailScope analysis server. Please make sure the backend is running.';
  }
  // Something else happened while setting up the request
  return error.message || 'An unexpected error occurred.';
}

/**
 * Upload a PCAP (or PCAPNG) file to the backend.
 * @param {File} file The file object selected by the user.
 * @returns {Promise<Object>} Resolves with the backend response containing capture_id, filename, size, status.
 */
export async function uploadPCAP(file) {
  const form = new FormData();
  form.append('file', file);
  try {
    const response = await apiClient.post('/upload', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Retrieve full analysis results for a given capture ID.
 * @param {string} captureId The ID returned from the upload step.
 * @returns {Promise<Object>} The complete analysis payload from the backend.
 */
export async function getAnalysisResults(captureId) {
  try {
    const response = await apiClient.get(`/analysis/${encodeURIComponent(captureId)}/results`);
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Get the current processing status for a capture.
 * @param {string} captureId The capture identifier.
 * @returns {Promise<Object>} Backend status payload.
 */
export async function getAnalysisStatus(captureId) {
  try {
    const response = await apiClient.get(`/analysis/${encodeURIComponent(captureId)}/status`);
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Retrieve all completed analyses for current authenticated user.
 * @returns {Promise<Object>} Object containing analyses list and total count.
 */
export async function getAnalyses() {
  try {
    const response = await apiClient.get('/analyses');
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Active SPF/DKIM/DMARC DNS check for a domain (separate from passive PCAP analysis).
 */
export async function checkEmailAuth(domain, dkimSelector) {
  try {
    const response = await apiClient.post('/email-auth-check', {
      domain: domain.trim(),
      dkim_selector: dkimSelector?.trim() || null,
    });
    return response.data;
  } catch (err) {
    throw new Error(err.response?.data?.detail || parseError(err));
  }
}

/**
 * Folder-monitoring status (enabled flag, current file, recently processed captures).
 * Never throws: a failed poll just reports monitoring as unavailable.
 */
export async function getWatchStatus() {
  try {
    const response = await apiClient.get('/watch/status');
    return response.data;
  } catch {
    return { enabled: false, running: false, recent: [] };
  }
}

/**
 * Trigger the analysis of a demo/sample PCAP file on the server.
 * @param {string} demoName The filename of the demo PCAP (e.g. smtp.pcap or rsasnakeoil2.cap).
 * @returns {Promise<Object>} The complete analysis payload.
 */
export async function uploadDemo(demoName) {
  try {
    const response = await apiClient.post(`/upload-demo?demo_name=${encodeURIComponent(demoName)}`);
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

// Backward‑compatible aliases used by existing components.
export const uploadPcap = uploadPCAP;
export const getAnalysis = getAnalysisResults;

/**
 * Check if the backend is reachable.
 * @returns {Promise<Object>} health data
 */
export async function checkBackendHealth() {
  try {
    const response = await apiClient.get('/health');
    return response.data;
  } catch (err) {
    throw new Error('Backend disconnected. Ensure SecureMailScope API server is reachable.');
  }
}

/**
 * Get available demo samples from the backend.
 * @returns {Promise<Object>} Available samples list.
 */
export async function getDemoSamples() {
  try {
    const response = await apiClient.get('/demo/samples');
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Load a sample preset demo.
 * @param {string} sampleId The dynamic sample preset ID (e.g. vulnerable_smtp, legacy_ssl3).
 * @returns {Promise<Object>} Analysis results.
 */
export async function loadDemo(sampleId) {
  try {
    const response = await apiClient.post(`/demo/load/${encodeURIComponent(sampleId)}`);
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Delete a specific analysis record by capture ID.
 * @param {string} captureId 
 * @returns {Promise<Object>}
 */
export async function deleteAnalysis(captureId) {
  try {
    const response = await apiClient.delete(`/analysis/${encodeURIComponent(captureId)}`);
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Batch delete multiple analysis records by array of capture IDs.
 * @param {Array<string>} captureIds 
 * @returns {Promise<Object>}
 */
export async function deleteAnalysesBatch(captureIds) {
  try {
    const response = await apiClient.post('/analyses/delete-batch', { capture_ids: captureIds });
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Retrieve structured TCP conversation stream details by capture ID and stream ID.
 * @param {string} captureId 
 * @param {string|number} streamId 
 * @returns {Promise<Object>}
 */
export async function getStreamDetails(captureId, streamId) {
  try {
    const response = await apiClient.get(`/analysis/${encodeURIComponent(captureId)}/stream/${encodeURIComponent(streamId)}`);
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Construct report URL path
 * @param {string} captureId
 * @param {'html' | 'pdf' | 'json'} format
 * @returns {string}
 */
export function getReportUrl(captureId, format = 'html') {
  return `${API_URL}/analysis/${encodeURIComponent(captureId)}/report?format=${format}`;
}

/**
 * Download a generated report (PDF, HTML, or JSON) with Supabase authentication attached.
 * @param {string} captureId
 * @param {'pdf' | 'html' | 'json'} format
 */
export async function downloadReport(captureId, format = 'pdf') {
  try {
    const cleanId = encodeURIComponent(captureId);
    const response = await apiClient.get(`/analysis/${cleanId}/report?format=${format}`, {
      responseType: 'blob',
    });

    const mimeTypes = {
      pdf: 'application/pdf',
      html: 'text/html',
      json: 'application/json',
    };
    const mimeType = mimeTypes[format] || 'application/octet-stream';
    const blob = new Blob([response.data], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `SecureMailScope_Report_${captureId}.${format}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    return true;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Open the HTML executive forensic report in a new browser tab with Supabase authentication attached.
 * @param {string} captureId
 */
export async function viewReportHtml(captureId) {
  try {
    const cleanId = encodeURIComponent(captureId);
    const response = await apiClient.get(`/analysis/${cleanId}/report?format=html`, {
      responseType: 'blob',
    });
    const blob = new Blob([response.data], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    window.open(url, '_blank', 'noopener,noreferrer');
    return true;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}
