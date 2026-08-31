// src/utils/api.js
// Real API service layer for SecureMailScope frontend.
// Uses Axios to communicate with the FastAPI backend at http://localhost:8001/api

import axios from 'axios';

// Create a reusable Axios instance with the required base URL.
const apiClient = axios.create({
  baseURL: 'http://localhost:8001/api',
  timeout: 15000, // 15 seconds timeout for all requests
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
    // Throw a clean error that callers can catch and display.
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
    const response = await apiClient.get(`/analysis/${captureId}/results`);
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
    const response = await apiClient.get(`/analysis/${captureId}/status`);
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Retrieve all completed analyses from the backend.
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
    throw new Error('Backend disconnected. Ensure FastAPI is running on port 8001.');
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


