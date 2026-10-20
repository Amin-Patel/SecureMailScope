// src/utils/api.js
// Complete Unified API service layer for SecureMailScope frontend.
// Supports both Supabase JWT session authentication and local auditor fallback.
// Communicates with the FastAPI backend at http://localhost:8001/api (or configured VITE_API_BASE_URL).

import axios from 'axios';
import { supabase } from '../lib/supabase';

export const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL || 'http://localhost:8001'
).replace(/\/+$/, '');

export const API_URL = API_BASE_URL.endsWith('/api')
  ? API_BASE_URL
  : `${API_BASE_URL}/api`;

// Create a reusable Axios instance with the resolved base URL
const apiClient = axios.create({
  baseURL: API_URL,
  timeout: 30000, // 30 seconds timeout
});

// Request Interceptor: Automatically attach Supabase JWT Token if present
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
 * Helper to trigger a real file download in the browser from a binary Blob.
 */
function triggerBlobDownload(blobData, filename, mimeType = 'application/pdf') {
  const url = window.URL.createObjectURL(new Blob([blobData], { type: mimeType }));
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}

// ─── CORE ANALYSIS ENDPOINTS ───

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
 * Backward‑compatible alias for uploadPCAP.
 */
export const uploadPcap = uploadPCAP;
export const getAnalysis = getAnalysisResults;

/**
 * Check backend health status.
 * @returns {Promise<Object>} Status payload.
 */
export async function checkBackendHealth() {
  try {
    const response = await apiClient.get('/health');
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

// ─── DEMO SCENARIO PRESETS ───

/**
 * Get pre-packaged demo scenarios.
 * @returns {Promise<Object>} Object with samples list.
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
 * Load and analyze a pre-packaged demo PCAP file on the backend.
 * @param {string} sampleId The ID of the demo sample (e.g. 'vulnerable_smtp', 'legacy_ssl3', 'secure_enterprise', 'sih_comprehensive')
 * @returns {Promise<Object>} Analysis results payload.
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
 * Alias for loadDemo for legacy component compatibility.
 */
export const uploadDemo = loadDemo;

// ─── RECORD DELETION ───

/**
 * Delete a specific analysis record by capture_id.
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
 * Batch delete multiple analyses.
 * @param {string[]} captureIds 
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

// ─── TCP STREAM RECONSTRUCTION & VIEWER (CQSP) ───

/**
 * Retrieve reconstructed TCP stream transcript by stream ID.
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

// ─── REPORTS & EXPORTS ───

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
    triggerBlobDownload(response.data, `SecureMailScope_Report_${captureId}.${format}`, mimeType);
    return true;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Open the HTML executive forensic report in a new browser tab with authentication attached.
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

// ─── EVIDENCE PROVENANCE GRAPH (USP 3) ───

/**
 * Retrieve the Evidence Provenance Graph for a given capture ID.
 * @param {string} captureId 
 * @returns {Promise<Object>} Full provenance graph payload with nodes, edges, metrics, and traceability index.
 */
export async function getProvenanceGraph(captureId) {
  try {
    const response = await apiClient.get(`/analysis/${encodeURIComponent(captureId)}/provenance`);
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Retrieve granular detail for a single provenance graph node.
 * @param {string} captureId 
 * @param {string} nodeId 
 * @returns {Promise<Object>}
 */
export async function getProvenanceNodeDetail(captureId, nodeId) {
  try {
    const response = await apiClient.get(`/analysis/${encodeURIComponent(captureId)}/provenance/node/${encodeURIComponent(nodeId)}`);
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

// ─── HISTORICAL FORENSICS & RECONSTRUCTION (USP 1) ───

/**
 * Retrieve chronological forensic timeline and host progression.
 * @param {string} captureId 
 * @returns {Promise<Object>}
 */
export async function getForensics(captureId) {
  try {
    const response = await apiClient.get(`/analysis/${encodeURIComponent(captureId)}/forensics`);
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

export const getForensicsTimeline = getForensics;

// ─── CRYPTOGRAPHIC BASELINES & DRIFT ENGINE (USP 6) ───

/**
 * Retrieve all registered cryptographic baselines.
 * @returns {Promise<Object>}
 */
export async function getBaselines() {
  try {
    const response = await apiClient.get('/baselines');
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Create a new cryptographic baseline profile.
 * @param {Object} data 
 * @returns {Promise<Object>}
 */
export async function createBaseline(data) {
  try {
    const response = await apiClient.post('/baselines', data);
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Retrieve a single baseline by ID.
 * @param {string} baselineId 
 * @returns {Promise<Object>}
 */
export async function getBaseline(baselineId) {
  try {
    const response = await apiClient.get(`/baselines/${encodeURIComponent(baselineId)}`);
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Delete a baseline by ID.
 * @param {string} baselineId 
 * @returns {Promise<Object>}
 */
export async function deleteBaseline(baselineId) {
  try {
    const response = await apiClient.delete(`/baselines/${encodeURIComponent(baselineId)}`);
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Compare an analysis capture against a baseline or another capture for cryptographic drift.
 * @param {Object} data 
 * @returns {Promise<Object>}
 */
export async function compareDrift(data) {
  try {
    const response = await apiClient.post('/drift/compare', data);
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Retrieve previous drift comparison history for a given capture.
 * @param {string} captureId 
 * @returns {Promise<Object>}
 */
export async function getDriftHistory(captureId) {
  try {
    const response = await apiClient.get(`/drift/history/${encodeURIComponent(captureId)}`);
    return response.data;
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

// ─── EXECUTIVE PDF REPORT GENERATION (USP 1 & 6) ───

/**
 * Download Report A: Historical Cryptographic Forensics PDF Report.
 * @param {string} captureId 
 */
export async function downloadForensicReportPdf(captureId) {
  try {
    const response = await apiClient.get(`/analysis/${encodeURIComponent(captureId)}/report/pdf`, {
      responseType: 'blob'
    });
    triggerBlobDownload(response.data, `SecureMailScope_Forensic_Report_${captureId}.pdf`);
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Download Report B: Cryptographic Drift & Baseline Comparison PDF Report.
 * @param {string} comparisonId 
 */
export async function downloadDriftReportPdf(comparisonId) {
  try {
    const response = await apiClient.get(`/drift/comparison/${encodeURIComponent(comparisonId)}/report/pdf`, {
      responseType: 'blob'
    });
    triggerBlobDownload(response.data, `SecureMailScope_Drift_Report_${comparisonId}.pdf`);
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

/**
 * Download Report C: Combined Cryptographic Investigation PDF Report.
 * @param {string} captureId 
 * @param {string} comparisonId 
 */
export async function downloadCombinedReportPdf(captureId, comparisonId) {
  try {
    const response = await apiClient.post('/reports/combined/pdf', {
      capture_id: captureId,
      comparison_id: comparisonId
    }, {
      responseType: 'blob'
    });
    triggerBlobDownload(response.data, `SecureMailScope_Combined_Report_${captureId}_${comparisonId}.pdf`);
  } catch (err) {
    const msg = parseError(err);
    const error = new Error(msg);
    error.original = err;
    throw error;
  }
}

// ─── ACTIVE EMAIL AUTHENTICATION CHECKER & WATCHER ───

/**
 * Active SPF/DKIM/DMARC DNS check for a domain (separate from passive PCAP analysis).
 * @param {string} domain
 * @param {string} [dkimSelector]
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

// ─── KNOWLEDGE BASE / RAG ADMIN SERVICES ───

export async function getKnowledgeSources() {
  try {
    const res = await apiClient.get('/admin/kb/sources');
    return res.data;
  } catch (err) {
    const msg = parseError(err);
    throw new Error(msg);
  }
}

export async function getKnowledgeGaps() {
  try {
    const res = await apiClient.get('/admin/kb/gaps');
    return res.data;
  } catch (err) {
    const msg = parseError(err);
    throw new Error(msg);
  }
}

export async function proposeKnowledgeGap(data) {
  try {
    const res = await apiClient.post('/admin/kb/proposals', data);
    return res.data;
  } catch (err) {
    const msg = parseError(err);
    throw new Error(msg);
  }
}

export async function getPendingProposals() {
  try {
    const res = await apiClient.get('/admin/kb/proposals');
    return res.data;
  } catch (err) {
    const msg = parseError(err);
    throw new Error(msg);
  }
}

export async function approveProposal(proposalId) {
  try {
    const res = await apiClient.put(`/admin/kb/proposals/${encodeURIComponent(proposalId)}/approve`);
    return res.data;
  } catch (err) {
    const msg = parseError(err);
    throw new Error(msg);
  }
}

export async function deleteProposal(proposalId) {
  try {
    const res = await apiClient.delete(`/admin/kb/proposals/${encodeURIComponent(proposalId)}`);
    return res.data;
  } catch (err) {
    const msg = parseError(err);
    throw new Error(msg);
  }
}

export async function getKnowledgeArticles() {
  try {
    const res = await apiClient.get('/admin/kb/articles');
    return res.data;
  } catch (err) {
    const msg = parseError(err);
    throw new Error(msg);
  }
}

export async function createKnowledgeArticle(data) {
  try {
    const res = await apiClient.post('/admin/kb/articles', data);
    return res.data;
  } catch (err) {
    const msg = parseError(err);
    throw new Error(msg);
  }
}

export async function approveKnowledgeArticle(articleId) {
  try {
    const res = await apiClient.put(`/admin/kb/articles/${encodeURIComponent(articleId)}/approve`);
    return res.data;
  } catch (err) {
    const msg = parseError(err);
    throw new Error(msg);
  }
}

export async function deleteKnowledgeArticle(articleId) {
  try {
    const res = await apiClient.delete(`/admin/kb/articles/${encodeURIComponent(articleId)}`);
    return res.data;
  } catch (err) {
    const msg = parseError(err);
    throw new Error(msg);
  }
}
