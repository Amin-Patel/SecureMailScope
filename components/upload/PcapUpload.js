// components/upload/PcapUpload.js

import { validateFile } from './uploadUtils.js';
import { UploadDropzone } from './UploadDropzone.js';
import { SelectedFile } from './SelectedFile.js';
import { UploadProgress } from './UploadProgress.js';
import { UploadError } from './UploadError.js';

export const UploadStatus = {
  BEFORE_UPLOAD: 'BEFORE_UPLOAD',
  FILE_SELECTED: 'FILE_SELECTED',
  UPLOADING: 'UPLOADING',
  READY: 'READY',
  FAILED: 'FAILED'
};

export class PcapUpload {
  constructor({
    containerId,
    onFileSelected = null,
    onUpload = null, // async upload handler(file, onProgress) -> returns promise
    onUploadSuccess = null,
    onUploadError = null,
    onAnalysisStart = null
  }) {
    this.container = document.getElementById(containerId);
    if (!this.container) {
      throw new Error(`PcapUpload: Container with ID "${containerId}" not found.`);
    }

    this.onFileSelectedCallback = onFileSelected;
    this.onUploadCallback = onUpload;
    this.onUploadSuccessCallback = onUploadSuccess;
    this.onUploadErrorCallback = onUploadError;
    this.onAnalysisStartCallback = onAnalysisStart;

    this.state = UploadStatus.BEFORE_UPLOAD;
    this.file = null;
    this.progress = null;
    this.errorMessage = '';

    // Sub-components instances
    this.dropzone = new UploadDropzone({ onFileSelected: (file) => this.handleFileSelected(file) });
    this.selectedFileView = null;
    this.progressView = null;
    this.errorView = null;

    // Render the initial UI
    this.render();
  }

  setState(newState, extra = {}) {
    this.state = newState;
    if (extra.errorMessage) this.errorMessage = extra.errorMessage;
    if (extra.progress !== undefined) this.progress = extra.progress;
    this.render();
  }

  // Handle file validation and state transition
  handleFileSelected(file) {
    const val = validateFile(file);
    if (!val.valid) {
      this.setState(UploadStatus.FAILED, { errorMessage: val.error, progress: null });
      if (this.onUploadErrorCallback) this.onUploadErrorCallback(file, val.error);
      return;
    }

    this.file = file;
    this.setState(UploadStatus.FILE_SELECTED);

    if (this.onFileSelectedCallback) {
      this.onFileSelectedCallback(file);
    }
  }

  // Handle removing a file
  handleRemove() {
    this.file = null;
    this.progress = null;
    this.errorMessage = '';
    this.dropzone.reset();
    this.setState(UploadStatus.BEFORE_UPLOAD);
  }

  // Handle trigger change (re-opens file picker)
  handleChange() {
    this.dropzone.openFilePicker();
  }

  // Orchestrate the upload phase
  async handleUpload() {
    if (!this.file) return;

    this.setState(UploadStatus.UPLOADING, { progress: null });

    // Custom upload handler provided by parent
    if (this.onUploadCallback) {
      try {
        const response = await this.onUploadCallback(this.file, (progressVal) => {
          // ProgressVal is a number between 0 and 1
          this.progress = progressVal;
          if (this.progressView) {
            this.progressView.updateProgress(progressVal);
          }
        });

        this.setState(UploadStatus.READY);
        if (this.onUploadSuccessCallback) this.onUploadSuccessCallback(this.file, response);
      } catch (err) {
        const msg = err.message || 'An error occurred during file upload.';
        this.setState(UploadStatus.FAILED, { errorMessage: msg });
        if (this.onUploadErrorCallback) this.onUploadErrorCallback(this.file, msg);
      }
    } else {
      // Default Mock Upload simulation for prototype testing
      this.runMockUpload();
    }
  }

  // Simulates upload over 2 seconds
  runMockUpload() {
    let mockPct = 0;
    this.progress = 0;

    // If filename has 'error' or 'fail', simulate failure at 50%
    const shouldFail = this.file.name.toLowerCase().includes('fail') || this.file.name.toLowerCase().includes('error');

    const interval = setInterval(() => {
      mockPct += 0.2;
      this.progress = Math.min(mockPct, 1);
      
      if (this.progressView) {
        this.progressView.updateProgress(this.progress);
      }

      if (shouldFail && this.progress >= 0.5) {
        clearInterval(interval);
        const msg = 'Connection timeout. Failed to connect to secure parser backend.';
        this.setState(UploadStatus.FAILED, { errorMessage: msg });
        if (this.onUploadErrorCallback) this.onUploadErrorCallback(this.file, msg);
      } else if (this.progress >= 1) {
        clearInterval(interval);
        this.setState(UploadStatus.READY);
        if (this.onUploadSuccessCallback) this.onUploadSuccessCallback(this.file, { status: 'success' });
      }
    }, 400);
  }

  // Trigger analysis start callback
  handleAnalyze() {
    if (this.state === UploadStatus.READY || this.state === UploadStatus.FILE_SELECTED) {
      if (this.onAnalysisStartCallback) {
        this.onAnalysisStartCallback(this.file);
      } else {
        // Fallback demo redirection
        alert(`Analysis triggered successfully for ${this.file.name}! Redirecting to workspace...`);
        window.location.href = `analysis.html?id=8320&file=${encodeURIComponent(this.file.name)}`;
      }
    }
  }

  // Render method updating DOM nodes dynamically
  render() {
    this.container.innerHTML = '';

    switch (this.state) {
      case UploadStatus.BEFORE_UPLOAD:
        this.container.appendChild(this.dropzone.render());
        break;

      case UploadStatus.FILE_SELECTED:
        this.selectedFileView = new SelectedFile({
          file: this.file,
          onRemove: () => this.handleRemove(),
          onChange: () => this.handleChange(),
          onAnalyze: () => this.handleUpload() // clicking analyze starts the upload -> pipeline flow
        });
        this.container.appendChild(this.selectedFileView.render());
        break;

      case UploadStatus.UPLOADING:
        this.progressView = new UploadProgress({
          filename: this.file.name,
          progress: this.progress
        });
        this.container.appendChild(this.progressView.render());
        break;

      case UploadStatus.READY:
        const readyCard = document.createElement('div');
        readyCard.className = 'upload-ready-container';
        readyCard.setAttribute('aria-live', 'polite');

        readyCard.innerHTML = `
          <div class="ready-card">
            <i class="fa-solid fa-circle-check ready-icon"></i>
            <div class="ready-text-details">
              <div class="ready-title-label">Ready for Analysis</div>
              <div class="ready-file-label">${this.file.name} successfully uploaded.</div>
            </div>
          </div>
          <button type="button" class="btn-analyze-start" aria-label="Start PCAP analysis">Start Analysis</button>
        `;

        readyCard.querySelector('.btn-analyze-start').addEventListener('click', () => {
          this.handleAnalyze();
        });

        this.container.appendChild(readyCard);
        break;

      case UploadStatus.FAILED:
        this.errorView = new UploadError({
          errorMessage: this.errorMessage,
          filename: this.file ? this.file.name : '',
          onRetry: () => {
            if (this.file) {
              // Retry upload
              this.handleUpload();
            } else {
              // No file existed (validation error), reset to dropzone
              this.handleRemove();
            }
          }
        });
        this.container.appendChild(this.errorView.render());
        break;
    }
  }
}
