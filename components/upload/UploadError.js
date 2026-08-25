// components/upload/UploadError.js

export class UploadError {
  constructor({ errorMessage, filename, onRetry }) {
    this.errorMessage = errorMessage;
    this.filename = filename;
    this.onRetry = onRetry;
    this.el = null;
  }

  render() {
    const container = document.createElement('div');
    container.className = 'upload-error-container';
    container.setAttribute('aria-live', 'assertive');

    container.innerHTML = `
      <div class="error-card">
        <div class="error-info-row">
          <i class="fa-solid fa-triangle-exclamation error-icon"></i>
          <div class="error-text-details">
            <div class="error-title-label">Upload Failed</div>
            <div class="error-desc-label">${this.errorMessage}</div>
            ${this.filename ? `<div class="error-file-label">File: ${this.filename}</div>` : ''}
          </div>
        </div>
        <button type="button" class="btn-retry" aria-label="Retry upload file">Retry</button>
      </div>
    `;

    this.el = container;
    this.setupEvents();
    return container;
  }

  setupEvents() {
    const retryBtn = this.el.querySelector('.btn-retry');
    if (retryBtn) {
      retryBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.onRetry();
      });
    }
  }
}
