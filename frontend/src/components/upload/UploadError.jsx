import React from 'react';

export function UploadError({ errorMessage, filename, onRetry }) {
  return (
    <div className="upload-error-container" aria-live="assertive">
      <div className="error-card">
        <div className="error-info-row">
          <i className="fa-solid fa-triangle-exclamation error-icon"></i>
          <div className="error-text-details">
            <div className="error-title-label">Upload Failed</div>
            <div className="error-desc-label">{errorMessage}</div>
            {filename && <div className="error-file-label">File: {filename}</div>}
          </div>
        </div>
        <button
          type="button"
          className="btn-retry"
          aria-label="Retry upload file"
          onClick={(e) => { e.stopPropagation(); onRetry(); }}
        >
          Retry
        </button>
      </div>
    </div>
  );
}
