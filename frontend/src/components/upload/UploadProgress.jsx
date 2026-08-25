import React from 'react';

export function UploadProgress({ filename, progress }) {
  const hasProgress = typeof progress === 'number' && progress >= 0 && progress <= 1;
  const pct = hasProgress ? Math.round(progress * 100) : 0;
  const progressText = hasProgress ? `Uploading... ${pct}%` : 'Uploading...';

  return (
    <div className="upload-progress-container" aria-live="polite">
      <div className="progress-details">
        <div className="progress-file-name" title={filename}>{filename}</div>
        <div className="progress-status-label">{progressText}</div>
      </div>
      <div
        className="progress-track"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={pct}
        aria-label="Upload Progress"
      >
        <div
          className={`progress-bar ${hasProgress ? 'determinate' : 'indeterminate'}`}
          style={{ width: hasProgress ? `${pct}%` : '100%' }}
        ></div>
      </div>
    </div>
  );
}
