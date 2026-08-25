import React from 'react';
import { formatBytes } from '../../utils/uploadUtils';

export function SelectedFile({ file, onRemove, onChange, onAnalyze }) {
  const fileSizeString = formatBytes(file.size);

  return (
    <div className="selected-file-container">
      <div className="selected-file-card">
        <div className="file-info-row">
          <i className="fa-solid fa-file-shield file-card-icon"></i>
          <div className="file-text-details">
            <div className="file-name-label" title={file.name}>{file.name}</div>
            <div className="file-size-label">{fileSizeString}</div>
          </div>
        </div>
        <div className="file-actions-row">
          <button
            type="button"
            className="btn-selected btn-change"
            aria-label="Change selected file"
            onClick={(e) => { e.stopPropagation(); onChange(); }}
          >
            Change
          </button>
          <button
            type="button"
            className="btn-selected btn-remove"
            aria-label="Remove selected file"
            onClick={(e) => { e.stopPropagation(); onRemove(); }}
          >
            Remove
          </button>
        </div>
      </div>
      <button
        type="button"
        className="btn-analyze-start"
        aria-label="Analyze PCAP file"
        onClick={(e) => { e.stopPropagation(); onAnalyze(); }}
      >
        Analyze PCAP
      </button>
    </div>
  );
}
