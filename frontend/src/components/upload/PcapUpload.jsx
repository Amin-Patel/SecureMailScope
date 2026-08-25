import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { validateFile } from '../../utils/uploadUtils';
import { UploadDropzone } from './UploadDropzone';
import { SelectedFile } from './SelectedFile';
import { UploadProgress } from './UploadProgress';
import { UploadError } from './UploadError';

const UploadStatus = {
  BEFORE_UPLOAD: 'BEFORE_UPLOAD',
  FILE_SELECTED: 'FILE_SELECTED',
  UPLOADING: 'UPLOADING',
  READY: 'READY',
  FAILED: 'FAILED',
};

export function PcapUpload({ onFileSelected, onUpload, onUploadSuccess, onUploadError, onAnalysisStart }) {
  const navigate = useNavigate();
  const [status, setStatus] = useState(UploadStatus.BEFORE_UPLOAD);
  const [file, setFile] = useState(null);
  const [progress, setProgress] = useState(null);
  const [errorMessage, setErrorMessage] = useState('');

  // Keep a ref to file so async intervals can access the latest value
  const fileRef = useRef(null);

  const handleFileSelected = (selectedFile) => {
    const val = validateFile(selectedFile);
    if (!val.valid) {
      setErrorMessage(val.error);
      setFile(null);
      setProgress(null);
      setStatus(UploadStatus.FAILED);
      if (onUploadError) onUploadError(selectedFile, val.error);
      return;
    }

    fileRef.current = selectedFile;
    setFile(selectedFile);
    setStatus(UploadStatus.FILE_SELECTED);
    if (onFileSelected) onFileSelected(selectedFile);
  };

  const handleRemove = () => {
    fileRef.current = null;
    setFile(null);
    setProgress(null);
    setErrorMessage('');
    setStatus(UploadStatus.BEFORE_UPLOAD);
  };

  const handleChange = () => {
    // Will be handled by UploadDropzone re-opening its file picker via a key reset trick
    handleRemove();
  };

  const runMockUpload = () => {
    let mockPct = 0;
    setProgress(0);
    const currentFile = fileRef.current;
    const shouldFail = currentFile && (
      currentFile.name.toLowerCase().includes('fail') ||
      currentFile.name.toLowerCase().includes('error')
    );

    const interval = setInterval(() => {
      mockPct += 0.2;
      const newProgress = Math.min(mockPct, 1);
      setProgress(newProgress);

      if (shouldFail && newProgress >= 0.5) {
        clearInterval(interval);
        const msg = 'Connection timeout. Failed to connect to secure parser backend.';
        setErrorMessage(msg);
        setStatus(UploadStatus.FAILED);
        if (onUploadError) onUploadError(currentFile, msg);
      } else if (newProgress >= 1) {
        clearInterval(interval);
        setStatus(UploadStatus.READY);
        if (onUploadSuccess) onUploadSuccess(currentFile, { status: 'success' });
      }
    }, 400);
  };

  const handleUpload = async () => {
    if (!file) return;
    setStatus(UploadStatus.UPLOADING);
    setProgress(null);

    if (onUpload) {
      try {
        const response = await onUpload(file, (progressVal) => {
          setProgress(progressVal);
        });
        setStatus(UploadStatus.READY);
        if (onUploadSuccess) onUploadSuccess(file, response);
      } catch (err) {
        const msg = err.message || 'An error occurred during file upload.';
        setErrorMessage(msg);
        setStatus(UploadStatus.FAILED);
        if (onUploadError) onUploadError(file, msg);
      }
    } else {
      runMockUpload();
    }
  };

  const handleAnalyze = () => {
    if (status === UploadStatus.READY || status === UploadStatus.FILE_SELECTED) {
      if (onAnalysisStart) {
        onAnalysisStart(file);
      } else {
        navigate(`/analysis?id=8320&file=${encodeURIComponent(file.name)}`);
      }
    }
  };

  const handleRetry = () => {
    if (file) {
      handleUpload();
    } else {
      handleRemove();
    }
  };

  switch (status) {
    case UploadStatus.BEFORE_UPLOAD:
      return <UploadDropzone onFileSelected={handleFileSelected} />;

    case UploadStatus.FILE_SELECTED:
      return (
        <SelectedFile
          file={file}
          onRemove={handleRemove}
          onChange={handleChange}
          onAnalyze={handleUpload}
        />
      );

    case UploadStatus.UPLOADING:
      return <UploadProgress filename={file.name} progress={progress} />;

    case UploadStatus.READY:
      return (
        <div className="upload-ready-container" aria-live="polite">
          <div className="ready-card">
            <div className="ready-info-row">
              <i className="fa-solid fa-circle-check ready-icon"></i>
              <div className="ready-text-details">
                <div className="ready-title-label">Ready for Analysis</div>
                <div className="ready-file-label">{file.name} successfully uploaded.</div>
              </div>
            </div>
          </div>
          <button
            type="button"
            className="btn-analyze-start"
            aria-label="Start PCAP analysis"
            onClick={handleAnalyze}
          >
            Start Analysis
          </button>
        </div>
      );

    case UploadStatus.FAILED:
      return (
        <UploadError
          errorMessage={errorMessage}
          filename={file ? file.name : ''}
          onRetry={handleRetry}
        />
      );

    default:
      return null;
  }
}
