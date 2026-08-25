import React, { useRef, useState } from 'react';

export function UploadDropzone({ onFileSelected }) {
  const inputRef = useRef(null);
  const [isDragOver, setIsDragOver] = useState(false);

  const handleContainerClick = () => {
    if (inputRef.current) inputRef.current.click();
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      handleContainerClick();
    }
  };

  const handleFileChange = (e) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      onFileSelected(files[0]);
    }
  };

  const handleDragEnter = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!isDragOver) setIsDragOver(true);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
    
    const files = e.dataTransfer.files;
    if (files && files.length > 0) {
      onFileSelected(files[0]);
    }
  };

  return (
    <div
      className={`upload-dropzone ${isDragOver ? 'dragover' : ''}`}
      tabIndex="0"
      role="button"
      aria-label="Select PCAP or drop file here"
      onClick={handleContainerClick}
      onKeyDown={handleKeyDown}
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      <div className="dropzone-inner">
        <i className="fa-solid fa-cloud-arrow-up dropzone-icon"></i>
        <div className="dropzone-text">Drop a PCAP here or select a file</div>
        <div className="dropzone-subtext">Supports .pcap and .pcapng files</div>
      </div>
      <input
        type="file"
        className="dropzone-input"
        accept=".pcap,.pcapng"
        style={{ display: 'none' }}
        ref={inputRef}
        onChange={handleFileChange}
      />
    </div>
  );
}
