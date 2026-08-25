// components/upload/SelectedFile.js

import { formatBytes } from './uploadUtils.js';

export class SelectedFile {
  constructor({ file, onRemove, onChange, onAnalyze }) {
    this.file = file;
    this.onRemove = onRemove;
    this.onChange = onChange;
    this.onAnalyze = onAnalyze;
    this.el = null;
  }

  render() {
    const container = document.createElement('div');
    container.className = 'selected-file-container';

    const fileSizeString = formatBytes(this.file.size);

    container.innerHTML = `
      <div class="selected-file-card">
        <div class="file-info-row">
          <i class="fa-solid fa-file-shield file-card-icon"></i>
          <div class="file-text-details">
            <div class="file-name-label" title="${this.file.name}">${this.file.name}</div>
            <div class="file-size-label">${fileSizeString}</div>
          </div>
        </div>
        <div class="file-actions-row">
          <button type="button" class="btn-selected btn-change" aria-label="Change selected file">Change</button>
          <button type="button" class="btn-selected btn-remove" aria-label="Remove selected file">Remove</button>
        </div>
      </div>
      <button type="button" class="btn-analyze-start" aria-label="Analyze PCAP file">Analyze PCAP</button>
    `;

    this.el = container;
    this.setupEvents();
    return container;
  }

  setupEvents() {
    this.el.querySelector('.btn-remove').addEventListener('click', (e) => {
      e.stopPropagation();
      this.onRemove();
    });

    this.el.querySelector('.btn-change').addEventListener('click', (e) => {
      e.stopPropagation();
      this.onChange();
    });

    this.el.querySelector('.btn-analyze-start').addEventListener('click', (e) => {
      e.stopPropagation();
      this.onAnalyze();
    });
  }
}
