// components/upload/UploadProgress.js

export class UploadProgress {
  constructor({ filename, progress = null }) {
    this.filename = filename;
    this.progress = progress; // number from 0 to 1, or null
    this.el = null;
  }

  render() {
    const container = document.createElement('div');
    container.className = 'upload-progress-container';
    container.setAttribute('aria-live', 'polite');

    const hasProgress = typeof this.progress === 'number' && this.progress >= 0 && this.progress <= 1;
    const pct = hasProgress ? Math.round(this.progress * 100) : 0;
    const progressText = hasProgress ? `Uploading... ${pct}%` : 'Uploading...';

    container.innerHTML = `
      <div class="progress-details">
        <div class="progress-file-name" title="${this.filename}">${this.filename}</div>
        <div class="progress-status-label">${progressText}</div>
      </div>
      <div class="progress-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${pct}" aria-label="Upload Progress">
        <div class="progress-bar ${hasProgress ? 'determinate' : 'indeterminate'}" style="width: ${hasProgress ? pct + '%' : '100%'}"></div>
      </div>
    `;

    this.el = container;
    return container;
  }

  updateProgress(progress) {
    this.progress = progress;
    if (this.el) {
      const hasProgress = typeof this.progress === 'number' && this.progress >= 0 && this.progress <= 1;
      const pct = hasProgress ? Math.round(this.progress * 100) : 0;
      const progressText = hasProgress ? `Uploading... ${pct}%` : 'Uploading...';

      const label = this.el.querySelector('.progress-status-label');
      if (label) label.textContent = progressText;

      const track = this.el.querySelector('.progress-track');
      if (track) track.setAttribute('aria-valuenow', pct.toString());

      const bar = this.el.querySelector('.progress-bar');
      if (bar) {
        if (hasProgress) {
          bar.classList.remove('indeterminate');
          bar.classList.add('determinate');
          bar.style.width = pct + '%';
        } else {
          bar.classList.remove('determinate');
          bar.classList.add('indeterminate');
          bar.style.width = '100%';
        }
      }
    }
  }
}
