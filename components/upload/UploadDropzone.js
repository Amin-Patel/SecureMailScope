// components/upload/UploadDropzone.js

export class UploadDropzone {
  constructor({ onFileSelected }) {
    this.onFileSelected = onFileSelected;
    this.el = null;
    this.inputEl = null;
  }

  render() {
    const container = document.createElement('div');
    container.className = 'upload-dropzone';
    container.setAttribute('tabindex', '0');
    container.setAttribute('role', 'button');
    container.setAttribute('aria-label', 'Select PCAP or drop file here');

    // Inner UI matching the style rules
    container.innerHTML = `
      <div class="dropzone-inner">
        <i class="fa-solid fa-cloud-arrow-up dropzone-icon"></i>
        <div class="dropzone-text">Drop a PCAP here or select a file</div>
        <div class="dropzone-subtext">Supports .pcap and .pcapng files</div>
      </div>
      <input type="file" class="dropzone-input" accept=".pcap,.pcapng" style="display: none;" />
    `;

    this.el = container;
    this.inputEl = container.querySelector('.dropzone-input');

    this.setupEvents();
    return container;
  }

  setupEvents() {
    // Trigger file input click on container click
    this.el.addEventListener('click', () => {
      this.inputEl.click();
    });

    // Keyboard support for accessibility
    this.el.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        this.inputEl.click();
      }
    });

    // Handle change of file input
    this.inputEl.addEventListener('change', (e) => {
      const files = e.target.files;
      if (files && files.length > 0) {
        this.onFileSelected(files[0]);
      }
    });

    // Drag and Drop event handling
    const preventDefaults = (e) => {
      e.preventDefault();
      e.stopPropagation();
    };

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      this.el.addEventListener(eventName, preventDefaults, false);
    });

    // Add/remove dragover active visual state
    ['dragenter', 'dragover'].forEach(eventName => {
      this.el.addEventListener(eventName, () => {
        this.el.classList.add('dragover');
      }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
      this.el.addEventListener(eventName, () => {
        this.el.classList.remove('dragover');
      }, false);
    });

    // Handle drop
    this.el.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      const files = dt.files;

      if (files && files.length > 0) {
        // If multiple files dropped, take first one as MVP, orchestrator can warn
        this.onFileSelected(files[0]);
      }
    });
  }

  // Allow trigger file picker externally (e.g. on Replace click)
  openFilePicker() {
    if (this.inputEl) {
      this.inputEl.click();
    }
  }

  reset() {
    if (this.inputEl) {
      this.inputEl.value = '';
    }
  }
}
