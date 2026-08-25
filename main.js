// main.js
import { PcapUpload } from './components/upload/PcapUpload.js';

document.addEventListener("DOMContentLoaded", () => {
  setupEntranceAnimations();
  setupStatsCounter();
  setupMobileMenu();
  setupPcapUpload();
});

function setupPcapUpload() {
  const container = document.getElementById('pcap-upload-container');
  if (container) {
    new PcapUpload({
      containerId: 'pcap-upload-container',
      onAnalysisStart: (file) => {
        alert(`Starting Analysis pipeline for ${file.name}...`);
        window.location.href = `analysis.html?id=8320&file=${encodeURIComponent(file.name)}`;
      }
    });
  }
}

// 1. Shared Entrance Animations
function setupEntranceAnimations() {
  const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (prefersReduced) {
    // Immediately show all animated elements
    document.querySelectorAll(".anim").forEach(el => {
      el.classList.add("reveal");
      el.style.opacity = "1";
      el.style.transform = "none";
      el.style.filter = "none";
    });
    return;
  }

  // Set up reveal animation for general elements
  const animElements = document.querySelectorAll(".anim");
  animElements.forEach(el => {
    // If it's a line inside the headline, it animates via CSS keyframes directly.
    // Otherwise, we trigger the reveal class when visible.
    if (!el.classList.contains("headline") && !el.closest(".headline")) {
      el.classList.add("reveal");
    }
  });
}

// 2. Stats Count-up Animation
function setupStatsCounter() {
  const statValues = document.querySelectorAll(".stat-value");
  const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const suffixes = ["ms", "%", "/7", "M"];

  if (prefersReduced) {
    statValues.forEach((el, i) => {
      const target = parseFloat(el.getAttribute("data-target"));
      const decimals = parseInt(el.getAttribute("data-decimals") || "0", 10);
      el.textContent = target.toFixed(decimals) + suffixes[i];
    });
    return;
  }

  const easeOutCubic = (t) => 1 - Math.pow(1 - t, 3);

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        statValues.forEach((el, i) => {
          const target = parseFloat(el.getAttribute("data-target"));
          const decimals = parseInt(el.getAttribute("data-decimals") || "0", 10);
          const suffix = suffixes[i];
          const duration = 1500 + i * 80;
          const startOffset = 480 + i * 90;

          setTimeout(() => {
            let startTime = null;

            function updateCounter(now) {
              if (!startTime) startTime = now;
              const progress = Math.min((now - startTime) / duration, 1);
              const easedProgress = easeOutCubic(progress);
              const currentValue = easedProgress * target;

              el.textContent = currentValue.toFixed(decimals) + suffix;

              if (progress < 1) {
                requestAnimationFrame(updateCounter);
              } else {
                el.textContent = target.toFixed(decimals) + suffix;
              }
            }

            requestAnimationFrame(updateCounter);
          }, startOffset);
        });

        observer.unobserve(entry.target);
      }
    });
  }, {
    threshold: 0.25
  });

  const footer = document.querySelector(".stats-footer");
  if (footer) {
    observer.observe(footer);
  }
}

// 3. Mobile Menu Interactions
function setupMobileMenu() {
  const burger = document.querySelector(".burger-btn");
  const overlay = document.querySelector(".menu-overlay");
  const sheet = document.querySelector(".menu-sheet");
  const body = document.body;

  if (!burger || !overlay || !sheet) return;

  function toggleMenu(forceClose = false) {
    const isOpen = forceClose ? true : burger.classList.contains("open");

    if (isOpen) {
      // Close
      burger.classList.remove("open");
      burger.setAttribute("aria-expanded", "false");
      overlay.classList.remove("open");
      sheet.classList.remove("open");
      body.classList.remove("menu-open");
    } else {
      // Open
      burger.classList.add("open");
      burger.setAttribute("aria-expanded", "true");
      overlay.classList.add("open");
      sheet.classList.add("open");
      body.classList.add("menu-open");

      // Accessibility / Focus Management: Focus the first link
      const firstLink = sheet.querySelector(".mobile-link");
      if (firstLink) firstLink.focus();
    }
  }

  burger.addEventListener("click", () => toggleMenu());
  overlay.addEventListener("click", () => toggleMenu(true));

  // Esc key closes menu
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && burger.classList.contains("open")) {
      toggleMenu(true);
      burger.focus();
    }
  });

  // Link click closes menu
  const links = sheet.querySelectorAll("a, button");
  links.forEach(link => {
    link.addEventListener("click", () => {
      toggleMenu(true);
    });
  });

  // Resize > 720px closes menu
  window.addEventListener("resize", () => {
    if (window.innerWidth > 720 && burger.classList.contains("open")) {
      toggleMenu(true);
    }
  });
}
