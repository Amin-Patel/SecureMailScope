import { useEffect, useRef } from 'react';

/**
 * Animates stat counters when the footer scrolls into view.
 * Mirrors the vanilla JS setupStatsCounter() logic from main.js.
 * 
 * @param {React.RefObject} footerRef - ref attached to the stats-footer element
 */
export function useStatsCounter(footerRef) {
  const hasAnimated = useRef(false);

  useEffect(() => {
    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const suffixes = ['ms', '%', '/7', 'M'];

    const animate = () => {
      if (hasAnimated.current) return;
      hasAnimated.current = true;

      const statValues = footerRef.current
        ? footerRef.current.querySelectorAll('.stat-value')
        : document.querySelectorAll('.stat-value');

      const easeOutCubic = (t) => 1 - Math.pow(1 - t, 3);

      if (prefersReduced) {
        statValues.forEach((el, i) => {
          const target = parseFloat(el.getAttribute('data-target'));
          const decimals = parseInt(el.getAttribute('data-decimals') || '0', 10);
          el.textContent = target.toFixed(decimals) + suffixes[i];
        });
        return;
      }

      statValues.forEach((el, i) => {
        const target = parseFloat(el.getAttribute('data-target'));
        const decimals = parseInt(el.getAttribute('data-decimals') || '0', 10);
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
    };

    const footer = footerRef.current;
    if (!footer) return;

    if (prefersReduced) {
      animate();
      return;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            animate();
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.25 }
    );

    observer.observe(footer);

    return () => observer.disconnect();
  }, [footerRef]);
}
