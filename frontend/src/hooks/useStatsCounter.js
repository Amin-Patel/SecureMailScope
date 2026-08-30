import { useEffect, useRef } from 'react';

/**
 * Animates stat counters when the footer scrolls into view.
 * 
 * @param {React.RefObject} footerRef - ref attached to the stats-footer element
 */
export function useStatsCounter(footerRef) {
  const hasAnimated = useRef(false);

  useEffect(() => {
    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const animate = () => {
      if (hasAnimated.current) return;
      hasAnimated.current = true;

      const statValues = footerRef.current
        ? footerRef.current.querySelectorAll('.stat-value')
        : document.querySelectorAll('.stat-value');

      const easeOutCubic = (t) => 1 - Math.pow(1 - t, 3);

      statValues.forEach((el, i) => {
        const rawTarget = el.getAttribute('data-target');
        if (!rawTarget || isNaN(parseFloat(rawTarget))) return;

        const target = parseFloat(rawTarget);
        const decimals = parseInt(el.getAttribute('data-decimals') || '0', 10);
        const prefix = el.getAttribute('data-prefix') || '';
        const suffix = el.getAttribute('data-suffix') || '';

        if (prefersReduced) {
          el.textContent = `${prefix}${target.toFixed(decimals)}${suffix}`;
          return;
        }

        const duration = 1500 + i * 80;
        const startOffset = 400 + i * 90;

        setTimeout(() => {
          let startTime = null;

          function updateCounter(now) {
            if (!startTime) startTime = now;
            const progress = Math.min((now - startTime) / duration, 1);
            const easedProgress = easeOutCubic(progress);
            const currentValue = easedProgress * target;

            el.textContent = `${prefix}${currentValue.toFixed(decimals)}${suffix}`;

            if (progress < 1) {
              requestAnimationFrame(updateCounter);
            } else {
              el.textContent = `${prefix}${target.toFixed(decimals)}${suffix}`;
            }
          }

          requestAnimationFrame(updateCounter);
        }, startOffset);
      });
    };

    const footer = footerRef.current;
    if (!footer) return;

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            animate();
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.15 }
    );

    observer.observe(footer);

    return () => observer.disconnect();
  }, [footerRef]);
}

