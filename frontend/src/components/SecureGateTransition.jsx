import React, { useState, useEffect } from 'react';

/**
 * SecureGateTransition
 *
 * Cinematic transition component representing establishing a secure channel
 * and opening the secure gate before navigating to /login.
 *
 * Sequence (~1.5s):
 *  1. Scrim fade & "ESTABLISHING SECURE CHANNEL" technical status.
 *  2. Horizontal scanline sweep.
 *  3. Network signal nodes converge toward center.
 *  4. Energy pulse collapses to center.
 *  5. Two dark translucent panels split horizontally to reveal the secure interface.
 *  6. Calls onComplete() to finalize navigation.
 */
export function SecureGateTransition({ open, onComplete }) {
  const [stage, setStage] = useState('idle'); // 'idle' | 'initiating' | 'scanning' | 'signal' | 'gate' | 'done'

  useEffect(() => {
    if (!open) {
      setStage('idle');
      return;
    }

    // Check for reduced motion preference
    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReduced) {
      if (onComplete) onComplete();
      return;
    }

    // Run transition sequence
    setStage('initiating');

    const t1 = setTimeout(() => setStage('scanning'), 250);
    const t2 = setTimeout(() => setStage('signal'), 600);
    const t3 = setTimeout(() => setStage('gate'), 1000);
    const t4 = setTimeout(() => {
      setStage('done');
      if (onComplete) onComplete();
    }, 1550);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
    };
  }, [open, onComplete]);

  if (!open || stage === 'idle') return null;

  return (
    <div
      className="secure-gate-overlay"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 99999,
        pointerEvents: 'all',
        overflow: 'hidden',
      }}
      aria-live="polite"
      aria-label="Establishing secure connection"
    >
      {/* Background Dimming Scrim */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.88)',
          backdropFilter: 'blur(10px)',
          WebkitBackdropFilter: 'blur(10px)',
          transition: 'opacity 0.4s ease',
          opacity: stage === 'gate' || stage === 'done' ? 0.95 : 0.85,
        }}
      />

      {/* Horizontal Scanline */}
      {(stage === 'scanning' || stage === 'signal') && (
        <div
          className="scanline-beam"
          style={{
            position: 'absolute',
            left: 0,
            right: 0,
            height: '2px',
            background: 'linear-gradient(90deg, transparent 0%, rgba(99, 102, 241, 0.8) 50%, transparent 100%)',
            boxShadow: '0 0 16px rgba(99, 102, 241, 0.9)',
            animation: 'scanlineSweep 0.7s cubic-bezier(0.4, 0, 0.2, 1) forwards',
          }}
        />
      )}

      {/* Center Technical Signal & Nodes */}
      {(stage === 'initiating' || stage === 'scanning' || stage === 'signal') && (
        <div
          style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '16px',
            zIndex: 10,
          }}
        >
          {/* Pulsing Concentric Ring */}
          <div
            style={{
              position: 'relative',
              width: '80px',
              height: '80px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <div
              style={{
                position: 'absolute',
                inset: 0,
                borderRadius: '50%',
                border: '1px solid rgba(99, 102, 241, 0.5)',
                animation: 'ringPulse 1s ease-out infinite',
              }}
            />
            <div
              style={{
                position: 'absolute',
                inset: '16px',
                borderRadius: '50%',
                border: '1px dashed rgba(255, 255, 255, 0.4)',
                animation: 'rotateDash 2s linear infinite',
              }}
            />
            <i
              className="fa-solid fa-shield-halved"
              style={{
                fontSize: '22px',
                color: '#a5b4fc',
                filter: 'drop-shadow(0 0 8px rgba(99,102,241,0.8))',
              }}
            />
          </div>

          {/* Technical Status Copy */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontFamily: 'monospace',
              fontSize: '12px',
              letterSpacing: '0.14em',
              textTransform: 'uppercase',
              color: '#e0e7ff',
              textShadow: '0 0 10px rgba(99, 102, 241, 0.7)',
            }}
          >
            <span
              style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                backgroundColor: '#34d399',
                boxShadow: '0 0 8px #34d399',
                animation: 'blink 0.5s infinite alternate',
              }}
            />
            {stage === 'signal' ? 'INITIALIZING WORKSPACE ACCESS' : 'ESTABLISHING SECURE CHANNEL'}
          </div>

          {/* Signal traces (SVG) */}
          <svg
            width="260"
            height="40"
            viewBox="0 0 260 40"
            style={{ opacity: stage === 'signal' ? 1 : 0.4, transition: 'opacity 0.3s ease' }}
          >
            <path
              d="M 10 20 L 90 20 L 110 8 L 130 32 L 150 8 L 170 20 L 250 20"
              fill="none"
              stroke="rgba(99, 102, 241, 0.6)"
              strokeWidth="1.5"
              strokeDasharray="12 4"
            />
            <circle cx="10" cy="20" r="3" fill="#a5b4fc" />
            <circle cx="250" cy="20" r="3" fill="#a5b4fc" />
          </svg>
        </div>
      )}

      {/* Dark Gate Panels splitting horizontally */}
      <div
        className="gate-panel gate-left"
        style={{
          position: 'absolute',
          top: 0,
          bottom: 0,
          left: 0,
          width: '50%',
          backgroundColor: '#09090e',
          borderRight: '1px solid rgba(99, 102, 241, 0.4)',
          boxShadow: '8px 0 30px rgba(0, 0, 0, 0.8)',
          zIndex: 20,
          transform: stage === 'gate' || stage === 'done' ? 'translateX(-100%)' : 'translateX(0)',
          transition: 'transform 0.55s cubic-bezier(0.77, 0, 0.175, 1)',
        }}
      />
      <div
        className="gate-panel gate-right"
        style={{
          position: 'absolute',
          top: 0,
          bottom: 0,
          right: 0,
          width: '50%',
          backgroundColor: '#09090e',
          borderLeft: '1px solid rgba(99, 102, 241, 0.4)',
          boxShadow: '-8px 0 30px rgba(0, 0, 0, 0.8)',
          zIndex: 20,
          transform: stage === 'gate' || stage === 'done' ? 'translateX(100%)' : 'translateX(0)',
          transition: 'transform 0.55s cubic-bezier(0.77, 0, 0.175, 1)',
        }}
      />

      {/* In-line CSS Keyframes */}
      <style>{`
        @keyframes scanlineSweep {
          0% { top: 0%; opacity: 0; }
          20% { opacity: 1; }
          80% { opacity: 1; }
          100% { top: 100%; opacity: 0; }
        }
        @keyframes ringPulse {
          0% { transform: scale(0.8); opacity: 0.8; }
          100% { transform: scale(1.6); opacity: 0; }
        }
        @keyframes rotateDash {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes blink {
          from { opacity: 0.3; }
          to { opacity: 1; }
        }
      `}</style>
    </div>
  );
}
