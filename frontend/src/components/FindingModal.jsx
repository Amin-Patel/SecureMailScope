import React, { useEffect } from 'react';
import { Link } from 'react-router-dom';
import { AIExplanation } from './AIExplanation';
import { RemediationCard } from './RemediationCard';

/**
 * FindingModal Component
 * Displays complete details for a selected security finding including large severity badge,
 * full description, raw evidence, AI explanation, remediation checklist, and affected sessions.
 */
export function FindingModal({ finding, onClose, activeJobId }) {
  // Keydown event listener for Escape key and locking body scroll
  useEffect(() => {
    if (!finding) return;

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    document.body.style.overflow = 'hidden';
    window.addEventListener('keydown', handleKeyDown);

    return () => {
      document.body.style.overflow = 'unset';
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [finding, onClose]);

  if (!finding) return null;

  const severity = (finding.severity || 'UNKNOWN').toUpperCase();
  const title = finding.title || 'Security Finding';
  const findingId = finding.id || '';
  const description = finding.description || 'No description provided.';
  const evidence = finding.evidence || '';

  // Extract session IDs safely
  const affectedSessions = Array.isArray(finding.affected_sessions)
    ? finding.affected_sessions
    : Array.isArray(finding.session_ids)
    ? finding.session_ids
    : Array.isArray(finding.sessions)
    ? finding.sessions
    : finding.session_id
    ? [finding.session_id]
    : [];

  const getBadgeStyle = (sev) => {
    switch (sev) {
      case 'CRITICAL':
        return { background: 'rgba(239, 68, 68, 0.25)', color: '#ef4444', border: '1.5px solid rgba(239, 68, 68, 0.4)' };
      case 'HIGH':
        return { background: 'rgba(249, 115, 22, 0.25)', color: '#f97316', border: '1.5px solid rgba(249, 115, 22, 0.4)' };
      case 'MEDIUM':
        return { background: 'rgba(234, 179, 8, 0.25)', color: '#eab308', border: '1.5px solid rgba(234, 179, 8, 0.4)' };
      case 'LOW':
      default:
        return { background: 'rgba(16, 185, 129, 0.25)', color: '#10b981', border: '1.5px solid rgba(16, 185, 129, 0.4)' };
    }
  };

  return (
    <div
      className="finding-modal-backdrop"
      onClick={onClose}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.75)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px',
      }}
    >
      <div
        className="finding-modal-container"
        onClick={(e) => e.stopPropagation()}
        style={{
          background: 'rgba(12, 12, 20, 0.95)',
          border: '1px solid rgba(255, 255, 255, 0.15)',
          borderRadius: '20px',
          width: '100%',
          maxWidth: '760px',
          maxHeight: '85vh',
          display: 'flex',
          flexDirection: 'column',
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.8), 0 0 30px rgba(99, 102, 241, 0.15)',
          overflow: 'hidden',
        }}
      >
        {/* Modal Header */}
        <div
          style={{
            padding: '20px 24px',
            borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
            display: 'flex',
            justify: 'space-between',
            alignItems: 'center',
            background: 'rgba(255, 255, 255, 0.02)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <i className="fa-solid fa-triangle-exclamation" style={{ color: '#818cf8', fontSize: '18px' }} />
            <span style={{ fontSize: '14px', fontWeight: 700, color: '#a5b4fc', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Finding Detail {findingId ? `(#${findingId})` : ''}
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={{
              width: '32px',
              height: '32px',
              borderRadius: '50%',
              background: 'rgba(255, 255, 255, 0.08)',
              border: 'none',
              color: '#ffffff',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'background 0.2s ease',
            }}
            onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(255, 255, 255, 0.18)')}
            onMouseLeave={(e) => (e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)')}
          >
            <i className="fa-solid fa-xmark" style={{ fontSize: '14px' }} />
          </button>
        </div>

        {/* Modal Body (Scrollable) */}
        <div
          style={{
            padding: '24px',
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            gap: '20px',
          }}
        >
          {/* 1. Large Severity Badge & Title */}
          <div>
            <div style={{ marginBottom: '10px' }}>
              <span
                style={{
                  ...getBadgeStyle(severity),
                  padding: '5px 14px',
                  borderRadius: '999px',
                  fontSize: '12px',
                  fontWeight: 800,
                  letterSpacing: '0.06em',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <i className="fa-solid fa-circle-dot" style={{ fontSize: '10px' }} />
                {severity} SEVERITY
              </span>
            </div>
            <h2 style={{ fontSize: 'clamp(18px, 2.5vw, 22px)', fontWeight: 800, color: '#ffffff', margin: '0 0 10px 0', lineHeight: 1.3 }}>
              {title}
            </h2>
            <p style={{ fontSize: '14px', lineHeight: '1.6', color: '#e4e4e7', margin: 0 }}>
              {description}
            </p>
          </div>

          {/* 2. Deterministic Evidence Section */}
          {evidence && (
            <div style={{ background: 'rgba(0, 0, 0, 0.35)', borderRadius: '12px', border: '1px solid rgba(255, 255, 255, 0.08)', padding: '16px' }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <i className="fa-solid fa-terminal" style={{ color: '#818cf8' }} />
                <span>Deterministic Evidence</span>
              </div>
              <div
                style={{
                  fontFamily: 'monospace, var(--font-mono, monospace)',
                  fontSize: '12px',
                  color: '#a1a1aa',
                  background: 'rgba(0, 0, 0, 0.4)',
                  padding: '12px',
                  borderRadius: '8px',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                  border: '1px solid rgba(255, 255, 255, 0.05)',
                }}
              >
                {evidence}
              </div>
            </div>
          )}

          {/* 3. Affected Sessions */}
          {affectedSessions.length > 0 && (
            <div style={{ background: 'rgba(255, 255, 255, 0.02)', borderRadius: '12px', border: '1px solid rgba(255, 255, 255, 0.06)', padding: '16px' }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <i className="fa-solid fa-network-wired" style={{ color: '#818cf8' }} />
                <span>Affected Sessions ({affectedSessions.length})</span>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                {affectedSessions.map((sessId, idx) => {
                  const sessLabel = typeof sessId === 'object' ? sessId.id || `session_${idx + 1}` : String(sessId);
                  const targetUrl = activeJobId ? `/analysis?job=${activeJobId}&tab=sessions` : '/analysis';

                  return (
                    <Link
                      key={idx}
                      to={targetUrl}
                      onClick={onClose}
                      style={{
                        background: 'rgba(99, 102, 241, 0.15)',
                        border: '1px solid rgba(99, 102, 241, 0.3)',
                        color: '#a5b4fc',
                        padding: '4px 12px',
                        borderRadius: '8px',
                        fontSize: '12px',
                        fontWeight: 600,
                        textDecoration: 'none',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        transition: 'all 0.15s ease',
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.background = 'rgba(99, 102, 241, 0.28)';
                        e.currentTarget.style.borderColor = 'rgba(99, 102, 241, 0.5)';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.background = 'rgba(99, 102, 241, 0.15)';
                        e.currentTarget.style.borderColor = 'rgba(99, 102, 241, 0.3)';
                      }}
                    >
                      <i className="fa-solid fa-link" style={{ fontSize: '10px' }} />
                      <span>{sessLabel}</span>
                    </Link>
                  );
                })}
              </div>
            </div>
          )}

          {/* 4. Reused AI Explanation Component */}
          <div>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '4px' }}>
              AI Analysis &amp; Interpretation
            </div>
            <AIExplanation finding={finding} />
          </div>

          {/* 5. Reused Remediation Card Component */}
          <div>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '8px' }}>
              Actionable Remediation Guidance
            </div>
            <RemediationCard finding={finding} />
          </div>
        </div>

        {/* Modal Footer */}
        <div
          style={{
            padding: '16px 24px',
            borderTop: '1px solid rgba(255, 255, 255, 0.08)',
            display: 'flex',
            justify: 'flex-end',
            background: 'rgba(255, 255, 255, 0.02)',
          }}
        >
          <button
            type="button"
            onClick={onClose}
            style={{
              padding: '8px 20px',
              borderRadius: '999px',
              background: 'rgba(255, 255, 255, 0.1)',
              border: '1px solid rgba(255, 255, 255, 0.15)',
              color: '#ffffff',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
            onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(255, 255, 255, 0.2)')}
            onMouseLeave={(e) => (e.currentTarget.style.background = 'rgba(255, 255, 255, 0.1)')}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

export default FindingModal;
