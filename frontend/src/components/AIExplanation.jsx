import React, { useState } from 'react';

/**
 * AIExplanation component renders an expandable AI Analysis panel for a security finding.
 * Consumes:
 * - finding.ai_explanation: string
 * - finding.ai_confidence: "HIGH" | "MEDIUM" | "LOW"
 */
export function AIExplanation({ finding }) {
  const [expanded, setExpanded] = useState(false);

  if (!finding) return null;

  // Extract AI fields safely
  const explanation = finding.ai_explanation;
  const confidence = finding.ai_confidence;

  // Check if valid explanation exists
  const hasExplanation =
    typeof explanation === 'string' && explanation.trim().length > 0;

  // Normalize confidence rating
  const normalizedConfidence =
    confidence && typeof confidence === 'string'
      ? confidence.trim().toUpperCase()
      : null;

  const getConfidenceBadge = (conf) => {
    if (!conf) return null;
    let badgeStyle = {
      background: 'rgba(99, 102, 241, 0.15)',
      color: '#a5b4fc',
      border: '1px solid rgba(99, 102, 241, 0.3)',
    };

    if (conf === 'HIGH') {
      badgeStyle = {
        background: 'rgba(16, 185, 129, 0.15)',
        color: '#34d399',
        border: '1px solid rgba(16, 185, 129, 0.3)',
      };
    } else if (conf === 'MEDIUM') {
      badgeStyle = {
        background: 'rgba(245, 158, 11, 0.15)',
        color: '#fbbf24',
        border: '1px solid rgba(245, 158, 11, 0.3)',
      };
    } else if (conf === 'LOW') {
      badgeStyle = {
        background: 'rgba(239, 68, 68, 0.15)',
        color: '#f87171',
        border: '1px solid rgba(239, 68, 68, 0.3)',
      };
    }

    return (
      <span
        style={{
          ...badgeStyle,
          padding: '3px 10px',
          borderRadius: '999px',
          fontSize: '11px',
          fontWeight: 700,
          letterSpacing: '0.05em',
          display: 'inline-flex',
          alignItems: 'center',
          gap: '5px',
        }}
      >
        <i className="fa-solid fa-gauge-high" style={{ fontSize: '10px' }} />
        {conf} CONFIDENCE
      </span>
    );
  };

  return (
    <div className="ai-explanation-wrapper" style={{ marginTop: '12px' }}>
      <button
        type="button"
        onClick={() => setExpanded(prev => !prev)}
        style={{
          background: 'rgba(139, 92, 246, 0.12)',
          border: '1px solid rgba(139, 92, 246, 0.28)',
          borderRadius: '8px',
          color: '#c084fc',
          fontSize: '12px',
          fontWeight: 600,
          padding: '6px 12px',
          cursor: 'pointer',
          display: 'inline-flex',
          alignItems: 'center',
          gap: '8px',
          transition: 'all 0.2s ease',
        }}
        onMouseEnter={e => {
          e.currentTarget.style.background = 'rgba(139, 92, 246, 0.22)';
          e.currentTarget.style.borderColor = 'rgba(139, 92, 246, 0.45)';
        }}
        onMouseLeave={e => {
          e.currentTarget.style.background = 'rgba(139, 92, 246, 0.12)';
          e.currentTarget.style.borderColor = 'rgba(139, 92, 246, 0.28)';
        }}
      >
        <i className="fa-solid fa-robot" style={{ color: '#a855f7', fontSize: '13px' }} />
        <span>{expanded ? 'Hide AI Analysis' : 'AI Analysis'}</span>
        <i
          className={`fa-solid fa-chevron-${expanded ? 'up' : 'down'}`}
          style={{ fontSize: '10px', opacity: 0.8 }}
        />
      </button>

      {expanded && (
        <div
          className="ai-explanation-panel"
          style={{
            marginTop: '10px',
            padding: '16px',
            borderRadius: '12px',
            background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.08) 0%, rgba(168, 85, 247, 0.08) 100%)',
            border: '1px solid rgba(168, 85, 247, 0.25)',
            boxShadow: '0 4px 20px rgba(139, 92, 246, 0.08)',
          }}
        >
          <div
            style={{
              display: 'flex',
              justify: 'space-between',
              alignItems: 'center',
              marginBottom: '10px',
              flexWrap: 'wrap',
              gap: '8px',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                color: '#c084fc',
                fontWeight: 700,
                fontSize: '13px',
                letterSpacing: '0.02em',
              }}
            >
              <i className="fa-solid fa-wand-magic-sparkles" style={{ color: '#a855f7' }} />
              <span>AI Analysis</span>
            </div>
            {hasExplanation && normalizedConfidence && getConfidenceBadge(normalizedConfidence)}
          </div>

          {hasExplanation ? (
            <div
              style={{
                fontSize: '13px',
                lineHeight: '1.6',
                color: '#e4e4e7',
                margin: '8px 0 14px',
                whiteSpace: 'pre-line',
              }}
            >
              {explanation}
            </div>
          ) : (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '12px 0',
                color: 'rgba(255, 255, 255, 0.65)',
                fontSize: '13px',
              }}
            >
              <i className="fa-solid fa-circle-notch fa-spin" style={{ color: '#a855f7', fontSize: '14px' }} />
              <span>Generating AI analysis...</span>
            </div>
          )}

          <div
            style={{
              borderTop: '1px solid rgba(255, 255, 255, 0.08)',
              paddingTop: '10px',
              marginTop: '10px',
              fontSize: '11px',
              color: 'rgba(255, 255, 255, 0.45)',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <i className="fa-solid fa-circle-info" style={{ fontSize: '11px', color: 'rgba(168, 85, 247, 0.7)' }} />
            <span>AI-generated interpretation. Verify against evidence.</span>
          </div>
        </div>
      )}
    </div>
  );
}

export default AIExplanation;
