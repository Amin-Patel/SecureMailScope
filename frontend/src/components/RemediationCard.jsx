import React, { useState } from 'react';

/**
 * RemediationCard Component
 * Displays remediation guidance for a security finding as an interactive checklist.
 * Parses step text for key-value config lines (e.g. Postfix: smtpd_tls_security_level = may).
 */
export function RemediationCard({ finding }) {
  const [checkedSteps, setCheckedSteps] = useState({});
  const [copied, setCopied] = useState(false);

  if (!finding) return null;

  const severity = (finding.severity || 'UNKNOWN').toUpperCase();
  const title = finding.title || 'Security Finding';
  const findingId = finding.id || '';
  const rawRemediation = finding.remediation || '';

  // Parse raw remediation text into individual structured steps
  const parseRemediationSteps = (text) => {
    if (!text || typeof text !== 'string') return [];
    
    const lines = text
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(Boolean);

    return lines.map((line, idx) => {
      // Check if line starts with a number or bullet (e.g., "1. ", "2) ", "- ")
      const numMatch = line.match(/^(?:(\d+)[\.\)]|[\-\*])\s*(.*)/);
      let stepNum = idx + 1;
      let content = line;

      if (numMatch) {
        if (numMatch[1]) stepNum = parseInt(numMatch[1], 10);
        content = numMatch[2];
      }

      // Detect configuration/code assignment (e.g., "Postfix: smtpd_tls_security_level = may" or "ssl = required")
      const configMatch = content.match(/^([A-Za-z0-9_\-\s]+:)?\s*([a-zA-Z0-9_\.\-]+\s*=\s*.+)$/);

      if (configMatch) {
        const label = configMatch[1] ? configMatch[1].trim() : '';
        const code = configMatch[2].trim();
        return {
          id: `step-${idx}`,
          stepNum,
          isConfig: true,
          label,
          code,
          text: content,
          rawLine: line,
        };
      }

      return {
        id: `step-${idx}`,
        stepNum,
        isConfig: false,
        text: content,
        rawLine: line,
      };
    });
  };

  const steps = parseRemediationSteps(rawRemediation);

  const toggleCheck = (stepId) => {
    setCheckedSteps(prev => ({
      ...prev,
      [stepId]: !prev[stepId],
    }));
  };

  const handleCopy = async () => {
    if (steps.length === 0) return;

    const formattedText = `Remediation Plan — ${findingId ? `[${findingId}] ` : ''}${title} (${severity})\n` +
      steps.map(s => `${s.stepNum}. ${s.rawLine.replace(/^(?:\d+[\.\)]|[\-\*])\s*/, '')}`).join('\n');

    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(formattedText);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = formattedText;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Copy failed:', err);
    }
  };

  // Severity badge styling helper
  const getBadgeStyle = (sev) => {
    switch (sev) {
      case 'CRITICAL':
        return { background: 'rgba(239, 68, 68, 0.2)', color: '#ef4444', border: '1px solid rgba(239, 68, 68, 0.3)' };
      case 'HIGH':
        return { background: 'rgba(249, 115, 22, 0.2)', color: '#f97316', border: '1px solid rgba(249, 115, 22, 0.3)' };
      case 'MEDIUM':
        return { background: 'rgba(234, 179, 8, 0.2)', color: '#eab308', border: '1px solid rgba(234, 179, 8, 0.3)' };
      case 'LOW':
      default:
        return { background: 'rgba(16, 185, 129, 0.2)', color: '#10b981', border: '1px solid rgba(16, 185, 129, 0.3)' };
    }
  };

  return (
    <div
      className="remediation-card"
      style={{
        background: 'rgba(255, 255, 255, 0.03)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '14px',
        padding: '18px',
        display: 'flex',
        flexDirection: 'column',
        gap: '14px',
        transition: 'border-color 0.2s ease',
      }}
    >
      {/* Header with Severity, ID, Title, and Copy Button */}
      <div
        style={{
          display: 'flex',
          justify: 'space-between',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
            <span className="badge" style={{ ...getBadgeStyle(severity), fontSize: '11px', padding: '3px 10px' }}>
              {severity}
            </span>
            {findingId && (
              <span style={{ fontSize: '12px', color: 'var(--muted)', fontWeight: 600 }}>
                {findingId}
              </span>
            )}
          </div>
          <h4 style={{ fontSize: '15px', fontWeight: 700, color: '#ffffff', margin: 0 }}>
            {title}
          </h4>
        </div>

        {steps.length > 0 && (
          <button
            type="button"
            onClick={handleCopy}
            style={{
              background: copied ? 'rgba(16, 185, 129, 0.2)' : 'rgba(255, 255, 255, 0.08)',
              border: `1px solid ${copied ? 'rgba(16, 185, 129, 0.4)' : 'rgba(255, 255, 255, 0.14)'}`,
              color: copied ? '#34d399' : '#e4e4e7',
              borderRadius: '8px',
              padding: '6px 14px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              transition: 'all 0.2s ease',
            }}
            onMouseEnter={e => {
              if (!copied) e.currentTarget.style.background = 'rgba(255, 255, 255, 0.15)';
            }}
            onMouseLeave={e => {
              if (!copied) e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)';
            }}
          >
            <i className={`fa-solid ${copied ? 'fa-check' : 'fa-copy'}`} style={{ fontSize: '12px' }} />
            <span>{copied ? 'Copied!' : 'Copy Remediation'}</span>
          </button>
        )}
      </div>

      {/* Checklist of Steps */}
      {steps.length === 0 ? (
        <p style={{ fontSize: '13px', color: 'var(--muted)', margin: 0, fontStyle: 'italic' }}>
          No specific remediation steps provided for this finding.
        </p>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {steps.map(step => {
            const isChecked = !!checkedSteps[step.id];

            return (
              <div
                key={step.id}
                onClick={() => toggleCheck(step.id)}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '12px',
                  padding: '10px 12px',
                  borderRadius: '10px',
                  background: isChecked ? 'rgba(16, 185, 129, 0.05)' : 'rgba(255, 255, 255, 0.02)',
                  border: `1px solid ${isChecked ? 'rgba(16, 185, 129, 0.2)' : 'rgba(255, 255, 255, 0.05)'}`,
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                {/* Visual Checkbox */}
                <div
                  style={{
                    width: '18px',
                    height: '18px',
                    borderRadius: '4px',
                    border: `1.5px solid ${isChecked ? '#10b981' : 'rgba(255, 255, 255, 0.3)'}`,
                    background: isChecked ? '#10b981' : 'transparent',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginTop: '2px',
                    flexShrink: 0,
                    transition: 'all 0.15s ease',
                  }}
                >
                  {isChecked && (
                    <i className="fa-solid fa-check" style={{ color: '#ffffff', fontSize: '11px' }} />
                  )}
                </div>

                {/* Step Content */}
                <div style={{ flex: 1, fontSize: '13px', lineHeight: '1.5' }}>
                  <div
                    style={{
                      color: isChecked ? 'rgba(255, 255, 255, 0.5)' : '#e4e4e7',
                      textDecoration: isChecked ? 'line-through' : 'none',
                      transition: 'color 0.15s ease',
                    }}
                  >
                    <strong style={{ color: isChecked ? 'rgba(255, 255, 255, 0.5)' : '#a5b4fc', marginRight: '6px' }}>
                      {step.stepNum}.
                    </strong>
                    {step.isConfig && step.label ? (
                      <span>{step.label}</span>
                    ) : !step.isConfig ? (
                      <span>{step.text}</span>
                    ) : null}
                  </div>

                  {/* Render Monospace Code Block for Configuration Lines */}
                  {step.isConfig && (
                    <div
                      onClick={e => e.stopPropagation()}
                      style={{
                        marginTop: '6px',
                        background: 'rgba(0, 0, 0, 0.45)',
                        border: '1px solid rgba(255, 255, 255, 0.1)',
                        borderRadius: '6px',
                        padding: '6px 10px',
                        fontFamily: 'monospace, var(--font-mono, monospace)',
                        fontSize: '12px',
                        color: '#34d399',
                        overflowX: 'auto',
                        whiteSpace: 'pre',
                      }}
                    >
                      {step.code}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default RemediationCard;
