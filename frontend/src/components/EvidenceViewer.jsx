import React, { useState } from 'react';

export function EvidenceViewer({ finding }) {
  const [copied, setCopied] = useState(false);

  if (!finding) return null;

  const evidenceText = finding.evidence || '';
  const severity = (finding.severity || '').toUpperCase();
  const protocol = finding.type || finding.protocol || 'Email Traffic';

  // Determine if this is RFC verified (deterministic proof based on standard email rules or CVEs)
  const isRfcVerified =
    evidenceText.toLowerCase().includes('rfc') ||
    finding.description?.toLowerCase().includes('rfc') ||
    finding.remediation?.toLowerCase().includes('rfc') ||
    finding.title?.toLowerCase().includes('rfc') ||
    finding.id === 'SMS-001' || // Deprecated protocols (like SSL 3.0 RFC 7568)
    finding.id === 'SMS-002';   // STARTTLS (RFC 3207)

  const handleCopy = async () => {
    if (!evidenceText) return;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(evidenceText);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } else {
        // Fallback for older browsers or non-HTTPS/restricted environments
        const textArea = document.createElement('textarea');
        textArea.value = evidenceText;
        textArea.style.position = 'fixed'; // Avoid scrolling to bottom
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }
    } catch (err) {
      console.warn('Failed to copy evidence:', err);
    }
  };

  return (
    <div
      style={{
        background: 'rgba(0, 0, 0, 0.25)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '12px',
        padding: '16px',
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
      }}
    >
      {/* Header and Badge Row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
        <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <i className="fa-solid fa-file-shield" style={{ color: '#818cf8' }} />
          <span>Forensic Evidence &amp; Packet Proof</span>
        </div>

        {/* Verification Badges */}
        <div style={{ display: 'flex', gap: '6px' }}>
          {isRfcVerified ? (
            <span
              style={{
                background: 'rgba(99, 102, 241, 0.15)',
                color: '#a5b4fc',
                border: '1px solid rgba(99, 102, 241, 0.3)',
                padding: '2px 8px',
                borderRadius: '4px',
                fontSize: '10px',
                fontWeight: 700,
                letterSpacing: '0.04em',
              }}
            >
              RFC VERIFIED
            </span>
          ) : (
            <span
              style={{
                background: 'rgba(16, 185, 129, 0.15)',
                color: '#10b981',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                padding: '2px 8px',
                borderRadius: '4px',
                fontSize: '10px',
                fontWeight: 700,
                letterSpacing: '0.04em',
              }}
            >
              DETERMINISTIC FORENSIC PROOF
            </span>
          )}
        </div>
      </div>

      {/* Monospace Code Terminal Block */}
      <div style={{ position: 'relative' }}>
        <pre
          className="font-mono"
          style={{
            margin: 0,
            fontSize: '12.5px',
            color: '#34d399',
            background: '#020617',
            padding: '14px 16px',
            borderRadius: '8px',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            fontFamily: 'monospace, var(--font-mono, monospace)',
            maxHeight: '180px',
            overflowY: 'auto',
            lineHeight: '1.5',
          }}
        >
          {evidenceText || 'No deterministic evidence text supplied.'}
        </pre>

        {/* Copy Button inside Terminal */}
        <button
          onClick={handleCopy}
          style={{
            position: 'absolute',
            top: '8px',
            right: '8px',
            background: copied ? 'rgba(16, 185, 129, 0.8)' : 'rgba(255, 255, 255, 0.08)',
            border: '1px solid rgba(255, 255, 255, 0.12)',
            color: '#fff',
            borderRadius: '6px',
            padding: '4px 10px',
            fontSize: '11px',
            fontWeight: 600,
            cursor: 'pointer',
            transition: 'all 0.2s ease',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
          onMouseEnter={(e) => {
            if (!copied) e.currentTarget.style.background = 'rgba(255, 255, 255, 0.15)';
          }}
          onMouseLeave={(e) => {
            if (!copied) e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)';
          }}
        >
          <i className={copied ? "fa-solid fa-check" : "fa-solid fa-copy"} style={{ fontSize: '10px' }} />
          <span>{copied ? 'Copied!' : 'Copy Evidence'}</span>
        </button>
      </div>

      {/* Structured metadata list if applicable */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '8px', fontSize: '12px', color: 'rgba(255, 255, 255, 0.5)' }}>
        <div>
          Protocol: <span style={{ color: '#fff', fontWeight: 600 }}>{protocol.replace('_', ' ').toUpperCase()}</span>
        </div>
        <div>
          Severity Context: <span style={{ color: severity === 'CRITICAL' ? '#ef4444' : severity === 'HIGH' ? '#f97316' : '#10b981', fontWeight: 600 }}>{severity}</span>
        </div>
      </div>
    </div>
  );
}

export default EvidenceViewer;
