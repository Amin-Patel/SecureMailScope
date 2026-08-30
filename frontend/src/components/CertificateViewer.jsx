import React from 'react';

/**
 * CertificateViewer component renders individual X.509 certificate details,
 * security warnings (weak sig, weak key size, self-signed, expired),
 * and a visual validity timeline.
 */
export function CertificateViewer({ certificate }) {
  if (!certificate) return null;

  const {
    frame = '--',
    timestamp = '--',
    src = '--',
    dst = '--',
    subject = '--',
    issuer = '--',
    serial = '--',
    not_before = '--',
    not_after = '--',
    signature_algorithm = '--',
    public_key_algorithm = '--',
    key_size,
    is_self_signed = false,
    is_expired = false,
  } = certificate;

  // Security Detection Rules
  const sigAlgoStr = String(signature_algorithm || '').toUpperCase();
  const isWeakSignature = sigAlgoStr.includes('MD5') || sigAlgoStr.includes('SHA-1') || sigAlgoStr.includes('SHA1') || sigAlgoStr.includes('MD2') || sigAlgoStr.includes('MD4');

  const pubKeyAlgoStr = String(public_key_algorithm || '').toUpperCase();
  const numericKeySize = typeof key_size === 'number' ? key_size : parseInt(key_size, 10);
  const isRsa = pubKeyAlgoStr.includes('RSA');
  const isWeakKeySize = isRsa && !isNaN(numericKeySize) && numericKeySize > 0 && numericKeySize < 2048;

  return (
    <div
      className="certificate-card"
      style={{
        background: 'rgba(255, 255, 255, 0.03)',
        border: `1px solid ${is_expired || isWeakSignature || isWeakKeySize ? 'rgba(239, 68, 68, 0.3)' : is_self_signed ? 'rgba(234, 179, 8, 0.3)' : 'rgba(255, 255, 255, 0.08)'}`,
        borderRadius: '14px',
        padding: '18px',
        display: 'flex',
        flexDirection: 'column',
        gap: '14px',
        transition: 'all 0.2s ease',
      }}
    >
      {/* Top Bar: Subject & Badges */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '11px', color: '#a5b4fc', background: 'rgba(99, 102, 241, 0.15)', border: '1px solid rgba(99, 102, 241, 0.3)', padding: '2px 8px', borderRadius: '999px', fontWeight: 600 }}>
              X.509 Certificate
            </span>
            {is_expired && (
              <span className="badge badge-critical" style={{ fontSize: '11px', padding: '2px 8px' }}>
                <i className="fa-solid fa-circle-exclamation" style={{ marginRight: '4px' }} />
                Expired
              </span>
            )}
            {is_self_signed && (
              <span className="badge badge-medium" style={{ fontSize: '11px', padding: '2px 8px', background: 'rgba(234, 179, 8, 0.2)', color: '#eab308', border: '1px solid rgba(234, 179, 8, 0.3)' }}>
                <i className="fa-solid fa-triangle-exclamation" style={{ marginRight: '4px' }} />
                Self-Signed
              </span>
            )}
          </div>
          <h4 style={{ fontSize: '15px', fontWeight: 700, color: '#ffffff', margin: 0, wordBreak: 'break-all' }}>
            {subject || 'Unknown Subject'}
          </h4>
        </div>

        <div style={{ fontSize: '11px', color: 'var(--muted)', textAlign: 'right' }}>
          <div>Frame #{frame}</div>
          <div style={{ fontSize: '10px', opacity: 0.7 }}>{timestamp}</div>
        </div>
      </div>

      {/* Network Traffic Endpoint Header */}
      <div style={{ fontSize: '12px', color: 'rgba(255, 255, 255, 0.65)', background: 'rgba(0, 0, 0, 0.25)', padding: '8px 12px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
        <i className="fa-solid fa-network-wired" style={{ color: '#818cf8', fontSize: '12px' }} />
        <span><strong>Flow:</strong> {src} &rarr; {dst}</span>
      </div>

      {/* Main Details Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px', fontSize: '12px' }}>
        {/* Issuer */}
        <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '10px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
          <div style={{ fontSize: '10px', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '4px' }}>
            Issuer
          </div>
          <div style={{ color: '#e4e4e7', fontWeight: 500, wordBreak: 'break-all' }}>
            {issuer || '--'}
          </div>
        </div>

        {/* Serial Number */}
        <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '10px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
          <div style={{ fontSize: '10px', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '4px' }}>
            Serial Number
          </div>
          <div style={{ color: '#a1a1aa', fontFamily: 'monospace', fontSize: '11px', wordBreak: 'break-all' }}>
            {serial || '--'}
          </div>
        </div>

        {/* Signature Algorithm */}
        <div style={{
          background: isWeakSignature ? 'rgba(239, 68, 68, 0.08)' : 'rgba(255, 255, 255, 0.02)',
          padding: '10px 12px',
          borderRadius: '8px',
          border: isWeakSignature ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid rgba(255, 255, 255, 0.05)'
        }}>
          <div style={{ fontSize: '10px', color: isWeakSignature ? '#f87171' : 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <span>Signature Algorithm</span>
            {isWeakSignature && <i className="fa-solid fa-triangle-exclamation" style={{ color: '#ef4444' }} />}
          </div>
          <div style={{ color: isWeakSignature ? '#ef4444' : '#e4e4e7', fontWeight: isWeakSignature ? 700 : 500 }}>
            {signature_algorithm || '--'}
            {isWeakSignature && <span style={{ fontSize: '10px', marginLeft: '6px', background: 'rgba(239, 68, 68, 0.2)', padding: '1px 6px', borderRadius: '4px' }}>WEAK HASH</span>}
          </div>
        </div>

        {/* Public Key & Key Size */}
        <div style={{
          background: isWeakKeySize ? 'rgba(239, 68, 68, 0.08)' : 'rgba(255, 255, 255, 0.02)',
          padding: '10px 12px',
          borderRadius: '8px',
          border: isWeakKeySize ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid rgba(255, 255, 255, 0.05)'
        }}>
          <div style={{ fontSize: '10px', color: isWeakKeySize ? '#f87171' : 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <span>Public Key &amp; Size</span>
            {isWeakKeySize && <i className="fa-solid fa-shield-cat" style={{ color: '#ef4444' }} />}
          </div>
          <div style={{ color: isWeakKeySize ? '#ef4444' : '#e4e4e7', fontWeight: isWeakKeySize ? 700 : 500 }}>
            {public_key_algorithm || 'Key'} {numericKeySize ? `(${numericKeySize} bits)` : ''}
            {isWeakKeySize && <span style={{ fontSize: '10px', marginLeft: '6px', background: 'rgba(239, 68, 68, 0.2)', padding: '1px 6px', borderRadius: '4px' }}>WEAK KEY (&lt; 2048)</span>}
          </div>
        </div>
      </div>

      {/* Visual Validity Timeline */}
      <div style={{ background: 'rgba(0, 0, 0, 0.2)', padding: '12px 14px', borderRadius: '10px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px', color: 'var(--muted)', marginBottom: '8px' }}>
          <span><i className="fa-regular fa-calendar-check" style={{ marginRight: '5px', color: '#10b981' }} />Valid From: <strong>{not_before || '--'}</strong></span>
          <span><i className="fa-regular fa-calendar-xmark" style={{ marginRight: '5px', color: is_expired ? '#ef4444' : '#60a5fa' }} />Valid To: <strong>{not_after || '--'}</strong></span>
        </div>

        {/* Timeline Progress Bar */}
        <div style={{ position: 'relative', height: '6px', background: 'rgba(255, 255, 255, 0.1)', borderRadius: '999px', overflow: 'hidden' }}>
          <div
            style={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background: is_expired
                ? 'linear-gradient(90deg, #f97316 0%, #ef4444 100%)'
                : 'linear-gradient(90deg, #10b981 0%, #06b6d4 100%)',
              borderRadius: '999px',
              opacity: is_expired ? 0.6 : 0.85,
            }}
          />
        </div>
      </div>
    </div>
  );
}

export default CertificateViewer;
