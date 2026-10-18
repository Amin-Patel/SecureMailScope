import React, { memo } from 'react';
import { Handle, Position } from '@xyflow/react';

// Status colors
const STATUS_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#10b981',
  compliant: '#10b981',
  valid: '#10b981',
  unsecured: '#ef4444',
  deprecated: '#f97316',
  weak_cipher: '#ef4444',
  weak_signature: '#f97316',
  insufficient_key: '#f97316',
  expired: '#ef4444',
  self_signed: '#eab308',
  rule_triggered: '#6366f1',
  passed: '#10b981',
  baseline_drift_detected: '#f97316',
  baseline_adherent: '#10b981',
};

function getBorderColor(status, isSelected, isHighlighted) {
  if (isSelected) return '#38bdf8';
  if (isHighlighted) return '#a855f7';
  return STATUS_COLORS[status] || 'rgba(255, 255, 255, 0.15)';
}

function getGlow(status, isSelected, isHighlighted) {
  if (isSelected) return '0 0 22px rgba(56, 189, 248, 0.45)';
  if (isHighlighted) return '0 0 20px rgba(168, 85, 247, 0.4)';
  const color = STATUS_COLORS[status];
  return color ? `0 4px 16px ${color}22` : '0 4px 16px rgba(0, 0, 0, 0.3)';
}

// ── 1. SOURCE ARTIFACT NODE ────────────────────────────────────────────────
export const ArtifactNode = memo(({ data, selected }) => {
  const meta = data.metadata || {};
  const isHighlighted = data.isHighlighted;
  const isDimmed = data.isDimmed;
  const status = data.assessment?.status || 'compliant';
  const borderColor = getBorderColor(status, selected, isHighlighted);

  return (
    <div
      style={{
        padding: '12px 16px',
        borderRadius: '12px',
        background: 'rgba(15, 23, 42, 0.92)',
        backdropFilter: 'blur(16px)',
        border: `1.5px solid ${borderColor}`,
        boxShadow: getGlow(status, selected, isHighlighted),
        minWidth: '220px',
        maxWidth: '280px',
        color: '#ffffff',
        fontFamily: 'var(--font-sans, inherit)',
        transition: 'all 0.25s ease',
        opacity: isDimmed ? 0.25 : 1,
        transform: selected ? 'scale(1.03)' : 'scale(1)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
        <div
          style={{
            width: '28px',
            height: '28px',
            borderRadius: '6px',
            background: 'rgba(56, 189, 248, 0.15)',
            border: '1px solid rgba(56, 189, 248, 0.4)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#38bdf8',
            fontSize: '13px',
          }}
        >
          <i className="fa-solid fa-file-waveform" />
        </div>
        <div style={{ flex: 1, overflow: 'hidden' }}>
          <div style={{ fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#38bdf8', fontWeight: 700 }}>
            Source Artifact
          </div>
          <div style={{ fontSize: '12px', fontWeight: 600, color: '#f8fafc', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={meta.filename}>
            {meta.filename || data.label}
          </div>
        </div>
      </div>

      <div style={{ fontSize: '11px', color: 'rgba(255, 255, 255, 0.65)', lineHeight: 1.4, display: 'flex', flexDirection: 'column', gap: '3px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
          <span>Packets:</span>
          <strong style={{ color: '#ffffff' }}>{meta.total_packets ?? '--'}</strong>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
          <span>Encryption Ratio:</span>
          <strong style={{ color: status === 'compliant' ? '#34d399' : '#f87171' }}>
            {data.assessment?.observed?.encryption_ratio ?? '--'}
          </strong>
        </div>
      </div>

      <Handle type="source" position={Position.Right} style={{ background: '#38bdf8', width: '8px', height: '8px' }} />
    </div>
  );
});

// ── 2. NETWORK SESSION NODE ────────────────────────────────────────────────
export const SessionNode = memo(({ data, selected }) => {
  const meta = data.metadata || {};
  const isHighlighted = data.isHighlighted;
  const isDimmed = data.isDimmed;
  const isEnc = meta.encrypted;
  const status = isEnc ? 'compliant' : 'unsecured';
  const borderColor = getBorderColor(status, selected, isHighlighted);

  return (
    <div
      style={{
        padding: '12px 14px',
        borderRadius: '12px',
        background: 'rgba(15, 23, 42, 0.92)',
        backdropFilter: 'blur(16px)',
        border: `1.5px solid ${borderColor}`,
        boxShadow: getGlow(status, selected, isHighlighted),
        minWidth: '220px',
        maxWidth: '280px',
        color: '#ffffff',
        fontFamily: 'var(--font-sans, inherit)',
        transition: 'all 0.25s ease',
        opacity: isDimmed ? 0.25 : 1,
        transform: selected ? 'scale(1.03)' : 'scale(1)',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: '#64748b', width: '8px', height: '8px' }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
        <div
          style={{
            width: '26px',
            height: '26px',
            borderRadius: '6px',
            background: isEnc ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
            border: `1px solid ${isEnc ? 'rgba(16, 185, 129, 0.4)' : 'rgba(239, 68, 68, 0.4)'}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: isEnc ? '#34d399' : '#f87171',
            fontSize: '12px',
          }}
        >
          <i className={`fa-solid ${isEnc ? 'fa-lock' : 'fa-lock-open'}`} />
        </div>
        <div style={{ flex: 1, overflow: 'hidden' }}>
          <div style={{ fontSize: '9px', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#94a3b8', fontWeight: 700 }}>
            Session • {meta.protocol || 'TCP'}
          </div>
          <div style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {meta.session_id}
          </div>
        </div>
        <span
          style={{
            fontSize: '9px',
            fontWeight: 700,
            padding: '2px 6px',
            borderRadius: '4px',
            background: isEnc ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
            color: isEnc ? '#34d399' : '#f87171',
            border: `1px solid ${isEnc ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
          }}
        >
          {isEnc ? 'TLS' : 'Plaintext'}
        </span>
      </div>

      <div style={{ fontSize: '10px', color: 'rgba(255, 255, 255, 0.65)', lineHeight: 1.3 }}>
        <div style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {meta.src} → {meta.dst}
        </div>
        <div style={{ marginTop: '2px', color: '#94a3b8' }}>
          Packets: <strong style={{ color: '#e2e8f0' }}>{meta.packet_count || 0}</strong>
        </div>
      </div>

      <Handle type="source" position={Position.Right} style={{ background: '#38bdf8', width: '8px', height: '8px' }} />
    </div>
  );
});

// ── 3. TLS HANDSHAKE NODE ──────────────────────────────────────────────────
export const HandshakeNode = memo(({ data, selected }) => {
  const meta = data.metadata || {};
  const isHighlighted = data.isHighlighted;
  const isDimmed = data.isDimmed;
  const tlsVer = meta.tls_version || 'Unknown';
  const isDeprecated = ['SSL 3.0', 'TLS 1.0', 'TLS 1.1'].includes(tlsVer);
  const status = isDeprecated ? 'deprecated' : 'compliant';
  const borderColor = getBorderColor(status, selected, isHighlighted);

  return (
    <div
      style={{
        padding: '12px 14px',
        borderRadius: '12px',
        background: 'rgba(15, 23, 42, 0.92)',
        backdropFilter: 'blur(16px)',
        border: `1.5px solid ${borderColor}`,
        boxShadow: getGlow(status, selected, isHighlighted),
        minWidth: '220px',
        maxWidth: '280px',
        color: '#ffffff',
        fontFamily: 'var(--font-sans, inherit)',
        transition: 'all 0.25s ease',
        opacity: isDimmed ? 0.25 : 1,
        transform: selected ? 'scale(1.03)' : 'scale(1)',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: '#64748b', width: '8px', height: '8px' }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
        <div
          style={{
            width: '26px',
            height: '26px',
            borderRadius: '6px',
            background: isDeprecated ? 'rgba(249, 115, 22, 0.15)' : 'rgba(16, 185, 129, 0.15)',
            border: `1px solid ${isDeprecated ? 'rgba(249, 115, 22, 0.4)' : 'rgba(16, 185, 129, 0.4)'}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: isDeprecated ? '#fb923c' : '#34d399',
            fontSize: '12px',
          }}
        >
          <i className="fa-solid fa-handshake-simple" />
        </div>
        <div style={{ flex: 1, overflow: 'hidden' }}>
          <div style={{ fontSize: '9px', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#94a3b8', fontWeight: 700 }}>
            Handshake Frame #{meta.frame}
          </div>
          <div style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>
            {tlsVer}
          </div>
        </div>
        {isDeprecated && (
          <span
            style={{
              fontSize: '9px',
              fontWeight: 700,
              padding: '2px 5px',
              borderRadius: '4px',
              background: 'rgba(249, 115, 22, 0.2)',
              color: '#fb923c',
              border: '1px solid rgba(249, 115, 22, 0.4)',
            }}
          >
            Deprecated
          </span>
        )}
      </div>

      <div style={{ fontSize: '10px', color: 'rgba(255, 255, 255, 0.65)', lineHeight: 1.3 }}>
        <div>Ciphers offered: <strong style={{ color: '#e2e8f0' }}>{meta.cipher_suites?.length || 0}</strong></div>
        <div style={{ color: '#94a3b8', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          SNI: {meta.sni || 'None'}
        </div>
      </div>

      <Handle type="source" position={Position.Right} style={{ background: '#38bdf8', width: '8px', height: '8px' }} />
    </div>
  );
});

// ── 4. X.509 CERTIFICATE NODE ──────────────────────────────────────────────
export const CertificateNode = memo(({ data, selected }) => {
  const meta = data.metadata || {};
  const isHighlighted = data.isHighlighted;
  const isDimmed = data.isDimmed;
  const isExp = meta.is_expired;
  const isSelf = meta.is_self_signed;
  const status = isExp ? 'expired' : isSelf ? 'self_signed' : meta.key_size < 2048 ? 'insufficient_key' : 'valid';
  const borderColor = getBorderColor(status, selected, isHighlighted);

  return (
    <div
      style={{
        padding: '12px 14px',
        borderRadius: '12px',
        background: 'rgba(15, 23, 42, 0.92)',
        backdropFilter: 'blur(16px)',
        border: `1.5px solid ${borderColor}`,
        boxShadow: getGlow(status, selected, isHighlighted),
        minWidth: '220px',
        maxWidth: '280px',
        color: '#ffffff',
        fontFamily: 'var(--font-sans, inherit)',
        transition: 'all 0.25s ease',
        opacity: isDimmed ? 0.25 : 1,
        transform: selected ? 'scale(1.03)' : 'scale(1)',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: '#64748b', width: '8px', height: '8px' }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
        <div
          style={{
            width: '26px',
            height: '26px',
            borderRadius: '6px',
            background: isExp || isSelf ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
            border: `1px solid ${isExp || isSelf ? 'rgba(239, 68, 68, 0.4)' : 'rgba(16, 185, 129, 0.4)'}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: isExp || isSelf ? '#f87171' : '#34d399',
            fontSize: '12px',
          }}
        >
          <i className="fa-solid fa-certificate" />
        </div>
        <div style={{ flex: 1, overflow: 'hidden' }}>
          <div style={{ fontSize: '9px', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#94a3b8', fontWeight: 700 }}>
            X.509 Certificate
          </div>
          <div style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={meta.subject}>
            {data.label}
          </div>
        </div>
      </div>

      <div style={{ fontSize: '10px', color: 'rgba(255, 255, 255, 0.65)', lineHeight: 1.3 }}>
        <div>Key: <strong style={{ color: meta.key_size < 2048 ? '#f87171' : '#e2e8f0' }}>{meta.key_size ? `${meta.key_size} bits` : 'Unknown'}</strong> ({meta.public_key_algorithm})</div>
        <div style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: '#94a3b8' }}>
          Sig: {meta.signature_algorithm}
        </div>
      </div>

      <Handle type="source" position={Position.Right} style={{ background: '#38bdf8', width: '8px', height: '8px' }} />
    </div>
  );
});

// ── 5. ANALYSIS OPERATION NODE ─────────────────────────────────────────────
export const OperationNode = memo(({ data, selected }) => {
  const meta = data.metadata || {};
  const isHighlighted = data.isHighlighted;
  const isDimmed = data.isDimmed;
  const isTriggered = meta.evaluation_status === 'VIOLATION_CONFIRMED';
  const status = isTriggered ? 'rule_triggered' : 'passed';
  const borderColor = getBorderColor(status, selected, isHighlighted);

  return (
    <div
      style={{
        padding: '12px 14px',
        borderRadius: '12px',
        background: 'rgba(15, 23, 42, 0.92)',
        backdropFilter: 'blur(16px)',
        border: `1.5px solid ${borderColor}`,
        boxShadow: getGlow(status, selected, isHighlighted),
        minWidth: '220px',
        maxWidth: '280px',
        color: '#ffffff',
        fontFamily: 'var(--font-sans, inherit)',
        transition: 'all 0.25s ease',
        opacity: isDimmed ? 0.25 : 1,
        transform: selected ? 'scale(1.03)' : 'scale(1)',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: '#64748b', width: '8px', height: '8px' }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
        <div
          style={{
            width: '26px',
            height: '26px',
            borderRadius: '6px',
            background: isTriggered ? 'rgba(99, 102, 241, 0.15)' : 'rgba(16, 185, 129, 0.15)',
            border: `1px solid ${isTriggered ? 'rgba(99, 102, 241, 0.4)' : 'rgba(16, 185, 129, 0.4)'}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: isTriggered ? '#818cf8' : '#34d399',
            fontSize: '12px',
          }}
        >
          <i className="fa-solid fa-microchip" />
        </div>
        <div style={{ flex: 1, overflow: 'hidden' }}>
          <div style={{ fontSize: '9px', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#818cf8', fontWeight: 700 }}>
            Analysis Rule
          </div>
          <div style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={data.label}>
            {data.label}
          </div>
        </div>
      </div>

      <div style={{ fontSize: '10px', color: 'rgba(255, 255, 255, 0.65)', lineHeight: 1.3 }}>
        <div style={{ color: '#94a3b8' }}>Standard: <strong style={{ color: '#e2e8f0' }}>{meta.standard}</strong></div>
        <div style={{ marginTop: '2px', color: isTriggered ? '#f87171' : '#34d399', fontWeight: 600 }}>
          {isTriggered ? '● Non-Compliance Detected' : '✔ Compliance Verified'}
        </div>
      </div>

      <Handle type="source" position={Position.Right} style={{ background: '#38bdf8', width: '8px', height: '8px' }} />
    </div>
  );
});

// ── 6. BASELINE NODE ───────────────────────────────────────────────────────
export const BaselineNode = memo(({ data, selected }) => {
  const isHighlighted = data.isHighlighted;
  const isDimmed = data.isDimmed;
  const status = data.assessment?.status || 'baseline_adherent';
  const borderColor = getBorderColor(status, selected, isHighlighted);

  return (
    <div
      style={{
        padding: '12px 14px',
        borderRadius: '12px',
        background: 'rgba(15, 23, 42, 0.92)',
        backdropFilter: 'blur(16px)',
        border: `1.5px solid ${borderColor}`,
        boxShadow: getGlow(status, selected, isHighlighted),
        minWidth: '220px',
        maxWidth: '280px',
        color: '#ffffff',
        fontFamily: 'var(--font-sans, inherit)',
        transition: 'all 0.25s ease',
        opacity: isDimmed ? 0.25 : 1,
        transform: selected ? 'scale(1.03)' : 'scale(1)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
        <div
          style={{
            width: '26px',
            height: '26px',
            borderRadius: '6px',
            background: 'rgba(168, 85, 247, 0.15)',
            border: '1px solid rgba(168, 85, 247, 0.4)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#c084fc',
            fontSize: '12px',
          }}
        >
          <i className="fa-solid fa-scale-balanced" />
        </div>
        <div style={{ flex: 1, overflow: 'hidden' }}>
          <div style={{ fontSize: '9px', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#c084fc', fontWeight: 700 }}>
            Policy Baseline
          </div>
          <div style={{ fontSize: '11px', fontWeight: 600, color: '#f8fafc' }}>
            NIST / RFC Baseline
          </div>
        </div>
      </div>

      <div style={{ fontSize: '10px', color: 'rgba(255, 255, 255, 0.65)', lineHeight: 1.3 }}>
        <div>Status: <strong style={{ color: status === 'baseline_drift_detected' ? '#fb923c' : '#34d399' }}>
          {status === 'baseline_drift_detected' ? 'Drift Observed' : 'Adherent'}
        </strong></div>
      </div>

      <Handle type="source" position={Position.Right} style={{ background: '#c084fc', width: '8px', height: '8px' }} />
    </div>
  );
});

// ── 7. SECURITY FINDING NODE ───────────────────────────────────────────────
export const FindingNode = memo(({ data, selected }) => {
  const meta = data.metadata || {};
  const isHighlighted = data.isHighlighted;
  const isDimmed = data.isDimmed;
  const sevLower = (meta.severity || 'medium').toLowerCase();
  const borderColor = getBorderColor(sevLower, selected, isHighlighted);

  return (
    <div
      style={{
        padding: '12px 14px',
        borderRadius: '12px',
        background: 'rgba(15, 23, 42, 0.95)',
        backdropFilter: 'blur(16px)',
        border: `2px solid ${borderColor}`,
        boxShadow: getGlow(sevLower, selected, isHighlighted),
        minWidth: '240px',
        maxWidth: '300px',
        color: '#ffffff',
        fontFamily: 'var(--font-sans, inherit)',
        transition: 'all 0.25s ease',
        opacity: isDimmed ? 0.25 : 1,
        transform: selected ? 'scale(1.04)' : 'scale(1)',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: borderColor, width: '8px', height: '8px' }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
        <div
          style={{
            width: '26px',
            height: '26px',
            borderRadius: '6px',
            background: `rgba(${sevLower === 'critical' ? '239, 68, 68' : sevLower === 'high' ? '249, 115, 22' : '234, 179, 8'}, 0.2)`,
            border: `1px solid ${borderColor}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: borderColor,
            fontSize: '12px',
          }}
        >
          <i className="fa-solid fa-triangle-exclamation" />
        </div>
        <div style={{ flex: 1, overflow: 'hidden' }}>
          <div style={{ fontSize: '9px', textTransform: 'uppercase', letterSpacing: '0.05em', color: borderColor, fontWeight: 700 }}>
            {meta.id} • {meta.severity}
          </div>
          <div style={{ fontSize: '11px', fontWeight: 700, color: '#f8fafc', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={meta.title}>
            {meta.title}
          </div>
        </div>
      </div>

      <div style={{ fontSize: '10px', color: 'rgba(255, 255, 255, 0.75)', lineHeight: 1.3, marginBottom: '6px' }}>
        <div style={{ overflow: 'hidden', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical' }}>
          {meta.description}
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid rgba(255, 255, 255, 0.08)', paddingTop: '6px' }}>
        <span style={{ fontSize: '9px', color: '#94a3b8' }}>
          Confidence: <strong style={{ color: '#e2e8f0' }}>{meta.ai_confidence || 'DETERMINISTIC'}</strong>
        </span>
        <span style={{ fontSize: '9px', color: '#38bdf8', fontWeight: 600 }}>
          Trace Evidence →
        </span>
      </div>
    </div>
  );
});
