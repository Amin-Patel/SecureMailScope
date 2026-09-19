import React, { useState } from 'react';
import { checkEmailAuth } from '../utils/api';

const STATUS_STYLE = {
  pass: { color: '#34d399', label: 'PASS' },
  warn: { color: '#fbbf24', label: 'WEAK' },
  fail: { color: '#f87171', label: 'FAIL' },
  missing: { color: '#f87171', label: 'MISSING' },
  not_found: { color: '#9ca3af', label: 'NOT FOUND' },
  error: { color: '#9ca3af', label: 'LOOKUP ERROR' },
};

function pickDefaultDomain(certificates) {
  for (const cert of certificates || []) {
    const candidates = [...(cert.subject_alternative_names || []), cert.common_name];
    const hit = candidates.find(n => typeof n === 'string' && /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(n));
    if (hit) return hit.toLowerCase();
  }
  return '';
}

function Row({ title, result }) {
  const style = STATUS_STYLE[result.status] || STATUS_STYLE.error;
  return (
    <div style={{ padding: '10px 0', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
        <strong style={{ fontSize: 13 }}>{title}</strong>
        <span style={{ fontSize: 11, fontWeight: 700, color: style.color, border: `1px solid ${style.color}`, borderRadius: 6, padding: '1px 8px' }}>
          {style.label}
        </span>
      </div>
      <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 4 }}>{result.summary}</div>
      {result.record && (
        <code style={{ display: 'block', marginTop: 6, fontSize: 11, wordBreak: 'break-all', opacity: 0.75 }}>{result.record}</code>
      )}
    </div>
  );
}

export function EmailAuthPanel({ certificates }) {
  const [domain, setDomain] = useState(() => pickDefaultDomain(certificates));
  const [selector, setSelector] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const run = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      setResult(await checkEmailAuth(domain, selector));
    } catch (err) {
      setResult(null);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const inputStyle = {
    background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.15)',
    borderRadius: 8, padding: '8px 10px', color: '#fff', fontSize: 13, minWidth: 0,
  };

  return (
    <div className="glass-card" style={{ borderColor: 'rgba(251,191,36,0.35)' }}>
      <div className="card-title">
        <i className="fa-solid fa-envelope-circle-check" style={{ color: '#fbbf24' }}></i> Email Authentication (Active Check)
      </div>
      <p style={{ fontSize: 12, color: '#fbbf24', margin: '0 0 12px' }}>
        Active DNS lookup of the domain's current public records. Not part of the passive PCAP analysis or the risk score above.
      </p>
      <form onSubmit={run} style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <input style={{ ...inputStyle, flex: '2 1 180px' }} placeholder="example.com" value={domain}
               onChange={e => setDomain(e.target.value)} aria-label="Domain to check" />
        <input style={{ ...inputStyle, flex: '1 1 120px' }} placeholder="DKIM selector (optional)" value={selector}
               onChange={e => setSelector(e.target.value)} aria-label="DKIM selector" />
        <button type="submit" className="btn-small" disabled={loading || !domain.trim()}>
          {loading ? 'Checking...' : 'Check'}
        </button>
      </form>
      {error && <p style={{ fontSize: 12, color: '#f87171', marginTop: 10 }}>{error}</p>}
      {result && (
        <div style={{ marginTop: 12 }}>
          <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 4 }}>Results for <strong>{result.domain}</strong></div>
          <Row title="SPF" result={result.spf} />
          <Row title="DKIM" result={result.dkim} />
          <Row title="DMARC" result={result.dmarc} />
        </div>
      )}
    </div>
  );
}

export default EmailAuthPanel;
