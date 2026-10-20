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

const SEVERITY_COLOR = { HIGH: '#f87171', MEDIUM: '#fbbf24', LOW: '#9ca3af' };

function suggestedDomains(certificates, emailAuth) {
  const out = [];
  const add = (d) => { if (d && !out.includes(d)) out.push(d); };
  (emailAuth?.messages || []).forEach(m => { add(m.from_domain); add(m.return_path_domain); });
  (emailAuth?.dns_records || []).forEach(r => add(r.domain));
  add(pickDefaultDomain(certificates));
  return out.slice(0, 6);
}

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

const RESULT_COLOR = { pass: '#34d399', fail: '#f87171', softfail: '#fbbf24', permerror: '#f87171', none: '#9ca3af' };

function Verdict({ label, value }) {
  const color = RESULT_COLOR[value] || '#9ca3af';
  return (
    <span style={{ fontSize: 11, marginRight: 10 }}>
      {label}: <strong style={{ color }}>{value || 'not asserted'}</strong>
    </span>
  );
}

export function EmailAuthEvidence({ emailAuth }) {
  if (!emailAuth || !emailAuth.summary) return null;
  const { summary, messages = [], dns_records: dns = [], limitations = [] } = emailAuth;
  return (
    <div className="glass-card">
      <div className="card-title">
        <i className="fa-solid fa-envelope-open-text" style={{ color: '#a5b4fc' }}></i> Email Authentication (from capture)
      </div>
      <p style={{ fontSize: 12, color: 'var(--muted)', margin: '0 0 10px' }}>
        Passive: read only from this capture's mail headers and DNS traffic. Findings appear in the list above.
      </p>
      <div style={{ fontSize: 12, marginBottom: 8 }}>
        {summary.messages_analyzed} plaintext message{summary.messages_analyzed === 1 ? '' : 's'} inspected,{' '}
        {summary.dns_records_found} DNS auth record{summary.dns_records_found === 1 ? '' : 's'} seen
        {summary.encrypted_mail_streams > 0 && (
          <span style={{ color: '#fbbf24' }}> — {summary.encrypted_mail_streams} encrypted stream(s) could not be inspected</span>
        )}
      </div>
      {messages.map((m, i) => (
        <div key={i} style={{ padding: '8px 0', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
          <div style={{ fontSize: 12, fontWeight: 600 }}>Message {i + 1} — From {m.from_domain || 'unknown'} <span style={{ opacity: 0.5 }}>({m.protocol}, stream {m.stream_id})</span></div>
          <Verdict label="SPF" value={m.spf.result} />
          <Verdict label="DKIM" value={m.dkim.results[0] || (m.dkim.signatures.length ? 'signed (unverified)' : 'unsigned')} />
          <Verdict label="DMARC" value={m.dmarc.result} />
          {m.dkim.signatures.map((sig, j) => (
            <div key={j} style={{ fontSize: 11, opacity: 0.75 }}>
              DKIM d={sig.domain} s={sig.selector} {sig.algorithm}{sig.aligned_with_from ? '' : ' (not aligned with From)'}
            </div>
          ))}
        </div>
      ))}
      {dns.map((r, i) => (
        <div key={`d${i}`} style={{ padding: '8px 0', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
          <div style={{ fontSize: 12, fontWeight: 600 }}>{r.kind.toUpperCase()} record for {r.domain} <span style={{ opacity: 0.5 }}>(frame {r.frame})</span></div>
          <code style={{ display: 'block', fontSize: 11, wordBreak: 'break-all', opacity: 0.75 }}>{r.record.slice(0, 220)}{r.record.length > 220 ? '...' : ''}</code>
        </div>
      ))}
      {summary.messages_analyzed === 0 && dns.length === 0 && (
        <p style={{ fontSize: 12, color: 'var(--muted)' }}>No SPF/DKIM/DMARC evidence found in this capture.</p>
      )}
      <ul style={{ fontSize: 11, color: 'var(--muted)', margin: '10px 0 0', paddingLeft: 16 }}>
        {limitations.map((l, i) => <li key={i}>{l}</li>)}
      </ul>
    </div>
  );
}

export function EmailAuthPanel({ certificates, emailAuth }) {
  const suggestions = suggestedDomains(certificates, emailAuth);
  const [domain, setDomain] = useState(() => suggestions[0] || '');
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
        Active DNS lookup of the domain's current public records, run only when you click Check. Alerts here are separate from the capture's findings and risk score.
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
      {suggestions.length > 0 && (
        <div style={{ marginTop: 8, fontSize: 11, color: 'var(--muted)' }}>
          From this capture:{' '}
          {suggestions.map(d => (
            <button key={d} type="button" onClick={() => setDomain(d)}
                    style={{ marginRight: 6, background: 'none', border: '1px solid rgba(255,255,255,0.2)', borderRadius: 6, color: '#a5b4fc', fontSize: 11, cursor: 'pointer', padding: '1px 8px' }}>
              {d}
            </button>
          ))}
        </div>
      )}
      {error && <p style={{ fontSize: 12, color: '#f87171', marginTop: 10 }}>{error}</p>}
      {result && result.alerts.length > 0 && (
        <div role="alert" style={{ marginTop: 12, padding: 12, borderRadius: 10, border: `1px solid ${SEVERITY_COLOR[result.alert_level]}`, background: 'rgba(248,113,113,0.08)' }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: SEVERITY_COLOR[result.alert_level], marginBottom: 6 }}>
            <i className="fa-solid fa-triangle-exclamation"></i> {result.alerts.length} DNS alert{result.alerts.length === 1 ? '' : 's'} for {result.domain}
          </div>
          {result.alerts.map((a, i) => (
            <div key={i} style={{ fontSize: 12, marginTop: 6 }}>
              <strong style={{ color: SEVERITY_COLOR[a.severity] }}>[{a.severity}] {a.title}</strong>
              <div style={{ opacity: 0.8 }}>{a.detail}</div>
              <div style={{ opacity: 0.6 }}>Fix: {a.remediation}</div>
            </div>
          ))}
        </div>
      )}
      {result && result.alerts.length === 0 && (
        <p style={{ fontSize: 12, color: '#34d399', marginTop: 12 }}>No dangerous DNS records found for {result.domain}.</p>
      )}
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
