import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { getAnalysis, pollAnalysis } from '../utils/api';

// ── Toast notification ────────────────────────────────────────────────────────
function Toast({ toasts, remove }) {
  return (
    <div className="toast-container">
      {toasts.map(t => (
        <div key={t.id} style={{
          background: t.type === 'success' ? 'rgba(16,185,129,0.15)' : 'rgba(99,102,241,0.15)',
          backdropFilter: 'blur(12px)',
          border: `1px solid ${t.type === 'success' ? 'rgba(16,185,129,0.4)' : 'rgba(99,102,241,0.4)'}`,
          borderRadius: 12, padding: '12px 20px',
          display: 'flex', alignItems: 'center', gap: 10,
          color: t.type === 'success' ? '#34d399' : '#a5b4fc',
          fontSize: 13, fontWeight: 600,
          boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
          animation: 'slideInToast 0.3s ease',
          pointerEvents: 'auto',
        }}>
          <i className={`fa-solid ${t.type === 'success' ? 'fa-circle-check' : 'fa-circle-info'}`}></i>
          {t.message}
        </div>
      ))}
    </div>
  );
}

// ── Skeleton shimmer row ──────────────────────────────────────────────────────
function SkeletonRows({ count = 4, cols = 5 }) {
  return Array.from({ length: count }).map((_, i) => (
    <tr key={i}>
      {Array.from({ length: cols }).map((_, j) => (
        <td key={j} style={{ padding: '14px 16px' }}>
          <div className="skeleton" style={{ height: 14, width: j === 2 ? '80%' : '60%' }} />
        </td>
      ))}
    </tr>
  ));
}

function getSessionTlsInfo(tlsVer) {
  if (tlsVer === 'Plaintext') {
    return {
      tls: 'TLS Protocol Version: Plaintext\nCipher Suite: None\nHandshake Success: N/A',
      cert: 'No certificate found in Plaintext stream.',
    };
  } else if (tlsVer === 'TLS 1.0') {
    return {
      tls: 'TLS Protocol Version: TLS 1.0 (Deprecated)\nCipher Suite: TLS_RSA_WITH_3DES_EDE_CBC_SHA\nHandshake: Completed (Weak)',
      cert: 'Subject: CN=mail.securemailscope.com\nIssuer: CN=SecureMailScope Local CA\nValidity: Aug 2024 - Aug 2027\nKey Size: RSA 2048-bit',
    };
  } else {
    return {
      tls: 'TLS Protocol Version: TLS 1.2\nCipher Suite: ECDHE-RSA-AES128-GCM-SHA256\nHandshake: Completed (Secure)',
      cert: 'Subject: CN=smtp.gmail.com\nIssuer: CN=Google Trust Services\nValidity: Jul 2026 - Oct 2026\nKey Size: EC 256-bit',
    };
  }
}

export function Analysis() {
  const [searchParams] = useSearchParams();
  const jobId = searchParams.get('job');
  const tabParam = searchParams.get('tab');

  const [activeTab, setActiveTab] = useState(tabParam || 'overview');
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [selectedSession, setSelectedSession] = useState(null);
  const [sessionSubTab, setSessionSubTab] = useState('info');
  const [analysisData, setAnalysisData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [toasts, setToasts] = useState([]);

  const [findingsSearch, setFindingsSearch] = useState('');
  const [findingsSeverity, setFindingsSeverity] = useState('all');
  const [sessionsSearch, setSessionsSearch] = useState('');
  const [sessionsStatus, setSessionsStatus] = useState('all');

  // ── Toast helper ────────────────────────────────────────────────────────────
  const addToast = useCallback((message, type = 'success') => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 3000);
  }, []);

  useEffect(() => {
    if (tabParam) setActiveTab(tabParam);
  }, [tabParam]);

  useEffect(() => {
    if (!jobId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    getAnalysis(jobId)
      .then(data => { setAnalysisData(data); setLoading(false); })
      .catch(err => { console.error(err); setError('Failed to load analysis data'); setLoading(false); });
  }, [jobId]);

  const findings = analysisData?.findings || [];
  const filteredFindings = findings.filter(f => {
    const matchSev = findingsSeverity === 'all' || f.severity === findingsSeverity;
    const q = findingsSearch.toLowerCase();
    const matchQ = !q || f.title.toLowerCase().includes(q) || f.endpoint.toLowerCase().includes(q) || f.category.toLowerCase().includes(q);
    return matchSev && matchQ;
  });

  const sessions = analysisData?.sessions || [];
  const filteredSessions = sessions.filter(s => {
    const matchStatus = sessionsStatus === 'all'
      || (sessionsStatus === 'weak' && s.statusLabel === 'Weak')
      || (sessionsStatus === 'secure' && s.statusLabel === 'Secure');
    const q = sessionsSearch.toLowerCase();
    const matchQ = !q || s.src.includes(q) || s.dst.includes(q) || s.protocol.toLowerCase().includes(q);
    return matchStatus && matchQ;
  });

  const openFinding  = f => { setSelectedFinding(f); setSelectedSession(null); };
  const openSession  = s => { setSelectedSession(s); setSelectedFinding(null); setSessionSubTab('info'); };
  const closeDrawer  = () => { setSelectedFinding(null); setSelectedSession(null); };

  // ── Export helpers ──────────────────────────────────────────────────────────
  const exportJson = () => {
    const blob = new Blob([JSON.stringify(analysisData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `analysis-${jobId}.json`; a.click();
    URL.revokeObjectURL(url);
    addToast('JSON report downloaded!', 'success');
  };

  const exportHtml = () => {
    addToast('HTML report generation coming soon…', 'info');
  };

  const drawerOpen = !!(selectedFinding || selectedSession);

  // No job selected — show the upload / start prompt
  if (!jobId && !loading) return (
    <main className="workspace-container" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '60vh', gap: '24px', textAlign: 'center' }}>
      <div style={{
        width: 72, height: 72, borderRadius: '50%',
        background: 'rgba(99,102,241,0.15)',
        border: '1px solid rgba(99,102,241,0.4)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: 28, color: '#a5b4fc',
        boxShadow: '0 0 24px rgba(99,102,241,0.25)',
      }}>
        <i className="fa-solid fa-magnifying-glass" />
      </div>
      <div>
        <h2 style={{ fontSize: 'clamp(18px,2.5vw,26px)', fontWeight: 700, color: '#ffffff', marginBottom: 8 }}>
          Analysis Workspace
        </h2>
        <p style={{ fontSize: 14, color: 'rgba(255,255,255,0.55)', maxWidth: 400, lineHeight: 1.6 }}>
          No analysis selected. Upload a PCAP file to start a new forensic investigation or select a previous analysis from History.
        </p>
      </div>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', justifyContent: 'center' }}>
        <a
          href="/workspace"
          style={{
            padding: '11px 26px', borderRadius: '999px',
            background: '#ffffff', color: '#000000',
            fontWeight: 700, fontSize: 14, textDecoration: 'none',
            display: 'inline-flex', alignItems: 'center', gap: 8,
            boxShadow: '0 0 18px rgba(255,255,255,0.2)',
          }}
        >
          <i className="fa-solid fa-upload" style={{ fontSize: 12 }} />
          Upload PCAP File
        </a>
        <a
          href="/history"
          style={{
            padding: '10px 24px', borderRadius: '999px',
            background: 'rgba(255,255,255,0.07)',
            border: '1.5px solid rgba(255,255,255,0.2)',
            color: '#ffffff', fontWeight: 600, fontSize: 14, textDecoration: 'none',
            display: 'inline-flex', alignItems: 'center', gap: 8,
          }}
        >
          <i className="fa-solid fa-clock-rotate-left" style={{ fontSize: 12 }} />
          View History
        </a>
      </div>
      {/* Quick demo shortcut for testing */}
      <p style={{ fontSize: 12, color: 'rgba(255,255,255,0.3)' }}>
        Or{' '}
        <a href="/analysis?job=8320" style={{ color: '#a5b4fc', textDecoration: 'underline' }}>
          load a sample analysis
        </a>
        {' '}to explore the workspace.
      </p>
    </main>
  );

  if (loading) return (
    <main className="workspace-container">
      <div className="workspace-title-bar">
        <div>
          <div className="skeleton" style={{ height: 22, width: 160, marginBottom: 8 }} />
          <div className="skeleton" style={{ height: 12, width: 260 }} />
        </div>
        <div className="skeleton" style={{ width: 52, height: 52, borderRadius: '50%' }} />
      </div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
        {['Overview','Findings','Sessions','Remediation','Report'].map(t => (
          <div key={t} className="skeleton" style={{ height: 36, width: 90, borderRadius: 8 }} />
        ))}
      </div>
      <div className="glass-card">
        {[1,2,3].map(i => <div key={i} className="skeleton" style={{ height: 14, marginBottom: 12, width: i === 2 ? '55%' : '85%' }} />)}
      </div>
    </main>
  );

  if (error) return (
    <div className="workspace-container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 300 }}>
      <div style={{ textAlign: 'center', color: '#ef4444' }}>
        <i className="fa-solid fa-triangle-exclamation" style={{ fontSize: 32, marginBottom: 12, display: 'block' }}></i>
        <p style={{ fontSize: 14 }}>{error}</p>
      </div>
    </div>
  );

  const { summary = {} } = analysisData || {};
  const score = summary.riskScore || 0;
  const riskColor = score >= 75 ? '#ef4444' : score >= 40 ? '#f59e0b' : '#10b981';

  return (
    <main className="workspace-container">
      <Toast toasts={toasts} remove={id => setToasts(prev => prev.filter(t => t.id !== id))} />

      {/* Drawer backdrop */}
      <div className={`drawer-backdrop ${drawerOpen ? 'open' : ''}`} onClick={closeDrawer} />

      {/* Title Bar */}
      <div className="workspace-title-bar">
        <div>
          <h2 style={{ fontSize: 'clamp(16px, 2.2vw, 22px)', fontWeight: 700, color: '#ffffff' }}>
            {summary.jobId ? `Job ${summary.jobId}` : 'Analysis Workspace'}
          </h2>
          <div className="analysis-meta-info">
            Analysis Workspace &bull; Job ID {jobId || '--'} &bull; Risk Score {score || '--'}
          </div>
        </div>
        {/* Dynamic score circle */}
        <div className="score-badge">
          <div className="score-circle-sm" style={{
            background: `rgba(${riskColor === '#ef4444' ? '239,68,68' : riskColor === '#f59e0b' ? '245,158,11' : '16,185,129'},0.12)`,
            borderColor: riskColor,
            boxShadow: `0 0 14px ${riskColor}55`,
            color: '#fff',
          }}>
            {score || '--'}
          </div>
          <span style={{ fontSize: '11px', color: 'var(--muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
            Risk Score
          </span>
        </div>
      </div>

      {/* Tab Bar */}
      <nav className="tabs-bar">
        {['overview', 'findings', 'sessions', 'remediation', 'report'].map(tab => (
          <button
            key={tab}
            className={`tab-btn ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setActiveTab(tab)}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </nav>

      {/* ── Overview ── */}
      {activeTab === 'overview' && (
        <section className="tab-content active">
          <div className="glass-card">
            <h3 className="drawer-section-title" style={{ marginBottom: 12 }}>Executive Summary</h3>
            <p style={{ fontSize: 14, lineHeight: 1.6, color: '#e4e4e7', marginBottom: 16 }}>
              {summary.description || 'No description available.'}
            </p>
            <div className="metrics-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
              <div className="metric-box"><div className="metric-value">{summary.emailPackets || '--'}</div><div className="metric-label">Email Packets</div></div>
              <div className="metric-box"><div className="metric-value">{summary.findingsCount || '--'}</div><div className="metric-label">Findings</div></div>
              <div className="metric-box"><div className="metric-value">{summary.sessions || '--'}</div><div className="metric-label">Sessions</div></div>
            </div>
          </div>
          <div className="glass-card">
            <h3 className="drawer-section-title" style={{ marginBottom: 12 }}>Security Findings Distribution</h3>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <span className="badge badge-critical" style={{ padding: '6px 12px' }}>2 Critical</span>
              <span className="badge badge-high"     style={{ padding: '6px 12px' }}>1 High</span>
              <span className="badge badge-medium"   style={{ padding: '6px 12px' }}>1 Medium</span>
            </div>
          </div>
        </section>
      )}

      {/* ── Findings ── */}
      {activeTab === 'findings' && (
        <section className="tab-content active">
          <div className="filters-row">
            <input type="text" className="search-input" placeholder="Search findings by title, IP, host…"
              value={findingsSearch} onChange={e => setFindingsSearch(e.target.value)} />
            <select className="filter-select" value={findingsSeverity} onChange={e => setFindingsSeverity(e.target.value)}>
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
            </select>
          </div>
          <div className="data-table-wrapper">
            <table className="data-table">
              <thead><tr><th>ID</th><th>Severity</th><th>Finding Title</th><th>Category</th><th>Affected Endpoint</th></tr></thead>
              <tbody>
                {filteredFindings.length === 0
                  ? <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--muted)', padding: 24 }}>No findings match your filter</td></tr>
                  : filteredFindings.map(f => (
                    <tr key={f.id} onClick={() => openFinding(f)}>
                      <td>{f.id}</td>
                      <td><span className={`badge badge-${f.severity}`}>{f.severityLabel}</span></td>
                      <td style={{ fontWeight: 500, color: '#ffffff' }}>{f.title}</td>
                      <td>{f.category}</td>
                      <td>{f.endpoint}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* ── Sessions ── */}
      {activeTab === 'sessions' && (
        <section className="tab-content active">
          <div className="filters-row">
            <input type="text" className="search-input" placeholder="Search sessions by IP, host…"
              value={sessionsSearch} onChange={e => setSessionsSearch(e.target.value)} />
            <select className="filter-select" value={sessionsStatus} onChange={e => setSessionsStatus(e.target.value)}>
              <option value="all">All Sessions</option>
              <option value="weak">Weak / Vulnerable</option>
              <option value="secure">Secure</option>
            </select>
          </div>
          <div className="data-table-wrapper">
            <table className="data-table">
              <thead><tr><th>Session ID</th><th>Source</th><th>Destination</th><th>Protocol</th><th>TLS Version</th><th>Security Status</th></tr></thead>
              <tbody>
                {filteredSessions.map(s => (
                  <tr key={s.id} onClick={() => openSession(s)}>
                    <td>{s.id}</td>
                    <td>{s.src}</td>
                    <td>{s.dst}</td>
                    <td>{s.protocol}</td>
                    <td>{s.tlsVer}</td>
                    <td>
                      {s.statusLabel === 'Secure'
                        ? <span className="badge badge-low" style={{ background: 'rgba(16,185,129,0.2)', color: '#10b981', border: '1px solid rgba(16,185,129,0.3)' }}>Secure</span>
                        : <span className={`badge ${s.statusClass}`}>{s.statusLabel}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* ── Remediation ── */}
      {activeTab === 'remediation' && (
        <section className="tab-content active">
          <div className="glass-card">
            <h3 className="drawer-section-title" style={{ marginBottom: 12 }}>Prioritized Recommendations</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {[
                { color: '#ef4444', title: '1. Enforce STARTTLS before AUTH exchanges (SMTP)', meta: 'F-01 · Critical', body: "Configure SMTP clients and server postfix or exim rules to forbid authentication over unencrypted SMTP connections. Update server config to require STARTTLS (smtpd_tls_auth_only = yes)." },
                { color: '#ef4444', title: '2. Replace Expired TLS Certificates',              meta: 'F-02 · Critical', body: 'Renew certificates bound to SMTP port 465 / 587. Enforce verification in client settings to reject expired certificates.' },
                { color: '#f97316', title: '3. Disable Legacy TLS Versions (TLS 1.0 & 1.1)', meta: 'F-03 · High',     body: 'Enforce TLSv1.2 or TLSv1.3. For Dovecot/IMAP, set ssl_min_protocol = TLSv1.2 in configuration settings.' },
              ].map(({ color, title, meta, body }) => (
                <div key={title} style={{ borderLeft: `4px solid ${color}`, paddingLeft: 16, paddingTop: 4, paddingBottom: 4 }}>
                  <h4 style={{ fontSize: 14, fontWeight: 600, color: '#ffffff', marginBottom: 4 }}>{title}</h4>
                  <p style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 6 }}>{meta}</p>
                  <p style={{ fontSize: 13, color: '#e4e4e7' }}>{body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {/* ── Report ── */}
      {activeTab === 'report' && (
        <section className="tab-content active">
          <div className="glass-card">
            <h3 className="drawer-section-title" style={{ marginBottom: 12 }}>Security &amp; Forensics Report</h3>
            <p style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 20 }}>Generate a complete assessment report from the findings, sessions and cryptographical forensics.</p>
            <div className="report-preview-box" style={{ marginBottom: 20 }}>
              <h1 style={{ fontSize: 18, fontWeight: 600, color: '#ffffff', marginBottom: 8, borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: 8 }}>SecureMailScope Security Assessment</h1>
              <p><strong>Target PCAP:</strong> Mail-Server-Audit.pcap</p>
              <p><strong>Overall Posture score:</strong> {score} / 100 ({score >= 75 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW'} RISK)</p>
              <br />
              <h2 style={{ fontSize: 14, fontWeight: 600, color: '#ffffff', marginBottom: 6 }}>Executive Summary</h2>
              <p>During the automated deep packet analysis, we detected severe cryptographic negotiation flaws. The most critical item is the plain-text negotiation of SMTP AUTH credentials over TCP port 25 without prior STARTTLS command negotiation.</p>
              <br />
              <h2 style={{ fontSize: 14, fontWeight: 600, color: '#ffffff', marginBottom: 6 }}>Vulnerability Summary</h2>
              <ul>
                <li>Critical: 2 (Plaintext AUTH, Expired TLS Certificate)</li>
                <li>High: 1 (TLS 1.0 negotiate)</li>
                <li>Medium: 1 (RC4 ciphers enabled)</li>
              </ul>
            </div>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <button className="btn-action" onClick={exportJson}>
                <i className="fa-solid fa-code"></i> Export JSON
              </button>
              <button className="btn-action btn-secondary" onClick={exportHtml}>
                <i className="fa-solid fa-download"></i> Download HTML
              </button>
            </div>
          </div>
        </section>
      )}

      {/* ── Finding Drawer ── */}
      <div className={`drawer ${selectedFinding ? 'open' : ''}`}>
        <div className="drawer-header">
          <span className="drawer-title">
            {selectedFinding ? `${selectedFinding.id} — ${selectedFinding.title}` : 'Finding Detail'}
          </span>
          <button className="drawer-close" onClick={closeDrawer} style={{ width: 32, height: 32, borderRadius: '50%', background: 'rgba(255,255,255,0.07)', display: 'flex', alignItems: 'center', justifyContent: 'center', transition: 'background 0.2s' }}
            onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.14)'}
            onMouseLeave={e => e.currentTarget.style.background = 'rgba(255,255,255,0.07)'}>
            <i className="fa-solid fa-xmark"></i>
          </button>
        </div>
        {selectedFinding && (
          <div className="drawer-body">
            <div><span className={`badge badge-${selectedFinding.severity}`}>{selectedFinding.severityLabel}</span></div>
            <div>
              <h3 style={{ fontSize: 16, fontWeight: 600, color: '#ffffff', marginBottom: 6 }}>{selectedFinding.title}</h3>
              <p style={{ fontSize: 12, color: 'var(--muted)' }}>Category: {selectedFinding.category} | Affected: {selectedFinding.endpoint}</p>
            </div>
            <div><div className="drawer-section-title">What Happened</div><p style={{ fontSize: 13, color: '#e4e4e7', lineHeight: 1.5 }}>{selectedFinding.desc}</p></div>
            <div><div className="drawer-section-title">Evidence (Packet Reconstruct)</div><div className="code-block">{selectedFinding.evidence}</div></div>
            <div><div className="drawer-section-title">Recommendation</div><p style={{ fontSize: 13, color: '#e4e4e7', lineHeight: 1.5 }}>{selectedFinding.reco}</p></div>
          </div>
        )}
      </div>

      {/* ── Session Drawer ── */}
      <div className={`drawer ${selectedSession ? 'open' : ''}`}>
        <div className="drawer-header">
          <span className="drawer-title">{selectedSession ? `${selectedSession.id} Details` : 'Session Detail'}</span>
          <button className="drawer-close" onClick={closeDrawer} style={{ width: 32, height: 32, borderRadius: '50%', background: 'rgba(255,255,255,0.07)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <i className="fa-solid fa-xmark"></i>
          </button>
        </div>
        {selectedSession && (() => {
          const tlsData = getSessionTlsInfo(selectedSession.tlsVer);
          return (
            <div className="drawer-body">
              <div>
                <h3 style={{ fontSize: 14, fontWeight: 600, color: '#ffffff', marginBottom: 4 }}>{selectedSession.src} → {selectedSession.dst}</h3>
                <p style={{ fontSize: 12, color: 'var(--muted)' }}>Protocol: {selectedSession.protocol} | TLS Version: {selectedSession.tlsVer}</p>
              </div>
              <div className="sub-tabs">
                {['info', 'tls', 'cert'].map(t => (
                  <button key={t} className={`sub-tab-btn ${sessionSubTab === t ? 'active' : ''}`} onClick={() => setSessionSubTab(t)}>
                    {t.charAt(0).toUpperCase() + t.slice(1)}
                  </button>
                ))}
              </div>
              {sessionSubTab === 'info' && <div className="sub-tab-content active"><div className="drawer-section-title">Session Assessment</div><p style={{ fontSize: 13, color: '#e4e4e7', lineHeight: 1.5 }}>{selectedSession.assess}</p></div>}
              {sessionSubTab === 'tls'  && <div className="sub-tab-content active"><div className="drawer-section-title">TLS Handshake</div><div className="code-block">{tlsData.tls}</div></div>}
              {sessionSubTab === 'cert' && <div className="sub-tab-content active"><div className="drawer-section-title">Certificate Information</div><div className="code-block">{tlsData.cert}</div></div>}
            </div>
          );
        })()}
      </div>
    </main>
  );
}
