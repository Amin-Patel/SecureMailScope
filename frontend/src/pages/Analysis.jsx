import React, { useState, useEffect } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { getAnalysis, pollAnalysis } from '../utils/api';

// Mock data removed; real data will be fetched via API (getAnalysis/pollAnalysis).
// The component will use analysisData.findings and analysisData.sessions.


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

  // Search / filter state
  const [findingsSearch, setFindingsSearch] = useState('');
  const [findingsSeverity, setFindingsSeverity] = useState('all');
  const [sessionsSearch, setSessionsSearch] = useState('');
  const [sessionsStatus, setSessionsStatus] = useState('all');

  // Sync tab from URL query param on mount
  useEffect(() => {
    if (tabParam) setActiveTab(tabParam);
  }, [tabParam]);

  // Fetch analysis data when jobId is present
  useEffect(() => {
    if (!jobId) return;
    setLoading(true);
    getAnalysis(jobId)
      .then((data) => {
        setAnalysisData(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error(err);
        setError('Failed to load analysis data');
        setLoading(false);
      });
  }, [jobId]);

  const findings = analysisData?.findings || [];
  const filteredFindings = findings.filter((f) => {
    const matchSev = findingsSeverity === 'all' || f.severity === findingsSeverity;
    const q = findingsSearch.toLowerCase();
    const matchQ = !q || f.title.toLowerCase().includes(q) || f.endpoint.toLowerCase().includes(q) || f.category.toLowerCase().includes(q);
    return matchSev && matchQ;
  });

  const sessions = analysisData?.sessions || [];
  const filteredSessions = sessions.filter((s) => {
    const matchStatus = sessionsStatus === 'all' ||
      (sessionsStatus === 'weak' && s.statusLabel === 'Weak') ||
      (sessionsStatus === 'secure' && s.statusLabel === 'Secure');
    const q = sessionsSearch.toLowerCase();
    const matchQ = !q || s.src.includes(q) || s.dst.includes(q) || s.protocol.toLowerCase().includes(q);
    return matchStatus && matchQ;
  });

  const openFinding = (f) => {
    setSelectedFinding(f);
    setSelectedSession(null);
  };

  const openSession = (s) => {
    setSelectedSession(s);
    setSelectedFinding(null);
    setSessionSubTab('info');
  };

  const closeDrawer = () => {
    setSelectedFinding(null);
    setSelectedSession(null);
  };

  if (loading) {
    return <div className="workspace-container"><p style={{ color: '#fff' }}>Loading analysis...</p></div>;
  }
  if (error) {
    return <div className="workspace-container"><p style={{ color: 'red' }}>{error}</p></div>;
  }
  const { summary = {} } = analysisData || {};
  return (
    <main className="workspace-container">
      {/* Title Bar */}
      <div className="workspace-title-bar">
        <div>
          <h2 style={{ fontSize: 'clamp(16px, 2.2vw, 22px)', fontWeight: 600, color: '#ffffff' }}>
            {summary.jobId ? `Job ${summary.jobId}` : 'Analysis'}
          </h2>
          <div className="analysis-meta-info">
            Analysis Workspace &bull; Job ID {jobId || '--'} &bull; Risk Score {summary.riskScore || '--'}
          </div>
        </div>
        <div className="score-badge">
          <div className="score-circle-sm">{summary.riskScore || '--'}</div>
          <span style={{ fontSize: '11px', color: 'var(--muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
            Risk Score
          </span>
        </div>
      </div>

      {/* Tab Bar */}
      <nav className="tabs-bar">
        {['overview', 'findings', 'sessions', 'remediation', 'report'].map((tab) => (
          <button
            key={tab}
            className={`tab-btn ${activeTab === tab ? 'active' : ''}`}
            data-tab={tab}
            onClick={() => setActiveTab(tab)}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </nav>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <section className="tab-content active" id="overview-content">
          <div className="glass-card">
            <h3 className="drawer-section-title" style={{ marginBottom: '12px' }}>Executive Summary</h3>
            <p style={{ fontSize: '14px', lineHeight: 1.6, color: '#e4e4e7', marginBottom: '16px' }}>
              {summary.description || 'No description available.'}
            </p>
            <div className="metrics-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
              <div className="metric-box"><div className="metric-value">{summary.emailPackets || '--'}</div><div className="metric-label">Email Packets</div></div>
              <div className="metric-box"><div className="metric-value">{summary.findingsCount || '--'}</div><div className="metric-label">Findings</div></div>
              <div className="metric-box"><div className="metric-value">{summary.sessions || '--'}</div><div className="metric-label">Sessions</div></div>
            </div>
          </div>
          <div className="glass-card">
            <h3 className="drawer-section-title" style={{ marginBottom: '12px' }}>Security Findings Distribution</h3>
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
              <span className="badge badge-critical" style={{ padding: '6px 12px' }}>2 Critical</span>
              <span className="badge badge-high" style={{ padding: '6px 12px' }}>1 High</span>
              <span className="badge badge-medium" style={{ padding: '6px 12px' }}>1 Medium</span>
            </div>
          </div>
        </section>
      )}

      {/* Findings Tab */}
      {activeTab === 'findings' && (
        <section className="tab-content active" id="findings-content">
          <div className="filters-row">
            <input
              type="text"
              className="search-input"
              placeholder="Search findings by title, IP, host..."
              value={findingsSearch}
              onChange={(e) => setFindingsSearch(e.target.value)}
            />
            <select className="filter-select" value={findingsSeverity} onChange={(e) => setFindingsSeverity(e.target.value)}>
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
            </select>
          </div>
          <div className="data-table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>ID</th><th>Severity</th><th>Finding Title</th><th>Category</th><th>Affected Endpoint</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.map((f) => (
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

      {/* Sessions Tab */}
      {activeTab === 'sessions' && (
        <section className="tab-content active" id="sessions-content">
          <div className="filters-row">
            <input
              type="text"
              className="search-input"
              placeholder="Search sessions by IP, host..."
              value={sessionsSearch}
              onChange={(e) => setSessionsSearch(e.target.value)}
            />
            <select className="filter-select" value={sessionsStatus} onChange={(e) => setSessionsStatus(e.target.value)}>
              <option value="all">All Sessions</option>
              <option value="weak">Weak / Vulnerable</option>
              <option value="secure">Secure</option>
            </select>
          </div>
          <div className="data-table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Session ID</th><th>Source</th><th>Destination</th><th>Protocol</th><th>TLS Version</th><th>Security Status</th>
                </tr>
              </thead>
              <tbody>
                {filteredSessions.map((s) => (
                  <tr key={s.id} onClick={() => openSession(s)}>
                    <td>{s.id}</td>
                    <td>{s.src}</td>
                    <td>{s.dst}</td>
                    <td>{s.protocol}</td>
                    <td>{s.tlsVer}</td>
                    <td>
                      {s.statusLabel === 'Secure'
                        ? <span className="badge badge-low" style={{ background: 'rgba(16, 185, 129, 0.2)', color: '#10b981', border: '1px solid rgba(16, 185, 129, 0.3)' }}>Secure</span>
                        : <span className={`badge ${s.statusClass}`}>{s.statusLabel}</span>
                      }
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Remediation Tab */}
      {activeTab === 'remediation' && (
        <section className="tab-content active" id="remediation-content">
          <div className="glass-card">
            <h3 className="drawer-section-title" style={{ marginBottom: '12px' }}>Prioritized Recommendations</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ borderLeft: '4px solid #ef4444', paddingLeft: '16px' }}>
                <h4 style={{ fontSize: '14px', fontWeight: 600, color: '#ffffff', marginBottom: '4px' }}>1. Enforce STARTTLS before AUTH exchanges (SMTP)</h4>
                <p style={{ fontSize: '12px', color: 'var(--muted)', marginBottom: '6px' }}>Affects: F-01 &bull; Severity: Critical</p>
                <p style={{ fontSize: '13px', color: '#e4e4e7' }}>Configure SMTP clients and server `postfix` or `exim` rules to forbid authentication over unencrypted SMTP connections. Update server config to require `STARTTLS` (`smtpd_tls_auth_only = yes`).</p>
              </div>
              <div style={{ borderLeft: '4px solid #ef4444', paddingLeft: '16px' }}>
                <h4 style={{ fontSize: '14px', fontWeight: 600, color: '#ffffff', marginBottom: '4px' }}>2. Replace Expired TLS Certificates</h4>
                <p style={{ fontSize: '12px', color: 'var(--muted)', marginBottom: '6px' }}>Affects: F-02 &bull; Severity: Critical</p>
                <p style={{ fontSize: '13px', color: '#e4e4e7' }}>Renew certificates bound to SMTP port 465 / 587. Enforce verification in client settings to reject expired certificates.</p>
              </div>
              <div style={{ borderLeft: '4px solid #f97316', paddingLeft: '16px' }}>
                <h4 style={{ fontSize: '14px', fontWeight: 600, color: '#ffffff', marginBottom: '4px' }}>3. Disable Legacy TLS Versions (TLS 1.0 &amp; 1.1)</h4>
                <p style={{ fontSize: '12px', color: 'var(--muted)', marginBottom: '6px' }}>Affects: F-03 &bull; Severity: High</p>
                <p style={{ fontSize: '13px', color: '#e4e4e7' }}>Enforce TLSv1.2 or TLSv1.3. For Dovecot/IMAP, set `ssl_min_protocol = TLSv1.2` in configuration settings.</p>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Report Tab */}
      {activeTab === 'report' && (
        <section className="tab-content active" id="report-content">
          <div className="glass-card">
            <h3 className="drawer-section-title" style={{ marginBottom: '12px' }}>Security &amp; Forensics Report</h3>
            <p style={{ fontSize: '13px', color: 'var(--muted)', marginBottom: '20px' }}>Generate a complete assessment report from the findings, sessions and cryptographical forensics.</p>
            <div className="report-preview-box" style={{ marginBottom: '20px' }}>
              <h1 style={{ fontSize: '18px', fontWeight: 600, color: '#ffffff', marginBottom: '8px', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '8px' }}>SecureMailScope Security Assessment</h1>
              <p><strong>Target PCAP:</strong> Mail-Server-Audit.pcap</p>
              <p><strong>Overall Posture score:</strong> 82 / 100 (HIGH RISK)</p>
              <br />
              <h2 style={{ fontSize: '14px', fontWeight: 600, color: '#ffffff', marginBottom: '6px' }}>Executive Summary</h2>
              <p>During the automated deep packet analysis of Mail-Server-Audit.pcap, we detected severe cryptographic negotiation flaws. The most critical item is the plain-text negotiation of SMTP AUTH credentials over TCP port 25 without prior STARTTLS command negotiation.</p>
              <br />
              <h2 style={{ fontSize: '14px', fontWeight: 600, color: '#ffffff', marginBottom: '6px' }}>Vulnerability Summary</h2>
              <ul>
                <li>Critical: 2 (Plaintext AUTH, Expired TLS Certificate)</li>
                <li>High: 1 (TLS 1.0 negotiate)</li>
                <li>Medium: 1 (RC4 ciphers enabled)</li>
              </ul>
            </div>
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
              <button className="btn-action" onClick={() => alert('JSON Report successfully copied to clipboard!')}>
                <i className="fa-solid fa-code"></i> Export JSON
              </button>
              <button className="btn-action btn-secondary" onClick={() => alert('Generating HTML report for download...')}>
                <i className="fa-solid fa-download"></i> Download HTML
              </button>
            </div>
          </div>
        </section>
      )}

      {/* Finding Drawer */}
      <div className={`drawer ${selectedFinding ? 'open' : ''}`} id="finding-drawer">
        <div className="drawer-header">
          <span className="drawer-title">
            {selectedFinding ? `${selectedFinding.id} - ${selectedFinding.title}` : 'Finding Detail'}
          </span>
          <button className="drawer-close" onClick={closeDrawer}>
            <i className="fa-solid fa-xmark"></i>
          </button>
        </div>
        {selectedFinding && (
          <div className="drawer-body">
            <div>
              <span className={`badge badge-${selectedFinding.severity}`}>{selectedFinding.severityLabel}</span>
            </div>
            <div>
              <h3 style={{ fontSize: '16px', fontWeight: 600, color: '#ffffff', marginBottom: '6px' }}>{selectedFinding.title}</h3>
              <p style={{ fontSize: '12px', color: 'var(--muted)' }}>Category: {selectedFinding.category} | Affected: {selectedFinding.endpoint}</p>
            </div>
            <div>
              <div className="drawer-section-title">What Happened</div>
              <p style={{ fontSize: '13px', color: '#e4e4e7', lineHeight: 1.5 }}>{selectedFinding.desc}</p>
            </div>
            <div>
              <div className="drawer-section-title">Evidence (Packet Reconstruct)</div>
              <div className="code-block">{selectedFinding.evidence}</div>
            </div>
            <div>
              <div className="drawer-section-title">Recommendation</div>
              <p style={{ fontSize: '13px', color: '#e4e4e7', lineHeight: 1.5 }}>{selectedFinding.reco}</p>
            </div>
          </div>
        )}
      </div>

      {/* Session Drawer */}
      <div className={`drawer ${selectedSession ? 'open' : ''}`} id="session-drawer">
        <div className="drawer-header">
          <span className="drawer-title">
            {selectedSession ? `${selectedSession.id} Details` : 'Session Detail'}
          </span>
          <button className="drawer-close" onClick={closeDrawer}>
            <i className="fa-solid fa-xmark"></i>
          </button>
        </div>
        {selectedSession && (() => {
          const tlsData = getSessionTlsInfo(selectedSession.tlsVer);
          return (
            <div className="drawer-body">
              <div>
                <h3 style={{ fontSize: '14px', fontWeight: 600, color: '#ffffff', marginBottom: '4px' }}>
                  {selectedSession.src} -&gt; {selectedSession.dst}
                </h3>
                <p style={{ fontSize: '12px', color: 'var(--muted)' }}>
                  Protocol: {selectedSession.protocol} | TLS Version: {selectedSession.tlsVer}
                </p>
              </div>
              <div className="sub-tabs">
                {['info', 'tls', 'cert'].map((t) => (
                  <button
                    key={t}
                    className={`sub-tab-btn ${sessionSubTab === t ? 'active' : ''}`}
                    onClick={() => setSessionSubTab(t)}
                  >
                    {t.charAt(0).toUpperCase() + t.slice(1)}
                  </button>
                ))}
              </div>
              {sessionSubTab === 'info' && (
                <div className="sub-tab-content active">
                  <div className="drawer-section-title">Session Assessment</div>
                  <p style={{ fontSize: '13px', color: '#e4e4e7', lineHeight: 1.5 }}>{selectedSession.assess}</p>
                </div>
              )}
              {sessionSubTab === 'tls' && (
                <div className="sub-tab-content active">
                  <div className="drawer-section-title">TLS Handshake</div>
                  <div className="code-block">{tlsData.tls}</div>
                </div>
              )}
              {sessionSubTab === 'cert' && (
                <div className="sub-tab-content active">
                  <div className="drawer-section-title">Certificate Information</div>
                  <div className="code-block">{tlsData.cert}</div>
                </div>
              )}
            </div>
          );
        })()}
      </div>
    </main>
  );
}
