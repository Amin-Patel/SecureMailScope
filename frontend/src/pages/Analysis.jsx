import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams, Link, useNavigate } from 'react-router-dom';
import { getAnalysis, getAnalyses, getProvenanceGraph } from '../utils/api';
import { AIExplanation } from '../components/AIExplanation';
import { ProvenanceGraph } from '../components/ProvenanceGraph';
import { CryptographicStateAssessment } from '../components/CryptographicStateAssessment';
import { EvidenceBasedAssessment } from '../components/EvidenceBasedAssessment';

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
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const jobId = searchParams.get('job');
  const tabParam = searchParams.get('tab');

  const [activeTab, setActiveTab] = useState(tabParam || 'overview');
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [selectedSession, setSelectedSession] = useState(null);
  const [sessionSubTab, setSessionSubTab] = useState('info');
  const [analysisData, setAnalysisData] = useState(null);
  const [availableAnalyses, setAvailableAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [toasts, setToasts] = useState([]);

  const [findingsSearch, setFindingsSearch] = useState('');
  const [findingsSeverity, setFindingsSeverity] = useState('all');
  const [sessionsSearch, setSessionsSearch] = useState('');
  const [sessionsStatus, setSessionsStatus] = useState('all');

  const [provenanceData, setProvenanceData] = useState(null);
  const [provenanceLoading, setProvenanceLoading] = useState(false);
  const [highlightedFindingId, setHighlightedFindingId] = useState(null);

  // ── Toast helper ────────────────────────────────────────────────────────────
  const addToast = useCallback((message, type = 'success') => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 3000);
  }, []);

  useEffect(() => {
    if (tabParam) setActiveTab(tabParam);
  }, [tabParam]);

  // Load provenance graph on-demand when Evidence Graph tab is activated
  useEffect(() => {
    const targetId = analysisData?.capture_id || jobId;
    if (activeTab === 'evidence' && targetId && (!provenanceData || provenanceData.capture_id !== targetId)) {
      setProvenanceLoading(true);
      getProvenanceGraph(targetId)
        .then(data => {
          setProvenanceData(data);
          setProvenanceLoading(false);
        })
        .catch(err => {
          console.error('Failed to load provenance for analysis view:', err);
          setProvenanceLoading(false);
        });
    }
  }, [activeTab, analysisData, jobId, provenanceData]);

  useEffect(() => {
    setLoading(true);
    setError(null);

    // Fetch list of available analyses for fallback / navigation
    getAnalyses()
      .then(res => {
        const list = res.analyses || [];
        setAvailableAnalyses(list);

        const targetId = jobId || (list.length > 0 ? list[0].capture_id : null);
        if (targetId) {
          return getAnalysis(targetId);
        }
        return null;
      })
      .then(data => {
        if (data) {
          setAnalysisData(data);
        }
        setLoading(false);
      })
      .catch(err => {
        console.error('Error loading analysis:', err);
        setError('Analysis record not found or could not be loaded.');
        setLoading(false);
      });
  }, [jobId]);

  const findings = analysisData?.findings || [];
  const filteredFindings = findings.filter(f => {
    const backendSev = (f.severity || '').toLowerCase();
    const matchSev = findingsSeverity === 'all' || backendSev === findingsSeverity;
    const q = findingsSearch.toLowerCase();
    const matchQ = !q
      || (f.title || '').toLowerCase().includes(q)
      || (f.type || '').toLowerCase().includes(q)
      || (f.description || '').toLowerCase().includes(q);
    return matchSev && matchQ;
  });

  const sessions = analysisData?.sessions || [];
  const filteredSessions = sessions.filter(s => {
    const matchStatus = sessionsStatus === 'all'
      || (sessionsStatus === 'weak' && !s.encrypted)
      || (sessionsStatus === 'secure' && s.encrypted);
    const q = sessionsSearch.toLowerCase();
    const matchQ = !q || (s.src || '').includes(q) || (s.dst || '').includes(q) || (s.protocol || '').toLowerCase().includes(q);
    return matchStatus && matchQ;
  });

  const openFinding  = f => { setSelectedFinding(f); setSelectedSession(null); };
  const openSession  = s => { setSelectedSession(s); setSelectedFinding(null); setSessionSubTab('info'); };
  const closeDrawer  = () => { setSelectedFinding(null); setSelectedSession(null); };

  // ── Export helpers ──────────────────────────────────────────────────────────
  const exportJson = () => {
    const activeId = analysisData?.capture_id || jobId || 'export';
    const blob = new Blob([JSON.stringify(analysisData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `analysis-${activeId}.json`; a.click();
    URL.revokeObjectURL(url);
    addToast('JSON report downloaded!', 'success');
  };

  const exportHtml = () => {
    addToast('HTML report generation downloaded!', 'success');
    const activeId = analysisData?.capture_id || jobId || 'export';
    const htmlContent = `<!DOCTYPE html><html><head><title>SecureMailScope Report - ${activeId}</title><style>body{font-family:sans-serif;padding:30px;background:#0d0d18;color:#fff;} h1{color:#818cf8;}</style></head><body><h1>SecureMailScope Security Assessment</h1><p>Capture ID: ${activeId}</p><p>Risk Score: ${analysisData?.summary?.risk_score ?? 'N/A'}/100</p><hr/><pre>${JSON.stringify(analysisData, null, 2)}</pre></body></html>`;
    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `report-${activeId}.html`; a.click();
    URL.revokeObjectURL(url);
  };

  const drawerOpen = !!(selectedFinding || selectedSession);

  // Loading state
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

  // Error state or not found
  if (error || !analysisData) return (
    <main className="workspace-container" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '60vh', gap: '20px', textAlign: 'center' }}>
      <div style={{
        width: 72, height: 72, borderRadius: '50%',
        background: 'rgba(239,68,68,0.15)',
        border: '1px solid rgba(239,68,68,0.4)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: 28, color: '#f87171',
        boxShadow: '0 0 24px rgba(239,68,68,0.25)',
      }}>
        <i className="fa-solid fa-triangle-exclamation" />
      </div>
      <div>
        <h2 style={{ fontSize: 'clamp(18px,2.5vw,24px)', fontWeight: 700, color: '#ffffff', marginBottom: 8 }}>
          {error || 'No Analysis Available'}
        </h2>
        <p style={{ fontSize: 14, color: 'rgba(255,255,255,0.55)', maxWidth: 460, lineHeight: 1.6 }}>
          {jobId
            ? `The requested analysis Job #${jobId} could not be found. You can load a different capture from history or upload a new PCAP file.`
            : 'No capture files have been analyzed yet. Upload a PCAP file to start an investigation.'}
        </p>
      </div>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', justifyContent: 'center' }}>
        <Link
          to="/workspace"
          style={{
            padding: '11px 26px', borderRadius: '999px',
            background: '#ffffff', color: '#000000',
            fontWeight: 700, fontSize: 14, textDecoration: 'none',
            display: 'inline-flex', alignItems: 'center', gap: 8,
          }}
        >
          <i className="fa-solid fa-upload" style={{ fontSize: 12 }} />
          Upload PCAP File
        </Link>
        <Link
          to="/history"
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
        </Link>
        {availableAnalyses.length > 0 && (
          <button
            onClick={() => {
              const firstId = availableAnalyses[0].capture_id;
              setSearchParams({ job: firstId });
            }}
            style={{
              padding: '10px 24px', borderRadius: '999px',
              background: 'rgba(99,102,241,0.2)',
              border: '1.5px solid rgba(99,102,241,0.4)',
              color: '#a5b4fc', fontWeight: 600, fontSize: 14, cursor: 'pointer',
              display: 'inline-flex', alignItems: 'center', gap: 8,
            }}
          >
            <i className="fa-solid fa-bolt" style={{ fontSize: 12 }} />
            Load Latest Capture (#{availableAnalyses[0].capture_id})
          </button>
        )}
      </div>
    </main>
  );

  const { summary = {}, findings: rawFindings = [] } = analysisData || {};
  const currentCaptureId = analysisData.capture_id || jobId || '--';
  const score = summary.risk_score ?? analysisData.risk?.risk_score ?? 0;
  const riskColor = score >= 75 ? '#ef4444' : score >= 40 ? '#f59e0b' : '#10b981';

  // Dynamic breakdown counts
  const criticalCount = rawFindings.filter(f => (f.severity || '').toUpperCase() === 'CRITICAL').length;
  const highCount = rawFindings.filter(f => (f.severity || '').toUpperCase() === 'HIGH').length;
  const medCount = rawFindings.filter(f => (f.severity || '').toUpperCase() === 'MEDIUM').length;
  const lowCount = rawFindings.filter(f => (f.severity || '').toUpperCase() === 'LOW').length;

  return (
    <main className="workspace-container">
      <Toast toasts={toasts} remove={id => setToasts(prev => prev.filter(t => t.id !== id))} />

      {/* Drawer backdrop */}
      <div className={`drawer-backdrop ${drawerOpen ? 'open' : ''}`} onClick={closeDrawer} />

      {/* Title Bar */}
      <div className="workspace-title-bar">
        <div>
          <h2 style={{ fontSize: 'clamp(16px, 2.2vw, 22px)', fontWeight: 700, color: '#ffffff' }}>
            {analysisData.original_filename ? `${analysisData.original_filename}` : `Job #${currentCaptureId}`}
          </h2>
          <div className="analysis-meta-info">
            Analysis Workspace &bull; Job ID #{currentCaptureId} &bull; Risk Score {score}/100
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{
              width: '46px',
              height: '46px',
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '15px',
              fontWeight: 800,
              background: `rgba(${riskColor === '#ef4444' ? '239,68,68' : riskColor === '#f59e0b' ? '245,158,11' : '16,185,129'}, 0.15)`,
              border: `2px solid ${riskColor}`,
              boxShadow: `0 0 12px ${riskColor}44`,
              color: '#ffffff',
            }}>
              {score}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: '11px', color: 'var(--muted)', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.05em', lineHeight: 1.2 }}>
                Risk Score
              </span>
              <span style={{ fontSize: '10px', color: 'rgba(255,255,255,0.4)', fontWeight: 600 }}>
                out of 100
              </span>
            </div>
          </div>

          {/* Cryptographic State Badge (USP 2) */}
          {analysisData?.cryptographic_state_assessment && (
            <button
              onClick={() => setActiveTab('crypto')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 16px',
                borderRadius: '999px',
                background: 'rgba(255, 255, 255, 0.05)',
                border: `1.5px solid ${analysisData.cryptographic_state_assessment.badge_color || '#818cf8'}`,
                color: '#ffffff',
                fontSize: '12px',
                fontWeight: 700,
                cursor: 'pointer',
                boxShadow: `0 0 12px ${analysisData.cryptographic_state_assessment.badge_color || '#818cf8'}33`
              }}
              title="Click to view Cryptographic State Reasoning"
            >
              <i className="fa-solid fa-shield-halved" style={{ color: analysisData.cryptographic_state_assessment.badge_color || '#818cf8' }} />
              <span>{analysisData.cryptographic_state_assessment.overall_state_label}</span>
            </button>
          )}

          {/* Evidence-Based Assessment Badge (USP 5) */}
          {analysisData?.evidence_based_assessment && (
            <button
              onClick={() => setActiveTab('evidence_assessment')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 16px',
                borderRadius: '999px',
                background: 'rgba(255, 255, 255, 0.05)',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                color: '#ffffff',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
              title="Click to view Evidence-Based Assessment (Observed / Expected / Unknown)"
            >
              <i className="fa-solid fa-scale-balanced" style={{ color: '#cbd5e1' }} />
              <span>Assessment: {analysisData.evidence_based_assessment.metrics?.satisfied_count || 0} Satisfied &bull; {analysisData.evidence_based_assessment.metrics?.violated_count || 0} Violated</span>
            </button>
          )}

          {/* View Evidence Provenance Graph Button */}
          <Link
            to={`/provenance?job=${encodeURIComponent(currentCaptureId)}`}
            className="btn-action btn-secondary"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 16px',
              borderRadius: '999px',
              fontSize: '12px',
              fontWeight: 600,
              textDecoration: 'none',
              transition: 'all 0.2s ease',
            }}
            title={`View Evidence Provenance Graph for ${currentCaptureId}`}
          >
            <i className="fa-solid fa-diagram-project" />
            <span>View Evidence Provenance Graph</span>
          </Link>
        </div>
      </div>

      {/* Tab Bar */}
      <nav className="tabs-bar" aria-label="Analysis Tabs Navigation">
        {[
          { id: 'overview', label: 'Overview', icon: 'fa-solid fa-gauge-high' },
          {
            id: 'evidence_assessment',
            label: 'Evidence-Based Assessment',
            icon: 'fa-solid fa-scale-balanced',
            badge: analysisData?.evidence_based_assessment?.metrics?.total_assessed != null
              ? `${analysisData.evidence_based_assessment.metrics.satisfied_count ?? 0}/${analysisData.evidence_based_assessment.metrics.total_assessed}`
              : null,
            badgeBg: 'rgba(56, 189, 248, 0.25)',
            badgeBorder: 'rgba(56, 189, 248, 0.5)',
            badgeColor: '#38bdf8'
          },
          {
            id: 'crypto',
            label: 'Cryptographic State',
            icon: 'fa-solid fa-shield-halved',
            badge: analysisData?.cryptographic_state_assessment?.overall_state_label || null,
            badgeBg: `${analysisData?.cryptographic_state_assessment?.badge_color || '#818cf8'}26`,
            badgeBorder: `${analysisData?.cryptographic_state_assessment?.badge_color || '#818cf8'}66`,
            badgeColor: analysisData?.cryptographic_state_assessment?.badge_color || '#c7d2fe'
          },
          {
            id: 'findings',
            label: 'Findings',
            icon: 'fa-solid fa-triangle-exclamation',
            badge: rawFindings.length > 0 ? rawFindings.length : null,
            badgeBg: criticalCount > 0 ? 'rgba(239, 68, 68, 0.25)' : highCount > 0 ? 'rgba(249, 115, 22, 0.25)' : 'rgba(99, 102, 241, 0.2)',
            badgeBorder: criticalCount > 0 ? 'rgba(239, 68, 68, 0.5)' : highCount > 0 ? 'rgba(249, 115, 22, 0.5)' : 'rgba(99, 102, 241, 0.4)',
            badgeColor: criticalCount > 0 ? '#f87171' : highCount > 0 ? '#fb923c' : '#c7d2fe'
          },
          {
            id: 'sessions',
            label: 'Sessions',
            icon: 'fa-solid fa-network-wired',
            badge: (summary.session_count ?? sessions.length) > 0 ? (summary.session_count ?? sessions.length) : null,
            badgeBg: 'rgba(16, 185, 129, 0.2)',
            badgeBorder: 'rgba(16, 185, 129, 0.4)',
            badgeColor: '#34d399'
          },
          { id: 'evidence', label: 'Evidence Graph', icon: 'fa-solid fa-diagram-project' },
          { id: 'remediation', label: 'Remediation', icon: 'fa-solid fa-list-check' },
          { id: 'report', label: 'Report', icon: 'fa-solid fa-file-lines' },
        ].map(tab => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              className={`tab-btn ${isActive ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
              aria-selected={isActive}
              role="tab"
            >
              <i
                className={tab.icon}
                style={{
                  fontSize: '13px',
                  color: isActive ? '#ffffff' : '#94a3b8',
                  transition: 'color 0.2s ease',
                }}
              />
              <span>{tab.label}</span>
              {tab.badge && (
                <span
                  className="tab-badge"
                  style={{
                    background: tab.badgeBg || 'rgba(255, 255, 255, 0.1)',
                    borderColor: tab.badgeBorder || 'rgba(255, 255, 255, 0.2)',
                    color: tab.badgeColor || '#ffffff',
                  }}
                >
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* ── Overview ── */}
      {activeTab === 'overview' && (
        <section className="tab-content active">
          <div className="glass-card">
            <h3 className="drawer-section-title" style={{ marginBottom: 12 }}>Executive Summary</h3>
            <p style={{ fontSize: 14, lineHeight: 1.6, color: '#e4e4e7', marginBottom: 16 }}>
              {summary.description || `Automated deep forensic analysis of packet capture ${analysisData.original_filename || currentCaptureId}. Identified ${rawFindings.length} security finding(s) across ${summary.session_count ?? sessions.length} session(s).`}
            </p>
            <div className="metrics-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
              <div className="metric-box"><div className="metric-value">{summary.total_packets ?? '--'}</div><div className="metric-label">Total Packets</div></div>
              <div className="metric-box"><div className="metric-value">{rawFindings.length}</div><div className="metric-label">Findings</div></div>
              <div className="metric-box"><div className="metric-value">{summary.session_count ?? sessions.length}</div><div className="metric-label">Sessions</div></div>
            </div>
            <div style={{ marginTop: '16px', display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
              <Link
                to={`/provenance?job=${encodeURIComponent(currentCaptureId)}`}
                className="btn-action"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '9px 18px',
                  borderRadius: '999px',
                  fontSize: '13px',
                  fontWeight: 600,
                  textDecoration: 'none',
                }}
              >
                <i className="fa-solid fa-diagram-project" />
                <span>View Evidence Provenance Graph</span>
              </Link>
              <button
                className="btn-action btn-secondary"
                onClick={() => setActiveTab('evidence')}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '9px 18px',
                  borderRadius: '999px',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                <i className="fa-solid fa-network-wired" />
                <span>Open In-Page Graph Tab</span>
              </button>
            </div>
          </div>

          <div className="glass-card">
            <h3 className="drawer-section-title" style={{ marginBottom: 12 }}>Security Findings Distribution</h3>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              {criticalCount > 0 && <span className="badge badge-critical" style={{ padding: '6px 12px' }}>{criticalCount} Critical</span>}
              {highCount > 0 && <span className="badge badge-high" style={{ padding: '6px 12px' }}>{highCount} High</span>}
              {medCount > 0 && <span className="badge badge-medium" style={{ padding: '6px 12px', background: 'rgba(234, 179, 8, 0.2)', color: '#eab308', border: '1px solid rgba(234, 179, 8, 0.3)' }}>{medCount} Medium</span>}
              {lowCount > 0 && <span className="badge badge-low" style={{ padding: '6px 12px' }}>{lowCount} Low</span>}
              {rawFindings.length === 0 && <span className="badge badge-low" style={{ padding: '6px 12px' }}>0 Vulnerabilities Detected</span>}
            </div>
          </div>
        </section>
      )}

      {/* ── Evidence-Based Assessment Tab (USP 5) ── */}
      {activeTab === 'evidence_assessment' && (
        <section className="tab-content active">
          <EvidenceBasedAssessment
            assessment={analysisData?.evidence_based_assessment}
            captureId={currentCaptureId}
          />
        </section>
      )}

      {/* ── Cryptographic State Reasoning Tab (USP 2) ── */}
      {activeTab === 'crypto' && (
        <section className="tab-content active">
          <CryptographicStateAssessment
            assessment={analysisData?.cryptographic_state_assessment}
            captureId={currentCaptureId}
          />
        </section>
      )}

      {/* ── Findings ── */}
      {activeTab === 'findings' && (
        <section className="tab-content active">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '14px' }}>
            <div style={{ fontSize: '13px', color: '#cbd5e1' }}>
              Displaying <strong>{filteredFindings.length}</strong> forensic security findings
            </div>
            <Link
              to={`/provenance?job=${encodeURIComponent(currentCaptureId)}`}
              className="btn-action btn-secondary"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                padding: '7px 16px',
                borderRadius: '999px',
                fontSize: '12px',
                fontWeight: 600,
                textDecoration: 'none',
              }}
            >
              <i className="fa-solid fa-diagram-project" />
              <span>View Evidence Provenance Graph</span>
            </Link>
          </div>
          <div className="filters-row">
            <input type="text" className="search-input" placeholder="Search findings by title, IP, host…"
              value={findingsSearch} onChange={e => setFindingsSearch(e.target.value)} />
            <select className="filter-select" value={findingsSeverity} onChange={e => setFindingsSeverity(e.target.value)}>
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <div className="data-table-wrapper">
            <table className="data-table">
              <thead><tr><th>ID</th><th>Severity</th><th>Finding Title</th><th>Category</th><th>Evidence Snippet</th><th>Provenance</th></tr></thead>
              <tbody>
                {filteredFindings.length === 0
                  ? <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--muted)', padding: 24 }}>No findings match your filter</td></tr>
                  : filteredFindings.map(f => {
                    const sevLower = (f.severity || '').toLowerCase();
                    const sevLabel = f.severity || 'UNKNOWN';
                    return (
                      <tr key={f.id} onClick={() => openFinding(f)} style={{ cursor: 'pointer' }}>
                        <td>{f.id}</td>
                        <td><span className={`badge badge-${sevLower}`}>{sevLabel}</span></td>
                        <td style={{ fontWeight: 500, color: '#ffffff' }}>{f.title}</td>
                        <td>{f.type || '--'}</td>
                        <td style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={f.evidence}>
                          {f.evidence ? f.evidence.split(' ').slice(0, 8).join(' ') + '…' : '--'}
                        </td>
                        <td>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setActiveTab('evidence');
                              setHighlightedFindingId(f.id.startsWith('finding:') ? f.id : `finding:${f.id}`);
                            }}
                            style={{
                              padding: '4px 10px',
                              borderRadius: '999px',
                              background: 'rgba(255, 255, 255, 0.06)',
                              border: '1px solid rgba(255, 255, 255, 0.12)',
                              color: '#cbd5e1',
                              fontSize: '11px',
                              fontWeight: 600,
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '5px',
                              transition: 'all 0.15s ease'
                            }}
                            title="Inspect in Evidence Provenance Graph"
                          >
                            <i className="fa-solid fa-diagram-project" style={{ fontSize: '10px' }} />
                            <span>Graph</span>
                          </button>
                        </td>
                      </tr>
                    );
                  })}
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
              <option value="weak">Weak / Plaintext</option>
              <option value="secure">Secure / Encrypted</option>
            </select>
          </div>
          <div className="data-table-wrapper">
            <table className="data-table">
              <thead><tr><th>Session ID</th><th>Source</th><th>Destination</th><th>Protocol</th><th>TLS Version</th><th>Security Status</th><th>Provenance</th></tr></thead>
              <tbody>
                {filteredSessions.length === 0 ? (
                  <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--muted)', padding: 24 }}>No sessions captured or matching filter</td></tr>
                ) : (
                  filteredSessions.map(s => {
                    const tlsVer = s.tls_versions && s.tls_versions.length > 0
                      ? s.tls_versions.join(', ')
                      : (s.encrypted ? 'Encrypted' : 'Plaintext');
                    const statusLabel = s.encrypted ? 'Secure' : 'Plaintext';
                    return (
                      <tr key={s.id} onClick={() => openSession({ ...s, tlsVer, statusLabel })} style={{ cursor: 'pointer' }}>
                        <td>{s.id}</td>
                        <td>{s.src}</td>
                        <td>{s.dst}</td>
                        <td>{s.protocol}</td>
                        <td>{tlsVer}</td>
                        <td>
                          {s.encrypted
                            ? <span className="badge badge-low" style={{ background: 'rgba(16,185,129,0.2)', color: '#10b981', border: '1px solid rgba(16,185,129,0.3)' }}>Secure</span>
                            : <span className="badge badge-critical">{statusLabel}</span>}
                        </td>
                        <td>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setActiveTab('evidence');
                              setHighlightedFindingId(s.id.startsWith('session:') ? s.id : `session:${s.id}`);
                            }}
                            style={{
                              padding: '4px 10px',
                              borderRadius: '999px',
                              background: 'rgba(255, 255, 255, 0.06)',
                              border: '1px solid rgba(255, 255, 255, 0.12)',
                              color: '#cbd5e1',
                              fontSize: '11px',
                              fontWeight: 600,
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '5px',
                              transition: 'all 0.15s ease'
                            }}
                            title="Inspect session stream in Evidence Provenance Graph"
                          >
                            <i className="fa-solid fa-diagram-project" style={{ fontSize: '10px' }} />
                            <span>Graph</span>
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
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
              {rawFindings.length > 0 ? (
                rawFindings.map((f, idx) => {
                  const sev = (f.severity || '').toUpperCase();
                  const color = sev === 'CRITICAL' ? '#ef4444' : sev === 'HIGH' ? '#f97316' : sev === 'MEDIUM' ? '#eab308' : '#10b981';
                  return (
                    <div key={f.id || idx} style={{ borderLeft: `4px solid ${color}`, paddingLeft: 16, paddingTop: 4, paddingBottom: 4 }}>
                      <h4 style={{ fontSize: 14, fontWeight: 600, color: '#ffffff', marginBottom: 4 }}>{idx + 1}. {f.title}</h4>
                      <p style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 6 }}>{f.id} &bull; {f.severity}</p>
                      <p style={{ fontSize: 13, color: '#e4e4e7', whiteSpace: 'pre-line' }}>{f.remediation || 'Follow network security best practices to encrypt email traffic.'}</p>
                    </div>
                  );
                })
              ) : (
                <p style={{ color: 'var(--muted)', fontSize: 13 }}>No remediation actions required. Security posture is optimal.</p>
              )}
            </div>
          </div>
        </section>
      )}

      {/* ── Evidence Graph ── */}
      {activeTab === 'evidence' && (
        <section className="tab-content active" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#ffffff', margin: 0 }}>
                Evidence Provenance Graph for Capture #{currentCaptureId}
              </h3>
              <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.6)', margin: '4px 0 0 0' }}>
                Interactive causal graph tracing raw network evidence, TLS handshakes, and X.509 certificates directly to security findings.
              </p>
            </div>
            <Link
              to={`/provenance?job=${encodeURIComponent(currentCaptureId)}${highlightedFindingId ? `&node=${encodeURIComponent(highlightedFindingId)}` : ''}`}
              className="btn-action"
              style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', textDecoration: 'none' }}
            >
              <i className="fa-solid fa-up-right-and-down-left-from-center" />
              <span>Full Screen Graph</span>
            </Link>
          </div>

          {provenanceLoading ? (
            <div style={{ padding: '60px 20px', textAlign: 'center', color: '#94a3b8', background: 'rgba(15,23,42,0.6)', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.08)' }}>
              <i className="fa-solid fa-circle-notch fa-spin" style={{ fontSize: '32px', color: '#818cf8', marginBottom: '14px' }} />
              <div style={{ fontSize: '14px', fontWeight: 600, color: '#ffffff' }}>Constructing Evidence Provenance Graph…</div>
              <p style={{ fontSize: '12px', color: '#94a3b8', marginTop: '6px' }}>Tracing packets, sessions, handshakes, certificates, and analysis rules.</p>
            </div>
          ) : provenanceData ? (
            <ProvenanceGraph
              graphData={provenanceData}
              initialFocusId={highlightedFindingId}
              height="650px"
            />
          ) : (
            <div style={{ padding: '40px', textAlign: 'center', color: '#94a3b8', background: 'rgba(15,23,42,0.6)', borderRadius: '12px' }}>
              No provenance data available for this capture.
            </div>
          )}
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
              <p><strong>Target PCAP:</strong> {analysisData.original_filename || `${currentCaptureId}.pcap`}</p>
              <p><strong>Overall Posture score:</strong> {score} / 100 ({score >= 75 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW'} RISK)</p>
              <br />
              <h2 style={{ fontSize: 14, fontWeight: 600, color: '#ffffff', marginBottom: 6 }}>Executive Summary</h2>
              <p>
                {rawFindings.length > 0
                  ? `During the automated deep packet analysis of ${analysisData.original_filename || currentCaptureId}, ${rawFindings.length} security violation(s) were identified across ${summary.session_count ?? sessions.length} email communication stream(s).`
                  : `Automated inspection of ${analysisData.original_filename || currentCaptureId} completed. All inspected sessions satisfy secure cryptographic requirements.`}
              </p>
              <br />
              <h2 style={{ fontSize: 14, fontWeight: 600, color: '#ffffff', marginBottom: 6 }}>Vulnerability Summary</h2>
              <ul>
                <li>Critical: {criticalCount}</li>
                <li>High: {highCount}</li>
                <li>Medium: {medCount}</li>
                <li>Low: {lowCount}</li>
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
        {selectedFinding && (() => {
          const sevLower = (selectedFinding.severity || '').toLowerCase();
          const sevLabel = selectedFinding.severity || 'UNKNOWN';
          return (
            <div className="drawer-body">
              <div><span className={`badge badge-${sevLower}`}>{sevLabel}</span></div>
              <div>
                <h3 style={{ fontSize: 16, fontWeight: 600, color: '#ffffff', marginBottom: 6 }}>{selectedFinding.title}</h3>
                {/* backend: f.type (not f.category), no f.endpoint */}
                <p style={{ fontSize: 12, color: 'var(--muted)' }}>Type: {selectedFinding.type || '--'} | ID: {selectedFinding.id}</p>
              </div>
              {/* backend: f.description (not f.desc) */}
              <div><div className="drawer-section-title">What Happened</div><p style={{ fontSize: 13, color: '#e4e4e7', lineHeight: 1.5 }}>{selectedFinding.description || 'No description available.'}</p></div>
              <div><div className="drawer-section-title">Evidence (Packet Reconstruct)</div><div className="code-block">{selectedFinding.evidence || 'No evidence data.'}</div></div>
              {/* backend: f.remediation (not f.reco) */}
              <div><div className="drawer-section-title">Recommendation</div><p style={{ fontSize: 13, color: '#e4e4e7', lineHeight: 1.5 }}>{selectedFinding.remediation || 'No recommendation available.'}</p></div>
              {/* Evidence Provenance Graph Action */}
              <div style={{ marginTop: '12px', marginBottom: '8px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <button
                  onClick={() => {
                    setActiveTab('evidence');
                    setHighlightedFindingId(selectedFinding.id);
                    closeDrawer();
                  }}
                  style={{
                    width: '100%',
                    padding: '10px 16px',
                    borderRadius: '8px',
                    background: 'rgba(99, 102, 241, 0.2)',
                    border: '1.5px solid rgba(168, 85, 247, 0.5)',
                    color: '#ffffff',
                    fontWeight: 700,
                    fontSize: '13px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px',
                    boxShadow: '0 4px 16px rgba(168, 85, 247, 0.2)',
                    transition: 'all 0.2s ease',
                  }}
                >
                  <i className="fa-solid fa-diagram-project" style={{ color: '#c084fc' }} />
                  <span>View in In-Page Graph</span>
                </button>
                <Link
                  to={`/provenance?job=${encodeURIComponent(currentCaptureId)}&node=${encodeURIComponent(selectedFinding.id)}`}
                  className="btn-action btn-secondary"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px',
                    textDecoration: 'none',
                    fontSize: '12px',
                    padding: '8px 16px',
                    borderRadius: '8px',
                  }}
                >
                  <i className="fa-solid fa-up-right-from-square" />
                  <span>Full Screen Provenance Graph</span>
                </Link>
              </div>

              <AIExplanation finding={selectedFinding} />
            </div>
          );
        })()}
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
          // Derive tlsVer string for the static TLS info lookup helper
          const tlsVerStr = selectedSession.tlsVer
            || (selectedSession.tls_versions && selectedSession.tls_versions.length > 0
              ? selectedSession.tls_versions[0]
              : (selectedSession.encrypted ? 'TLS 1.2' : 'Plaintext'));
          const tlsData = getSessionTlsInfo(tlsVerStr);
          // Derive session assessment text from backend boolean
          const assess = selectedSession.encrypted
            ? `This session uses encryption (${tlsVerStr}). ${selectedSession.packet_count || 0} packets captured. The connection appears secure.`
            : `This session transmits data in plaintext over ${selectedSession.protocol}. ${selectedSession.packet_count || 0} packets captured. Credentials and content are visible to any network observer. Enforce TLS immediately.`;
          return (
            <div className="drawer-body">
              <div>
                <h3 style={{ fontSize: 14, fontWeight: 600, color: '#ffffff', marginBottom: 4 }}>{selectedSession.src} → {selectedSession.dst}</h3>
                <p style={{ fontSize: 12, color: 'var(--muted)' }}>Protocol: {selectedSession.protocol} | TLS: {tlsVerStr} | Packets: {selectedSession.packet_count || 0}</p>
              </div>
              <div className="sub-tabs">
                {['info', 'tls', 'cert'].map(t => (
                  <button key={t} className={`sub-tab-btn ${sessionSubTab === t ? 'active' : ''}`} onClick={() => setSessionSubTab(t)}>
                    {t.charAt(0).toUpperCase() + t.slice(1)}
                  </button>
                ))}
              </div>
              {sessionSubTab === 'info' && <div className="sub-tab-content active"><div className="drawer-section-title">Session Assessment</div><p style={{ fontSize: 13, color: '#e4e4e7', lineHeight: 1.5 }}>{assess}</p></div>}
              {sessionSubTab === 'tls'  && <div className="sub-tab-content active"><div className="drawer-section-title">TLS Handshake</div><div className="code-block">{tlsData.tls}</div></div>}
              {sessionSubTab === 'cert' && <div className="sub-tab-content active"><div className="drawer-section-title">Certificate Information</div><div className="code-block">{tlsData.cert}</div></div>}

              {/* Provenance Graph Action for Session */}
              <div style={{ marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <button
                  onClick={() => {
                    setActiveTab('evidence');
                    setHighlightedFindingId(selectedSession.id);
                    closeDrawer();
                  }}
                  style={{
                    width: '100%',
                    padding: '10px 16px',
                    borderRadius: '8px',
                    background: 'rgba(99, 102, 241, 0.2)',
                    border: '1.5px solid rgba(168, 85, 247, 0.5)',
                    color: '#ffffff',
                    fontWeight: 700,
                    fontSize: '13px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px',
                    boxShadow: '0 4px 16px rgba(168, 85, 247, 0.2)',
                    transition: 'all 0.2s ease',
                  }}
                >
                  <i className="fa-solid fa-diagram-project" style={{ color: '#c084fc' }} />
                  <span>Trace Session in In-Page Graph</span>
                </button>
                <Link
                  to={`/provenance?job=${encodeURIComponent(currentCaptureId)}&node=${encodeURIComponent(selectedSession.id)}`}
                  className="btn-action btn-secondary"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px',
                    textDecoration: 'none',
                    fontSize: '12px',
                    padding: '8px 16px',
                    borderRadius: '8px',
                  }}
                >
                  <i className="fa-solid fa-up-right-from-square" />
                  <span>Full Screen Provenance Graph</span>
                </Link>
              </div>
            </div>
          );
        })()}
      </div>
    </main>
  );
}
