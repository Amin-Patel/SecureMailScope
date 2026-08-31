import React, { useEffect, useState } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import '../pages/Dashboard.css';
import { getAnalysisResults, getAnalyses } from '../utils/api';
import { DashboardCharts } from './DashboardCharts';
import { AIExplanation } from './AIExplanation';
import { RemediationCard } from './RemediationCard';
import { CertificateViewer } from './CertificateViewer';
import { FindingModal } from './FindingModal';
import { SessionTimeline } from './SessionTimeline';
import { ReportExportModal } from './ReportExportModal';
import { PrintableReport } from './PrintableReport';

const SEVERITY_ORDER = {
  CRITICAL: 1,
  HIGH: 2,
  MEDIUM: 3,
  LOW: 4,
};

// Color range helper: 0-20 Green, 21-40 Yellow, 41-69 Orange, 70-100 Red
function getRiskColor(score) {
  const s = Number(score) || 0;
  if (s <= 20) return '#10b981'; // Green
  if (s <= 40) return '#f59e0b'; // Yellow
  if (s <= 69) return '#f97316'; // Orange
  return '#ef4444';             // Red
}

export function Dashboard() {
  const { captureId } = useParams();
  const navigate = useNavigate();
  const [activeJobId, setActiveJobId] = useState(captureId || null);
  const [recentAnalyses, setRecentAnalyses] = useState([]);
  const [findings, setFindings] = useState([]);
  const [certificates, setCertificates] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [rawResults, setRawResults] = useState(null);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [reportDropdownOpen, setReportDropdownOpen] = useState(false);
  
  // Risk object state directly sourced from API
  const [riskInfo, setRiskInfo] = useState({
    risk_score: 0,
    risk_level: 'UNKNOWN',
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
  });

  const [metrics, setMetrics] = useState({
    totalSize: "0 MB",
    sessions: 0,
    tlsSessions: 0,
    plaintextEmails: 0,
  });

  useEffect(() => {
    let isMounted = true;
    setLoading(true);
    setError(null);

    getAnalyses()
      .then(res => {
        if (!isMounted) return;
        const list = res.analyses || [];
        setRecentAnalyses(list);

        const targetId = captureId || (list.length > 0 ? list[0].capture_id : null);
        setActiveJobId(targetId);
        if (targetId && !captureId) {
          navigate(`/dashboard/${targetId}`, { replace: true });
        }

        if (targetId) {
          return getAnalysisResults(targetId);
        }
        return null;
      })
      .then(data => {
        if (!isMounted) return;
        if (data) {
          setRawResults(data);
          const summary = data.summary || {};
          const fileSizeBytes = data.file_size || 0;
          const totalSizeMB = fileSizeBytes > 0
            ? (fileSizeBytes / (1024 * 1024)).toFixed(2)
            : '0';
          const encryptedSessions = (data.sessions || []).filter(s => s.encrypted).length;
          const plaintextCount = (data.sessions || []).filter(s => !s.encrypted).length;
          const findingsList = data.findings || [];
          const certsList = data.certificates || [];

          setFindings(findingsList);
          setCertificates(certsList);

          // Sourcing risk object directly from backend API
          const backendRisk = data.risk || {};
          const critical = findingsList.filter(f => (f.severity || '').toUpperCase() === 'CRITICAL').length;
          const high = findingsList.filter(f => (f.severity || '').toUpperCase() === 'HIGH').length;
          const med = findingsList.filter(f => (f.severity || '').toUpperCase() === 'MEDIUM').length;
          const low = findingsList.filter(f => (f.severity || '').toUpperCase() === 'LOW').length;

          setRiskInfo({
            risk_score: backendRisk.risk_score ?? summary.risk_score ?? 0,
            risk_level: backendRisk.risk_level || summary.risk_level || 'UNKNOWN',
            critical_count: backendRisk.critical_count ?? critical,
            high_count: backendRisk.high_count ?? high,
            medium_count: backendRisk.medium_count ?? med,
            low_count: backendRisk.low_count ?? low,
          });

          setMetrics({
            totalSize: totalSizeMB,
            sessions: summary.session_count || (data.sessions || []).length,
            tlsSessions: encryptedSessions,
            plaintextEmails: plaintextCount,
          });
        }
        setLoading(false);
      })
      .catch(err => {
        if (!isMounted) return;
        console.error('Failed to load dashboard data:', err);
        setError('Failed to load dashboard data. Ensure backend is running.');
        setLoading(false);
      });

    return () => { isMounted = false; };
  }, [captureId]);

  if (loading) {
    return (
      <main className="dashboard-container">
        <h1 style={{
          background: 'linear-gradient(135deg, #ffffff 0%, #a5b4fc 100%)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          backgroundClip: 'text',
          fontSize: 'clamp(24px, 3vw, 36px)',
          fontWeight: 800,
          letterSpacing: '-0.03em',
          marginBottom: '20px',
        }}>Dashboard</h1>
        <div className="glass-card" style={{ padding: '30px', textAlign: 'center' }}>
          <div className="skeleton" style={{ height: 24, width: 180, margin: '0 auto 16px' }} />
          <div className="skeleton" style={{ height: 14, width: '60%', margin: '0 auto' }} />
        </div>
      </main>
    );
  }

  if (error || !activeJobId) {
    return (
      <main className="dashboard-container">
        <h1 style={{
          background: 'linear-gradient(135deg, #ffffff 0%, #a5b4fc 100%)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          backgroundClip: 'text',
          fontSize: 'clamp(24px, 3vw, 36px)',
          fontWeight: 800,
          letterSpacing: '-0.03em',
          marginBottom: '20px',
        }}>Dashboard</h1>
        <div className="glass-card" style={{ textAlign: 'center', padding: '50px 20px', color: 'rgba(255,255,255,0.7)' }}>
          <i className="fa-solid fa-folder-open" style={{ fontSize: 36, color: '#818cf8', marginBottom: 16, display: 'block' }}></i>
          <h2 style={{ fontSize: 18, fontWeight: 700, color: '#fff', marginBottom: 8 }}>
            {error ? error : 'No Analyses Available Yet'}
          </h2>
          <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.5)', maxWidth: 400, margin: '0 auto 20px' }}>
            Upload a PCAP capture file in the workspace to inspect email traffic encryption and security postures.
          </p>
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
            Start New Analysis
          </Link>
        </div>
      </main>
    );
  }

  const score = riskInfo.risk_score || 0;
  const riskColor = getRiskColor(score);
  const riskLabel = riskInfo.risk_level || (score >= 70 ? 'HIGH' : score >= 41 ? 'MEDIUM' : 'LOW');

  // Sort findings by severity: CRITICAL -> HIGH -> MEDIUM -> LOW
  const sortedFindings = [...findings].sort((a, b) => {
    const rankA = SEVERITY_ORDER[(a.severity || '').toUpperCase()] || 99;
    const rankB = SEVERITY_ORDER[(b.severity || '').toUpperCase()] || 99;
    return rankA - rankB;
  });

  return (
    <>
      {rawResults && <PrintableReport results={rawResults} />}

      <main className="dashboard-container">
        {/* Report Export Modal */}
        {rawResults && (
          <ReportExportModal
            isOpen={isReportModalOpen}
            onClose={() => setIsReportModalOpen(false)}
            results={rawResults}
          />
        )}

        {/* Finding Detail Modal */}
        <FindingModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          activeJobId={activeJobId}
        />

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: 12, width: '100%', maxWidth: '1200px' }}>
          <h1 className="no-print" style={{
            background: 'linear-gradient(135deg, #ffffff 0%, #a5b4fc 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text',
            fontSize: 'clamp(24px, 3vw, 36px)',
            fontWeight: 800,
            letterSpacing: '-0.03em',
            margin: 0,
          }}>Dashboard</h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {activeJobId && (
              <span className="no-print" style={{ fontSize: 12, color: 'rgba(255,255,255,0.5)', background: 'rgba(255,255,255,0.06)', padding: '6px 14px', borderRadius: 999 }}>
                Active Capture: <strong style={{ color: '#a5b4fc' }}>#{activeJobId}</strong>
              </span>
            )}
            {activeJobId && (
              <div className="no-print" style={{ position: 'relative' }}>
                <button
                  onClick={() => setReportDropdownOpen(!reportDropdownOpen)}
                  className="btn-action"
                  style={{
                    margin: 0,
                    padding: '6px 16px',
                    borderRadius: '999px',
                    fontSize: '12px',
                    fontWeight: 700,
                    cursor: 'pointer',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 6,
                    background: '#ffffff',
                    color: '#000000',
                    border: 'none',
                  }}
                >
                  <i className="fa-solid fa-file-contract" style={{ fontSize: 11 }}></i>
                  Export Report <i className="fa-solid fa-chevron-down" style={{ fontSize: 9, marginLeft: 2 }} />
                </button>
                {reportDropdownOpen && (
                  <div style={{
                    position: 'absolute',
                    top: '100%',
                    right: 0,
                    marginTop: '6px',
                    background: 'rgba(10, 10, 15, 0.98)',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    borderRadius: '8px',
                    padding: '6px 0',
                    width: '240px',
                    zIndex: 9999,
                    boxShadow: '0 10px 15px -3px rgba(0,0,0,0.5)'
                  }}>
                    <a
                      href={`http://localhost:8001/api/analysis/${activeJobId}/report?format=html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={() => setReportDropdownOpen(false)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        padding: '10px 16px',
                        color: 'rgba(255, 255, 255, 0.9)',
                        fontSize: '12px',
                        textDecoration: 'none',
                        transition: 'background 0.2s',
                        fontWeight: 600
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      <i className="fa-solid fa-print" style={{ color: '#a5b4fc', width: '14px' }}></i>
                      <span>View / Print Executive Report</span>
                    </a>
                    <a
                      href={`http://localhost:8001/api/analysis/${activeJobId}/report?format=json`}
                      download
                      onClick={() => setReportDropdownOpen(false)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        padding: '10px 16px',
                        color: 'rgba(255, 255, 255, 0.9)',
                        fontSize: '12px',
                        textDecoration: 'none',
                        transition: 'background 0.2s',
                        fontWeight: 600
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      <i className="fa-solid fa-download" style={{ color: '#10b981', width: '14px' }}></i>
                      <span>Download SIEM JSON</span>
                    </a>
                    <div style={{ height: '1px', background: 'rgba(255,255,255,0.08)', margin: '4px 0' }} />
                    <button
                      onClick={() => {
                        setReportDropdownOpen(false);
                        setIsReportModalOpen(true);
                      }}
                      style={{
                        width: '100%',
                        background: 'none',
                        border: 'none',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        padding: '10px 16px',
                        color: 'rgba(255, 255, 255, 0.7)',
                        fontSize: '12px',
                        textAlign: 'left',
                        cursor: 'pointer',
                        transition: 'background 0.2s',
                        fontWeight: 600
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      <i className="fa-solid fa-display" style={{ color: '#818cf8', width: '14px' }}></i>
                      <span>Preview Print Layout (Modal)</span>
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

      <div className="dashboard-body">
        {/* Left / Main Panel */}
        <section className="main-panel">
          {/* Security Posture Card with Semicircular Risk Gauge */}
          <div className="glass-card">
            <div className="card-title">
              <i className="fa-solid fa-shield-halved"></i> Security Posture
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px' }}>
              {/* Semicircular Risk Gauge */}
              <div style={{ position: 'relative', width: '100%', maxWidth: '280px', margin: '0 auto', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                <svg viewBox="0 0 200 120" style={{ width: '100%', height: 'auto', overflow: 'visible' }}>
                  {/* Track Arc */}
                  <path
                    d="M 20 100 A 80 80 0 0 1 180 100"
                    fill="none"
                    stroke="rgba(255, 255, 255, 0.08)"
                    strokeWidth="16"
                    strokeLinecap="round"
                  />
                  {/* Active Dynamic Risk Arc */}
                  <path
                    d="M 20 100 A 80 80 0 0 1 180 100"
                    fill="none"
                    stroke={riskColor}
                    strokeWidth="16"
                    strokeLinecap="round"
                    strokeDasharray="251.327"
                    strokeDashoffset={251.327 - (Math.min(Math.max(score, 0), 100) / 100) * 251.327}
                    style={{
                      transition: 'stroke-dashoffset 0.8s ease, stroke 0.4s ease',
                      filter: `drop-shadow(0px 0px 8px ${riskColor}88)`,
                    }}
                  />
                  {/* Risk Score Display */}
                  <text
                    x="100"
                    y="80"
                    textAnchor="middle"
                    fill="#ffffff"
                    fontSize="36"
                    fontWeight="800"
                    fontFamily="system-ui, var(--font-display)"
                  >
                    {score}
                  </text>
                  <text
                    x="100"
                    y="98"
                    textAnchor="middle"
                    fill="rgba(255, 255, 255, 0.5)"
                    fontSize="12"
                    fontWeight="600"
                  >
                    / 100
                  </text>
                </svg>

                {/* Risk Level Badge */}
                <div style={{ marginTop: '-8px', textAlign: 'center' }}>
                  <h3 style={{ fontSize: '18px', fontWeight: 800, color: riskColor, margin: 0, textShadow: `0 0 16px ${riskColor}88`, letterSpacing: '0.04em' }}>
                    {riskLabel} RISK
                  </h3>
                </div>
              </div>

              {/* Risk Breakdown Counts directly sourced from API risk object */}
              <div
                style={{
                  width: '100%',
                  marginTop: '8px',
                  paddingTop: '14px',
                  borderTop: '1px solid rgba(255, 255, 255, 0.08)',
                  display: 'flex',
                  alignItems: 'center',
                  justify: 'center',
                  flexWrap: 'wrap',
                  gap: '12px',
                  fontSize: '13px',
                  fontWeight: 600,
                  color: '#e4e4e7',
                }}
              >
                <span>Critical: <strong style={{ color: '#ef4444' }}>{riskInfo.critical_count}</strong></span>
                <span style={{ color: 'rgba(255, 255, 255, 0.2)' }}>|</span>
                <span>High: <strong style={{ color: '#f97316' }}>{riskInfo.high_count}</strong></span>
                <span style={{ color: 'rgba(255, 255, 255, 0.2)' }}>|</span>
                <span>Medium: <strong style={{ color: '#f59e0b' }}>{riskInfo.medium_count}</strong></span>
                <span style={{ color: 'rgba(255, 255, 255, 0.2)' }}>|</span>
                <span>Low: <strong style={{ color: '#10b981' }}>{riskInfo.low_count}</strong></span>
              </div>
            </div>
          </div>

          {/* Charts */}
          <DashboardCharts jobId={activeJobId} />

          {/* Interactive Session Timeline */}
          <SessionTimeline sessions={rawResults?.sessions || []} />

          {/* Security Findings Section with AI Explanation & Modal trigger */}
          <div className="glass-card">
            <div className="card-title" style={{ justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <i className="fa-solid fa-triangle-exclamation"></i> Security Findings
              </div>
              {findings.length > 0 && (
                <span style={{ fontSize: 12, color: 'var(--muted)', fontWeight: 500 }}>
                  {findings.length} Finding{findings.length === 1 ? '' : 's'}
                </span>
              )}
            </div>

            {findings.length === 0 ? (
              <p style={{ fontSize: 13, color: 'var(--muted)', padding: '10px 0' }}>
                No security violations detected in this capture.
              </p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {findings.map((f, idx) => {
                  const sevLower = (f.severity || '').toLowerCase();
                  const sevLabel = f.severity || 'UNKNOWN';
                  return (
                    <div
                      key={f.id || idx}
                      onClick={() => setSelectedFinding(f)}
                      style={{
                        background: 'rgba(255, 255, 255, 0.03)',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        borderRadius: 12,
                        padding: 16,
                        cursor: 'pointer',
                        transition: 'all 0.2s ease',
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.background = 'rgba(255, 255, 255, 0.06)';
                        e.currentTarget.style.borderColor = 'rgba(99, 102, 241, 0.3)';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.background = 'rgba(255, 255, 255, 0.03)';
                        e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.08)';
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 8, marginBottom: 8 }}>
                        <div>
                          <span className={`badge badge-${sevLower}`} style={{ marginRight: 8 }}>{sevLabel}</span>
                          <span style={{ fontSize: 12, color: 'var(--muted)', fontWeight: 600 }}>{f.id}</span>
                          <h4 style={{ fontSize: 15, fontWeight: 700, color: '#fff', marginTop: 6, marginBottom: 4 }}>
                            {f.title}
                          </h4>
                        </div>
                        <button
                          type="button"
                          style={{
                            background: 'rgba(99, 102, 241, 0.15)',
                            border: '1px solid rgba(99, 102, 241, 0.3)',
                            color: '#a5b4fc',
                            padding: '4px 10px',
                            borderRadius: '6px',
                            fontSize: '11px',
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                          }}
                        >
                          <span>Full Detail</span>
                          <i className="fa-solid fa-up-right-from-square" style={{ fontSize: '10px' }} />
                        </button>
                      </div>

                      {f.description && (
                        <p style={{ fontSize: 13, color: '#e4e4e7', marginBottom: 10, lineHeight: 1.5 }}>
                          {f.description}
                        </p>
                      )}

                      {f.evidence && (
                        <div style={{ marginBottom: 12 }}>
                          <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                            Deterministic Evidence
                          </div>
                          <div className="code-block" style={{ fontSize: 12, background: 'rgba(0, 0, 0, 0.4)', padding: '8px 12px', borderRadius: 8, color: '#a1a1aa' }}>
                            {f.evidence}
                          </div>
                        </div>
                      )}

                      {/* AI Explanation Panel */}
                      <div onClick={(e) => e.stopPropagation()}>
                        <AIExplanation finding={f} />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Certificate Analysis Section */}
          <div className="glass-card">
            <div className="card-title" style={{ justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <i className="fa-solid fa-certificate" style={{ color: '#a5b4fc' }}></i> Certificate Analysis
              </div>
              {certificates.length > 0 && (
                <span style={{ fontSize: 12, color: 'var(--muted)', fontWeight: 500 }}>
                  {certificates.length} Certificate{certificates.length === 1 ? '' : 's'}
                </span>
              )}
            </div>

            {certificates.length === 0 ? (
              <p style={{ fontSize: 13, color: 'var(--muted)', padding: '10px 0' }}>
                No certificates detected in this capture
              </p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {certificates.map((cert, idx) => (
                  <CertificateViewer key={cert.serial || idx} certificate={cert} />
                ))}
              </div>
            )}
          </div>

          {/* Recent Analyses */}
          <div className="glass-card">
            <div className="card-title">
              <i className="fa-solid fa-clock-rotate-left"></i> Recent Analyses
            </div>
            <div className="analyses-list">
              {recentAnalyses.length === 0 ? (
                <p style={{ fontSize: 13, color: 'var(--muted)', padding: '10px 0' }}>No recent captures found.</p>
              ) : (
                recentAnalyses.slice(0, 4).map(item => {
                  const ts = item.timestamp ? new Date(item.timestamp) : null;
                  const dateStr = ts && !isNaN(ts.getTime())
                    ? ts.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
                    : '--';
                  return (
                    <div key={item.capture_id} className="analysis-row">
                      <div className="analysis-info">
                        <span className="analysis-name">{item.filename || 'Unknown Capture'}</span>
                        <div className="analysis-meta">
                          <span>ID: #{item.capture_id}</span>{' '}
                          <span>{dateStr}</span>{' '}
                          <span>{item.session_count ?? 0} Sessions</span>
                        </div>
                      </div>
                      <Link to={`/analysis?job=${item.capture_id}`} className="btn-small">View</Link>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </section>

        {/* Right / Side Panel */}
        <section className="side-panel">
          {/* Capture Summary */}
          <div className="glass-card">
            <div className="card-title">
              <i className="fa-solid fa-file-invoice"></i> Capture Summary
            </div>
            <div className="metrics-grid">
              <div className="metric-box">
                <div className="metric-value">{metrics.totalSize} <span style={{ fontSize: '14px' }}>MB</span></div>
                <div className="metric-label">Total Size</div>
              </div>
              <div className="metric-box">
                <div className="metric-value">{metrics.sessions}</div>
                <div className="metric-label">Sessions</div>
              </div>
              <div className="metric-box">
                <div className="metric-value">{metrics.tlsSessions}</div>
                <div className="metric-label">TLS Sessions</div>
              </div>
              <div className="metric-box">
                <div className="metric-value">{metrics.plaintextEmails}</div>
                <div className="metric-label">Plaintext Emails</div>
              </div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="glass-card">
            <div className="card-title">
              <i className="fa-solid fa-bolt"></i> Quick Actions
            </div>
            <div className="action-stack">
              <Link to="/workspace" className="btn-action">
                <i className="fa-solid fa-upload"></i>
                <span>New Analysis</span>
              </Link>
              <Link to={`/analysis?job=${activeJobId}&tab=findings`} className="btn-action">
                <i className="fa-solid fa-triangle-exclamation"></i>
                <span>View Findings</span>
              </Link>
              <Link to={`/analysis?job=${activeJobId}&tab=sessions`} className="btn-action">
                <i className="fa-solid fa-network-wired"></i>
                <span>Explore Sessions</span>
              </Link>
            </div>
          </div>
        </section>
      </div>

      {/* Global Action Plan Section (Consolidated Roadmap at Bottom of Dashboard) */}
      <div style={{ width: '100%', maxWidth: '1200px' }}>
        <div className="glass-card" style={{ width: '100%', margin: 0 }}>
          <div className="card-title" style={{ justifyContent: 'space-between', marginBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <i className="fa-solid fa-list-check" style={{ color: '#818cf8' }}></i>
              <span style={{ fontSize: 'clamp(18px, 2.5vw, 22px)', fontWeight: 800 }}>Action Plan</span>
            </div>
            {sortedFindings.length > 0 && (
              <span style={{ fontSize: 12, color: 'var(--muted)', background: 'rgba(255,255,255,0.06)', padding: '4px 12px', borderRadius: 999 }}>
                {sortedFindings.length} Action Item{sortedFindings.length === 1 ? '' : 's'}
              </span>
            )}
          </div>

          <p style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 20, maxWidth: 680, lineHeight: 1.5 }}>
            Consolidated remediation roadmap across all security findings in this packet capture, prioritized by severity (Critical → High → Medium → Low).
          </p>

          {sortedFindings.length === 0 ? (
            <p style={{ fontSize: 13, color: 'var(--muted)', padding: '16px 0', textAlign: 'center' }}>
              No security remediation actions required for this capture.
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {sortedFindings.map((f, idx) => (
                <RemediationCard key={f.id || idx} finding={f} />
              ))}
            </div>
          )}
        </div>
      </div>
    </main>
    </>
  );
}

export default Dashboard;
