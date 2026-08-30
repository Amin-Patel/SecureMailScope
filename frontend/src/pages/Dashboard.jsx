import React, { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import './Dashboard.css';
import { getAnalysisResults, getAnalyses } from '../utils/api';
import { DashboardCharts } from '../components/DashboardCharts';

export function Dashboard() {
  const { captureId } = useParams();
  const [activeJobId, setActiveJobId] = useState(captureId || null);
  const [recentAnalyses, setRecentAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [metrics, setMetrics] = useState({
    totalSize: "0 MB",
    sessions: 0,
    tlsSessions: 0,
    plaintextEmails: 0,
    riskScore: 0,
    riskLevel: 'UNKNOWN',
    criticalCount: 0,
    highCount: 0,
    medCount: 0,
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

        if (targetId) {
          return getAnalysisResults(targetId);
        }
        return null;
      })
      .then(data => {
        if (!isMounted) return;
        if (data) {
          const summary = data.summary || {};
          const fileSizeBytes = data.file_size || 0;
          const totalSizeMB = fileSizeBytes > 0
            ? (fileSizeBytes / (1024 * 1024)).toFixed(2)
            : '0';
          const encryptedSessions = (data.sessions || []).filter(s => s.encrypted).length;
          const plaintextCount = (data.sessions || []).filter(s => !s.encrypted).length;
          const findings = data.findings || [];

          const critical = findings.filter(f => (f.severity || '').toUpperCase() === 'CRITICAL').length;
          const high = findings.filter(f => (f.severity || '').toUpperCase() === 'HIGH').length;
          const med = findings.filter(f => (f.severity || '').toUpperCase() === 'MEDIUM').length;

          setMetrics({
            totalSize: totalSizeMB,
            sessions: summary.session_count || (data.sessions || []).length,
            tlsSessions: encryptedSessions,
            plaintextEmails: plaintextCount,
            riskScore: summary.risk_score ?? data.risk?.risk_score ?? 0,
            riskLevel: summary.risk_level || data.risk?.risk_level || 'UNKNOWN',
            criticalCount: critical,
            highCount: high,
            medCount: med,
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

  const score = metrics.riskScore || 0;
  const deg = Math.round((score / 100) * 360);
  const riskColor = score >= 75 ? '#ef4444' : score >= 40 ? '#f59e0b' : '#10b981';
  const riskLabel = score >= 75 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';

  return (
    <main className="dashboard-container">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: 12 }}>
        <h1 style={{
          background: 'linear-gradient(135deg, #ffffff 0%, #a5b4fc 100%)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          backgroundClip: 'text',
          fontSize: 'clamp(24px, 3vw, 36px)',
          fontWeight: 800,
          letterSpacing: '-0.03em',
          margin: 0,
        }}>Dashboard</h1>
        {activeJobId && (
          <span style={{ fontSize: 12, color: 'rgba(255,255,255,0.5)', background: 'rgba(255,255,255,0.06)', padding: '6px 14px', borderRadius: 999 }}>
            Active Capture: <strong style={{ color: '#a5b4fc' }}>#{activeJobId}</strong>
          </span>
        )}
      </div>

      <div className="dashboard-body">
        {/* Left / Main Panel */}
        <section className="main-panel">
          {/* Security Posture Card */}
          <div className="glass-card">
            <div className="card-title">
              <i className="fa-solid fa-shield-halved"></i> Security Posture
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '24px', alignItems: 'center', justifyContent: 'space-between' }}>
              <div className="score-circle-wrapper">
                <div className="score-circle" style={{
                  background: `conic-gradient(${riskColor} 0deg ${deg}deg, rgba(255,255,255,0.08) ${deg}deg)`,
                  boxShadow: `0 0 24px rgba(${riskColor === '#ef4444' ? '239,68,68' : riskColor === '#f59e0b' ? '245,158,11' : '16,185,129'},0.4)`,
                }}>
                  <span className="score-number">{score}</span>
                  <span className="score-max">/100</span>
                </div>
                <div>
                  <h3 style={{ fontSize: '18px', fontWeight: 700, color: riskColor, marginBottom: '4px', textShadow: `0 0 16px ${riskColor}99` }}>
                    {riskLabel} RISK
                  </h3>
                  <p style={{ fontSize: '12px', color: 'var(--muted)', maxWidth: '280px' }}>
                    {score >= 75
                      ? 'Critical cryptographic and plaintext mail traffic violations identified.'
                      : score >= 40
                      ? 'Moderate security issues detected. Review findings and remediate.'
                      : 'No critical issues detected. Mail security posture is healthy.'}
                  </p>
                </div>
              </div>
              <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                {metrics.criticalCount > 0 && <span className="badge badge-critical">{metrics.criticalCount} Critical</span>}
                {metrics.highCount > 0 && <span className="badge badge-high">{metrics.highCount} High</span>}
                {metrics.medCount > 0 && <span className="badge badge-medium" style={{ background: 'rgba(234, 179, 8, 0.2)', color: '#eab308', border: '1px solid rgba(234, 179, 8, 0.3)' }}>{metrics.medCount} Medium</span>}
                {metrics.criticalCount === 0 && metrics.highCount === 0 && metrics.medCount === 0 && (
                  <span className="badge badge-low">0 Violations</span>
                )}
              </div>
            </div>
          </div>

          {/* Charts */}
          <DashboardCharts jobId={activeJobId} />

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
    </main>
  );
}

