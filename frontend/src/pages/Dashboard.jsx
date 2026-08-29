import React, { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import './Dashboard.css';
import { getAnalysisResults } from '../utils/api';
import { DashboardCharts } from '../components/DashboardCharts';

export function Dashboard() {
  const { captureId } = useParams();
  const jobId = captureId || '8320'; // fallback for backward compatibility
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [metrics, setMetrics] = useState({ totalSize: "0 MB", sessions: 0, tlsSessions: 0, plaintextEmails: 0, riskScore: 0, riskLevel: 'UNKNOWN' });

  useEffect(() => {
    if (!jobId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    getAnalysisResults(jobId)
      .then((data) => {
        const summary = data.summary || {};
        setMetrics({
          totalSize: summary.totalSize || "0 MB",
          sessions: summary.sessions || 0,
          tlsSessions: summary.tlsSessions || 0,
          plaintextEmails: summary.plaintextEmails || 0,
          riskScore: summary.riskScore || 0,
          riskLevel: summary.riskLevel || 'UNKNOWN',
        });
        setLoading(false);
      })
      .catch((err) => {
        console.error(err);
        setError('Failed to load dashboard data');
        setLoading(false);
      });
  }, [jobId]);

  if (loading) return <div className="dashboard-loading" style={{ color: '#fff' }}>Loading dashboard...</div>;
  if (error) return <div className="dashboard-error" style={{ color: 'red' }}>{error}</div>;

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
        marginBottom: '4px',
      }}>Dashboard</h1>
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
              {/* Dynamic conic-gradient: arc = (score/100)*360deg */}
              {(() => {
                const score = metrics.riskScore || 0;
                const deg = Math.round((score / 100) * 360);
                const riskColor = score >= 75 ? '#ef4444' : score >= 40 ? '#f59e0b' : '#10b981';
                const riskLabel = score >= 75 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';
                return (
                  <>
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
                  </>
                );
              })()}
            </div>
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
              <span className="badge badge-critical">2 Critical</span>
              <span className="badge badge-high">3 High</span>
              <span className="badge badge-high" style={{ background: 'rgba(234, 179, 8, 0.2)', color: '#eab308', border: '1px solid rgba(234, 179, 8, 0.3)' }}>4 Medium</span>
            </div>
          </div>
        </div>

        {/* Recent Analyses */}
        <DashboardCharts jobId={jobId} />
        <div className="glass-card">
          <div className="card-title">
            <i className="fa-solid fa-clock-rotate-left"></i> Recent Analyses
          </div>
          <div className="analyses-list">
            <div className="analysis-row">
              <div className="analysis-info">
                <span className="analysis-name">Mail-Server-Audit.pcap</span>
                <div className="analysis-meta">
                  <span>ID: #8320</span>{' '}
                  <span>Aug 24, 2026</span>{' '}
                  <span>9 Sessions</span>
                </div>
              </div>
              <Link to="/analysis?job=8320" className="btn-small">View</Link>
            </div>
            <div className="analysis-row">
              <div className="analysis-info">
                <span className="analysis-name">Internal-SMTP-Leaked-Traffic.pcapng</span>
                <div className="analysis-meta">
                  <span>ID: #8318</span>{' '}
                  <span>Aug 21, 2026</span>{' '}
                  <span>34 Sessions</span>
                </div>
              </div>
              <Link to="/analysis?job=8318" className="btn-small">View</Link>
            </div>
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
            <Link to="/" className="btn-action">
              <i className="fa-solid fa-upload"></i>
              <span>New Analysis</span>
            </Link>
            <Link to="/analysis?job=8320&tab=findings" className="btn-action">
              <i className="fa-solid fa-triangle-exclamation"></i>
              <span>View Findings</span>
            </Link>
            <Link to="/analysis?job=8320&tab=sessions" className="btn-action">
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
