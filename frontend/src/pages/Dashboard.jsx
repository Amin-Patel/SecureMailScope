import React from 'react';
import { Link } from 'react-router-dom';

export function Dashboard() {
  return (
    <main className="dashboard-container">
      {/* Left / Main Panel */}
      <section className="main-panel">
        {/* Security Posture Card */}
        <div className="glass-card">
          <div className="card-title">
            <i className="fa-solid fa-shield-halved"></i> Security Posture
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '24px', alignItems: 'center', justifyContent: 'space-between' }}>
            <div className="score-circle-wrapper">
              <div className="score-circle">
                <span className="score-number">82</span>
                <span className="score-max">/100</span>
              </div>
              <div>
                <h3 style={{ fontSize: '18px', fontWeight: 600, color: '#ef4444', marginBottom: '4px' }}>HIGH RISK</h3>
                <p style={{ fontSize: '12px', color: 'var(--muted)', maxWidth: '280px' }}>
                  Critical cryptographic and plaintext mail traffic violations identified.
                </p>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
              <span className="badge badge-critical">2 Critical</span>
              <span className="badge badge-high">3 High</span>
              <span className="badge badge-high" style={{ background: 'rgba(234, 179, 8, 0.2)', color: '#eab308', border: '1px solid rgba(234, 179, 8, 0.3)' }}>4 Medium</span>
            </div>
          </div>
        </div>

        {/* Recent Analyses */}
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
              <Link to="/analysis?id=8320" className="btn-small">View</Link>
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
              <Link to="/analysis?id=8318" className="btn-small">View</Link>
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
              <div className="metric-value">45.2 <span style={{ fontSize: '14px' }}>MB</span></div>
              <div className="metric-label">Total Size</div>
            </div>
            <div className="metric-box">
              <div className="metric-value">918</div>
              <div className="metric-label">Sessions</div>
            </div>
            <div className="metric-box">
              <div className="metric-value">124</div>
              <div className="metric-label">TLS Sessions</div>
            </div>
            <div className="metric-box">
              <div className="metric-value">3</div>
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
            <Link to="/analysis?id=8320&tab=findings" className="btn-action">
              <i className="fa-solid fa-triangle-exclamation"></i>
              <span>View Findings</span>
            </Link>
            <Link to="/analysis?id=8320&tab=sessions" className="btn-action">
              <i className="fa-solid fa-network-wired"></i>
              <span>Explore Sessions</span>
            </Link>
          </div>
        </div>
      </section>
    </main>
  );
}
