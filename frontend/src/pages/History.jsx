import React from 'react';
import { Link } from 'react-router-dom';

const HISTORY_DATA = [
  { id: '8320', name: 'Mail-Server-Audit.pcap', date: 'Aug 24, 2026 22:30', findings: 4, score: 82, scoreColor: '#ef4444' },
  { id: '8318', name: 'Internal-SMTP-Leaked-Traffic.pcapng', date: 'Aug 21, 2026 14:15', findings: 12, score: 64, scoreColor: '#f97316' },
  { id: '8310', name: 'External-SMTP-Test.pcap', date: 'Aug 15, 2026 09:12', findings: 0, score: 100, scoreColor: '#10b981' },
];

export function History() {
  return (
    <main className="history-container">
      <div className="history-title-bar">
        <h2 style={{ fontSize: 'clamp(16px, 2.2vw, 22px)', fontWeight: 600, color: '#ffffff' }}>
          Analysis History
        </h2>
      </div>

      <div className="history-list">
        {HISTORY_DATA.map((entry) => (
          <div className="history-card" key={entry.id}>
            <div className="history-details">
              <span className="history-name">{entry.name}</span>
              <div className="history-meta">
                <span>Job ID: #{entry.id}</span>{' '}
                <span>{entry.date}</span>{' '}
                <span>{entry.findings} Findings</span>
              </div>
            </div>
            <div className="history-stats">
              <div className="score-badge" style={{ borderColor: entry.scoreColor }}>
                {entry.score}
              </div>
              <div className="btn-group">
                <Link to={`/analysis?id=${entry.id}`} className="btn-action">Open Workspace</Link>
                <Link to={`/analysis?id=${entry.id}&tab=report`} className="btn-action btn-secondary">Report</Link>
              </div>
            </div>
          </div>
        ))}
      </div>
    </main>
  );
}
