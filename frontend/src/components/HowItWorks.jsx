import React from 'react';
import './HowItWorks.css';

export default function HowItWorks() {
  const forensicStages = [
    {
      num: 'STAGE 01',
      title: 'PCAP',
      desc: 'Upload a captured network trace containing email traffic.',
      tech: '.pcap / .pcapng',
      extract: 'Packets',
      icon: 'fa-solid fa-file-import',
      color: '#3b82f6',
      bg: 'rgba(59, 130, 246, 0.1)',
      border: 'rgba(59, 130, 246, 0.25)'
    },
    {
      num: 'STAGE 02',
      title: 'Email Traffic Detection',
      desc: 'Identify SMTP, IMAP, POP3 and related email communication from the capture.',
      tech: 'Protocol Detection',
      extract: 'SMTP / IMAP / POP3',
      icon: 'fa-solid fa-envelope',
      color: '#06b6d4',
      bg: 'rgba(6, 182, 212, 0.1)',
      border: 'rgba(6, 182, 212, 0.25)'
    },
    {
      num: 'STAGE 03',
      title: 'TLS & Certificate Analysis',
      desc: 'Inspect TLS handshakes, versions, certificates and cryptographic parameters.',
      tech: 'TLS • X.509 • Crypto',
      extract: 'TLS Versions / Certificates / Ciphers',
      icon: 'fa-solid fa-certificate',
      color: '#6366f1',
      bg: 'rgba(99, 102, 241, 0.1)',
      border: 'rgba(99, 102, 241, 0.25)'
    },
    {
      num: 'STAGE 04',
      title: 'Security Assessment',
      desc: 'Evaluate encryption, certificate validity and cryptographic security conditions.',
      tech: 'Forensic Analysis',
      extract: 'Encryption & Crypto Weaknesses',
      icon: 'fa-solid fa-shield-halved',
      color: '#a855f7',
      bg: 'rgba(168, 85, 247, 0.1)',
      border: 'rgba(168, 85, 247, 0.25)'
    },
    {
      num: 'STAGE 05',
      title: 'Risk & Findings',
      desc: 'Convert observed weaknesses into prioritized security findings and risk levels.',
      tech: 'CRITICAL • HIGH • MEDIUM • LOW',
      extract: 'Severity / Evidence / Risk Score',
      icon: 'fa-solid fa-triangle-exclamation',
      color: '#ef4444',
      bg: 'rgba(239, 68, 68, 0.1)',
      border: 'rgba(239, 68, 68, 0.25)'
    }
  ];

  const intelligenceStages = [
    {
      num: 'STAGE 06',
      title: 'AI Explanation',
      desc: 'Explain what the evidence means, why it matters and how it affects email security.',
      tech: 'AI Security Interpretation',
      extract: 'Context / Interpretation',
      icon: 'fa-solid fa-robot',
      color: '#d946ef',
      bg: 'rgba(217, 70, 239, 0.1)',
      border: 'rgba(217, 70, 239, 0.25)'
    },
    {
      num: 'STAGE 07',
      title: 'Remediation',
      desc: 'Translate findings into practical actions for improving email security.',
      tech: 'Action Plan',
      extract: 'Recommended Actions',
      icon: 'fa-solid fa-wrench',
      color: '#10b981',
      bg: 'rgba(16, 185, 129, 0.1)',
      border: 'rgba(16, 185, 129, 0.25)'
    },
    {
      num: 'STAGE 08',
      title: 'Report',
      desc: 'Package the assessment into an executive forensic report and machine-readable output.',
      tech: 'HTML • PDF • JSON',
      extract: 'Forensic Assessment',
      icon: 'fa-solid fa-file-contract',
      color: '#3b82f6',
      bg: 'rgba(59, 130, 246, 0.1)',
      border: 'rgba(59, 130, 246, 0.25)'
    }
  ];

  return (
    <section className="how-it-works-section" id="how-it-works">
      <h2>How SecureMailScope Works</h2>
      <p className="sub-desc">
        From captured email traffic to verified security findings, SecureMailScope follows a structured forensic pipeline to identify encryption, TLS, certificate and cryptographic weaknesses.
      </p>

      {/* Group 1: Forensic Analysis */}
      <div className="pipeline-group forensic">
        <div className="group-header">
          <i className="fa-solid fa-magnifying-glass-chart" />
          <span>Forensic Processing &amp; Verification</span>
        </div>
        <div className="flow-row">
          {forensicStages.map((stage, idx) => (
            <React.Fragment key={stage.num}>
              <div
                className="flow-card"
                style={{
                  border: `1px solid ${stage.border}`,
                  boxShadow: `0 4px 20px ${stage.bg}`
                }}
              >
                {/* Visual Top Glow Accent Bar */}
                <div style={{ height: '3px', background: stage.color, margin: '-14px -14px 12px', boxShadow: `0 2px 8px ${stage.color}aa` }} />
                
                <div className="card-top">
                  <div className="card-num">{stage.num}</div>
                  <div className="card-title-row">
                    <i className={stage.icon} style={{ color: stage.color }} />
                    <h3>{stage.title}</h3>
                  </div>
                  <p>{stage.desc}</p>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: 'auto' }}>
                  <div className="extraction-badge">
                    <i className="fa-solid fa-arrow-right-from-bracket" style={{ fontSize: '8px', opacity: 0.7 }} />
                    <span>Extracts: {stage.extract}</span>
                  </div>
                  <div className="card-tech-label" style={{ color: stage.color }}>
                    {stage.tech}
                  </div>
                </div>
              </div>
              {idx < forensicStages.length - 1 && (
                <div className="connector-arrow">
                  <i className="fa-solid fa-chevron-right" />
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Transition indicator */}
      <div className="down-connector">
        <i className="fa-solid fa-chevron-down" style={{ fontSize: '20px' }} />
      </div>

      {/* Group 2: Intelligence & Response */}
      <div className="pipeline-group intelligence">
        <div className="group-header">
          <i className="fa-solid fa-brain" />
          <span>Intelligence &amp; Response Action</span>
        </div>
        <div className="flow-row" style={{ maxWidth: '80%', margin: '0 auto' }}>
          {intelligenceStages.map((stage, idx) => (
            <React.Fragment key={stage.num}>
              <div
                className="flow-card"
                style={{
                  border: `1px solid ${stage.border}`,
                  boxShadow: `0 4px 20px ${stage.bg}`
                }}
              >
                {/* Visual Top Glow Accent Bar */}
                <div style={{ height: '3px', background: stage.color, margin: '-14px -14px 12px', boxShadow: `0 2px 8px ${stage.color}aa` }} />
                
                <div className="card-top">
                  <div className="card-num">{stage.num}</div>
                  <div className="card-title-row">
                    <i className={stage.icon} style={{ color: stage.color }} />
                    <h3>{stage.title}</h3>
                  </div>
                  <p>{stage.desc}</p>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: 'auto' }}>
                  <div className="extraction-badge">
                    <i className="fa-solid fa-arrow-right-from-bracket" style={{ fontSize: '8px', opacity: 0.7 }} />
                    <span>Extracts: {stage.extract}</span>
                  </div>
                  <div className="card-tech-label" style={{ color: stage.color }}>
                    {stage.tech}
                  </div>
                </div>
              </div>
              {idx < intelligenceStages.length - 1 && (
                <div className="connector-arrow">
                  <i className="fa-solid fa-chevron-right" />
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>
    </section>
  );
}
