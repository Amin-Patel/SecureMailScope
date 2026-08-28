import React, { useState } from 'react';

const FAQ_DATA = [
  {
    question: 'What is SecureMailScope?',
    answer:
      'SecureMailScope is an AI-driven email-security assessment and forensics platform. Its primary purpose is to inspect raw network capture files (.pcap/.pcapng), reconstruct email transport streams (SMTP, IMAP, POP3), audit TLS and X.509 certificate characteristics, and deliver precise security findings alongside prioritized remediation steps and automated PDF/JSON security reports.',
  },
  {
    question: 'How does the analysis workflow operate?',
    extra: (
      <>
        <p style={{ marginBottom: 4 }}>The pipeline functions in sequence:</p>
        <ol style={{ marginLeft: 20, marginTop: 6, display: 'flex', flexDirection: 'column', gap: 6 }}>
          <li><strong>PCAP Ingestion:</strong> The packet capture is processed using protocol analysis engines.</li>
          <li><strong>Session Reconstruction:</strong> Reconstructs raw mail connections into interactive audit streams.</li>
          <li><strong>TLS / Certificate Audit:</strong> Analyzes negotiated cipher strengths and validates certificates.</li>
          <li><strong>Risk Engine:</strong> Scores the security posture based on deterministic security rules.</li>
          <li><strong>AI Explanations:</strong> Connects raw packet evidence with explanations detailing why findings matter.</li>
        </ol>
      </>
    ),
  },
  {
    question: 'What do the Finding Severities indicate?',
    extra: (
      <>
        <p style={{ marginBottom: 10 }}>Findings are classified under 4 severities to guide remediation:</p>
        <div className="help-icon-list">
          {[
            { cls: 'badge-critical', label: 'Critical', desc: 'Immediate exploit risk (e.g., credentials leaked in plaintext, invalid trust chains).' },
            { cls: 'badge-high',     label: 'High',     desc: 'Vulnerable setup allowing decryption or interception (e.g., deprecated TLS 1.0 protocols).' },
            { cls: 'badge-medium',   label: 'Medium',   desc: 'Suboptimal configurations or deprecated suites (e.g., legacy RC4 or 3DES ciphers).' },
            { cls: 'badge-low',      label: 'Low',      desc: 'Informational or minor audit inconsistencies.' },
          ].map(({ cls, label, desc }) => (
            <div className="help-icon-item" key={label}>
              <span className={`badge ${cls}`}>{label}</span>
              <span>{desc}</span>
            </div>
          ))}
        </div>
      </>
    ),
  },
  {
    question: 'What input file formats are supported?',
    answer:
      'SecureMailScope supports standard network packet capture formats including .pcap and .pcapng. Ensure that the packet capture contains valid mail traffic (SMTP/IMAP/POP3 over ports 25, 465, 587, 993, 110, or custom defined mail ports).',
  },
  {
    question: 'Can I export my analysis results?',
    answer:
      'Yes. Navigate to the Analysis Workspace for any job and open the Report tab. You can export a structured JSON report containing all findings, sessions, and risk scoring data. HTML report export is coming in a future release.',
  },
];

function AccordionItem({ question, answer, extra }) {
  const [open, setOpen] = useState(false);

  return (
    <div className={`accordion-item ${open ? 'active' : ''}`}>
      <div className="accordion-header" onClick={() => setOpen(prev => !prev)}>
        <span>{question}</span>
        <i className="fa-solid fa-chevron-down"></i>
      </div>
      <div className="accordion-content">
        {answer && <p>{answer}</p>}
        {extra}
      </div>
    </div>
  );
}

export function Help() {
  return (
    <main className="help-container">
      {/* Title */}
      <div className="help-title-bar">
        <h2 style={{
          background: 'linear-gradient(135deg, #ffffff 0%, #a5b4fc 100%)',
          WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
          backgroundClip: 'text',
          fontSize: 'clamp(22px, 3vw, 32px)', fontWeight: 800, letterSpacing: '-0.03em', marginBottom: 6,
        }}>
          Help &amp; Knowledge Base
        </h2>
        <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.45)' }}>Answers to common questions about SecureMailScope</p>
      </div>

      {/* FAQ */}
      {FAQ_DATA.map(item => (
        <AccordionItem key={item.question} {...item} />
      ))}

      {/* Contact footer */}
      <div style={{
        marginTop: 28,
        background: 'rgba(10,10,18,0.65)', backdropFilter: 'blur(16px)',
        border: '1px solid rgba(255,255,255,0.08)', borderRadius: 14,
        padding: '20px 24px',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16,
      }}>
        <div>
          <div style={{ fontSize: 14, fontWeight: 600, color: '#fff', marginBottom: 4 }}>Still have questions?</div>
          <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.45)' }}>Reach out to the SecureMailScope team</div>
        </div>
        <a
          href="mailto:support@securemailscope.com"
          style={{
            display: 'inline-flex', alignItems: 'center', gap: 8,
            padding: '10px 20px', borderRadius: 10,
            background: 'rgba(99,102,241,0.2)', border: '1px solid rgba(99,102,241,0.35)',
            color: '#a5b4fc', fontSize: 13, fontWeight: 600, textDecoration: 'none',
          }}
        >
          <i className="fa-solid fa-envelope"></i>
          Contact Support
        </a>
      </div>
    </main>
  );
}
