import React, { useState } from 'react';

const FAQ_DATA = [
  {
    question: 'What is SecureMailScope?',
    answer:
      'SecureMailScope is an AI-driven email-security assessment and forensics platform. Its primary purpose is to inspect raw network capture files (.pcap/.pcapng), reconstruct email transport streams (SMTP, IMAP, POP3), audit TLS and X.509 certificate characteristics, and deliver precise security findings alongside prioritized remediation steps and automated PDF/JSON security reports.',
    extra: null,
  },
  {
    question: 'How does the analysis workflow operate?',
    answer: null,
    extra: (
      <>
        <p style={{ marginBottom: '4px' }}>The pipeline functions in sequence:</p>
        <ol style={{ marginLeft: '20px', marginTop: '6px' }}>
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
    answer: null,
    extra: (
      <>
        <p style={{ marginBottom: '10px' }}>Findings are classified under 4 severities to guide remediation:</p>
        <div className="help-icon-list">
          {[
            { cls: 'badge-critical', label: 'Critical', desc: 'Immediate exploit risk (e.g., credentials leaked in plaintext, invalid trust chains).' },
            { cls: 'badge-high', label: 'High', desc: 'Vulnerable setup allowing decryption or interception (e.g., deprecated TLS 1.0 protocols).' },
            { cls: 'badge-medium', label: 'Medium', desc: 'Suboptimal configurations or deprecated suites (e.g., legacy RC4 or 3DES ciphers).' },
            { cls: 'badge-low', label: 'Low', desc: 'Informational or minor audit inconsistencies.' },
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
    extra: null,
  },
];

function AccordionItem({ question, answer, extra }) {
  const [open, setOpen] = useState(false);

  return (
    <div className={`accordion-item ${open ? 'active' : ''}`}>
      <div className="accordion-header" onClick={() => setOpen((prev) => !prev)}>
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
      <div className="help-title-bar">
        <h2 style={{ fontSize: 'clamp(16px, 2.2vw, 22px)', fontWeight: 600, color: '#ffffff' }}>
          Help &amp; Knowledge Base
        </h2>
      </div>

      {FAQ_DATA.map((item) => (
        <AccordionItem key={item.question} {...item} />
      ))}
    </main>
  );
}
