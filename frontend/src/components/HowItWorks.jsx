import React from 'react';
import './HowItWorks.css';

export default function HowItWorks() {
  return (
    <section className="how-it-works-section" style={{ padding: '2rem', textAlign: 'center', color: '#ffffff' }}>
      {/* Placeholder: visual representation of the analysis pipeline will be added later */}
      <h2 style={{ fontFamily: 'var(--font-display)', fontSize: 'clamp(24px,5vw,36px)', marginBottom: '1rem' }}>How SecureMailScope Works</h2>
      <p style={{ fontFamily: 'var(--font-sans)', fontSize: 'clamp(14px,1.6vw,16px)' }}>
        PCAP → Email Traffic Detection → TLS &amp; Certificate Analysis → Security Assessment →
        Risk &amp; Findings → AI Explanation → Remediation → Report
      </p>
    </section>
  );
}
