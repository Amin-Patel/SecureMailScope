import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { PcapUpload } from '../components/upload/PcapUpload';
import HowItWorks from '../components/HowItWorks';
import { uploadPcap } from '../utils/api';

export function NewAnalysis() {
  const navigate = useNavigate();

  // Entrance animations (mirrors setupEntranceAnimations from main.js)
  useEffect(() => {
    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const animElements = document.querySelectorAll('.anim');

    if (prefersReduced) {
      animElements.forEach((el) => {
        el.classList.add('reveal');
        el.style.opacity = '1';
        el.style.transform = 'none';
        el.style.filter = 'none';
      });
      return;
    }

    animElements.forEach((el) => {
      if (!el.classList.contains('headline') && !el.closest('.headline')) {
        el.classList.add('reveal');
      }
    });
  }, []);

  return (
    <>
      <main className="hero">
        {/* Page Title */}
        <h2 className="product-name" style={{ fontFamily: 'var(--font-display)', fontSize: 'clamp(24px,5vw,48px)', color: '#ffffff', marginBottom: '0.5rem' }}>SecureMailScope</h2>

        {/* Subhead */}
        <p className="subhead anim" style={{ '--d': '0.28s', fontSize: 'clamp(14px,1.6vw,16px)', marginBottom: '1rem' }}>
          Upload a PCAP or PCAPNG file to start a new forensic email security investigation.
        </p>

        {/* CTA Buttons */}
        <div className="cta-group" style={{ display: 'flex', gap: '12px', marginBottom: '1.5rem' }}>
          <button className="cta-btn" onClick={() => navigate('/analysis?job=8320')}>Load Sample Analysis</button>
          <button className="cta-btn secondary-cta" onClick={() => document.getElementById('how-it-works').scrollIntoView({ behavior: 'smooth' })}>See How It Works</button>
        </div>

        {/* PCAP Upload */}
        <div id="pcap-upload-container" className="anim" style={{ '--d': '0.4s', width: '100%', maxWidth: '480px', margin: '0 auto' }}>
          <PcapUpload onAnalysisStart={async (file) => {
            try {
              const response = await uploadPcap(file);
              const captureId = response.capture_id;
              navigate(`/dashboard/${captureId}`);
            } catch (err) {
              console.error('Upload failed', err);
            }
          }} />
        </div>
      </main>
      <section id="how-it-works" className="how-it-works-section">
        <HowItWorks />
      </section>
    </>
  );
}
