import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { PcapUpload } from '../components/upload/PcapUpload';

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
    <main className="hero">
      {/* Trust Row */}
      <div className="trust-row anim" style={{ '--d': '0.05s' }}>
        <div className="trust-avatars">
          <div className="trust-avatar avatar-microsoft">
            <div className="inner-circle">
              <i className="fa-brands fa-microsoft"></i>
            </div>
          </div>
          <div className="trust-avatar avatar-amazon">
            <div className="inner-circle">
              <i className="fa-brands fa-amazon"></i>
            </div>
          </div>
          <div className="trust-avatar avatar-google">
            <div className="inner-circle">
              <i className="fa-brands fa-google"></i>
            </div>
          </div>
        </div>
        <div className="trust-pill">Trusted by 2000+ Enterprises</div>
      </div>

      {/* Headline */}
      <h1 className="headline">
        <span className="line-1">Intelligence</span>
        <span className="line-2">Designed To Evolve</span>
      </h1>

      {/* Subhead */}
      <p className="subhead anim" style={{ '--d': '0.28s' }}>
        Build applications that reason, adapt and collaborate using a modular AI platform designed
        for production.
      </p>

      {/* PCAP Upload */}
      <div
        id="pcap-upload-container"
        className="anim"
        style={{ '--d': '0.4s', width: '100%', maxWidth: '480px', margin: '0 auto' }}
      >
        <PcapUpload
          onAnalysisStart={(file) => {
            navigate(`/analysis?id=8320&file=${encodeURIComponent(file.name)}`);
          }}
        />
      </div>
    </main>
  );
}
