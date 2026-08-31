import React, { useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { PcapUpload } from '../components/upload/PcapUpload';
import HowItWorks from '../components/HowItWorks';
import { uploadPcap, loadDemo, getDemoSamples } from '../utils/api';

export function NewAnalysis() {
  const navigate = useNavigate();
  const location = useLocation();
  const [demoLoading, setDemoLoading] = useState(null);
  const [samples, setSamples] = useState([]);

  useEffect(() => {
    if (location.hash === '#how-it-works') {
      const el = document.getElementById('how-it-works');
      if (el) {
        setTimeout(() => {
          el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 200);
      }
    }
  }, [location.hash]);

  useEffect(() => {
    getDemoSamples()
      .then(res => {
        if (res && res.samples) {
          setSamples(res.samples);
        }
      })
      .catch(err => {
        console.error('Failed to load demo samples:', err);
        setSamples([
          {
            id: "vulnerable_smtp",
            name: "Vulnerable SMTP Infrastructure",
            description: "SMTP capture showing plaintext transmission and missing authentication security layers.",
            file: "smtp.pcap",
            expected_risk: "HIGH"
          },
          {
            id: "legacy_ssl3",
            name: "Legacy SSL 3.0 Handshake",
            description: "SSL 3.0 legacy protocol negotiation, exhibiting vulnerability to the POODLE exploit vector.",
            file: "rsasnakeoil2.cap",
            expected_risk: "CRITICAL"
          }
        ]);
      });
  }, []);

  const handleLoadDemo = async (sampleId) => {
    try {
      setDemoLoading(sampleId);
      const response = await loadDemo(sampleId);
      const captureId = response.capture_id;
      navigate(`/dashboard/${captureId}`);
    } catch (err) {
      console.error('Demo loading failed:', err);
      alert(err.message || 'Failed to load demo PCAP file. Ensure backend is running.');
    } finally {
      setDemoLoading(null);
    }
  };

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
          <button className="cta-btn" onClick={() => navigate('/analysis')}>Load Sample Analysis</button>
          <button className="cta-btn secondary-cta" onClick={() => document.getElementById('how-it-works').scrollIntoView({ behavior: 'smooth' })}>See How It Works</button>
        </div>

        {/* PCAP Upload */}
        <div id="pcap-upload-container" className="anim" style={{ '--d': '0.4s', width: '100%', maxWidth: '480px', margin: '0 auto' }}>
          <PcapUpload onAnalysisStart={async (file) => {
            try {
              const response = await uploadPcap(file);
              const captureId = response.capture_id;
              // Navigate to dashboard
              navigate(`/dashboard/${captureId}`);
            } catch (err) {
              console.error('Upload failed', err);
              alert(err.message || 'Analysis failed. Make sure FastAPI is running.');
            }
          }} />
        </div>

        {/* Quick Demo Presets */}
        <div className="anim" style={{ '--d': '0.5s', width: '100%', maxWidth: '480px', margin: '1.5rem auto 0' }}>
          <div className="glass-card" style={{ padding: '16px', background: 'rgba(10, 10, 15, 0.45)', borderRadius: '12px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <i className="fa-solid fa-bolt" style={{ color: '#818cf8' }} />
              <span>Quick Demo Presets</span>
            </div>
            
            {demoLoading ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '8px 0', color: '#fff', fontSize: '13px' }}>
                <i className="fa-solid fa-circle-notch fa-spin" style={{ color: '#818cf8', fontSize: '16px' }} />
                <span>Loading sample capture and running forensic engine...</span>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {samples.map((sample) => {
                  const isCritical = sample.expected_risk === 'CRITICAL';
                  const bg = isCritical ? 'rgba(239, 68, 68, 0.1)' : 'rgba(245, 158, 11, 0.1)';
                  const border = isCritical ? '1px solid rgba(239, 68, 68, 0.25)' : '1px solid rgba(245, 158, 11, 0.25)';
                  const color = isCritical ? '#f87171' : '#fbbf24';
                  const dotBg = isCritical ? '#ef4444' : '#f59e0b';
                  
                  return (
                    <button
                      key={sample.id}
                      onClick={() => handleLoadDemo(sample.id)}
                      disabled={demoLoading !== null}
                      style={{
                        width: '100%',
                        padding: '10px 14px',
                        borderRadius: '8px',
                        background: bg,
                        border: border,
                        color: color,
                        fontSize: '12.5px',
                        fontWeight: 600,
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        transition: 'background 0.2s',
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = isCritical ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)'}
                      onMouseLeave={e => e.currentTarget.style.background = bg}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', background: dotBg }} />
                        <span>{sample.name}</span>
                      </div>
                      <span style={{
                        fontSize: '9px',
                        textTransform: 'uppercase',
                        background: 'rgba(255, 255, 255, 0.08)',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        color: 'var(--muted)',
                        fontWeight: 700
                      }}>
                        Instant Demo — No file required
                      </span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </main>
      <section id="how-it-works" className="how-it-works-section">
        <HowItWorks />
      </section>
    </>
  );
}
