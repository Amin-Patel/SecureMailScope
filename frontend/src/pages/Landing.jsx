import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { SecureGateTransition } from '../components/SecureGateTransition';

const VIDEO_SRC =
  'https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260808_112712_da9d53df-6d27-4b12-bdf6-aa9dc2622bdf.mp4';

const WORKFLOW_STEPS = [
  { step: '01', title: 'PCAP Ingestion', desc: 'Accepts raw .pcap and .pcapng network capture files from tcpdump or Wireshark.' },
  { step: '02', title: 'Protocol Detection', desc: 'Isolates SMTP (25, 465, 587), IMAP (143, 993), and POP3 (110, 995) conversations.' },
  { step: '03', title: 'Session Reconstruction', desc: 'Reassembles TCP streams into interactive, bi-directional email audit records.' },
  { step: '04', title: 'TLS & Cert Forensics', desc: 'Dissects ClientHello/ServerHello handshakes, cipher strengths, and X.509 chains.' },
  { step: '05', title: 'Cryptographic Audit', desc: 'Detects plaintext authentication, missing STARTTLS, expired certs, and deprecated suites.' },
  { step: '06', title: 'Deterministic Risk Score', desc: 'Calculates composite 0–100 posture scores based on weighted security rules.' },
  { step: '07', title: 'Actionable Reporting', desc: 'Generates evidence-backed findings, remediation guides, and exportable JSON reports.' },
];

const CAPABILITIES = [
  {
    icon: 'fa-shield-halved',
    title: 'PCAP & PCAPNG Parsing',
    desc: 'Native deep packet inspection for all standard network capture formats with automatic protocol recognition.',
  },
  {
    icon: 'fa-lock-open',
    title: 'STARTTLS Enforcement Audit',
    desc: 'Detects cleartext SMTP/IMAP credential leaks where STARTTLS command negotiation was omitted or failed.',
  },
  {
    icon: 'fa-certificate',
    title: 'X.509 Certificate Validation',
    desc: 'Audits expiration dates, trust chains, self-signed certificates, and cryptographic signature algorithms.',
  },
  {
    icon: 'fa-key',
    title: 'Cipher Suite Inspection',
    desc: 'Flags obsolete protocols (TLS 1.0, 1.1) and vulnerable ciphers including RC4, 3DES, and export suites.',
  },
  {
    icon: 'fa-chart-line',
    title: 'Evidence-Backed Risk Score',
    desc: 'Scores overall email infrastructure health on a 0–100 scale with Critical, High, Medium, and Low findings.',
  },
  {
    icon: 'fa-file-code',
    title: 'Forensic Report Export',
    desc: 'Generates structured JSON exports and security assessment summaries ready for compliance and remediation.',
  },
];

const FAQS = [
  {
    q: 'What capture formats does SecureMailScope support?',
    a: 'SecureMailScope accepts standard network capture formats including .pcap, .pcapng, and .cap captured via tcpdump, Wireshark, Zeek, or hardware packet brokers.',
  },
  {
    q: 'How does SecureMailScope identify email vulnerabilities?',
    a: 'The engine inspects TCP conversations across standard email ports (25, 465, 587, 143, 993, 110, 995), validates TLS handshakes, audits cryptographic cipher negotiations, and checks certificate validity against security standards.',
  },
  {
    q: 'Is my packet capture data kept private and secure?',
    a: 'Yes. SecureMailScope performs analysis within your local security workspace without forwarding captured packet payloads to external advertising or data brokers.',
  },
  {
    q: 'Can I export assessment results for compliance audits?',
    a: 'Yes. Every analysis produces evidence-backed findings with packet reconstructions that can be exported as structured JSON or compiled into audit summaries.',
  },
];

export function Landing() {
  const navigate = useNavigate();
  const [transitioning, setTransitioning] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [openFaq, setOpenFaq] = useState(null);

  // Trigger Secure Gate transition
  const handleStartAnalysis = (e) => {
    if (e) e.preventDefault();
    setTransitioning(true);
  };

  const handleTransitionComplete = () => {
    navigate('/login');
  };

  const scrollToSection = (id) => {
    setMenuOpen(false);
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <>
      {/* Secure Gate Transition Component */}
      <SecureGateTransition open={transitioning} onComplete={handleTransitionComplete} />

      {/* Full-bleed Cinematic Background Video */}
      <div className="bg" style={{ position: 'fixed', inset: 0, zIndex: 0 }}>
        <video
          className="bg-video"
          autoPlay
          muted
          loop
          playsInline
          preload="auto"
          aria-hidden="true"
          style={{ width: '100%', height: '100%', objectFit: 'cover' }}
        >
          <source src={VIDEO_SRC} type="video/mp4" />
        </video>
        {/* Atmospheric Dark Overlay Scrim */}
        <div
          className="bg-overlay"
          style={{
            position: 'absolute',
            inset: 0,
            background: 'linear-gradient(180deg, rgba(0,0,0,0.55) 0%, rgba(0,0,0,0.42) 40%, rgba(0,0,0,0.75) 100%)',
            pointerEvents: 'none',
          }}
        />
      </div>

      {/* Landing Page Content Container */}
      <div
        className="landing-page"
        style={{
          position: 'relative',
          zIndex: 1,
          minHeight: '100vh',
          display: 'flex',
          flexDirection: 'column',
          color: '#ffffff',
          fontFamily: 'var(--font-sans)',
        }}
      >
        {/* ── Top Navigation ── */}
        <header
          style={{
            position: 'sticky',
            top: 0,
            zIndex: 100,
            padding: '16px clamp(16px, 4vw, 48px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            backdropFilter: 'blur(16px)',
            WebkitBackdropFilter: 'blur(16px)',
            backgroundColor: 'rgba(0, 0, 0, 0.45)',
            borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          }}
        >
          {/* Brand Mark */}
          <Link
            to="/"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              textDecoration: 'none',
              color: '#ffffff',
            }}
          >
            <div
              style={{
                width: '38px',
                height: '38px',
                borderRadius: '10px',
                backgroundColor: 'transparent',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                overflow: 'hidden',
              }}
            >
              <img
                src="/assets/logo.png"
                alt="SecureMailScope"
                style={{ width: '100%', height: '100%', objectFit: 'contain' }}
              />
            </div>
            <span
              style={{
                fontFamily: 'var(--font-display)',
                fontSize: '18px',
                fontWeight: 700,
                letterSpacing: '-0.02em',
                color: '#ffffff',
              }}
            >
              SecureMailScope
            </span>
          </Link>

          {/* Desktop Navigation Links */}
          <nav
            className="landing-nav-links"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '28px',
            }}
          >
            <button
              onClick={() => scrollToSection('about')}
              style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.7)', fontSize: '14px', cursor: 'pointer', fontWeight: 500 }}
              onMouseEnter={(e) => (e.target.style.color = '#ffffff')}
              onMouseLeave={(e) => (e.target.style.color = 'rgba(255,255,255,0.7)')}
            >
              About
            </button>
            <button
              onClick={() => scrollToSection('how-it-works')}
              style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.7)', fontSize: '14px', cursor: 'pointer', fontWeight: 500 }}
              onMouseEnter={(e) => (e.target.style.color = '#ffffff')}
              onMouseLeave={(e) => (e.target.style.color = 'rgba(255,255,255,0.7)')}
            >
              How It Works
            </button>
            <button
              onClick={() => scrollToSection('features')}
              style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.7)', fontSize: '14px', cursor: 'pointer', fontWeight: 500 }}
              onMouseEnter={(e) => (e.target.style.color = '#ffffff')}
              onMouseLeave={(e) => (e.target.style.color = 'rgba(255,255,255,0.7)')}
            >
              Features
            </button>
            <button
              onClick={() => scrollToSection('faq')}
              style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.7)', fontSize: '14px', cursor: 'pointer', fontWeight: 500 }}
              onMouseEnter={(e) => (e.target.style.color = '#ffffff')}
              onMouseLeave={(e) => (e.target.style.color = 'rgba(255,255,255,0.7)')}
            >
              FAQ
            </button>
          </nav>

          {/* Right Action: Get Started Pill */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <button
              onClick={handleStartAnalysis}
              className="cta-btn"
              style={{
                padding: '9px 22px',
                borderRadius: '999px',
                backgroundColor: '#ffffff',
                color: '#000000',
                fontSize: '13.5px',
                fontWeight: 700,
                border: 'none',
                cursor: 'pointer',
                boxShadow: '0 2px 14px rgba(255, 255, 255, 0.25)',
                transition: 'transform 0.2s ease, box-shadow 0.2s ease',
              }}
            >
              GET STARTED
            </button>

            {/* Mobile Hamburger Toggle */}
            <button
              className="landing-burger-btn"
              onClick={() => setMenuOpen((prev) => !prev)}
              aria-label="Toggle Navigation"
              style={{
                background: 'rgba(255, 255, 255, 0.1)',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                borderRadius: '8px',
                color: '#ffffff',
                padding: '8px 12px',
                cursor: 'pointer',
              }}
            >
              <i className={`fa-solid ${menuOpen ? 'fa-xmark' : 'fa-bars'}`} />
            </button>
          </div>
        </header>

        {/* Mobile Navigation Dropdown */}
        {menuOpen && (
          <div
            style={{
              position: 'fixed',
              top: '70px',
              left: '16px',
              right: '16px',
              backgroundColor: 'rgba(10, 10, 18, 0.95)',
              backdropFilter: 'blur(20px)',
              borderRadius: '16px',
              padding: '20px',
              border: '1px solid rgba(255, 255, 255, 0.15)',
              zIndex: 99,
              display: 'flex',
              flexDirection: 'column',
              gap: '16px',
              boxShadow: '0 20px 40px rgba(0,0,0,0.6)',
            }}
          >
            <button
              onClick={() => scrollToSection('about')}
              style={{ background: 'none', border: 'none', color: '#ffffff', fontSize: '16px', textAlign: 'left', cursor: 'pointer' }}
            >
              About
            </button>
            <button
              onClick={() => scrollToSection('how-it-works')}
              style={{ background: 'none', border: 'none', color: '#ffffff', fontSize: '16px', textAlign: 'left', cursor: 'pointer' }}
            >
              How It Works
            </button>
            <button
              onClick={() => scrollToSection('features')}
              style={{ background: 'none', border: 'none', color: '#ffffff', fontSize: '16px', textAlign: 'left', cursor: 'pointer' }}
            >
              Features
            </button>
            <button
              onClick={() => scrollToSection('faq')}
              style={{ background: 'none', border: 'none', color: '#ffffff', fontSize: '16px', textAlign: 'left', cursor: 'pointer' }}
            >
              FAQ
            </button>
            <button
              onClick={handleStartAnalysis}
              className="cta-btn"
              style={{
                width: '100%',
                padding: '12px',
                borderRadius: '999px',
                backgroundColor: '#ffffff',
                color: '#000000',
                fontWeight: 700,
                fontSize: '14px',
                border: 'none',
                cursor: 'pointer',
                marginTop: '8px',
              }}
            >
              Start Analysis
            </button>
          </div>
        )}

        {/* ── First Viewport Hero Section ── */}
        <section
          style={{
            minHeight: 'calc(100vh - 72px)',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center',
            padding: 'clamp(32px, 6vh, 64px) clamp(20px, 6vw, 80px)',
            maxWidth: '1300px',
            margin: '0 auto',
            width: '100%',
            boxSizing: 'border-box',
          }}
        >
          {/* Left-aligned Hero Content */}
          <div style={{ maxWidth: '680px', zIndex: 5 }}>
            {/* Technical Category Tag */}
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                padding: '6px 14px',
                borderRadius: '999px',
                backgroundColor: 'rgba(99, 102, 241, 0.12)',
                border: '1px solid rgba(99, 102, 241, 0.35)',
                color: '#a5b4fc',
                fontSize: '12px',
                fontWeight: 600,
                letterSpacing: '0.06em',
                textTransform: 'uppercase',
                marginBottom: '20px',
                boxShadow: '0 0 16px rgba(99, 102, 241, 0.2)',
              }}
            >
              <i className="fa-solid fa-shield-halved" style={{ fontSize: '11px' }} />
              AI-Driven Email Security Assessment &amp; Forensics
            </div>

            {/* Primary Headline */}
            <h1
              className="hero-headline"
              style={{
                fontFamily: 'var(--font-sans)',
                fontSize: 'clamp(36px, 5.5vw, 68px)',
                fontWeight: 700,
                lineHeight: 1.08,
                letterSpacing: '-0.035em',
                color: '#ffffff',
                marginBottom: '18px',
                textShadow: '0 2px 24px rgba(0, 0, 0, 0.9), 0 4px 48px rgba(0, 0, 0, 0.7)',
              }}
            >
              See Beyond <br />
              <span
                style={{
                  background: 'linear-gradient(135deg, #ffffff 30%, #a5b4fc 100%)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                  backgroundClip: 'text',
                }}
              >
                the Message.
              </span>
            </h1>

            {/* Secondary Supporting Copy */}
            <p
              style={{
                fontSize: 'clamp(15px, 1.8vw, 18px)',
                color: 'rgba(255, 255, 255, 0.85)',
                lineHeight: 1.6,
                fontWeight: 400,
                maxWidth: '560px',
                marginBottom: '32px',
                textShadow: '0 1px 12px rgba(0,0,0,0.85)',
              }}
            >
              Analyze email traffic, TLS sessions, certificates, and cryptographic evidence to uncover security
              weaknesses hidden beneath the message.
            </p>

            {/* CTA Button Group */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '16px',
                flexWrap: 'wrap',
                marginBottom: '48px',
              }}
            >
              <button
                onClick={handleStartAnalysis}
                className="cta-btn"
                style={{
                  padding: '13px 32px',
                  borderRadius: '999px',
                  backgroundColor: '#ffffff',
                  color: '#000000',
                  fontSize: '15px',
                  fontWeight: 700,
                  border: 'none',
                  cursor: 'pointer',
                  boxShadow: '0 0 24px rgba(255, 255, 255, 0.35)',
                  transition: 'transform 0.2s ease, box-shadow 0.2s ease',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '10px',
                }}
              >
                Start Analysis
                <i className="fa-solid fa-arrow-right" style={{ fontSize: '13px' }} />
              </button>

              <button
                onClick={() => scrollToSection('about')}
                className="secondary-cta"
                style={{
                  padding: '12px 28px',
                  borderRadius: '999px',
                  background: 'rgba(255, 255, 255, 0.06)',
                  border: '1.5px solid rgba(255, 255, 255, 0.25)',
                  color: '#ffffff',
                  fontSize: '15px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  backdropFilter: 'blur(8px)',
                  transition: 'background 0.2s ease, border-color 0.2s ease, transform 0.2s ease',
                }}
              >
                Explore SecureMailScope
              </button>
            </div>

            {/* Technical Capability Badges */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '20px',
                flexWrap: 'wrap',
                paddingTop: '20px',
                borderTop: '1px solid rgba(255, 255, 255, 0.12)',
              }}
            >
              {[
                { icon: 'fa-envelope', label: 'SMTP / IMAP / POP3' },
                { icon: 'fa-lock', label: 'TLS 1.3 & Cipher Audit' },
                { icon: 'fa-certificate', label: 'X.509 Trust Validation' },
                { icon: 'fa-chart-pie', label: 'Deterministic Scoring' },
              ].map(({ icon, label }) => (
                <div
                  key={label}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    fontSize: '12px',
                    color: 'rgba(255, 255, 255, 0.65)',
                    fontWeight: 500,
                  }}
                >
                  <i className={`fa-solid ${icon}`} style={{ color: '#a5b4fc', fontSize: '12px' }} />
                  <span>{label}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── Section 1: What's hidden beneath an email? ── */}
        <section
          id="about"
          style={{
            padding: 'clamp(48px, 8vh, 96px) clamp(20px, 6vw, 80px)',
            maxWidth: '1200px',
            margin: '0 auto',
            width: '100%',
            boxSizing: 'border-box',
          }}
        >
          <div style={{ textAlign: 'center', maxWidth: '720px', margin: '0 auto 48px' }}>
            <div
              style={{
                fontSize: '12px',
                color: '#a5b4fc',
                fontWeight: 700,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                marginBottom: '10px',
              }}
            >
              Network Forensic Depth
            </div>
            <h2
              style={{
                fontSize: 'clamp(24px, 3.5vw, 42px)',
                fontWeight: 700,
                letterSpacing: '-0.025em',
                marginBottom: '16px',
                color: '#ffffff',
              }}
            >
              What is hidden beneath an email?
            </h2>
            <p style={{ fontSize: '15px', color: 'rgba(255, 255, 255, 0.65)', lineHeight: 1.6 }}>
              Every email transmission carries a complex cryptographic and protocol negotiation trail. Without deep
              packet analysis, vulnerabilities remain invisible until exploited.
            </p>
          </div>

          {/* 4 Feature Pillars */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
              gap: '20px',
            }}
          >
            {[
              {
                icon: 'fa-shield-halved',
                title: 'Cleartext Protocol Exposures',
                desc: 'Unencrypted SMTP, IMAP, and POP3 transmissions expose authentication credentials, attachments, and sensitive mail payloads to packet sniffing.',
              },
              {
                icon: 'fa-key',
                title: 'Cryptographic Weaknesses',
                desc: 'Deprecated protocols (TLS 1.0, 1.1) and obsolete ciphers (RC4, 3DES, CBC suites) allow passive decryption and downgrade attacks.',
              },
              {
                icon: 'fa-certificate',
                title: 'Certificate & Trust Flaws',
                desc: 'Expired certificates, self-signed chains, and hostname mismatches compromise server identity and permit man-in-the-middle impersonation.',
              },
              {
                icon: 'fa-arrow-down-wide-short',
                title: 'Missing STARTTLS Enforcement',
                desc: 'Servers that do not mandate STARTTLS permit silent plaintext downgrades during SMTP HELO/EHLO handshake exchanges.',
              },
            ].map(({ icon, title, desc }) => (
              <div
                key={title}
                className="glass-card"
                style={{
                  background: 'rgba(10, 10, 18, 0.65)',
                  backdropFilter: 'blur(16px)',
                  WebkitBackdropFilter: 'blur(16px)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: '16px',
                  padding: '28px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '14px',
                  transition: 'transform 0.2s ease, border-color 0.2s ease',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.transform = 'translateY(-3px)';
                  e.currentTarget.style.borderColor = 'rgba(99, 102, 241, 0.4)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = 'translateY(0)';
                  e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.1)';
                }}
              >
                <div
                  style={{
                    width: '44px',
                    height: '44px',
                    borderRadius: '12px',
                    backgroundColor: 'rgba(99, 102, 241, 0.15)',
                    border: '1px solid rgba(99, 102, 241, 0.3)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#a5b4fc',
                    fontSize: '18px',
                  }}
                >
                  <i className={`fa-solid ${icon}`} />
                </div>
                <h3 style={{ fontSize: '17px', fontWeight: 600, color: '#ffffff' }}>{title}</h3>
                <p style={{ fontSize: '13.5px', color: 'rgba(255, 255, 255, 0.6)', lineHeight: 1.6 }}>{desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ── Section 2: From packet capture to security insight ── */}
        <section
          id="how-it-works"
          style={{
            padding: 'clamp(48px, 8vh, 96px) clamp(20px, 6vw, 80px)',
            maxWidth: '1200px',
            margin: '0 auto',
            width: '100%',
            boxSizing: 'border-box',
            borderTop: '1px solid rgba(255, 255, 255, 0.08)',
          }}
        >
          <div style={{ textAlign: 'center', maxWidth: '720px', margin: '0 auto 48px' }}>
            <div
              style={{
                fontSize: '12px',
                color: '#a5b4fc',
                fontWeight: 700,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                marginBottom: '10px',
              }}
            >
              Investigation Pipeline
            </div>
            <h2
              style={{
                fontSize: 'clamp(24px, 3.5vw, 42px)',
                fontWeight: 700,
                letterSpacing: '-0.025em',
                marginBottom: '16px',
                color: '#ffffff',
              }}
            >
              From packet capture to security insight.
            </h2>
            <p style={{ fontSize: '15px', color: 'rgba(255, 255, 255, 0.65)', lineHeight: 1.6 }}>
              A deterministic seven-stage forensic workflow turns raw network traffic into structured vulnerabilities
              and executive-ready assessments.
            </p>
          </div>

          {/* Workflow Step Grid */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
              gap: '16px',
            }}
          >
            {WORKFLOW_STEPS.map(({ step, title, desc }) => (
              <div
                key={step}
                style={{
                  background: 'rgba(10, 10, 18, 0.55)',
                  backdropFilter: 'blur(12px)',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  borderRadius: '14px',
                  padding: '22px 24px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                }}
              >
                <div style={{ fontSize: '12px', fontWeight: 800, color: '#a5b4fc', letterSpacing: '0.08em' }}>
                  {step}
                </div>
                <h3 style={{ fontSize: '16px', fontWeight: 600, color: '#ffffff' }}>{title}</h3>
                <p style={{ fontSize: '13px', color: 'rgba(255, 255, 255, 0.6)', lineHeight: 1.55 }}>{desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ── Section 3: Built for investigation ── */}
        <section
          id="features"
          style={{
            padding: 'clamp(48px, 8vh, 96px) clamp(20px, 6vw, 80px)',
            maxWidth: '1200px',
            margin: '0 auto',
            width: '100%',
            boxSizing: 'border-box',
            borderTop: '1px solid rgba(255, 255, 255, 0.08)',
          }}
        >
          <div style={{ textAlign: 'center', maxWidth: '720px', margin: '0 auto 48px' }}>
            <div
              style={{
                fontSize: '12px',
                color: '#a5b4fc',
                fontWeight: 700,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                marginBottom: '10px',
              }}
            >
              Core Capabilities
            </div>
            <h2
              style={{
                fontSize: 'clamp(24px, 3.5vw, 42px)',
                fontWeight: 700,
                letterSpacing: '-0.025em',
                marginBottom: '16px',
                color: '#ffffff',
              }}
            >
              Built for security investigation.
            </h2>
            <p style={{ fontSize: '15px', color: 'rgba(255, 255, 255, 0.65)', lineHeight: 1.6 }}>
              Comprehensive forensic toolset built for security engineers, incident responders, and network auditors.
            </p>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
              gap: '20px',
            }}
          >
            {CAPABILITIES.map(({ icon, title, desc }) => (
              <div
                key={title}
                style={{
                  background: 'rgba(10, 10, 18, 0.65)',
                  backdropFilter: 'blur(16px)',
                  border: '1px solid rgba(255, 255, 255, 0.09)',
                  borderRadius: '16px',
                  padding: '24px',
                  display: 'flex',
                  gap: '18px',
                  alignItems: 'flex-start',
                }}
              >
                <div
                  style={{
                    width: '42px',
                    height: '42px',
                    borderRadius: '10px',
                    backgroundColor: 'rgba(99, 102, 241, 0.15)',
                    border: '1px solid rgba(99, 102, 241, 0.3)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#a5b4fc',
                    fontSize: '16px',
                    flexShrink: 0,
                  }}
                >
                  <i className={`fa-solid ${icon}`} />
                </div>
                <div>
                  <h3 style={{ fontSize: '16px', fontWeight: 600, color: '#ffffff', marginBottom: '6px' }}>{title}</h3>
                  <p style={{ fontSize: '13px', color: 'rgba(255, 255, 255, 0.6)', lineHeight: 1.55 }}>{desc}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ── Section 4: Frequently Asked Questions ── */}
        <section
          id="faq"
          style={{
            padding: 'clamp(48px, 8vh, 96px) clamp(20px, 6vw, 80px)',
            maxWidth: '900px',
            margin: '0 auto',
            width: '100%',
            boxSizing: 'border-box',
            borderTop: '1px solid rgba(255, 255, 255, 0.08)',
          }}
        >
          <div style={{ textAlign: 'center', marginBottom: '40px' }}>
            <div
              style={{
                fontSize: '12px',
                color: '#a5b4fc',
                fontWeight: 700,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                marginBottom: '10px',
              }}
            >
              FAQ
            </div>
            <h2
              style={{
                fontSize: 'clamp(24px, 3.5vw, 38px)',
                fontWeight: 700,
                letterSpacing: '-0.025em',
                color: '#ffffff',
              }}
            >
              Frequently Asked Questions
            </h2>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {FAQS.map(({ q, a }, idx) => {
              const isOpen = openFaq === idx;
              return (
                <div
                  key={q}
                  style={{
                    background: 'rgba(10, 10, 18, 0.65)',
                    backdropFilter: 'blur(16px)',
                    border: `1px solid ${isOpen ? 'rgba(99, 102, 241, 0.4)' : 'rgba(255, 255, 255, 0.09)'}`,
                    borderRadius: '14px',
                    overflow: 'hidden',
                    transition: 'border-color 0.2s ease',
                  }}
                >
                  <button
                    onClick={() => setOpenFaq(isOpen ? null : idx)}
                    style={{
                      width: '100%',
                      padding: '18px 24px',
                      background: 'none',
                      border: 'none',
                      color: '#ffffff',
                      fontSize: '15px',
                      fontWeight: 600,
                      textAlign: 'left',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      cursor: 'pointer',
                      gap: '12px',
                    }}
                  >
                    <span>{q}</span>
                    <i
                      className="fa-solid fa-chevron-down"
                      style={{
                        fontSize: '13px',
                        color: 'rgba(255,255,255,0.4)',
                        transform: isOpen ? 'rotate(180deg)' : 'rotate(0)',
                        transition: 'transform 0.25s ease',
                      }}
                    />
                  </button>
                  {isOpen && (
                    <div
                      style={{
                        padding: '0 24px 20px',
                        fontSize: '13.5px',
                        color: 'rgba(255, 255, 255, 0.7)',
                        lineHeight: 1.6,
                      }}
                    >
                      {a}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>

        {/* ── Section 5: Final Call to Action ── */}
        <section
          style={{
            padding: 'clamp(56px, 10vh, 110px) clamp(20px, 6vw, 80px)',
            maxWidth: '1000px',
            margin: '0 auto',
            width: '100%',
            textAlign: 'center',
            boxSizing: 'border-box',
          }}
        >
          <div
            className="glass-card"
            style={{
              background: 'rgba(10, 10, 18, 0.85)',
              backdropFilter: 'blur(24px)',
              WebkitBackdropFilter: 'blur(24px)',
              border: '1px solid rgba(99, 102, 241, 0.3)',
              borderRadius: '24px',
              padding: 'clamp(36px, 6vw, 64px) 24px',
              boxShadow: '0 24px 60px rgba(0, 0, 0, 0.6), 0 0 40px rgba(99, 102, 241, 0.15)',
            }}
          >
            <h2
              style={{
                fontSize: 'clamp(28px, 4vw, 44px)',
                fontWeight: 700,
                letterSpacing: '-0.025em',
                color: '#ffffff',
                marginBottom: '16px',
              }}
            >
              Ready to see beyond the message?
            </h2>
            <p
              style={{
                fontSize: '16px',
                color: 'rgba(255, 255, 255, 0.7)',
                maxWidth: '560px',
                margin: '0 auto 32px',
                lineHeight: 1.6,
              }}
            >
              Inspect captured network traffic and diagnose email security risks in seconds.
            </p>
            <button
              onClick={handleStartAnalysis}
              className="cta-btn"
              style={{
                padding: '14px 38px',
                borderRadius: '999px',
                backgroundColor: '#ffffff',
                color: '#000000',
                fontSize: '16px',
                fontWeight: 700,
                border: 'none',
                cursor: 'pointer',
                boxShadow: '0 0 28px rgba(255, 255, 255, 0.4)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '10px',
              }}
            >
              Start Analysis
              <i className="fa-solid fa-arrow-right" style={{ fontSize: '13px' }} />
            </button>
          </div>
        </section>

        {/* ── Footer ── */}
        <footer
          style={{
            marginTop: 'auto',
            padding: '32px clamp(20px, 6vw, 80px)',
            borderTop: '1px solid rgba(255, 255, 255, 0.08)',
            backgroundColor: 'rgba(0, 0, 0, 0.65)',
            backdropFilter: 'blur(12px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '16px',
            fontSize: '12.5px',
            color: 'rgba(255, 255, 255, 0.5)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontWeight: 600, color: '#ffffff' }}>SecureMailScope</span>
            <span>&bull;</span>
            <span>AI-Driven Email Security Assessment &amp; Forensics</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: '#10b981' }} />
              All Systems Operational
            </span>
            <span>&copy; {new Date().getFullYear()} SecureMailScope</span>
          </div>
        </footer>
      </div>

      {/* Responsive media query helper styles */}
      <style>{`
        @media (max-width: 768px) {
          .landing-nav-links {
            display: none !important;
          }
          .landing-burger-btn {
            display: block !important;
          }
        }
        @media (min-width: 769px) {
          .landing-burger-btn {
            display: none !important;
          }
        }
      `}</style>
    </>
  );
}
