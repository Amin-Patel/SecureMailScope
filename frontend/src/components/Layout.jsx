import React, { useState, useEffect, useRef } from 'react';
import { useLocation, Link } from 'react-router-dom';
import { useStatsCounter } from '../hooks/useStatsCounter';

const VIDEO_SRC =
  'https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260809_012548_ef22562c-c0ae-4816-ad9d-f8922af4e6a7.mp4';

const NAV_LINKS = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/workspace', label: 'Workspace' },
  { to: '/analysis', label: 'Analysis' },
  { to: '/history', label: 'History' },
  { to: '/help', label: 'Help' },
];

const STATS = [
  { icon: 'fa-bolt', target: 250, decimals: 0, prefix: '<', suffix: 'ms', fallback: '<250ms', label: 'Analysis Speed' },
  { icon: 'fa-shield-check', target: 35, decimals: 0, prefix: '', suffix: '+', fallback: '35+', label: 'RFC Rules Audited' },
  { icon: 'fa-certificate', target: 100, decimals: 0, prefix: '', suffix: '%', fallback: '100%', label: 'Deterministic Proof' },
  { icon: 'fa-envelope-open-text', target: 4, decimals: 0, prefix: '', suffix: '', fallback: '4', label: 'Email Protocols' },
];

export function Layout({ children }) {
  const location = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const footerRef = useRef(null);
  useStatsCounter(footerRef);

  // Close menu on resize > 720px
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth > 720 && menuOpen) {
        setMenuOpen(false);
      }
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [menuOpen]);

  // Escape key closes menu
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && menuOpen) {
        setMenuOpen(false);
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [menuOpen]);

  // Lock body scroll when menu is open
  useEffect(() => {
    if (menuOpen) {
      document.body.classList.add('menu-open');
    } else {
      document.body.classList.remove('menu-open');
    }
    return () => document.body.classList.remove('menu-open');
  }, [menuOpen]);

  // Close menu on route change
  useEffect(() => {
    setMenuOpen(false);
  }, [location.pathname]);

  const isActive = (to) => {
    if (to === '/') return location.pathname === '/';
    return location.pathname.startsWith(to);
  };

  const isSettings = location.pathname === '/settings';

  return (
    <>
      {/* Background Video */}
      <div className="bg">
        <video className="bg-video" autoPlay muted loop playsInline>
          <source src={VIDEO_SRC} type="video/mp4" />
        </video>
        {/* Persistent dark overlay — ensures text readability on all pages regardless of video frame */}
        <div className="bg-overlay" />
      </div>

      <div className="page">
        {/* Header */}
        <header className="header">
          <Link
            to="/dashboard"
            className="logo"
            aria-label="Logo Home"
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: 'clamp(40px, 4.4vw, 46px)',
              height: 'clamp(40px, 4.4vw, 46px)',
              borderRadius: '50%',
              backgroundColor: '#ffffff',
              textDecoration: 'none',
              boxShadow: '0 2px 10px rgba(0,0,0,0.3)',
            }}
          >
            <img
              src="/assets/logo.png"
              alt="SecureMailScope Logo"
              style={{ width: '100%', height: '100%', borderRadius: '50%', objectFit: 'cover' }}
            />
          </Link>

          <nav className="nav-pill">
            {NAV_LINKS.map(({ to, label }) => (
              <Link
                key={to}
                to={to}
                className={`nav-link ${isActive(to) ? 'active' : ''}`}
              >
                {label}
              </Link>
            ))}
          </nav>

          <Link
            to="/settings"
            className={`sign-in-btn ${isSettings ? 'active' : ''}`}
            style={{ textDecoration: 'none' }}
          >
            Settings
          </Link>

          <button
            className={`burger-btn ${menuOpen ? 'open' : ''}`}
            aria-label="Toggle Navigation"
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen((prev) => !prev)}
          >
            <span></span>
            <span></span>
            <span></span>
          </button>
        </header>

        {/* Mobile Menu */}
        <div
          className={`menu-overlay ${menuOpen ? 'open' : ''}`}
          onClick={() => setMenuOpen(false)}
        ></div>
        <div className={`menu-sheet ${menuOpen ? 'open' : ''}`}>
          <nav className="mobile-nav">
            {NAV_LINKS.map(({ to, label }) => (
              <Link
                key={to}
                to={to}
                className={`mobile-link ${isActive(to) ? 'active' : ''}`}
                onClick={() => setMenuOpen(false)}
              >
                {label}
              </Link>
            ))}
            <Link
              to="/settings"
              className={`mobile-link ${isSettings ? 'active' : ''}`}
              onClick={() => setMenuOpen(false)}
            >
              Settings
            </Link>
          </nav>
        </div>

        {/* Page Content */}
        {children}

        {/* Stats Footer */}
        <footer className="stats-footer" ref={footerRef}>
          {STATS.map(({ icon, target, decimals, prefix, suffix, fallback, label }, i) => (
            <div
              className="stat-col"
              key={label}
              style={{ '--d': `${0.5 + i * 0.08}s` }}
            >
              <i className={`fa-solid ${icon} stat-icon`} style={{ fontSize: 'clamp(14px,1.8vw,18px)', color: 'rgba(255,255,255,0.6)' }}></i>
              <div>
                <span
                  className="stat-value"
                  data-target={target}
                  data-decimals={decimals}
                  data-prefix={prefix}
                  data-suffix={suffix}
                >
                  {fallback}
                </span>
                <span className="stat-label" style={{ display: 'block' }}>{label}</span>
              </div>
            </div>
          ))}
        </footer>
      </div>
    </>
  );
}
