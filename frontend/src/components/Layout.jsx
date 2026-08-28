import React, { useState, useEffect, useRef } from 'react';
import { useLocation, Link } from 'react-router-dom';
import { useStatsCounter } from '../hooks/useStatsCounter';

const VIDEO_SRC =
  'https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260809_012548_ef22562c-c0ae-4816-ad9d-f8922af4e6a7.mp4';

const NAV_LINKS = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/', label: 'New Analysis' },
  { to: '/history', label: 'Analyses' },
  { to: '/help', label: 'Help' },
];

const STATS = [
  { icon: 'fa-bolt',          value: '<120ms',  label: 'Inference Time' },
  { icon: 'fa-shield-check',  value: '99.99%',  label: 'Platform Uptime' },
  { icon: 'fa-clock',         value: '24/7',    label: 'Runtime' },
  { icon: 'fa-layer-group',   value: '2.4B',    label: 'Ctx Windows' },
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
            to="/"
            className="logo"
            aria-label="Logo Home"
            style={{
              display: 'grid',
              placeItems: 'center',
              width: 'clamp(40px, 4.4vw, 46px)',
              height: 'clamp(40px, 4.4vw, 46px)',
              borderRadius: '50%',
              backgroundColor: '#ffffff',
              textDecoration: 'none',
            }}
          >
            <img
              src="/assets/logo.png"
              alt=""
              width="52"
              height="52"
              style={{ width: '72%', height: '72%', objectFit: 'contain' }}
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
          {STATS.map(({ icon, value, label }, i) => (
            <div
              className="stat-col"
              key={label}
              style={{ '--d': `${0.5 + i * 0.08}s` }}
            >
              <i className={`fa-solid ${icon} stat-icon`} style={{ fontSize: 'clamp(14px,1.8vw,18px)', color: 'rgba(255,255,255,0.6)' }}></i>
              <div>
                <span className="stat-value">{value}</span>
                <span className="stat-label" style={{ display: 'block' }}>{label}</span>
              </div>
            </div>
          ))}
        </footer>
      </div>
    </>
  );
}
