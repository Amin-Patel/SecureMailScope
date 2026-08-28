import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';

const VIDEO_SRC =
  'https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260808_112712_da9d53df-6d27-4b12-bdf6-aa9dc2622bdf.mp4';

export function Login() {
  const navigate = useNavigate();

  // Mode: 'signin' | 'signup'
  const [authMode, setAuthMode] = useState('signin');

  // Form Fields
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  // States
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const validateEmail = (val) => {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    const trimmedEmail = email.trim();
    if (!trimmedEmail) {
      setError('Please enter your email address.');
      return;
    }
    if (!validateEmail(trimmedEmail)) {
      setError('Please enter a valid email address.');
      return;
    }

    if (authMode === 'signup') {
      if (!fullName.trim()) {
        setError('Please enter your full name.');
        return;
      }
      if (!password || password.length < 6) {
        setError('Password must be at least 6 characters.');
        return;
      }
      if (password !== confirmPassword) {
        setError('Passwords do not match. Please verify and try again.');
        return;
      }
    } else {
      if (!password) {
        setError('Please enter your password.');
        return;
      }
    }

    setLoading(true);

    try {
      // Simulate authenticating against SecureMailScope security platform
      await new Promise((resolve) => setTimeout(resolve, 750));

      // Persist authenticated state
      localStorage.setItem('sms_auth', 'true');
      localStorage.setItem('sms_email', trimmedEmail);
      localStorage.setItem(
        'sms_username',
        authMode === 'signup' && fullName.trim() ? fullName.trim() : trimmedEmail.split('@')[0]
      );

      // Redirect to the dashboard
      navigate('/analysis', { replace: true });
    } catch (err) {
      setError('Unable to sign in. Check your email and password and try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleAuth = async () => {
    setError(null);
    setLoading(true);

    try {
      // Integration point for OAuth provider
      await new Promise((resolve) => setTimeout(resolve, 600));

      // Check if external OAuth config is active; if not configured, show clear notice
      const oauthConfigured = false;

      if (!oauthConfigured) {
        setError('Google sign-in is not yet configured for this workspace. Please sign in with email.');
        setLoading(false);
        return;
      }

      localStorage.setItem('sms_auth', 'true');
      navigate('/analysis', { replace: true });
    } catch (err) {
      setError('Google sign-in was unsuccessful. Please try again.');
      setLoading(false);
    }
  };

  return (
    <>
      {/* Background Video & Scrim Overlay */}
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
        {/* Dark Scrim for Authentication Focus */}
        <div
          className="bg-overlay"
          style={{
            position: 'absolute',
            inset: 0,
            background: 'linear-gradient(180deg, rgba(0,0,0,0.72) 0%, rgba(0,0,0,0.65) 50%, rgba(0,0,0,0.85) 100%)',
            pointerEvents: 'none',
          }}
        />
      </div>

      <div
        className="page"
        style={{
          position: 'relative',
          zIndex: 1,
          minHeight: '100vh',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center',
          padding: 'clamp(20px, 4vh, 48px) clamp(16px, 4vw, 40px)',
          fontFamily: 'var(--font-sans)',
          color: '#ffffff',
        }}
      >
        {/* Top Mini Brand Bar */}
        <div
          style={{
            width: '100%',
            maxWidth: '1040px',
            marginBottom: 'clamp(20px, 3vh, 32px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <Link
            to="/"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              textDecoration: 'none',
              color: '#ffffff',
            }}
          >
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '50%',
                backgroundColor: '#ffffff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: '0 2px 10px rgba(0,0,0,0.3)',
              }}
            >
              <img
                src="/assets/logo.png"
                alt="SecureMailScope Logo"
                width="24"
                height="24"
                style={{ width: '68%', height: '68%', objectFit: 'contain' }}
              />
            </div>
            <span
              style={{
                fontFamily: 'var(--font-display)',
                fontSize: '17px',
                fontWeight: 700,
                letterSpacing: '-0.02em',
              }}
            >
              SecureMailScope
            </span>
          </Link>

          <Link
            to="/"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '13px',
              color: 'rgba(255, 255, 255, 0.65)',
              textDecoration: 'none',
              transition: 'color 0.2s ease',
            }}
            onMouseEnter={(e) => (e.target.style.color = '#ffffff')}
            onMouseLeave={(e) => (e.target.style.color = 'rgba(255, 255, 255, 0.65)')}
          >
            <i className="fa-solid fa-arrow-left" style={{ fontSize: '11px' }} />
            Back to Overview
          </Link>
        </div>

        {/* Two-Zone Authentication Grid */}
        <main
          className="login-grid"
          style={{
            width: '100%',
            maxWidth: '1040px',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
            gap: 'clamp(24px, 4vw, 48px)',
            alignItems: 'center',
            margin: 'auto 0',
          }}
        >
          {/* ── LEFT ZONE: Security Intelligence Message ── */}
          <div className="login-left-zone" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <div>
              <div
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '5px 12px',
                  borderRadius: '999px',
                  backgroundColor: 'rgba(99, 102, 241, 0.15)',
                  border: '1px solid rgba(99, 102, 241, 0.35)',
                  color: '#a5b4fc',
                  fontSize: '11px',
                  fontWeight: 700,
                  letterSpacing: '0.08em',
                  textTransform: 'uppercase',
                  marginBottom: '16px',
                }}
              >
                <i className="fa-solid fa-shield-halved" />
                Secure Access Gate
              </div>

              <h1
                style={{
                  fontSize: 'clamp(28px, 3.5vw, 44px)',
                  fontWeight: 700,
                  letterSpacing: '-0.03em',
                  lineHeight: 1.12,
                  marginBottom: '14px',
                  color: '#ffffff',
                }}
              >
                Secure access to your <br />
                <span
                  style={{
                    background: 'linear-gradient(135deg, #ffffff 40%, #a5b4fc 100%)',
                    WebkitBackgroundClip: 'text',
                    WebkitTextFillColor: 'transparent',
                    backgroundClip: 'text',
                  }}
                >
                  email security intelligence.
                </span>
              </h1>

              <p
                style={{
                  fontSize: '14.5px',
                  color: 'rgba(255, 255, 255, 0.65)',
                  lineHeight: 1.6,
                  maxWidth: '440px',
                }}
              >
                Inspect raw packet captures, uncover cryptographic negotiation flaws, and turn deep forensic evidence
                into prioritized remediation steps.
              </p>
            </div>

            {/* Live Security Capability Statuses */}
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '12px',
                paddingTop: '16px',
                borderTop: '1px solid rgba(255, 255, 255, 0.1)',
                maxWidth: '420px',
              }}
            >
              {[
                { icon: 'fa-microchip', label: 'Analysis Engine', val: 'Fast tshark / Zeek Protocol Parser' },
                { icon: 'fa-lock', label: 'Cryptographic Audit', val: 'TLS 1.0–1.3 & X.509 Chain Verification' },
                { icon: 'fa-shield-check', label: 'Local Security', val: 'Zero External Telemetry' },
              ].map(({ icon, label, val }) => (
                <div
                  key={label}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '12px',
                    fontSize: '13px',
                    color: 'rgba(255, 255, 255, 0.75)',
                  }}
                >
                  <div
                    style={{
                      width: '28px',
                      height: '28px',
                      borderRadius: '8px',
                      backgroundColor: 'rgba(255, 255, 255, 0.06)',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: '#a5b4fc',
                      fontSize: '12px',
                      flexShrink: 0,
                    }}
                  >
                    <i className={`fa-solid ${icon}`} />
                  </div>
                  <div>
                    <span style={{ fontSize: '11px', color: 'rgba(255, 255, 255, 0.45)', display: 'block' }}>
                      {label}
                    </span>
                    <span style={{ fontWeight: 500 }}>{val}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* ── RIGHT ZONE: Authentication Panel ── */}
          <div
            className="glass-card"
            style={{
              background: 'rgba(10, 10, 18, 0.82)',
              backdropFilter: 'blur(24px)',
              WebkitBackdropFilter: 'blur(24px)',
              border: '1px solid rgba(255, 255, 255, 0.14)',
              borderRadius: '24px',
              padding: 'clamp(24px, 4vw, 36px)',
              boxShadow: '0 24px 60px rgba(0, 0, 0, 0.65)',
            }}
          >
            {/* Header */}
            <div style={{ marginBottom: '20px' }}>
              <h2
                style={{
                  fontSize: '22px',
                  fontWeight: 700,
                  letterSpacing: '-0.02em',
                  color: '#ffffff',
                  marginBottom: '4px',
                }}
              >
                Welcome to SecureMailScope
              </h2>
              <p style={{ fontSize: '13px', color: 'rgba(255, 255, 255, 0.6)' }}>
                {authMode === 'signin'
                  ? 'Sign in to continue to your security workspace.'
                  : 'Create an account to start analyzing email traffic.'}
              </p>
            </div>

            {/* Mode Switcher Segmented Control */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                backgroundColor: 'rgba(0, 0, 0, 0.4)',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                borderRadius: '12px',
                padding: '4px',
                marginBottom: '20px',
              }}
            >
              <button
                type="button"
                onClick={() => {
                  setAuthMode('signin');
                  setError(null);
                }}
                style={{
                  padding: '8px 16px',
                  borderRadius: '8px',
                  border: 'none',
                  backgroundColor: authMode === 'signin' ? 'rgba(99, 102, 241, 0.25)' : 'transparent',
                  color: authMode === 'signin' ? '#ffffff' : 'rgba(255, 255, 255, 0.55)',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  transition: 'background-color 0.2s ease, color 0.2s ease',
                }}
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => {
                  setAuthMode('signup');
                  setError(null);
                }}
                style={{
                  padding: '8px 16px',
                  borderRadius: '8px',
                  border: 'none',
                  backgroundColor: authMode === 'signup' ? 'rgba(99, 102, 241, 0.25)' : 'transparent',
                  color: authMode === 'signup' ? '#ffffff' : 'rgba(255, 255, 255, 0.55)',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  transition: 'background-color 0.2s ease, color 0.2s ease',
                }}
              >
                Sign Up
              </button>
            </div>

            {/* Error Message Banner */}
            {error && (
              <div
                role="alert"
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '10px',
                  padding: '12px 14px',
                  borderRadius: '10px',
                  backgroundColor: 'rgba(239, 68, 68, 0.14)',
                  border: '1px solid rgba(239, 68, 68, 0.35)',
                  color: '#fca5a5',
                  fontSize: '13px',
                  lineHeight: 1.45,
                  marginBottom: '18px',
                }}
              >
                <i className="fa-solid fa-circle-exclamation" style={{ marginTop: '2px', color: '#ef4444', flexShrink: 0 }} />
                <span>{error}</span>
              </div>
            )}

            {/* Form */}
            <form onSubmit={handleSubmit} noValidate>
              {/* Full Name field on Sign Up */}
              {authMode === 'signup' && (
                <div className="form-group" style={{ marginBottom: '14px' }}>
                  <label
                    htmlFor="fullName"
                    style={{
                      display: 'block',
                      fontSize: '12px',
                      fontWeight: 600,
                      color: 'rgba(255, 255, 255, 0.75)',
                      marginBottom: '6px',
                      textTransform: 'uppercase',
                      letterSpacing: '0.04em',
                    }}
                  >
                    Full Name
                  </label>
                  <div style={{ position: 'relative' }}>
                    <i
                      className="fa-solid fa-user"
                      style={{
                        position: 'absolute',
                        left: '14px',
                        top: '50%',
                        transform: 'translateY(-50%)',
                        color: 'rgba(255, 255, 255, 0.35)',
                        fontSize: '13px',
                        pointerEvents: 'none',
                      }}
                    />
                    <input
                      id="fullName"
                      type="text"
                      name="fullName"
                      placeholder="Jane Doe"
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      disabled={loading}
                      style={{
                        width: '100%',
                        padding: '10px 14px 10px 38px',
                        borderRadius: '10px',
                        background: 'rgba(0, 0, 0, 0.35)',
                        border: '1px solid rgba(255, 255, 255, 0.12)',
                        color: '#ffffff',
                        fontFamily: 'var(--font-sans)',
                        fontSize: '14px',
                        outline: 'none',
                        boxSizing: 'border-box',
                      }}
                      onFocus={(e) => (e.target.style.borderColor = 'rgba(99, 102, 241, 0.65)')}
                      onBlur={(e) => (e.target.style.borderColor = 'rgba(255, 255, 255, 0.12)')}
                    />
                  </div>
                </div>
              )}

              {/* Email field */}
              <div className="form-group" style={{ marginBottom: '14px' }}>
                <label
                  htmlFor="email"
                  style={{
                    display: 'block',
                    fontSize: '12px',
                    fontWeight: 600,
                    color: 'rgba(255, 255, 255, 0.75)',
                    marginBottom: '6px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.04em',
                  }}
                >
                  Email Address
                </label>
                <div style={{ position: 'relative' }}>
                  <i
                    className="fa-solid fa-envelope"
                    style={{
                      position: 'absolute',
                      left: '14px',
                      top: '50%',
                      transform: 'translateY(-50%)',
                      color: 'rgba(255, 255, 255, 0.35)',
                      fontSize: '13px',
                      pointerEvents: 'none',
                    }}
                  />
                  <input
                    id="email"
                    type="email"
                    name="email"
                    autoComplete="email"
                    placeholder="you@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    disabled={loading}
                    style={{
                      width: '100%',
                      padding: '10px 14px 10px 38px',
                      borderRadius: '10px',
                      background: 'rgba(0, 0, 0, 0.35)',
                      border: '1px solid rgba(255, 255, 255, 0.12)',
                      color: '#ffffff',
                      fontFamily: 'var(--font-sans)',
                      fontSize: '14px',
                      outline: 'none',
                      boxSizing: 'border-box',
                    }}
                    onFocus={(e) => (e.target.style.borderColor = 'rgba(99, 102, 241, 0.65)')}
                    onBlur={(e) => (e.target.style.borderColor = 'rgba(255, 255, 255, 0.12)')}
                  />
                </div>
              </div>

              {/* Password field */}
              <div className="form-group" style={{ marginBottom: authMode === 'signup' ? '14px' : '18px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <label
                    htmlFor="password"
                    style={{
                      fontSize: '12px',
                      fontWeight: 600,
                      color: 'rgba(255, 255, 255, 0.75)',
                      textTransform: 'uppercase',
                      letterSpacing: '0.04em',
                    }}
                  >
                    Password
                  </label>
                  {authMode === 'signin' && (
                    <span
                      style={{ fontSize: '11px', color: '#a5b4fc', cursor: 'pointer' }}
                      onClick={() => setError('Password reset instructions will be sent to your email.')}
                    >
                      Forgot password?
                    </span>
                  )}
                </div>
                <div style={{ position: 'relative' }}>
                  <i
                    className="fa-solid fa-lock"
                    style={{
                      position: 'absolute',
                      left: '14px',
                      top: '50%',
                      transform: 'translateY(-50%)',
                      color: 'rgba(255, 255, 255, 0.35)',
                      fontSize: '13px',
                      pointerEvents: 'none',
                    }}
                  />
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    name="password"
                    autoComplete={authMode === 'signup' ? 'new-password' : 'current-password'}
                    placeholder={authMode === 'signup' ? 'Create a strong password' : 'Enter your password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    disabled={loading}
                    style={{
                      width: '100%',
                      padding: '10px 40px 10px 38px',
                      borderRadius: '10px',
                      background: 'rgba(0, 0, 0, 0.35)',
                      border: '1px solid rgba(255, 255, 255, 0.12)',
                      color: '#ffffff',
                      fontFamily: 'var(--font-sans)',
                      fontSize: '14px',
                      outline: 'none',
                      boxSizing: 'border-box',
                    }}
                    onFocus={(e) => (e.target.style.borderColor = 'rgba(99, 102, 241, 0.65)')}
                    onBlur={(e) => (e.target.style.borderColor = 'rgba(255, 255, 255, 0.12)')}
                  />
                  <button
                    type="button"
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    onClick={() => setShowPassword((prev) => !prev)}
                    style={{
                      position: 'absolute',
                      right: '12px',
                      top: '50%',
                      transform: 'translateY(-50%)',
                      background: 'none',
                      border: 'none',
                      color: 'rgba(255, 255, 255, 0.45)',
                      cursor: 'pointer',
                      padding: '4px',
                      fontSize: '13px',
                    }}
                  >
                    <i className={`fa-solid ${showPassword ? 'fa-eye-slash' : 'fa-eye'}`} />
                  </button>
                </div>
              </div>

              {/* Confirm Password field on Sign Up */}
              {authMode === 'signup' && (
                <div className="form-group" style={{ marginBottom: '18px' }}>
                  <label
                    htmlFor="confirmPassword"
                    style={{
                      display: 'block',
                      fontSize: '12px',
                      fontWeight: 600,
                      color: 'rgba(255, 255, 255, 0.75)',
                      marginBottom: '6px',
                      textTransform: 'uppercase',
                      letterSpacing: '0.04em',
                    }}
                  >
                    Confirm Password
                  </label>
                  <div style={{ position: 'relative' }}>
                    <i
                      className="fa-solid fa-shield-check"
                      style={{
                        position: 'absolute',
                        left: '14px',
                        top: '50%',
                        transform: 'translateY(-50%)',
                        color: 'rgba(255, 255, 255, 0.35)',
                        fontSize: '13px',
                        pointerEvents: 'none',
                      }}
                    />
                    <input
                      id="confirmPassword"
                      type={showPassword ? 'text' : 'password'}
                      name="confirmPassword"
                      autoComplete="new-password"
                      placeholder="Confirm your password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      disabled={loading}
                      style={{
                        width: '100%',
                        padding: '10px 14px 10px 38px',
                        borderRadius: '10px',
                        background: 'rgba(0, 0, 0, 0.35)',
                        border: '1px solid rgba(255, 255, 255, 0.12)',
                        color: '#ffffff',
                        fontFamily: 'var(--font-sans)',
                        fontSize: '14px',
                        outline: 'none',
                        boxSizing: 'border-box',
                      }}
                      onFocus={(e) => (e.target.style.borderColor = 'rgba(99, 102, 241, 0.65)')}
                      onBlur={(e) => (e.target.style.borderColor = 'rgba(255, 255, 255, 0.12)')}
                    />
                  </div>
                </div>
              )}

              {/* Remember Me on Sign In */}
              {authMode === 'signin' && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    marginBottom: '20px',
                    fontSize: '13px',
                    color: 'rgba(255, 255, 255, 0.65)',
                  }}
                >
                  <input
                    id="rememberMe"
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    style={{ accentColor: '#6366f1', cursor: 'pointer' }}
                  />
                  <label htmlFor="rememberMe" style={{ cursor: 'pointer' }}>
                    Remember me on this browser
                  </label>
                </div>
              )}

              {/* Primary Authentication Button */}
              <button
                type="submit"
                disabled={loading}
                className="cta-btn"
                style={{
                  width: '100%',
                  padding: '12px 20px',
                  borderRadius: '999px',
                  backgroundColor: '#ffffff',
                  color: '#000000',
                  fontFamily: 'var(--font-sans)',
                  fontSize: '14.5px',
                  fontWeight: 700,
                  letterSpacing: '-0.01em',
                  cursor: loading ? 'not-allowed' : 'pointer',
                  opacity: loading ? 0.75 : 1,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                  boxShadow: '0 0 20px rgba(255, 255, 255, 0.25)',
                  transition: 'transform 0.2s ease, box-shadow 0.2s ease',
                  border: 'none',
                }}
              >
                {loading ? (
                  <>
                    <i className="fa-solid fa-circle-notch fa-spin" />
                    {authMode === 'signin' ? 'Signing in...' : 'Creating account...'}
                  </>
                ) : authMode === 'signin' ? (
                  'Sign In'
                ) : (
                  'Create Account'
                )}
              </button>
            </form>

            {/* Divider */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '14px',
                margin: '20px 0',
              }}
            >
              <div style={{ flex: 1, height: '1px', backgroundColor: 'rgba(255, 255, 255, 0.1)' }} />
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 600,
                  color: 'rgba(255, 255, 255, 0.4)',
                  letterSpacing: '0.08em',
                  textTransform: 'uppercase',
                }}
              >
                OR
              </span>
              <div style={{ flex: 1, height: '1px', backgroundColor: 'rgba(255, 255, 255, 0.1)' }} />
            </div>

            {/* Google Authentication Button */}
            <button
              type="button"
              onClick={handleGoogleAuth}
              disabled={loading}
              className="secondary-cta"
              style={{
                width: '100%',
                padding: '11px 20px',
                borderRadius: '999px',
                background: 'rgba(255, 255, 255, 0.05)',
                border: '1.5px solid rgba(255, 255, 255, 0.2)',
                color: '#ffffff',
                fontFamily: 'var(--font-sans)',
                fontSize: '14px',
                fontWeight: 600,
                cursor: loading ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '10px',
              }}
            >
              <svg width="18" height="18" viewBox="0 0 24 24">
                <path
                  fill="#EA4335"
                  d="M12 5c1.6 0 3 .6 4.1 1.6l3.1-3.1C17.3 1.7 14.8 1 12 1 7.5 1 3.7 3.6 1.9 7.3l3.7 2.9C6.5 7.4 9 5 12 5z"
                />
                <path
                  fill="#4285F4"
                  d="M23.5 12.3c0-.8-.1-1.6-.2-2.3H12v4.6h6.5c-.3 1.5-1.1 2.8-2.4 3.7l3.7 2.9c2.2-2 3.7-5 3.7-8.9z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.6 14.8c-.2-.7-.4-1.5-.4-2.3 0-.8.2-1.6.4-2.3L1.9 7.3C.7 9.7 0 12.3 0 15s.7 5.3 1.9 7.7l3.7-2.9z"
                />
                <path
                  fill="#34A853"
                  d="M12 23c3.2 0 6-1.1 8-3l-3.7-2.9c-1.1.8-2.5 1.3-4.3 1.3-3 0-5.5-2.4-6.4-5.2L1.9 16.1C3.7 19.8 7.5 23 12 23z"
                />
              </svg>
              Continue with Google
            </button>

            {/* Bottom Mode Switch Link */}
            <div
              style={{
                textAlign: 'center',
                marginTop: '20px',
                fontSize: '13px',
                color: 'rgba(255, 255, 255, 0.55)',
              }}
            >
              {authMode === 'signin' ? (
                <>
                  Don't have an account?{' '}
                  <button
                    type="button"
                    onClick={() => {
                      setAuthMode('signup');
                      setError(null);
                    }}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: '#a5b4fc',
                      fontWeight: 600,
                      cursor: 'pointer',
                      fontSize: '13px',
                      padding: 0,
                    }}
                  >
                    Sign up
                  </button>
                </>
              ) : (
                <>
                  Already have an account?{' '}
                  <button
                    type="button"
                    onClick={() => {
                      setAuthMode('signin');
                      setError(null);
                    }}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: '#a5b4fc',
                      fontWeight: 600,
                      cursor: 'pointer',
                      fontSize: '13px',
                      padding: 0,
                    }}
                  >
                    Sign in
                  </button>
                </>
              )}
            </div>
          </div>
        </main>

        {/* Security Footer */}
        <div
          style={{
            marginTop: 'clamp(20px, 3vh, 32px)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '12px',
            color: 'rgba(255, 255, 255, 0.4)',
          }}
        >
          <i className="fa-solid fa-shield-halved" style={{ fontSize: '11px' }} />
          <span>Encrypted Security Workspace &bull; Zero-Telemetry Local Assessment</span>
        </div>
      </div>
    </>
  );
}
