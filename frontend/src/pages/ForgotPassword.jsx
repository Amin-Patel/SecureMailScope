import React from 'react';
import { Link } from 'react-router-dom';

const VIDEO_SRC =
  'https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260808_112712_da9d53df-6d27-4b12-bdf6-aa9dc2622bdf.mp4';

export function ForgotPassword() {
  return (
    <>
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
        <div
          className="bg-overlay"
          style={{
            position: 'absolute',
            inset: 0,
            background: 'linear-gradient(180deg, rgba(0,0,0,0.65) 0%, rgba(0,0,0,0.5) 50%, rgba(0,0,0,0.85) 100%)',
            pointerEvents: 'none',
          }}
        />
      </div>

      <div
        style={{
          position: 'relative',
          zIndex: 1,
          minHeight: '100vh',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '24px 16px',
          fontFamily: 'var(--font-sans)',
        }}
      >
        {/* Brand Mark */}
        <Link
          to="/"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '12px',
            textDecoration: 'none',
            marginBottom: '32px',
          }}
        >
          <div
            style={{
              width: '44px',
              height: '44px',
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
              fontSize: '22px',
              fontWeight: 700,
              color: '#ffffff',
              letterSpacing: '-0.02em',
            }}
          >
            SecureMailScope
          </span>
        </Link>

        {/* Card */}
        <div
          style={{
            width: '100%',
            maxWidth: '440px',
            backgroundColor: 'rgba(10, 10, 18, 0.75)',
            backdropFilter: 'blur(24px)',
            WebkitBackdropFilter: 'blur(24px)',
            border: '1px solid rgba(255, 255, 255, 0.12)',
            borderRadius: '24px',
            padding: '36px clamp(20px, 5vw, 36px)',
            boxShadow: '0 24px 60px rgba(0, 0, 0, 0.7), 0 0 40px rgba(99, 102, 241, 0.1)',
            boxSizing: 'border-box',
          }}
        >
          <div style={{ textAlign: 'center', marginBottom: '28px' }}>
            <div
              style={{
                width: '48px',
                height: '48px',
                borderRadius: '14px',
                backgroundColor: 'rgba(99, 102, 241, 0.15)',
                border: '1px solid rgba(99, 102, 241, 0.3)',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#a5b4fc',
                fontSize: '20px',
                marginBottom: '16px',
              }}
            >
              <i className="fa-solid fa-key" />
            </div>
            <h1
              style={{
                fontSize: '22px',
                fontWeight: 700,
                color: '#ffffff',
                marginBottom: '8px',
                letterSpacing: '-0.02em',
              }}
            >
              Forgot Password
            </h1>
            <p style={{ fontSize: '13.5px', color: 'rgba(255, 255, 255, 0.6)', lineHeight: 1.5 }}>
              Password reset functionality is coming later.
            </p>
          </div>

          {/* Coming Later Notice */}
          <div
            style={{
              padding: '16px',
              borderRadius: '12px',
              backgroundColor: 'rgba(251, 191, 36, 0.1)',
              border: '1px solid rgba(251, 191, 36, 0.3)',
              color: '#fbbf24',
              fontSize: '13px',
              lineHeight: 1.55,
              display: 'flex',
              alignItems: 'flex-start',
              gap: '10px',
              marginBottom: '20px',
            }}
          >
            <i className="fa-solid fa-clock" style={{ fontSize: '15px', marginTop: '2px', flexShrink: 0 }} />
            <div>
              Password reset via email is not yet available. Please contact your administrator if you need to reset your password.
            </div>
          </div>

          <div style={{ marginTop: '24px', textAlign: 'center', borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '18px' }}>
            <Link
              to="/login"
              style={{
                fontSize: '13px',
                color: '#a5b4fc',
                textDecoration: 'none',
                fontWeight: 600,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
              }}
            >
              <i className="fa-solid fa-arrow-left" style={{ fontSize: '11px' }} />
              Back to Sign In
            </Link>
          </div>
        </div>
      </div>
    </>
  );
}
