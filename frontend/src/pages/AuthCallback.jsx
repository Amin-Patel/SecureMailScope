import React, { useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { supabase, cleanAuthTokensFromUrl } from '../lib/supabase';
import { useAuth } from '../context/AuthContext';

export function AuthCallback() {
  const navigate = useNavigate();
  const location = useLocation();
  const { session, isAuthenticated } = useAuth();
  const [errorMessage, setErrorMessage] = useState(null);

  useEffect(() => {
    let isMounted = true;
    let timeoutId = null;

    const processAuth = async () => {
      // 1. Inspect URL hash and query string for OAuth errors
      const fullUrl = window.location.href;
      const hash = window.location.hash || '';
      const search = window.location.search || '';

      const searchParams = new URLSearchParams(search);
      const hashParams = new URLSearchParams(hash.startsWith('#') ? hash.substring(1) : hash);

      const error = searchParams.get('error') || hashParams.get('error');
      const errorDesc =
        searchParams.get('error_description') ||
        hashParams.get('error_description') ||
        searchParams.get('error_code') ||
        hashParams.get('error_code');

      if (error) {
        cleanAuthTokensFromUrl();
        const friendlyMsg =
          error === 'access_denied'
            ? 'Sign-in was cancelled or access was denied by Google.'
            : (errorDesc ? decodeURIComponent(errorDesc.replace(/\+/g, ' ')) : 'Authentication was declined.');
        if (isMounted) {
          setErrorMessage(friendlyMsg);
          setTimeout(() => navigate('/login', { state: { error: friendlyMsg }, replace: true }), 1500);
        }
        return;
      }

      // 2. If already authenticated via AuthContext, clean tokens and redirect
      if (isAuthenticated || session) {
        cleanAuthTokensFromUrl();
        navigate('/dashboard', { replace: true });
        return;
      }

      // 3. Check current session directly from Supabase client
      try {
        const { data: { session: activeSession }, error: sessionError } = await supabase.auth.getSession();
        if (sessionError) throw sessionError;

        if (activeSession) {
          cleanAuthTokensFromUrl();
          if (isMounted) {
            navigate('/dashboard', { replace: true });
          }
          return;
        }

        // 4. Handle PKCE code exchange if query param 'code' exists
        const code = searchParams.get('code');
        if (code) {
          const { data, error: exchangeError } = await supabase.auth.exchangeCodeForSession(code);
          if (exchangeError) throw exchangeError;
          if (data?.session) {
            cleanAuthTokensFromUrl();
            if (isMounted) {
              navigate('/dashboard', { replace: true });
            }
            return;
          }
        }
      } catch (err) {
        console.warn('[AuthCallback] Session extraction notice:', err);
      }

      // 5. Setup auth state listener as primary or fallback detection
      const { data: { subscription } } = supabase.auth.onAuthStateChange((event, currentSession) => {
        if (currentSession && (event === 'SIGNED_IN' || event === 'INITIAL_SESSION' || event === 'TOKEN_REFRESHED')) {
          cleanAuthTokensFromUrl();
          subscription?.unsubscribe();
          if (isMounted) {
            navigate('/dashboard', { replace: true });
          }
        }
      });

      // 6. Safety timeout to prevent indefinite loading spinner
      timeoutId = setTimeout(async () => {
        subscription?.unsubscribe();
        const { data: { session: checkSession } } = await supabase.auth.getSession();
        if (checkSession) {
          cleanAuthTokensFromUrl();
          if (isMounted) navigate('/dashboard', { replace: true });
        } else {
          cleanAuthTokensFromUrl();
          if (isMounted) {
            navigate('/login', {
              state: { error: 'Authentication could not be completed. Please try signing in again.' },
              replace: true,
            });
          }
        }
      }, 4000);
    };

    processAuth();

    return () => {
      isMounted = false;
      if (timeoutId) clearTimeout(timeoutId);
    };
  }, [navigate, location, isAuthenticated, session]);

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: '#0a0a12',
        color: '#ffffff',
        fontFamily: 'var(--font-sans)',
        padding: '20px',
      }}
    >
      <div
        style={{
          width: '56px',
          height: '56px',
          borderRadius: '16px',
          backgroundColor: 'rgba(99, 102, 241, 0.15)',
          border: '1px solid rgba(99, 102, 241, 0.35)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          marginBottom: '24px',
          color: '#a5b4fc',
          fontSize: '24px',
        }}
      >
        {errorMessage ? (
          <i className="fa-solid fa-triangle-exclamation" style={{ color: '#ef4444' }} />
        ) : (
          <i className="fa-solid fa-circle-notch fa-spin" />
        )}
      </div>

      <h2
        style={{
          fontSize: '20px',
          fontWeight: 700,
          letterSpacing: '-0.02em',
          marginBottom: '8px',
          color: errorMessage ? '#fca5a5' : '#ffffff',
        }}
      >
        {errorMessage ? 'Authentication Notice' : 'Authenticating Session'}
      </h2>

      <p
        style={{
          fontSize: '14px',
          color: 'rgba(255, 255, 255, 0.6)',
          textAlign: 'center',
          maxWidth: '380px',
          lineHeight: 1.5,
        }}
      >
        {errorMessage || 'Verifying your credentials and establishing a secure session...'}
      </p>
    </div>
  );
}
