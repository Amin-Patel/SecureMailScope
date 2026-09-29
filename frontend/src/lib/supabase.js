import { createClient } from '@supabase/supabase-js';

// Project reference: ymwflcngyzawphnvezmr (ap-southeast-1)
export const DEFAULT_SUPABASE_URL = 'https://ymwflcngyzawphnvezmr.supabase.co';
export const DEFAULT_ANON_KEY =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inltd2ZsY25neXphd3BobnZlem1yIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODgxOTQ1NzIsImV4cCI6MjEwMzc3MDU3Mn0.MvYhQt303khczJ91W77N5L5Ds2rHGWEMZwGxxAZmU2Y';

// Resolve configuration from Vite environment
const rawUrl = (import.meta.env.VITE_SUPABASE_URL || '').trim();
const rawKey = (
  import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY ||
  import.meta.env.VITE_SUPABASE_ANON_KEY ||
  ''
).trim();

export const supabaseUrl = rawUrl && !rawUrl.includes('your-project-ref') ? rawUrl : DEFAULT_SUPABASE_URL;

// Ensure placeholder values never poison production runtime
const isPlaceholder = (key) =>
  !key ||
  key.includes('your_supabase') ||
  key.includes('placeholder') ||
  key.length < 50;

export const supabaseAnonKey = isPlaceholder(rawKey) ? DEFAULT_ANON_KEY : rawKey;

// Initialize Supabase Client with full browser session detection
export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
    storage: typeof window !== 'undefined' ? window.localStorage : undefined,
  },
});

/**
 * Constructs an environment-aware OAuth redirect URL.
 * In production browser (https://mailscope.dpdns.org): returns https://mailscope.dpdns.org/auth/callback
 * In local development (http://localhost:3000): returns http://localhost:3000/auth/callback
 * In local Vite default (http://localhost:5173): returns http://localhost:5173/auth/callback
 * 
 * @param {string} targetPath - Relative application path to return to (default: '/auth/callback')
 * @returns {string} Fully qualified absolute redirect URL
 */
export function getOAuthRedirectUrl(targetPath = '/auth/callback') {
  const normalizedPath = targetPath.startsWith('/') ? targetPath : `/${targetPath}`;

  // 1. In browser environment: Always dynamically resolve current window origin
  if (typeof window !== 'undefined' && window.location?.origin) {
    return `${window.location.origin}${normalizedPath}`;
  }

  // 2. Fallback to explicit environment site URL if defined
  const envSite = (import.meta.env.VITE_SITE_URL || '').trim().replace(/\/+$/, '');
  if (envSite) {
    return `${envSite}${normalizedPath}`;
  }

  // 3. Fallback to canonical production URL
  return `https://mailscope.dpdns.org${normalizedPath}`;
}

/**
 * Checks whether the current URL contains OAuth callback tokens, PKCE codes, or OAuth errors.
 * @returns {boolean}
 */
export function hasAuthParamsInUrl() {
  if (typeof window === 'undefined') return false;
  const hash = window.location.hash || '';
  const search = window.location.search || '';

  return (
    hash.includes('access_token=') ||
    hash.includes('error=') ||
    hash.includes('error_description=') ||
    search.includes('code=') ||
    search.includes('error=')
  );
}

/**
 * Cleans OAuth access_token and refresh_token from the browser address bar
 * without reloading the page or losing current route location.
 */
export function cleanAuthTokensFromUrl() {
  if (typeof window === 'undefined' || !window.history?.replaceState) return;

  const hash = window.location.hash || '';
  if (hash.includes('access_token=') || hash.includes('refresh_token=') || hash.includes('token_type=')) {
    const cleanUrl = window.location.pathname + (window.location.search || '');
    window.history.replaceState(null, document.title, cleanUrl);
  }
}
