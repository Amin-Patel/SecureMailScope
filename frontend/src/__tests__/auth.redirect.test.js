import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Helpers: mock window.location and window.history ─────────────────────────

function setWindowLocation({ origin, pathname = '/', hash = '', search = '' }) {
  const url = `${origin}${pathname}${search}${hash}`;
  const loc = {
    origin,
    pathname,
    hash,
    search,
    href: url,
    toString: () => url,
  };
  Object.defineProperty(window, 'location', {
    value: loc,
    writable: true,
    configurable: true,
  });
}

// ─── Unit tests for getOAuthRedirectUrl ───────────────────────────────────────

describe('getOAuthRedirectUrl — OAuth redirect construction', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it('returns production origin when running on https://mailscope.dpdns.org', async () => {
    setWindowLocation({ origin: 'https://mailscope.dpdns.org', pathname: '/login' });

    const { getOAuthRedirectUrl } = await import('../lib/supabase.js');
    const url = getOAuthRedirectUrl('/auth/callback');

    expect(url).toBe('https://mailscope.dpdns.org/auth/callback');
    expect(url).not.toContain('localhost');
  });

  it('returns localhost:5173 origin when running locally (Vite default)', async () => {
    setWindowLocation({ origin: 'http://localhost:5173', pathname: '/login' });

    const { getOAuthRedirectUrl } = await import('../lib/supabase.js');
    const url = getOAuthRedirectUrl('/auth/callback');

    expect(url).toBe('http://localhost:5173/auth/callback');
    expect(url).not.toContain('mailscope.dpdns.org');
  });

  it('returns localhost:3000 origin when running on legacy local port', async () => {
    setWindowLocation({ origin: 'http://localhost:3000', pathname: '/login' });

    const { getOAuthRedirectUrl } = await import('../lib/supabase.js');
    const url = getOAuthRedirectUrl('/auth/callback');

    expect(url).toBe('http://localhost:3000/auth/callback');
  });

  it('uses /auth/callback as default path if no path argument given', async () => {
    setWindowLocation({ origin: 'https://mailscope.dpdns.org' });

    const { getOAuthRedirectUrl } = await import('../lib/supabase.js');
    const url = getOAuthRedirectUrl();

    expect(url).toBe('https://mailscope.dpdns.org/auth/callback');
  });

  it('correctly prepends leading slash to target path if missing', async () => {
    setWindowLocation({ origin: 'https://mailscope.dpdns.org' });

    const { getOAuthRedirectUrl } = await import('../lib/supabase.js');
    const url = getOAuthRedirectUrl('auth/callback');

    expect(url).toMatch(/^https:\/\/mailscope\.dpdns\.org\/auth\/callback/);
  });

  it('NEVER returns a URL containing localhost when window.origin is production', async () => {
    setWindowLocation({ origin: 'https://mailscope.dpdns.org' });

    const { getOAuthRedirectUrl } = await import('../lib/supabase.js');
    const url = getOAuthRedirectUrl('/auth/callback');

    expect(url).not.toMatch(/localhost/);
    expect(url).not.toMatch(/127\.0\.0\.1/);
    expect(url).not.toMatch(/:3000/);
    expect(url).not.toMatch(/:5173/);
  });

  it('NEVER returns a production URL when window.origin is localhost', async () => {
    setWindowLocation({ origin: 'http://localhost:5173' });

    const { getOAuthRedirectUrl } = await import('../lib/supabase.js');
    const url = getOAuthRedirectUrl('/auth/callback');

    expect(url).not.toMatch(/mailscope\.dpdns\.org/);
  });
});

// ─── Unit tests for hasAuthParamsInUrl ────────────────────────────────────────

describe('hasAuthParamsInUrl — OAuth URL detection', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it('detects access_token in URL hash', async () => {
    setWindowLocation({
      origin: 'https://mailscope.dpdns.org',
      pathname: '/',
      hash: '#access_token=eyJhbGci...&token_type=bearer&expires_in=3600',
    });
    const { hasAuthParamsInUrl } = await import('../lib/supabase.js');
    expect(hasAuthParamsInUrl()).toBe(true);
  });

  it('detects error in URL hash', async () => {
    setWindowLocation({
      origin: 'https://mailscope.dpdns.org',
      pathname: '/',
      hash: '#error=access_denied&error_description=User+cancelled',
    });
    const { hasAuthParamsInUrl } = await import('../lib/supabase.js');
    expect(hasAuthParamsInUrl()).toBe(true);
  });

  it('detects PKCE code in URL query string', async () => {
    setWindowLocation({
      origin: 'https://mailscope.dpdns.org',
      pathname: '/auth/callback',
      search: '?code=abc123xyz&state=some_state',
    });
    const { hasAuthParamsInUrl } = await import('../lib/supabase.js');
    expect(hasAuthParamsInUrl()).toBe(true);
  });

  it('returns false when no auth params present', async () => {
    setWindowLocation({
      origin: 'https://mailscope.dpdns.org',
      pathname: '/login',
      hash: '',
      search: '',
    });
    const { hasAuthParamsInUrl } = await import('../lib/supabase.js');
    expect(hasAuthParamsInUrl()).toBe(false);
  });
});

// ─── Unit tests for cleanAuthTokensFromUrl ────────────────────────────────────

describe('cleanAuthTokensFromUrl — URL token cleanup', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it('calls history.replaceState to strip access_token from hash', async () => {
    setWindowLocation({
      origin: 'https://mailscope.dpdns.org',
      pathname: '/auth/callback',
      hash: '#access_token=tok&refresh_token=ref&token_type=bearer',
      search: '',
    });

    const replaceSpy = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {});

    const { cleanAuthTokensFromUrl } = await import('../lib/supabase.js');
    cleanAuthTokensFromUrl();

    expect(replaceSpy).toHaveBeenCalledWith(
      null,
      expect.anything(),
      '/auth/callback'
    );
    replaceSpy.mockRestore();
  });

  it('does NOT call history.replaceState if no tokens in hash', async () => {
    setWindowLocation({
      origin: 'https://mailscope.dpdns.org',
      pathname: '/dashboard',
      hash: '',
      search: '',
    });

    const replaceSpy = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {});

    const { cleanAuthTokensFromUrl } = await import('../lib/supabase.js');
    cleanAuthTokensFromUrl();

    expect(replaceSpy).not.toHaveBeenCalled();
    replaceSpy.mockRestore();
  });
});
