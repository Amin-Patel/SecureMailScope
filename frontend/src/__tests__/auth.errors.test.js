import { describe, it, expect, vi } from 'vitest';

// Top-level mock for Supabase and utility functions needed by AuthContext
vi.mock('../lib/supabase.js', () => ({
  supabase: {
    auth: {
      getSession: vi.fn().mockResolvedValue({ data: { session: null }, error: null }),
      onAuthStateChange: vi.fn(() => ({
        data: { subscription: { unsubscribe: vi.fn() } },
      })),
      signInWithPassword: vi.fn(),
      signUp: vi.fn(),
      signInWithOAuth: vi.fn(),
      signOut: vi.fn(),
    },
  },
  getOAuthRedirectUrl: vi.fn(() => 'https://mailscope.dpdns.org/auth/callback'),
  cleanAuthTokensFromUrl: vi.fn(),
  hasAuthParamsInUrl: vi.fn(() => false),
}));

import { parseAuthError } from '../context/AuthContext.jsx';

describe('parseAuthError — error message mapping', () => {
  it('maps "Invalid login credentials" to friendly message', () => {
    const msg = parseAuthError({ message: 'Invalid login credentials' });
    expect(msg.toLowerCase()).toContain('invalid email or password');
  });

  it('maps "User already registered" to existing account message', () => {
    const msg = parseAuthError({ message: 'User already registered' });
    expect(msg.toLowerCase()).toContain('already exists');
  });

  it('maps "Password should be at least" to password length message', () => {
    const msg = parseAuthError({ message: 'Password should be at least 6 characters' });
    expect(msg.toLowerCase()).toContain('6 characters');
  });

  it('maps "provider is not enabled" to Google not configured message', () => {
    const msg = parseAuthError({ message: 'provider is not enabled' });
    expect(msg.toLowerCase()).toContain('google sign-in is not');
  });

  it('maps network errors to connection problem message', () => {
    const msg = parseAuthError({ message: 'Failed to fetch' });
    expect(msg.toLowerCase()).toContain('network');
  });

  it('maps rate limit error to wait message', () => {
    const msg = parseAuthError({ message: 'Too many requests' });
    expect(msg.toLowerCase()).toContain('too many');
  });

  it('returns raw message for unknown errors', () => {
    const msg = parseAuthError({ message: 'Some unknown error' });
    expect(msg).toBe('Some unknown error');
  });

  it('handles null/undefined without throwing', () => {
    expect(() => parseAuthError(null)).not.toThrow();
    expect(() => parseAuthError(undefined)).not.toThrow();
    expect(parseAuthError(null)).toBeTruthy();
  });

  it('handles string errors directly', () => {
    const msg = parseAuthError('Invalid login credentials');
    expect(msg.toLowerCase()).toContain('invalid email or password');
  });

  it('handles email confirmation required error', () => {
    const msg = parseAuthError({ message: 'Email not confirmed' });
    expect(msg.toLowerCase()).toContain('confirmed');
  });
});
