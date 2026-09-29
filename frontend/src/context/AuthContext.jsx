import React, { createContext, useContext, useState, useEffect } from 'react';
import {
  supabase,
  getOAuthRedirectUrl,
  cleanAuthTokensFromUrl,
  hasAuthParamsInUrl,
} from '../lib/supabase';

const AuthContext = createContext({});

/**
 * Maps Supabase auth error messages and exception objects into user-friendly strings.
 * Preserves security by not logging or leaking raw tokens, stack traces, or credentials.
 * 
 * @param {any} error
 * @returns {string} User-facing error message
 */
export function parseAuthError(error) {
  if (!error) return 'An unexpected error occurred.';
  const msg = error.message || String(error);
  const lowerMsg = msg.toLowerCase();

  if (
    lowerMsg.includes('invalid login credentials') ||
    lowerMsg.includes('invalid_grant') ||
    lowerMsg.includes('invalid username or password')
  ) {
    return 'Invalid email or password. Please verify your credentials and try again.';
  }
  if (
    lowerMsg.includes('user already registered') ||
    lowerMsg.includes('already exists')
  ) {
    return 'An account with this email address already exists. Please sign in instead.';
  }
  if (
    lowerMsg.includes('password should be at least') ||
    lowerMsg.includes('weak password')
  ) {
    return 'Password must be at least 6 characters long.';
  }
  if (
    lowerMsg.includes('email not confirmed') ||
    lowerMsg.includes('email_not_confirmed')
  ) {
    return 'Your email address has not been confirmed yet. Please check your inbox for the confirmation link.';
  }
  if (lowerMsg.includes('error sending confirmation email')) {
    return 'Email confirmation is currently enabled in your Supabase project without custom SMTP. In Supabase Dashboard -> Authentication -> Providers -> Email, please turn OFF "Confirm email" or configure custom SMTP.';
  }
  if (
    lowerMsg.includes('unable to validate email') ||
    lowerMsg.includes('invalid format') ||
    lowerMsg.includes('invalid email')
  ) {
    return 'Please enter a valid email address.';
  }
  if (
    lowerMsg.includes('access_denied') ||
    lowerMsg.includes('user cancelled') ||
    lowerMsg.includes('flow cancelled')
  ) {
    return 'Sign-in was cancelled by the user.';
  }
  if (
    lowerMsg.includes('provider is not enabled') ||
    lowerMsg.includes('unsupported provider')
  ) {
    return 'Google Sign-In is not enabled for this project in the Supabase Dashboard. Please sign in with email and password.';
  }
  if (
    lowerMsg.includes('failed to fetch') ||
    lowerMsg.includes('networkerror') ||
    lowerMsg.includes('network error') ||
    lowerMsg.includes('connection refused')
  ) {
    return 'Network connection problem. Please verify your internet connection and check if backend services are accessible.';
  }
  if (
    lowerMsg.includes('jwt expired') ||
    lowerMsg.includes('token has expired') ||
    lowerMsg.includes('session expired')
  ) {
    return 'Your authentication session has expired. Please sign in again.';
  }
  if (lowerMsg.includes('rate limit') || lowerMsg.includes('too many requests')) {
    return 'Too many login attempts. Please wait a moment and try again.';
  }

  return msg;
}

export function AuthProvider({ children }) {
  const [session, setSession] = useState(null);
  const [user, setUser] = useState(null);
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);

  // Fetch or sync user profile from Supabase public.profiles table
  const fetchProfile = async (currentUser) => {
    if (!currentUser) {
      setProfile(null);
      return;
    }
    try {
      const { data, error } = await supabase
        .from('profiles')
        .select('*')
        .eq('id', currentUser.id)
        .single();

      if (!error && data) {
        setProfile(data);
      } else {
        // Fallback profile if table query fails or profile is pending trigger creation
        setProfile({
          id: currentUser.id,
          email: currentUser.email,
          full_name:
            currentUser.user_metadata?.full_name ||
            currentUser.email?.split('@')[0] ||
            'User',
          avatar_url: currentUser.user_metadata?.avatar_url || null,
        });
      }
    } catch (err) {
      console.warn('[AuthContext] Profile fetch warning:', err);
      setProfile({
        id: currentUser.id,
        email: currentUser.email,
        full_name:
          currentUser.user_metadata?.full_name ||
          currentUser.email?.split('@')[0] ||
          'User',
        avatar_url: currentUser.user_metadata?.avatar_url || null,
      });
    }
  };

  useEffect(() => {
    let isMounted = true;
    const hasPendingAuth = hasAuthParamsInUrl();

    // 1. Initial active session retrieval
    supabase.auth
      .getSession()
      .then(({ data: { session: initSession }, error: sessionError }) => {
        if (!isMounted) return;
        if (sessionError) {
          console.warn('[AuthContext] Session notice:', sessionError.message);
        }

        if (initSession) {
          setSession(initSession);
          const currUser = initSession.user ?? null;
          setUser(currUser);
          cleanAuthTokensFromUrl();
          if (currUser) {
            fetchProfile(currUser).finally(() => {
              if (isMounted) setLoading(false);
            });
          } else {
            setLoading(false);
          }
        } else if (!hasPendingAuth) {
          // No active session and no OAuth URL params to wait for
          setLoading(false);
        }
      })
      .catch((err) => {
        console.warn('[AuthContext] Session retrieval notice:', err);
        if (isMounted && !hasPendingAuth) {
          setLoading(false);
        }
      });

    // 2. Listen for auth changes (SIGNED_IN, SIGNED_OUT, TOKEN_REFRESHED, USER_UPDATED)
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange(async (event, currentSession) => {
      if (!isMounted) return;

      setSession(currentSession);
      const currUser = currentSession?.user ?? null;
      setUser(currUser);

      if (currentSession) {
        cleanAuthTokensFromUrl();
      }

      if (currUser) {
        await fetchProfile(currUser);
      } else {
        setProfile(null);
      }

      setLoading(false);
    });

    // 3. Safety fallback timer: prevents indefinite loading if OAuth params were present but unhandled
    let safetyTimer = null;
    if (hasPendingAuth) {
      safetyTimer = setTimeout(() => {
        if (isMounted) {
          cleanAuthTokensFromUrl();
          setLoading(false);
        }
      }, 4000);
    }

    return () => {
      isMounted = false;
      if (safetyTimer) clearTimeout(safetyTimer);
      subscription?.unsubscribe();
    };
  }, []);

  // Email + Password Sign Up
  const signUp = async ({ email, password, fullName }) => {
    const redirectUrl = getOAuthRedirectUrl('/auth/callback');
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          full_name: fullName,
        },
        emailRedirectTo: redirectUrl,
      },
    });
    if (error) throw new Error(parseAuthError(error));
    return data;
  };

  // Email + Password Sign In
  const signIn = async ({ email, password }) => {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });
    if (error) throw new Error(parseAuthError(error));
    return data;
  };

  // Sign Out
  const signOut = async () => {
    try {
      await supabase.auth.signOut();
    } catch (error) {
      console.warn('[AuthContext] SignOut notice:', error);
    } finally {
      setUser(null);
      setSession(null);
      setProfile(null);
      cleanAuthTokensFromUrl();
      if (typeof window !== 'undefined' && window.localStorage) {
        localStorage.removeItem('sms_auth');
        localStorage.removeItem('sms_email');
      }
    }
  };

  // Update Profile details
  const updateProfile = async ({ fullName, email: newEmail }) => {
    if (!user) throw new Error('No authenticated user.');
    try {
      const { data, error } = await supabase
        .from('profiles')
        .upsert({
          id: user.id,
          email: newEmail || user.email,
          full_name: fullName,
          updated_at: new Date().toISOString(),
        })
        .select()
        .single();

      if (!error && data) {
        setProfile(data);
      } else {
        setProfile((prev) => ({ ...prev, full_name: fullName }));
      }
    } catch (err) {
      setProfile((prev) => ({ ...prev, full_name: fullName }));
    }
  };

  // Google OAuth Sign In — dynamically uses current browser origin
  const signInWithGoogle = async () => {
    const redirectUrl = getOAuthRedirectUrl('/auth/callback');
    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: {
        redirectTo: redirectUrl,
      },
    });
    if (error) {
      if (
        error.message?.includes('provider is not enabled') ||
        error.message?.includes('Unsupported provider')
      ) {
        throw new Error(
          'Google Sign-In is not yet enabled in the Supabase Dashboard. Please sign in with email and password.'
        );
      }
      throw new Error(parseAuthError(error));
    }
    return data;
  };

  const value = {
    session,
    user,
    profile,
    loading,
    signUp,
    signIn,
    signOut,
    updateProfile,
    signInWithGoogle,
    isAuthenticated: !!user,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
