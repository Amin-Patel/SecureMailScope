import React, { createContext, useContext, useState, useEffect } from 'react';
import { supabase } from '../lib/supabase';

const AuthContext = createContext({});

export function parseAuthError(error) {
  if (!error) return 'An unexpected error occurred.';
  const msg = error.message || String(error);

  if (msg.includes('Invalid login credentials')) {
    return 'Invalid email or password.';
  }
  if (msg.includes('User already registered')) {
    return 'An account with this email address already exists.';
  }
  if (msg.includes('Password should be at least')) {
    return 'Password must be at least 6 characters long.';
  }
  if (msg.toLowerCase().includes('error sending confirmation email')) {
    return 'Email confirmation is enabled in your Supabase project. In Supabase Dashboard -> Authentication -> Providers -> Email, please turn OFF "Confirm email".';
  }

  return msg;
}

export function AuthProvider({ children }) {
  const [session, setSession] = useState(null);
  const [user, setUser] = useState(null);
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);

  // Fetch or sync user profile from Supabase profiles table
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
        // Fallback profile if table query fails or profile is pending creation
        setProfile({
          id: currentUser.id,
          email: currentUser.email,
          full_name: currentUser.user_metadata?.full_name || currentUser.email?.split('@')[0] || 'User',
          avatar_url: currentUser.user_metadata?.avatar_url || null,
        });
      }
    } catch (err) {
      console.warn('[AuthContext] Profile fetch warning:', err);
      setProfile({
        id: currentUser.id,
        email: currentUser.email,
        full_name: currentUser.user_metadata?.full_name || currentUser.email?.split('@')[0] || 'User',
        avatar_url: currentUser.user_metadata?.avatar_url || null,
      });
    }
  };

  useEffect(() => {
    // 1. Get initial active session
    supabase.auth.getSession().then(({ data: { session: initSession } }) => {
      setSession(initSession);
      const currUser = initSession?.user ?? null;
      setUser(currUser);
      if (currUser) {
        fetchProfile(currUser).finally(() => setLoading(false));
      } else {
        setLoading(false);
      }
    }).catch(err => {
      console.warn('[AuthContext] Session retrieval notice:', err);
      setLoading(false);
    });

    // 2. Listen for auth changes (SIGN_IN, SIGN_OUT, USER_UPDATED)
    const { data: { subscription } } = supabase.auth.onAuthStateChange(async (event, currentSession) => {
      setSession(currentSession);
      const currUser = currentSession?.user ?? null;
      setUser(currUser);

      if (currUser) {
        await fetchProfile(currUser);
      } else {
        setProfile(null);
      }

      setLoading(false);
    });

    return () => {
      subscription?.unsubscribe();
    };
  }, []);

  // Email + Password Sign Up (no email confirmation required)
  const signUp = async ({ email, password, fullName }) => {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          full_name: fullName,
        },
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
    const { error } = await supabase.auth.signOut();
    setUser(null);
    setSession(null);
    setProfile(null);
    localStorage.removeItem('sms_auth');
    if (error) console.warn('[AuthContext] SignOut notice:', error);
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
        setProfile(prev => ({ ...prev, full_name: fullName }));
      }
    } catch (err) {
      setProfile(prev => ({ ...prev, full_name: fullName }));
    }
  };

  // Google OAuth Sign In
  const signInWithGoogle = async () => {
    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: {
        redirectTo: window.location.origin + '/dashboard',
      },
    });
    if (error) {
      if (error.message?.includes('provider is not enabled') || error.message?.includes('Unsupported provider')) {
        throw new Error('Google Sign-In is not yet enabled in the Supabase Dashboard. Please sign in with email and password.');
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
