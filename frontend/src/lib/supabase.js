import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || 'https://ymwflcngyzawphnvezmr.supabase.co';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY || import.meta.env.VITE_SUPABASE_ANON_KEY || '';

if (!supabaseAnonKey) {
  console.warn(
    '[SecureMailScope] VITE_SUPABASE_PUBLISHABLE_KEY is not defined in your environment (.env file). Auth functions will require a valid publishable key.'
  );
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey || 'placeholder-anon-key', {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
  },
});
