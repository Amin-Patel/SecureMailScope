import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';

function Toast({ message, onDone }) {
  useEffect(() => {
    const t = setTimeout(onDone, 2800);
    return () => clearTimeout(t);
  }, [onDone]);
  return (
    <div style={{
      position: 'fixed', bottom: 28, right: 28, zIndex: 9999,
      background: 'rgba(16,185,129,0.15)', backdropFilter: 'blur(12px)',
      border: '1px solid rgba(16,185,129,0.4)', borderRadius: 12,
      padding: '12px 20px', display: 'flex', alignItems: 'center', gap: 10,
      color: '#34d399', fontSize: 13, fontWeight: 600,
      boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
      animation: 'slideInToast 0.3s ease',
    }}>
      <i className="fa-solid fa-circle-check"></i>
      {message}
      <style>{`@keyframes slideInToast { from { opacity:0; transform: translateY(12px); } to { opacity:1; transform: translateY(0); } }`}</style>
    </div>
  );
}

export function Settings() {
  const { user, profile, updateProfile, signOut } = useAuth();
  const [username, setUsername] = useState(() => profile?.full_name || user?.user_metadata?.full_name || localStorage.getItem('sms_username') || 'Security Analyst');
  const [email, setEmail]       = useState(() => user?.email || profile?.email || localStorage.getItem('sms_email') || 'analyst@securemailscope.com');
  const [toast, setToast]       = useState(null);
  const [saving, setSaving]     = useState(false);

  useEffect(() => {
    if (profile?.full_name) {
      setUsername(profile.full_name);
    }
    if (user?.email) {
      setEmail(user.email);
    }
  }, [profile, user]);

  const initials = (username || 'Security Analyst').split(/\s+/).map(w => w[0]).join('').toUpperCase().slice(0, 2);

  const handleSave = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      await updateProfile({ fullName: username });
      localStorage.setItem('sms_username', username);
      setToast('Profile updated successfully!');
    } catch (err) {
      setToast('Failed to update profile.');
    } finally {
      setSaving(false);
    }
  };

  const fieldStyle = {
    width: '100%', padding: '11px 14px', borderRadius: 10, boxSizing: 'border-box',
    background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
    color: '#fff', fontSize: 14, outline: 'none',
    transition: 'border-color 0.2s ease',
  };

  return (
    <main style={{ width: '100%', maxWidth: 680, margin: '0 auto', padding: '0 16px', position: 'relative', zIndex: 5 }}>
      {toast && <Toast message={toast} onDone={() => setToast(null)} />}

      {/* Title */}
      <div style={{ marginBottom: 24 }}>
        <h2 style={{
          background: 'linear-gradient(135deg, #ffffff 0%, #a5b4fc 100%)',
          WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
          backgroundClip: 'text',
          fontSize: 'clamp(22px, 3vw, 32px)', fontWeight: 800, letterSpacing: '-0.03em', marginBottom: 6,
        }}>
          Settings &amp; Account
        </h2>
        <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.45)' }}>Manage your user identity and platform preferences</p>
      </div>

      {/* Profile Card */}
      <div style={{
        background: 'rgba(10,10,18,0.65)', backdropFilter: 'blur(16px)',
        border: '1px solid rgba(255,255,255,0.1)', borderRadius: 16,
        padding: '24px', marginBottom: 16,
      }}>
        {/* Avatar row */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 24 }}>
          <div style={{
            width: 56, height: 56, borderRadius: '50%', flexShrink: 0,
            background: 'linear-gradient(135deg, #6366f1, #a855f7)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 20, fontWeight: 800, color: '#fff',
            boxShadow: '0 0 20px rgba(99,102,241,0.45)',
          }}>
            {initials}
          </div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, color: '#fff' }}>{username}</div>
            <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.45)', marginTop: 2 }}>{email}</div>
            {user?.id && (
              <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', fontFamily: 'monospace', marginTop: 4 }}>
                ID: {user.id}
              </div>
            )}
          </div>
        </div>

        <div style={{ fontSize: 12, fontWeight: 700, color: 'rgba(255,255,255,0.5)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 16 }}>
          Profile Details
        </div>
        <form onSubmit={handleSave}>
          <div style={{ marginBottom: 14 }}>
            <label style={{ display: 'block', fontSize: 12, color: 'rgba(255,255,255,0.55)', marginBottom: 6 }}>Full Name / Display Name</label>
            <input
              style={fieldStyle}
              onFocus={e => e.target.style.borderColor = 'rgba(99,102,241,0.6)'}
              onBlur={e => e.target.style.borderColor = 'rgba(255,255,255,0.1)'}
              type="text" value={username}
              onChange={e => setUsername(e.target.value)}
            />
          </div>
          <div style={{ marginBottom: 20 }}>
            <label style={{ display: 'block', fontSize: 12, color: 'rgba(255,255,255,0.55)', marginBottom: 6 }}>Email Address (Managed by Supabase Auth)</label>
            <input
              style={{ ...fieldStyle, opacity: 0.7, cursor: 'not-allowed' }}
              type="email" value={email} disabled
            />
          </div>
          <button
            type="submit"
            disabled={saving}
            style={{
              padding: '11px 28px', borderRadius: 10, border: 'none', cursor: saving ? 'not-allowed' : 'pointer',
              background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
              color: '#fff', fontSize: 14, fontWeight: 700,
              boxShadow: '0 4px 16px rgba(99,102,241,0.4)',
              transition: 'transform 0.15s ease, box-shadow 0.15s ease',
            }}
            onMouseEnter={e => { e.target.style.transform = 'translateY(-2px)'; e.target.style.boxShadow = '0 6px 24px rgba(99,102,241,0.6)'; }}
            onMouseLeave={e => { e.target.style.transform = ''; e.target.style.boxShadow = '0 4px 16px rgba(99,102,241,0.4)'; }}
          >
            {saving ? 'Saving...' : 'Save Profile'}
          </button>
        </form>
      </div>

      {/* System Info Card */}
      <div style={{
        background: 'rgba(10,10,18,0.65)', backdropFilter: 'blur(16px)',
        border: '1px solid rgba(255,255,255,0.1)', borderRadius: 16,
        padding: '24px',
      }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: 'rgba(255,255,255,0.5)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 16 }}>
          System Information
        </div>
        {[
          { icon: 'fa-code-branch',    label: 'Software Version',    value: 'SecureMailScope v1.0.4-beta' },
          { icon: 'fa-microchip',      label: 'Core Engine',         value: 'Zeek / tshark v4.2.1' },
          { icon: 'fa-shield-halved',  label: 'Risk Scoring Rules',  value: 'Ruleset v2.10.4' },
          { icon: 'fa-database',       label: 'Auth Provider',       value: 'Supabase Auth (PostgreSQL 17)' },
          { icon: 'fa-circle-dot',     label: 'Status',              value: 'Operational', green: true },
        ].map(({ icon, label, value, green }) => (
          <div key={label} style={{
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            padding: '12px 0', borderBottom: '1px solid rgba(255,255,255,0.05)',
          }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13, color: 'rgba(255,255,255,0.5)' }}>
              <i className={`fa-solid ${icon}`} style={{ width: 14, textAlign: 'center' }}></i>
              {label}
            </span>
            <span style={{ fontSize: 13, fontWeight: 600, color: green ? '#10b981' : '#fff' }}>
              {green && <i className="fa-solid fa-circle-check" style={{ marginRight: 6 }}></i>}
              {value}
            </span>
          </div>
        ))}
      </div>

      {/* Account Session / Sign Out Card */}
      <div style={{
        marginTop: 16,
        background: 'rgba(10,10,18,0.65)', backdropFilter: 'blur(16px)',
        border: '1px solid rgba(255,255,255,0.1)', borderRadius: 16,
        padding: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16,
      }}>
        <div>
          <div style={{ fontSize: 14, fontWeight: 600, color: '#fff', marginBottom: 4 }}>Account Session</div>
          <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.45)' }}>Sign out of your SecureMailScope session</div>
        </div>
        <button
          type="button"
          onClick={() => signOut()}
          style={{
            padding: '9px 20px', borderRadius: 10, border: '1px solid rgba(239,68,68,0.3)', cursor: 'pointer',
            background: 'rgba(239,68,68,0.1)', color: '#f87171', fontSize: 13, fontWeight: 600,
            display: 'inline-flex', alignItems: 'center', gap: 8,
            transition: 'background 0.2s ease',
          }}
          onMouseEnter={e => e.currentTarget.style.background = 'rgba(239,68,68,0.2)'}
          onMouseLeave={e => e.currentTarget.style.background = 'rgba(239,68,68,0.1)'}
        >
          <i className="fa-solid fa-right-from-bracket" />
          Sign Out
        </button>
      </div>
    </main>
  );
}

