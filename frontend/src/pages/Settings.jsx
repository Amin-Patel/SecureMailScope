import React, { useState } from 'react';

export function Settings() {
  const [username, setUsername] = useState('SecurityAnalyst');
  const [email, setEmail] = useState('analyst@securemailscope.com');

  const handleSave = (e) => {
    e.preventDefault();
    alert('Profile settings successfully saved!');
  };

  return (
    <main className="settings-container">
      <div className="settings-title-bar">
        <h2 style={{ fontSize: 'clamp(16px, 2.2vw, 22px)', fontWeight: 600, color: '#ffffff' }}>
          User Settings &amp; Profile
        </h2>
      </div>

      {/* Profile Card */}
      <div className="glass-card">
        <h3 className="form-label" style={{ fontSize: '13px', color: '#ffffff', marginBottom: '16px' }}>
          Profile Settings
        </h3>
        <form onSubmit={handleSave}>
          <div className="form-group">
            <label className="form-label" htmlFor="username">Username</label>
            <input
              className="form-input"
              type="text"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="email">Email Address</label>
            <input
              className="form-input"
              type="email"
              id="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <button className="btn-save" type="submit">Save Changes</button>
        </form>
      </div>

      {/* System Info Card */}
      <div className="glass-card">
        <h3 className="form-label" style={{ fontSize: '13px', color: '#ffffff', marginBottom: '16px' }}>
          System Information
        </h3>
        <div className="app-info-grid">
          <div className="app-info-item">
            <span className="form-label">Software Version</span>
            <span>SecureMailScope v1.0.4-beta</span>
          </div>
          <div className="app-info-item">
            <span className="form-label">Core Engine</span>
            <span>Zeek / tshark v4.2.1</span>
          </div>
          <div className="app-info-item">
            <span className="form-label">Risk Scoring Rules</span>
            <span>Ruleset v2.10.4</span>
          </div>
          <div className="app-info-item">
            <span className="form-label">Status</span>
            <span style={{ color: '#10b981' }}>
              <i className="fa-solid fa-circle-check"></i> Operational
            </span>
          </div>
        </div>
      </div>
    </main>
  );
}
