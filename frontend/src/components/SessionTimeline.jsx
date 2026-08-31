import React, { useState, useMemo } from 'react';

export function SessionTimeline({ sessions = [] }) {
  const [filter, setFilter] = useState('all'); // 'all', 'encrypted', 'plaintext'
  const [searchQuery, setSearchQuery] = useState('');

  // Local filtering & searching to prevent reloading or network requests
  const filteredSessions = useMemo(() => {
    return sessions.filter((session) => {
      // 1. Filter by encryption status
      if (filter === 'encrypted' && !session.encrypted) return false;
      if (filter === 'plaintext' && session.encrypted) return false;

      // 2. Filter by search query (IP address, ports, protocols)
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const srcMatch = (session.src || '').toLowerCase().includes(query);
        const dstMatch = (session.dst || '').toLowerCase().includes(query);
        const protoMatch = (session.protocol || '').toLowerCase().includes(query);
        const tlsMatch = Array.isArray(session.tls_versions)
          ? session.tls_versions.some(v => v.toLowerCase().includes(query))
          : typeof session.tls_versions === 'string'
          ? session.tls_versions.toLowerCase().includes(query)
          : false;
        
        if (!srcMatch && !dstMatch && !protoMatch && !tlsMatch) {
          return false;
        }
      }

      return true;
    });
  }, [sessions, filter, searchQuery]);

  const handleSearchChange = (e) => {
    setSearchQuery(e.target.value);
  };

  const getProtocolBadgeStyle = (protocol) => {
    const p = (protocol || '').toUpperCase();
    if (['SMTPS', 'IMAPS', 'POP3S'].includes(p) || p.endsWith('S')) {
      return {
        background: 'rgba(99, 102, 241, 0.15)',
        color: '#a5b4fc',
        border: '1px solid rgba(99, 102, 241, 0.4)',
      };
    }
    return {
      background: 'rgba(156, 163, 175, 0.15)',
      color: '#d1d5db',
      border: '1px solid rgba(156, 163, 175, 0.3)',
    };
  };

  return (
    <div className="glass-card timeline-container" style={{ width: '100%' }}>
      {/* Title */}
      <div className="card-title" style={{ justifyContent: 'space-between', marginBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <i className="fa-solid fa-network-wired" style={{ color: '#818cf8' }}></i>
          <span>Interactive Session Timeline</span>
        </div>
        {sessions.length > 0 && (
          <span style={{ fontSize: '12px', color: 'var(--muted)', fontWeight: 500 }}>
            {filteredSessions.length} of {sessions.length} Session{sessions.length === 1 ? '' : 's'}
          </span>
        )}
      </div>

      {/* Filters and Search Bar */}
      <div
        className="timeline-controls"
        style={{
          display: 'flex',
          gap: '12px',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          marginBottom: '20px',
        }}
      >
        {/* Search Field */}
        <div style={{ position: 'relative', flex: '1', minWidth: '240px' }}>
          <i
            className="fa-solid fa-magnifying-glass"
            style={{
              position: 'absolute',
              left: '12px',
              top: '50%',
              transform: 'translateY(-50%)',
              color: 'rgba(255, 255, 255, 0.4)',
              fontSize: '13px',
            }}
          ></i>
          <input
            type="text"
            placeholder="Search IP address or port..."
            value={searchQuery}
            onChange={handleSearchChange}
            style={{
              width: '100%',
              padding: '9px 12px 9px 36px',
              borderRadius: '8px',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              background: 'rgba(0, 0, 0, 0.3)',
              color: '#fff',
              fontSize: '13px',
              outline: 'none',
              transition: 'border-color 0.2s',
            }}
            onFocus={(e) => (e.target.style.borderColor = 'rgba(99, 102, 241, 0.6)')}
            onBlur={(e) => (e.target.style.borderColor = 'rgba(255, 255, 255, 0.12)')}
          />
        </div>

        {/* Filter Pill Group */}
        <div style={{ display: 'flex', gap: '6px', background: 'rgba(0, 0, 0, 0.2)', padding: '4px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
          {[
            { id: 'all', label: 'All Sessions' },
            { id: 'encrypted', label: 'Encrypted Only' },
            { id: 'plaintext', label: 'Plaintext Only' },
          ].map((btn) => (
            <button
              key={btn.id}
              onClick={() => setFilter(btn.id)}
              style={{
                padding: '6px 12px',
                borderRadius: '6px',
                border: 'none',
                background: filter === btn.id ? 'rgba(255, 255, 255, 0.08)' : 'transparent',
                color: filter === btn.id ? '#fff' : 'rgba(255, 255, 255, 0.6)',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              {btn.label}
            </button>
          ))}
        </div>
      </div>

      {/* Session Cards list */}
      {filteredSessions.length === 0 ? (
        <div
          style={{
            textAlign: 'center',
            padding: '40px 20px',
            color: 'rgba(255, 255, 255, 0.4)',
            background: 'rgba(0, 0, 0, 0.15)',
            border: '1px dashed rgba(255, 255, 255, 0.08)',
            borderRadius: '12px',
          }}
        >
          <i className="fa-solid fa-circle-nodes" style={{ fontSize: '32px', color: '#818cf8', marginBottom: '12px', display: 'block' }}></i>
          <h4 style={{ color: '#fff', fontSize: '15px', fontWeight: 700, margin: '0 0 6px 0' }}>
            No Email Sessions Detected
          </h4>
          <p style={{ margin: 0, fontSize: '13px', maxWidth: '380px', marginLeft: 'auto', marginRight: 'auto', lineHeight: '1.4' }}>
            No reconstructable email sessions were found in this capture matching the filters.
          </p>
        </div>
      ) : (
        <div
          className="timeline-list"
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '12px',
            maxHeight: '450px',
            overflowY: 'auto',
            paddingRight: '4px',
          }}
        >
          {filteredSessions.map((session, idx) => {
            const isEncrypted = session.encrypted === true;
            const tlsVer = Array.isArray(session.tls_versions) && session.tls_versions.length > 0
              ? session.tls_versions.join(', ')
              : session.tls_versions || '';

            return (
              <div
                key={session.id || idx}
                style={{
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid rgba(255, 255, 255, 0.06)',
                  borderRadius: '12px',
                  padding: '14px 16px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '16px',
                  flexWrap: 'wrap',
                  transition: 'all 0.2s ease',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = 'rgba(255, 255, 255, 0.04)';
                  e.currentTarget.style.borderColor = 'rgba(99, 102, 241, 0.25)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = 'rgba(255, 255, 255, 0.02)';
                  e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.06)';
                }}
              >
                {/* Left block: Protocol & Endpoints */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flexWrap: 'wrap', flex: '1', minWidth: '220px' }}>
                  {/* Protocol Badge */}
                  <span
                    className="badge"
                    style={{
                      ...getProtocolBadgeStyle(session.protocol),
                      fontSize: '11px',
                      fontWeight: '800',
                      padding: '4px 10px',
                      borderRadius: '6px',
                      textTransform: 'uppercase',
                    }}
                  >
                    {session.protocol || 'EMAIL'}
                  </span>

                  {/* Endpoints connection */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', fontWeight: 600 }}>
                    <span style={{ color: '#fff', fontFamily: 'monospace' }}>{session.src}</span>
                    <i className="fa-solid fa-arrow-right" style={{ fontSize: '10px', color: 'rgba(255,255,255,0.4)' }}></i>
                    <span style={{ color: '#fff', fontFamily: 'monospace' }}>{session.dst}</span>
                  </div>
                </div>

                {/* Right block: Packet counts & Encryption Status & TLS */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flexWrap: 'wrap' }}>
                  {/* Packet Count */}
                  <div style={{ fontSize: '12px', color: 'rgba(255, 255, 255, 0.5)' }}>
                    <strong style={{ color: '#fff', marginRight: '4px' }}>{session.packet_count ?? 0}</strong> packets
                  </div>

                  {/* Encryption Status Badge */}
                  {isEncrypted ? (
                    <span
                      className="badge"
                      style={{
                        background: 'rgba(16, 185, 129, 0.15)',
                        color: '#10b981',
                        border: '1px solid rgba(16, 185, 129, 0.3)',
                        fontSize: '11px',
                        padding: '3px 8px',
                        gap: '4px',
                      }}
                    >
                      <i className="fa-solid fa-lock" style={{ fontSize: '10px' }}></i>
                      {tlsVer ? `TLS / ${tlsVer}` : 'Encrypted'}
                    </span>
                  ) : (
                    <span
                      className="badge"
                      style={{
                        background: 'rgba(239, 68, 68, 0.15)',
                        color: '#ef4444',
                        border: '1px solid rgba(239, 68, 68, 0.3)',
                        fontSize: '11px',
                        padding: '3px 8px',
                        gap: '4px',
                      }}
                    >
                      <i className="fa-solid fa-lock-open" style={{ fontSize: '10px' }}></i>
                      Plaintext
                    </span>
                  )}

                  {/* Start/End Time display if available */}
                  {(session.start_time || session.end_time) && (
                    <div style={{ fontSize: '11px', color: 'rgba(255, 255, 255, 0.35)', textAlign: 'right' }}>
                      {session.start_time && <div>Start: {session.start_time}</div>}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default SessionTimeline;
