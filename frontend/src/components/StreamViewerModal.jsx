import React, { useState, useMemo } from 'react';

/**
 * StreamViewerModal - Interactive Forensic TCP Conversation Stream Viewer
 * Color-codes bidirectional client/server conversation, supports ASCII/HEX modes,
 * text search, transcript copying, and explicit redaction indicators.
 */
export function StreamViewerModal({ stream, onClose }) {
  const [viewMode, setViewMode] = useState('ascii'); // 'ascii' | 'hex'
  const [searchQuery, setSearchQuery] = useState('');
  const [copied, setCopied] = useState(false);

  if (!stream) return null;

  const {
    stream_id,
    protocol,
    client = {},
    server = {},
    packet_count = 0,
    payload_bytes = 0,
    duration = 0,
    encrypted = false,
    redacted = false,
    redaction_count = 0,
    chunks = []
  } = stream;

  // Filter chunks by search query
  const filteredChunks = useMemo(() => {
    if (!searchQuery.trim()) return chunks;
    const q = searchQuery.toLowerCase();
    return chunks.filter(c => 
      (c.payload && c.payload.toLowerCase().includes(q)) ||
      (c.hex_payload && c.hex_payload.toLowerCase().includes(q)) ||
      String(c.frame_number).includes(q)
    );
  }, [chunks, searchQuery]);

  // Handle transcript copy
  const handleCopyTranscript = () => {
    const transcript = chunks.map(c => {
      const dir = c.direction === 'client_to_server' ? 'CLIENT -> SERVER' : 'SERVER -> CLIENT';
      return `[Frame ${c.frame_number} | +${c.timestamp}s] ${dir}:\n${c.payload}\n`;
    }).join('\n');

    navigator.clipboard.writeText(transcript);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  return (
    <div className="modal-backdrop" onClick={onClose} style={{
      position: 'fixed',
      inset: 0,
      backgroundColor: 'rgba(5, 5, 12, 0.85)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 9999,
      padding: '24px'
    }}>
      <div className="modal-content glass-card" onClick={e => e.stopPropagation()} style={{
        width: '100%',
        maxWidth: '960px',
        maxHeight: '90vh',
        backgroundColor: '#0d0e1a',
        border: '1px solid rgba(99, 102, 241, 0.25)',
        borderRadius: '16px',
        boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 40px rgba(99, 102, 241, 0.15)',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        animation: 'modalSlideIn 0.25s cubic-bezier(0.16, 1, 0.3, 1)'
      }}>
        
        {/* ── Modal Header ── */}
        <div style={{
          padding: '20px 24px',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          backgroundColor: 'rgba(15, 17, 30, 0.95)'
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
              <h2 style={{ fontSize: '18px', fontWeight: 700, color: '#ffffff', margin: 0 }}>
                TCP Conversation Stream #{stream_id}
              </h2>
              <span className="badge" style={{
                backgroundColor: 'rgba(99, 102, 241, 0.2)',
                color: '#818cf8',
                border: '1px solid rgba(99, 102, 241, 0.35)',
                padding: '3px 8px',
                fontSize: '11px',
                fontWeight: 600,
                borderRadius: '6px'
              }}>
                {protocol}
              </span>
              {encrypted && (
                <span className="badge badge-low" style={{
                  backgroundColor: 'rgba(16, 185, 129, 0.2)',
                  color: '#34d399',
                  border: '1px solid rgba(16, 185, 129, 0.35)',
                  padding: '3px 8px',
                  fontSize: '11px',
                  fontWeight: 600,
                  borderRadius: '6px'
                }}>
                  <i className="fa-solid fa-lock" style={{ marginRight: '4px' }} /> TLS Encrypted
                </span>
              )}
            </div>

            <div style={{
              fontSize: '13px',
              fontFamily: 'monospace',
              color: '#94a3b8',
              display: 'flex',
              alignItems: 'center',
              gap: '16px'
            }}>
              <span style={{ color: '#38bdf8' }}>{client.ip}:{client.port}</span>
              <i className="fa-solid fa-arrow-right-arrow-left" style={{ fontSize: '11px', color: '#64748b' }} />
              <span style={{ color: '#34d399' }}>{server.ip}:{server.port}</span>
              <span style={{ color: '#64748b' }}>•</span>
              <span>{packet_count} Packets</span>
              <span style={{ color: '#64748b' }}>•</span>
              <span>{(payload_bytes / 1024).toFixed(1)} KB</span>
              <span style={{ color: '#64748b' }}>•</span>
              <span>{duration}s Duration</span>
            </div>
          </div>

          <button
            onClick={onClose}
            style={{
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              borderRadius: '8px',
              color: '#94a3b8',
              width: '32px',
              height: '32px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer',
              transition: 'all 0.2s ease'
            }}
            title="Close Stream Viewer"
          >
            <i className="fa-solid fa-xmark" />
          </button>
        </div>

        {/* ── Status Banner (Redaction / Encryption) ── */}
        <div style={{ padding: '12px 24px', backgroundColor: 'rgba(10, 11, 20, 0.7)', borderBottom: '1px solid rgba(255, 255, 255, 0.05)', display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          {redacted && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontSize: '12px',
              color: '#fbbf24',
              backgroundColor: 'rgba(245, 158, 11, 0.12)',
              border: '1px solid rgba(245, 158, 11, 0.25)',
              padding: '6px 12px',
              borderRadius: '8px',
              fontWeight: 500
            }}>
              <i className="fa-solid fa-shield-halved" />
              <span><strong>{redaction_count}</strong> sensitive credentials/tokens sanitized via protocol-aware masking</span>
            </div>
          )}

          {encrypted && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontSize: '12px',
              color: '#38bdf8',
              backgroundColor: 'rgba(56, 189, 248, 0.1)',
              border: '1px solid rgba(56, 189, 248, 0.2)',
              padding: '6px 12px',
              borderRadius: '8px',
              fontWeight: 500
            }}>
              <i className="fa-solid fa-circle-info" />
              <span>Application payload encrypted. Plaintext reconstruction unavailable without TLS session keys.</span>
            </div>
          )}
        </div>

        {/* ── Action Toolbar ── */}
        <div style={{
          padding: '12px 24px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          backgroundColor: 'rgba(15, 17, 30, 0.5)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.05)'
        }}>
          {/* Mode switch */}
          <div style={{ display: 'flex', gap: '6px' }}>
            <button
              onClick={() => setViewMode('ascii')}
              style={{
                padding: '6px 14px',
                borderRadius: '8px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
                border: 'none',
                backgroundColor: viewMode === 'ascii' ? '#6366f1' : 'rgba(255, 255, 255, 0.06)',
                color: viewMode === 'ascii' ? '#ffffff' : '#94a3b8'
              }}
            >
              <i className="fa-solid fa-code" style={{ marginRight: '6px' }} /> ASCII View
            </button>
            <button
              onClick={() => setViewMode('hex')}
              style={{
                padding: '6px 14px',
                borderRadius: '8px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
                border: 'none',
                backgroundColor: viewMode === 'hex' ? '#6366f1' : 'rgba(255, 255, 255, 0.06)',
                color: viewMode === 'hex' ? '#ffffff' : '#94a3b8'
              }}
            >
              <i className="fa-solid fa-binary" style={{ marginRight: '6px' }} /> HEX Stream
            </button>
          </div>

          {/* Search & Copy */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ position: 'relative' }}>
              <i className="fa-solid fa-magnifying-glass" style={{
                position: 'absolute',
                left: '10px',
                top: '50%',
                transform: 'translateY(-50%)',
                color: '#64748b',
                fontSize: '12px'
              }} />
              <input
                type="text"
                placeholder="Search stream payload..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                style={{
                  padding: '6px 12px 6px 30px',
                  backgroundColor: 'rgba(0, 0, 0, 0.3)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: '8px',
                  color: '#ffffff',
                  fontSize: '12px',
                  outline: 'none',
                  width: '200px'
                }}
              />
            </div>

            <button
              onClick={handleCopyTranscript}
              style={{
                padding: '6px 14px',
                backgroundColor: copied ? 'rgba(16, 185, 129, 0.2)' : 'rgba(255, 255, 255, 0.06)',
                border: `1px solid ${copied ? 'rgba(16, 185, 129, 0.4)' : 'rgba(255, 255, 255, 0.1)'}`,
                borderRadius: '8px',
                color: copied ? '#34d399' : '#e2e8f0',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px'
              }}
            >
              <i className={`fa-solid ${copied ? 'fa-check' : 'fa-copy'}`} />
              {copied ? 'Copied Transcript' : 'Copy'}
            </button>
          </div>
        </div>

        {/* ── Conversation Stream Chunks ── */}
        <div style={{
          padding: '20px 24px',
          overflowY: 'auto',
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          gap: '16px',
          backgroundColor: '#07080f'
        }}>
          {filteredChunks.length === 0 ? (
            <div style={{ textAlign: 'center', color: '#64748b', padding: '40px 0', fontSize: '13px' }}>
              {searchQuery ? 'No stream chunks matching query.' : 'No payload bytes transmitted in this stream.'}
            </div>
          ) : (
            filteredChunks.map((chunk, idx) => {
              const isClient = chunk.direction === 'client_to_server';
              const themeColor = isClient ? '#38bdf8' : '#34d399';
              const bgColor = isClient ? 'rgba(56, 189, 248, 0.04)' : 'rgba(52, 211, 153, 0.04)';
              const borderColor = isClient ? 'rgba(56, 189, 248, 0.25)' : 'rgba(52, 211, 153, 0.25)';

              return (
                <div key={idx} style={{
                  backgroundColor: bgColor,
                  border: `1px solid ${borderColor}`,
                  borderRadius: '10px',
                  padding: '12px 16px',
                  fontFamily: 'monospace'
                }}>
                  {/* Chunk Header */}
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginBottom: '8px',
                    fontSize: '11px',
                    color: '#94a3b8',
                    borderBottom: `1px solid ${borderColor}`,
                    paddingBottom: '6px'
                  }}>
                    <span style={{ color: themeColor, fontWeight: 700 }}>
                      <i className={`fa-solid ${isClient ? 'fa-arrow-right' : 'fa-arrow-left'}`} style={{ marginRight: '6px' }} />
                      {isClient ? 'CLIENT → SERVER' : 'SERVER → CLIENT'}
                    </span>
                    <div style={{ display: 'flex', gap: '12px' }}>
                      <span>Frame #{chunk.frame_number}</span>
                      <span>+{chunk.timestamp}s</span>
                    </div>
                  </div>

                  {/* Chunk Body */}
                  <pre style={{
                    margin: 0,
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    fontSize: '13px',
                    lineHeight: '1.5',
                    color: isClient ? '#e0f2fe' : '#dcfce7'
                  }}>
                    {viewMode === 'ascii' ? (chunk.payload || '(empty payload)') : (chunk.hex_payload || '(no hex)')}
                  </pre>
                </div>
              );
            })
          )}
        </div>

      </div>
    </div>
  );
}
