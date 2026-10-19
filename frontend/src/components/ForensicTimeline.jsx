import React, { useState, useEffect } from 'react';
import { getForensics, downloadForensicReportPdf } from '../utils/api';

export function ForensicTimeline({ analysisData, onNavigateFinding }) {
  const [forensics, setForensics] = useState(analysisData?.forensic_reconstruction || null);
  const [loading, setLoading] = useState(!analysisData?.forensic_reconstruction);
  const [filterType, setFilterType] = useState('ALL');
  const [exportingPdf, setExportingPdf] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);

  const captureId = analysisData?.capture_id;

  useEffect(() => {
    if (!analysisData?.forensic_reconstruction && captureId) {
      setLoading(true);
      getForensics(captureId)
        .then(data => {
          setForensics(data);
          setLoading(false);
        })
        .catch(err => {
          console.error('Error fetching forensics:', err);
          setLoading(false);
        });
    } else if (analysisData?.forensic_reconstruction) {
      setForensics(analysisData.forensic_reconstruction);
      setLoading(false);
    }
  }, [captureId, analysisData]);

  const handleDownloadPdf = async () => {
    if (!captureId) return;
    try {
      setExportingPdf(true);
      await downloadForensicReportPdf(captureId);
    } catch (err) {
      console.error('Failed to download forensic report PDF:', err);
      alert('Failed to generate Forensic PDF report: ' + (err.message || 'Unknown error'));
    } finally {
      setExportingPdf(false);
    }
  };

  if (loading) {
    return (
      <div className="glass-card" style={{ padding: '40px', textAlign: 'center', color: '#94a3b8' }}>
        <i className="fa-solid fa-circle-notch fa-spin" style={{ fontSize: '32px', color: '#818cf8', marginBottom: '14px' }} />
        <div style={{ fontSize: '15px', fontWeight: 600, color: '#ffffff' }}>Reconstructing Historical Cryptographic Events…</div>
        <p style={{ fontSize: '13px', color: '#94a3b8', marginTop: '6px' }}>Correlating TCP streams, STARTTLS handshakes, and PKI evidence.</p>
      </div>
    );
  }

  const timeline = forensics?.chronological_timeline || [];
  const metrics = forensics?.forensic_metrics || {};
  const regressions = forensics?.host_regressions || [];

  const filteredTimeline = timeline.filter(evt => {
    if (filterType === 'ALL') return true;
    if (filterType === 'TLS') return evt.event_type?.includes('TLS') || evt.protocol === 'TLS';
    if (filterType === 'STARTTLS') return evt.event_type?.includes('STARTTLS');
    if (filterType === 'FINDINGS') return evt.related_findings?.length > 0;
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Banner & PDF Export */}
      <div className="glass-card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{
              background: 'rgba(99, 102, 241, 0.2)',
              border: '1px solid rgba(99, 102, 241, 0.4)',
              color: '#a5b4fc',
              fontSize: '11px',
              fontWeight: 800,
              padding: '3px 8px',
              borderRadius: '6px',
              letterSpacing: '0.05em'
            }}>FORENSIC AUDIT</span>
            <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#ffffff', margin: 0 }}>
              Historical Cryptographic Forensics
            </h3>
          </div>
          <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.65)', margin: '6px 0 0 0' }}>
            Chronological wire-level event timeline across TCP streams with forensic provenance, state progression, and evidentiary uncertainty.
          </p>
        </div>

        <button
          onClick={handleDownloadPdf}
          disabled={exportingPdf}
          className="btn-action"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '10px 20px',
            borderRadius: '999px',
            background: 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)',
            color: '#ffffff',
            fontWeight: 700,
            fontSize: '13px',
            border: 'none',
            cursor: exportingPdf ? 'not-allowed' : 'pointer',
            boxShadow: '0 4px 16px rgba(99,102,241,0.3)'
          }}
        >
          <i className={exportingPdf ? "fa-solid fa-spinner fa-spin" : "fa-solid fa-file-pdf"} />
          <span>{exportingPdf ? "Generating PDF…" : "Export Forensic Report (PDF)"}</span>
        </button>
      </div>

      {/* Forensic Metrics Grid */}
      <div className="metrics-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        <div className="metric-box">
          <div className="metric-value">{metrics.total_events ?? timeline.length}</div>
          <div className="metric-label">Reconstructed Events</div>
        </div>
        <div className="metric-box">
          <div className="metric-value">{metrics.crypto_transitions ?? 0}</div>
          <div className="metric-label">Crypto Transitions</div>
        </div>
        <div className="metric-box">
          <div className="metric-value">{metrics.sessions_tracked ?? 0}</div>
          <div className="metric-label">Correlated Sessions</div>
        </div>
        <div className="metric-box">
          <div className="metric-value" style={{ color: regressions.length > 0 ? '#ef4444' : '#10b981' }}>
            {regressions.length}
          </div>
          <div className="metric-label">Temporal Regressions</div>
        </div>
      </div>

      {/* Temporal Downgrade / Regression Alert Banner (if any) */}
      {regressions.length > 0 && (
        <div style={{
          background: 'rgba(239, 68, 68, 0.12)',
          border: '1.5px solid rgba(239, 68, 68, 0.4)',
          borderRadius: '12px',
          padding: '16px 20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#f87171', fontWeight: 700, fontSize: '14px' }}>
            <i className="fa-solid fa-triangle-exclamation" />
            <span>Longitudinal Host Regression Detected</span>
          </div>
          {regressions.map((reg, idx) => (
            <p key={idx} style={{ margin: 0, fontSize: '13px', color: '#e2e8f0', lineHeight: 1.5 }}>
              Host <strong>{reg.host}</strong>: {reg.message} (Previous risk: {reg.previous_risk_score} &rarr; Current: {reg.current_risk_score})
            </p>
          ))}
        </div>
      )}

      {/* Timeline Filter Controls */}
      <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
        <span style={{ fontSize: '12px', color: 'rgba(255,255,255,0.5)', fontWeight: 600, marginRight: '4px' }}>
          Filter Events:
        </span>
        {[
          { id: 'ALL', label: 'All Events' },
          { id: 'STARTTLS', label: 'STARTTLS Upgrades' },
          { id: 'TLS', label: 'TLS Handshakes' },
          { id: 'FINDINGS', label: 'Has Findings' },
        ].map(btn => (
          <button
            key={btn.id}
            onClick={() => setFilterType(btn.id)}
            style={{
              padding: '6px 14px',
              borderRadius: '999px',
              border: filterType === btn.id ? '1px solid #818cf8' : '1px solid rgba(255,255,255,0.1)',
              background: filterType === btn.id ? 'rgba(99,102,241,0.25)' : 'rgba(255,255,255,0.04)',
              color: filterType === btn.id ? '#ffffff' : '#94a3b8',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.2s ease'
            }}
          >
            {btn.label}
          </button>
        ))}
        <span style={{ marginLeft: 'auto', fontSize: '12px', color: 'rgba(255,255,255,0.4)' }}>
          Showing {filteredTimeline.length} of {timeline.length} events
        </span>
      </div>

      {/* Chronological Event Stream */}
      <div className="glass-card" style={{ padding: '20px' }}>
        {filteredTimeline.length === 0 ? (
          <div style={{ padding: '30px', textAlign: 'center', color: '#94a3b8' }}>
            No events match the selected filter.
          </div>
        ) : (
          <div style={{ position: 'relative', paddingLeft: '32px' }}>
            {/* Vertical timeline spine */}
            <div style={{
              position: 'absolute',
              left: '12px',
              top: '10px',
              bottom: '10px',
              width: '2px',
              background: 'linear-gradient(to bottom, #6366f1, #3b82f6, #10b981)'
            }} />

            {filteredTimeline.map((evt, idx) => {
              const hasFindings = evt.related_findings && evt.related_findings.length > 0;
              const isEncrypted = evt.is_encrypted;
              const nodeColor = hasFindings ? '#ef4444' : isEncrypted ? '#10b981' : '#38bdf8';

              return (
                <div key={evt.event_id || idx} style={{ position: 'relative', marginBottom: '24px' }}>
                  {/* Timeline Node Dot */}
                  <div style={{
                    position: 'absolute',
                    left: '-26px',
                    top: '4px',
                    width: '14px',
                    height: '14px',
                    borderRadius: '50%',
                    background: nodeColor,
                    border: '3px solid #0f172a',
                    boxShadow: `0 0 10px ${nodeColor}88`
                  }} />

                  {/* Event Card */}
                  <div style={{
                    background: 'rgba(255,255,255,0.03)',
                    border: '1px solid rgba(255,255,255,0.08)',
                    borderRadius: '10px',
                    padding: '14px 18px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '8px'
                  }}>
                    {/* Header Row */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{
                          fontFamily: 'monospace',
                          fontSize: '11px',
                          color: '#818cf8',
                          fontWeight: 700
                        }}>
                          {evt.event_id}
                        </span>
                        <span style={{
                          background: 'rgba(255,255,255,0.08)',
                          color: '#ffffff',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          fontSize: '11px',
                          fontWeight: 700
                        }}>
                          {evt.protocol}
                        </span>
                        <span style={{ fontSize: '13px', fontWeight: 700, color: '#ffffff' }}>
                          {evt.event_type}
                        </span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <span style={{ fontSize: '11px', color: 'rgba(255,255,255,0.4)', fontFamily: 'monospace' }}>
                          {evt.timestamp ? evt.timestamp.replace('T', ' ').substring(0, 19) : `T+${idx * 0.12}s`}
                        </span>
                        {evt.uncertainty && (
                          <span style={{
                            fontSize: '10px',
                            color: '#eab308',
                            background: 'rgba(234, 179, 8, 0.1)',
                            border: '1px solid rgba(234, 179, 8, 0.3)',
                            padding: '2px 6px',
                            borderRadius: '4px'
                          }}>
                            {evt.uncertainty}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Description */}
                    <div style={{ fontSize: '13px', color: '#cbd5e1', lineHeight: 1.5 }}>
                      {evt.description}
                    </div>

                    {/* Metadata & Evidence References */}
                    <div style={{
                      display: 'flex',
                      flexWrap: 'wrap',
                      gap: '12px',
                      fontSize: '11px',
                      color: '#94a3b8',
                      paddingTop: '6px',
                      borderTop: '1px solid rgba(255,255,255,0.05)'
                    }}>
                      {evt.endpoint && (
                        <span><strong style={{ color: '#e2e8f0' }}>Endpoint:</strong> {evt.endpoint}</span>
                      )}
                      {evt.stream_id != null && (
                        <span><strong style={{ color: '#e2e8f0' }}>Stream ID:</strong> {evt.stream_id}</span>
                      )}
                      {evt.packet_range && (
                        <span><strong style={{ color: '#e2e8f0' }}>Packets:</strong> #{evt.packet_range}</span>
                      )}
                      {evt.crypto_state && (
                        <span><strong style={{ color: '#e2e8f0' }}>State:</strong> {evt.crypto_state}</span>
                      )}
                    </div>

                    {/* Linked Findings */}
                    {hasFindings && (
                      <div style={{
                        marginTop: '4px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        background: 'rgba(239, 68, 68, 0.1)',
                        border: '1px solid rgba(239, 68, 68, 0.3)',
                        borderRadius: '6px',
                        padding: '6px 10px'
                      }}>
                        <i className="fa-solid fa-triangle-exclamation" style={{ color: '#ef4444', fontSize: '11px' }} />
                        <span style={{ fontSize: '11px', color: '#fca5a5', fontWeight: 600 }}>
                          Correlated Finding:
                        </span>
                        {evt.related_findings.map((fid, fidx) => (
                          <button
                            key={fidx}
                            onClick={() => onNavigateFinding && onNavigateFinding(fid)}
                            style={{
                              background: 'transparent',
                              border: 'none',
                              color: '#ffffff',
                              textDecoration: 'underline',
                              cursor: 'pointer',
                              fontFamily: 'monospace',
                              fontSize: '11px',
                              fontWeight: 700
                            }}
                            title="Click to view finding details"
                          >
                            {fid}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
