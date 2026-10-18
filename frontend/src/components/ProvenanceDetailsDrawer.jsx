import React from 'react';

export function ProvenanceDetailsDrawer({
  selectedNode,
  onClose,
  onFocusNode,
  onTraceUpstream,
  onTraceDownstream,
  rawGraph,
}) {
  if (!selectedNode) return null;

  const data = selectedNode.data || {};
  const meta = data.metadata || {};
  const assessment = data.assessment || {};
  const observed = assessment.observed || {};
  const expected = assessment.expected || {};
  const unknown = assessment.unknown || [];
  const status = assessment.status || 'unknown';

  // Determine incoming & outgoing edges
  const incoming = (rawGraph?.edges || []).filter(e => e.target === selectedNode.id);
  const outgoing = (rawGraph?.edges || []).filter(e => e.source === selectedNode.id);

  // Upstream / downstream from index
  const isFinding = selectedNode.type === 'finding';
  const findingId = meta.finding_id || meta.id || selectedNode.id.replace('finding:', '');
  const upstreamRefs = rawGraph?.traceability_index?.finding_to_evidence?.[findingId] || [];
  const downstreamRefs = rawGraph?.traceability_index?.evidence_to_findings?.[selectedNode.id] || [];

  return (
    <aside
      className="provenance-details-drawer"
      style={{
        width: '400px',
        maxWidth: '92vw',
        background: 'rgba(11, 15, 25, 0.97)',
        backdropFilter: 'blur(24px)',
        borderLeft: '1px solid rgba(255, 255, 255, 0.12)',
        display: 'flex',
        flexDirection: 'column',
        zIndex: 50,
        height: '100%',
        maxHeight: '100%',
        minHeight: 0,
        flexShrink: 0,
        boxShadow: '-8px 0 32px rgba(0, 0, 0, 0.65)',
        color: '#f8fafc',
        fontFamily: 'var(--font-sans, inherit)',
        overflow: 'hidden',
      }}
      onWheel={(e) => e.stopPropagation()}
    >
      {/* Header (Sticky at top) */}
      <div
        style={{
          padding: '16px 20px',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'rgba(15, 23, 42, 0.95)',
          backdropFilter: 'blur(16px)',
          flexShrink: 0,
          zIndex: 10,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div
            style={{
              width: '32px',
              height: '32px',
              borderRadius: '8px',
              background: 'rgba(99, 102, 241, 0.15)',
              border: '1px solid rgba(99, 102, 241, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#818cf8',
              fontSize: '14px',
            }}
          >
            <i className={
              selectedNode.type === 'finding' ? 'fa-solid fa-triangle-exclamation' :
              selectedNode.type === 'certificate' ? 'fa-solid fa-certificate' :
              selectedNode.type === 'handshake' ? 'fa-solid fa-handshake-simple' :
              selectedNode.type === 'session' ? 'fa-solid fa-network-wired' :
              selectedNode.type === 'analysis_operation' ? 'fa-solid fa-microchip' :
              selectedNode.type === 'baseline' ? 'fa-solid fa-scale-balanced' :
              'fa-solid fa-file-waveform'
            } />
          </div>
          <div>
            <div style={{ fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.06em', color: '#94a3b8', fontWeight: 700 }}>
              {selectedNode.type?.replace('_', ' ')}
            </div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: '#ffffff' }}>
              {data.label || selectedNode.id}
            </div>
          </div>
        </div>
        <button
          onClick={onClose}
          style={{
            background: 'rgba(255, 255, 255, 0.08)',
            border: 'none',
            color: '#cbd5e1',
            width: '28px',
            height: '28px',
            borderRadius: '50%',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            transition: 'all 0.2s ease',
          }}
          onMouseEnter={e => {
            e.currentTarget.style.background = 'rgba(239, 68, 68, 0.2)';
            e.currentTarget.style.color = '#f87171';
          }}
          onMouseLeave={e => {
            e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)';
            e.currentTarget.style.color = '#cbd5e1';
          }}
          title="Close Details"
        >
          <i className="fa-solid fa-xmark" />
        </button>
      </div>

      {/* Body (Scrollable container with room at bottom) */}
      <div
        className="provenance-drawer-scrollable"
        style={{
          padding: '20px 20px 36px 20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '20px',
          flex: 1,
          minHeight: 0,
          overflowY: 'auto',
          overflowX: 'hidden',
          overscrollBehavior: 'contain',
        }}
        onWheel={(e) => e.stopPropagation()}
      >
        
        {/* Selected Evidence Context Summary (Requirement B7) */}
        <div
          style={{
            background: 'rgba(56, 189, 248, 0.06)',
            border: '1px solid rgba(56, 189, 248, 0.25)',
            borderRadius: '10px',
            padding: '12px 14px',
          }}
        >
          <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.06em', color: '#38bdf8', fontWeight: 800, marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <i className="fa-solid fa-fingerprint" />
            <span>Selected Evidence</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 12px', fontSize: '11px', lineHeight: 1.4 }}>
            <span style={{ color: '#94a3b8', fontWeight: 600 }}>Type:</span>
            <span style={{ color: '#ffffff', fontWeight: 700, textTransform: 'capitalize' }}>
              {selectedNode.type === 'session' ? 'Network Session / Stream' :
               selectedNode.type === 'handshake' ? 'TLS Handshake (Packet Evidence)' :
               selectedNode.type === 'certificate' ? 'X.509 Certificate (PKI Evidence)' :
               selectedNode.type === 'source_artifact' ? 'PCAP Source Capture' :
               selectedNode.type === 'analysis_operation' ? 'Security Policy Rule' :
               selectedNode.type === 'finding' ? 'Security Finding' :
               selectedNode.type?.replace(/_/g, ' ')}
            </span>

            <span style={{ color: '#94a3b8', fontWeight: 600 }}>Identifier:</span>
            <code style={{ color: '#38bdf8', fontFamily: 'monospace', fontWeight: 700 }}>
              {selectedNode.id}
            </code>

            {(rawGraph?.capture_id || rawGraph?.filename || meta.capture_id) && (
              <>
                <span style={{ color: '#94a3b8', fontWeight: 600 }}>Analysis:</span>
                <span style={{ color: '#cbd5e1' }}>
                  {rawGraph?.filename || rawGraph?.capture_id || meta.capture_id}
                </span>
              </>
            )}

            {(isFinding || (downstreamRefs && downstreamRefs.length > 0)) && (
              <>
                <span style={{ color: '#94a3b8', fontWeight: 600 }}>Related finding:</span>
                <span style={{ color: '#f87171', fontWeight: 600 }}>
                  {isFinding ? `${findingId} (${data.label || meta.title || 'Violation'})` : downstreamRefs.join(', ')}
                </span>
              </>
            )}

            {(meta.protocol || meta.tls_version || meta.standard || meta.frame !== undefined) && (
              <>
                <span style={{ color: '#94a3b8', fontWeight: 600 }}>Evidence context:</span>
                <span style={{ color: '#e2e8f0' }}>
                  {[
                    meta.frame !== undefined ? `Frame #${meta.frame}` : null,
                    meta.protocol ? `Protocol ${meta.protocol}` : null,
                    meta.tls_version ? `TLS ${meta.tls_version}` : null,
                    meta.standard ? `Standard ${meta.standard}` : null,
                  ].filter(Boolean).join(' • ')}
                </span>
              </>
            )}
          </div>
        </div>

        {/* Quick Actions */}
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <button
            onClick={() => onTraceUpstream(selectedNode.id)}
            style={{
              flex: 1,
              padding: '8px 12px',
              borderRadius: '8px',
              background: 'rgba(56, 189, 248, 0.15)',
              border: '1px solid rgba(56, 189, 248, 0.4)',
              color: '#38bdf8',
              fontSize: '11px',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '6px',
            }}
          >
            <i className="fa-solid fa-arrow-left" />
            <span>Trace Upstream</span>
          </button>
          <button
            onClick={() => onTraceDownstream(selectedNode.id)}
            style={{
              flex: 1,
              padding: '8px 12px',
              borderRadius: '8px',
              background: 'rgba(168, 85, 247, 0.15)',
              border: '1px solid rgba(168, 85, 247, 0.4)',
              color: '#c084fc',
              fontSize: '11px',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '6px',
            }}
          >
            <span>Trace Findings</span>
            <i className="fa-solid fa-arrow-right" />
          </button>
        </div>

        {/* Status / Assessment Banner */}
        <div
          style={{
            padding: '12px 14px',
            borderRadius: '10px',
            background: 'rgba(255, 255, 255, 0.03)',
            border: '1px solid rgba(255, 255, 255, 0.08)',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
            <span style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.04em' }}>
              Forensic Assessment
            </span>
            <span
              style={{
                fontSize: '10px',
                fontWeight: 700,
                padding: '2px 8px',
                borderRadius: '999px',
                textTransform: 'uppercase',
                background: status === 'compliant' || status === 'valid' || status === 'passed' ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)',
                color: status === 'compliant' || status === 'valid' || status === 'passed' ? '#34d399' : '#f87171',
                border: `1px solid ${status === 'compliant' || status === 'valid' || status === 'passed' ? 'rgba(16,185,129,0.4)' : 'rgba(239,68,68,0.4)'}`,
              }}
            >
              {status}
            </span>
          </div>
          <div style={{ fontSize: '11px', color: 'rgba(255,255,255,0.7)', lineHeight: 1.4 }}>
            Source Reference: <code style={{ color: '#38bdf8', background: 'rgba(56,189,248,0.1)', padding: '2px 6px', borderRadius: '4px' }}>{data.source_ref || selectedNode.id}</code>
          </div>
        </div>

        {/* Observed vs Expected vs Unknown Cards */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#818cf8', fontWeight: 700 }}>
            Tri-State Evidence Analysis
          </div>

          {/* Observed */}
          <div
            style={{
              padding: '12px',
              borderRadius: '8px',
              background: 'rgba(16, 185, 129, 0.05)',
              border: '1px solid rgba(16, 185, 129, 0.2)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#34d399', fontSize: '11px', fontWeight: 700, marginBottom: '6px' }}>
              <i className="fa-solid fa-eye" />
              <span>OBSERVED (Direct Network Packet Evidence)</span>
            </div>
            {typeof observed === 'object' && Object.keys(observed).length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '11px', color: '#e2e8f0' }}>
                {Object.entries(observed).map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', justifyContent: 'space-between', gap: '10px' }}>
                    <span style={{ color: '#94a3b8' }}>{k.replace(/_/g, ' ')}:</span>
                    <strong style={{ textAlign: 'right', wordBreak: 'break-all' }}>
                      {Array.isArray(v) ? v.join(', ') : String(v)}
                    </strong>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ fontSize: '11px', color: '#e2e8f0' }}>{String(observed || 'No direct observation record')}</div>
            )}
          </div>

          {/* Expected */}
          <div
            style={{
              padding: '12px',
              borderRadius: '8px',
              background: 'rgba(56, 189, 248, 0.05)',
              border: '1px solid rgba(56, 189, 248, 0.2)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#38bdf8', fontSize: '11px', fontWeight: 700, marginBottom: '6px' }}>
              <i className="fa-solid fa-shield-halved" />
              <span>EXPECTED (RFC / Baseline Standard)</span>
            </div>
            {typeof expected === 'object' && Object.keys(expected).length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '11px', color: '#e2e8f0' }}>
                {Object.entries(expected).map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', justifyContent: 'space-between', gap: '10px' }}>
                    <span style={{ color: '#94a3b8' }}>{k.replace(/_/g, ' ')}:</span>
                    <strong style={{ textAlign: 'right', wordBreak: 'break-all' }}>
                      {Array.isArray(v) ? v.join(', ') : String(v)}
                    </strong>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ fontSize: '11px', color: '#e2e8f0' }}>{String(expected || 'Standard baseline')}</div>
            )}
          </div>

          {/* Unknown / Unverified */}
          <div
            style={{
              padding: '12px',
              borderRadius: '8px',
              background: 'rgba(234, 179, 8, 0.05)',
              border: '1px solid rgba(234, 179, 8, 0.2)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#facc15', fontSize: '11px', fontWeight: 700, marginBottom: '6px' }}>
              <i className="fa-solid fa-circle-question" />
              <span>UNKNOWN / UNVERIFIED LIMITATIONS</span>
            </div>
            {unknown.length > 0 ? (
              <ul style={{ margin: 0, paddingLeft: '16px', fontSize: '11px', color: '#fef08a', lineHeight: 1.4 }}>
                {unknown.map((u, i) => (
                  <li key={i} style={{ marginBottom: '4px' }}>{u}</li>
                ))}
              </ul>
            ) : (
              <div style={{ fontSize: '11px', color: '#94a3b8' }}>All required attributes successfully extracted and verified.</div>
            )}
          </div>
        </div>

        {/* Upstream Evidence Links (if this is a finding) */}
        {isFinding && upstreamRefs.length > 0 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#38bdf8', fontWeight: 700 }}>
              Supporting Evidence Chain ({upstreamRefs.length})
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {upstreamRefs.map(refId => {
                const nodeObj = (rawGraph?.nodes || []).find(n => n.id === refId);
                return (
                  <button
                    key={refId}
                    onClick={() => onFocusNode(refId)}
                    style={{
                      padding: '8px 12px',
                      borderRadius: '6px',
                      background: 'rgba(255, 255, 255, 0.04)',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      color: '#ffffff',
                      fontSize: '11px',
                      textAlign: 'left',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      transition: 'background 0.2s ease',
                    }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(56, 189, 248, 0.15)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'rgba(255, 255, 255, 0.04)'}
                  >
                    <span>{nodeObj?.data?.label || refId}</span>
                    <i className="fa-solid fa-crosshairs" style={{ color: '#38bdf8', fontSize: '10px' }} />
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Downstream Findings Links (if this is an evidence node) */}
        {!isFinding && downstreamRefs.length > 0 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#c084fc', fontWeight: 700 }}>
              Findings Supported by this Evidence ({downstreamRefs.length})
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {downstreamRefs.map(fId => {
                const fullId = `finding:${fId}`;
                const nodeObj = (rawGraph?.nodes || []).find(n => n.id === fullId || n.data?.metadata?.id === fId);
                return (
                  <button
                    key={fId}
                    onClick={() => onFocusNode(nodeObj?.id || fullId)}
                    style={{
                      padding: '8px 12px',
                      borderRadius: '6px',
                      background: 'rgba(239, 68, 68, 0.08)',
                      border: '1px solid rgba(239, 68, 68, 0.25)',
                      color: '#f87171',
                      fontSize: '11px',
                      fontWeight: 600,
                      textAlign: 'left',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                    }}
                  >
                    <span>[{fId}] {nodeObj?.data?.label || 'Security Violation'}</span>
                    <i className="fa-solid fa-triangle-exclamation" style={{ fontSize: '10px' }} />
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Ingested Metadata Key-Values */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#94a3b8', fontWeight: 700 }}>
            Raw Extracted Attributes
          </div>
          <div
            style={{
              padding: '12px',
              borderRadius: '8px',
              background: 'rgba(0, 0, 0, 0.3)',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              fontFamily: 'monospace',
              fontSize: '11px',
              color: '#94a3b8',
              maxHeight: '180px',
              overflowY: 'auto',
            }}
          >
            {Object.entries(meta).map(([k, v]) => (
              <div key={k} style={{ marginBottom: '4px' }}>
                <span style={{ color: '#38bdf8' }}>{k}:</span>{' '}
                <span style={{ color: '#f8fafc' }}>{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Incoming & Outgoing Relations */}
        <div style={{ fontSize: '10px', color: '#64748b', display: 'flex', justifyContent: 'space-between' }}>
          <span>Incoming Relationships: <strong>{incoming.length}</strong></span>
          <span>Outgoing Relationships: <strong>{outgoing.length}</strong></span>
        </div>
      </div>
    </aside>
  );
}
