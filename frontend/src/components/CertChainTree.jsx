import React, { useState } from 'react';

/**
 * CertChainTree - Visual X.509 Certificate Chain & CA Trust Hierarchy Viewer
 * Displays Root -> Intermediate -> Leaf tree structure with trust anchors,
 * SAN/Hostname validation, key usage badges, and interactive forensic inspection.
 */
export function CertChainTree({ chains = [] }) {
  const [selectedCert, setSelectedCert] = useState(null);

  if (!chains || chains.length === 0) {
    return (
      <div style={{
        padding: '36px',
        textAlign: 'center',
        backgroundColor: 'rgba(255, 255, 255, 0.02)',
        borderRadius: '12px',
        border: '1px dashed rgba(255, 255, 255, 0.1)',
        color: '#94a3b8'
      }}>
        <i className="fa-solid fa-certificate" style={{ fontSize: '32px', marginBottom: '12px', color: '#6366f1' }} />
        <p style={{ margin: 0, fontSize: '14px' }}>No TLS X.509 certificate handshakes captured in this traffic.</p>
      </div>
    );
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: selectedCert ? '1fr 1fr' : '1fr', gap: '24px', alignItems: 'start' }}>
      
      {/* ── Left / Main: Chain Hierarchy Trees ── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {chains.map((ch, chainIdx) => {
          const trustPath = ch.built_trust_path || ch.presented_chain || [];
          // Display in top-down Root -> Intermediate -> Leaf hierarchy
          const rootToLeaf = [...trustPath].reverse();

          return (
            <div key={chainIdx} className="glass-card" style={{
              padding: '20px 24px',
              border: `1px solid ${ch.is_trusted ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
              borderRadius: '16px',
              backgroundColor: 'rgba(15, 17, 30, 0.6)'
            }}>
              {/* Chain Header */}
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '16px',
                borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
                paddingBottom: '12px'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <i className={`fa-solid ${ch.is_trusted ? 'fa-shield-halved' : 'fa-triangle-exclamation'}`}
                    style={{ color: ch.is_trusted ? '#10b981' : '#ef4444', fontSize: '18px' }} />
                  <div>
                    <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 600, color: '#ffffff' }}>
                      TLS Certificate Chain #{chainIdx + 1}
                    </h4>
                    <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '2px' }}>
                      Frame #{ch.frame_number} • Stream #{ch.tcp_stream} {ch.sni ? `• SNI: ${ch.sni}` : ''}
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '8px' }}>
                  {ch.is_trusted ? (
                    <span className="badge badge-low" style={{
                      backgroundColor: 'rgba(16, 185, 129, 0.15)',
                      color: '#34d399',
                      border: '1px solid rgba(16, 185, 129, 0.3)'
                    }}>
                      <i className="fa-solid fa-circle-check" style={{ marginRight: '4px' }} /> Valid Trust Path
                    </span>
                  ) : (
                    <span className="badge badge-critical">
                      <i className="fa-solid fa-circle-xmark" style={{ marginRight: '4px' }} /> Untrusted / Incomplete
                    </span>
                  )}
                </div>
              </div>

              {/* Visual Tree Nodes */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', paddingLeft: '8px' }}>
                {rootToLeaf.map((cert, nodeIdx) => {
                  const isLeaf = (nodeIdx === rootToLeaf.length - 1);
                  const isRoot = (nodeIdx === 0);
                  const isSelected = selectedCert && selectedCert.serial_number === cert.serial_number;
                  
                  let badgeColor = '#38bdf8';
                  let nodeType = 'Intermediate CA';
                  let icon = 'fa-building-columns';

                  if (isRoot) {
                    nodeType = cert.is_self_signed ? 'Root CA' : 'Trust Anchor';
                    badgeColor = cert.trust_status === 'TRUSTED_ROOT' ? '#10b981' : '#f59e0b';
                    icon = 'fa-lock';
                  } else if (isLeaf) {
                    nodeType = 'Leaf Certificate';
                    badgeColor = '#818cf8';
                    icon = 'fa-globe';
                  }

                  return (
                    <div key={cert.serial_number || nodeIdx} style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      {/* Tree Indentation Connector */}
                      <div style={{
                        width: '24px',
                        display: 'flex',
                        justifyContent: 'center',
                        color: '#64748b',
                        fontSize: '14px'
                      }}>
                        {nodeIdx > 0 && <i className="fa-solid fa-arrow-turn-down" style={{ transform: 'scaleX(-1)' }} />}
                      </div>

                      {/* Certificate Node Card */}
                      <div
                        onClick={() => setSelectedCert(cert)}
                        style={{
                          flex: 1,
                          padding: '12px 16px',
                          borderRadius: '10px',
                          backgroundColor: isSelected ? 'rgba(99, 102, 241, 0.15)' : 'rgba(255, 255, 255, 0.03)',
                          border: `1px solid ${isSelected ? '#6366f1' : 'rgba(255, 255, 255, 0.08)'}`,
                          cursor: 'pointer',
                          transition: 'all 0.2s ease',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center'
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                          <div style={{
                            width: '32px',
                            height: '32px',
                            borderRadius: '8px',
                            backgroundColor: `${badgeColor}20`,
                            color: badgeColor,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontSize: '14px'
                          }}>
                            <i className={`fa-solid ${icon}`} />
                          </div>
                          <div>
                            <div style={{ fontSize: '13px', fontWeight: 600, color: '#ffffff' }}>
                              {cert.common_name || cert.subject}
                            </div>
                            <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '2px' }}>
                              {nodeType} • {cert.public_key_algorithm} ({cert.key_size} bits)
                            </div>
                          </div>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          {cert.is_presented ? (
                            <span style={{
                              fontSize: '10px',
                              fontWeight: 600,
                              padding: '2px 6px',
                              borderRadius: '4px',
                              backgroundColor: 'rgba(56, 189, 248, 0.15)',
                              color: '#38bdf8',
                              border: '1px solid rgba(56, 189, 248, 0.3)'
                            }}>
                              Observed in PCAP
                            </span>
                          ) : (
                            <span style={{
                              fontSize: '10px',
                              fontWeight: 600,
                              padding: '2px 6px',
                              borderRadius: '4px',
                              backgroundColor: 'rgba(16, 185, 129, 0.15)',
                              color: '#34d399',
                              border: '1px solid rgba(16, 185, 129, 0.3)'
                            }}>
                              Trust Store Anchor
                            </span>
                          )}

                          {cert.is_expired && (
                            <span className="badge badge-critical" style={{ fontSize: '10px', padding: '2px 6px' }}>
                              Expired
                            </span>
                          )}

                          <i className="fa-solid fa-chevron-right" style={{ fontSize: '11px', color: isSelected ? '#818cf8' : '#64748b' }} />
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* PKI Findings Snippet if present on this chain */}
              {ch.pki_findings && ch.pki_findings.length > 0 && (
                <div style={{ marginTop: '16px', paddingTop: '12px', borderTop: '1px dashed rgba(255, 255, 255, 0.08)' }}>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: '#fbbf24', marginBottom: '8px' }}>
                    <i className="fa-solid fa-circle-exclamation" style={{ marginRight: '6px' }} /> PKI Compliance Issues:
                  </div>
                  {ch.pki_findings.map((f, fIdx) => (
                    <div key={fIdx} style={{ fontSize: '12px', color: '#cbd5e1', marginBottom: '4px', paddingLeft: '16px' }}>
                      • <strong>[{f.rule_id}]</strong> {f.title}
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* ── Right: Detailed Certificate Inspector Drawer ── */}
      {selectedCert && (
        <div className="glass-card" style={{
          padding: '24px',
          borderRadius: '16px',
          backgroundColor: '#0d0e1a',
          border: '1px solid rgba(99, 102, 241, 0.3)',
          boxShadow: '0 20px 40px rgba(0,0,0,0.5)',
          position: 'sticky',
          top: '20px'
        }}>
          {/* Inspector Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '12px' }}>
            <div>
              <span className="badge" style={{ backgroundColor: 'rgba(99, 102, 241, 0.2)', color: '#818cf8', marginBottom: '6px' }}>
                X.509 Forensic Inspection
              </span>
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#ffffff', margin: '4px 0 0 0' }}>
                {selectedCert.common_name}
              </h3>
            </div>
            <button
              onClick={() => setSelectedCert(null)}
              style={{
                background: 'rgba(255, 255, 255, 0.06)',
                border: 'none',
                color: '#94a3b8',
                width: '28px',
                height: '28px',
                borderRadius: '6px',
                cursor: 'pointer'
              }}
            >
              <i className="fa-solid fa-xmark" />
            </button>
          </div>

          {/* Details Table */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', fontSize: '13px' }}>
            <div>
              <div style={{ color: '#64748b', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Subject (DN)</div>
              <div style={{ color: '#e2e8f0', fontFamily: 'monospace', wordBreak: 'break-all', marginTop: '2px' }}>{selectedCert.subject}</div>
            </div>

            <div>
              <div style={{ color: '#64748b', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Issuer (CA)</div>
              <div style={{ color: '#e2e8f0', fontFamily: 'monospace', wordBreak: 'break-all', marginTop: '2px' }}>{selectedCert.issuer}</div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div>
                <div style={{ color: '#64748b', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Serial Number</div>
                <div style={{ color: '#38bdf8', fontFamily: 'monospace', fontSize: '11px', marginTop: '2px', wordBreak: 'break-all' }}>{selectedCert.serial_number}</div>
              </div>
              <div>
                <div style={{ color: '#64748b', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Basic Constraints</div>
                <div style={{ color: selectedCert.is_ca ? '#34d399' : '#e2e8f0', fontWeight: 600, marginTop: '2px' }}>
                  {selectedCert.is_ca ? 'CA: TRUE' : 'CA: FALSE (End Entity)'}
                </div>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div>
                <div style={{ color: '#64748b', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Valid From</div>
                <div style={{ color: '#e2e8f0', marginTop: '2px' }}>{new Date(selectedCert.not_before).toLocaleDateString()}</div>
              </div>
              <div>
                <div style={{ color: '#64748b', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Valid Until</div>
                <div style={{ color: selectedCert.is_expired ? '#ef4444' : '#34d399', fontWeight: 600, marginTop: '2px' }}>
                  {new Date(selectedCert.not_after).toLocaleDateString()} {selectedCert.is_expired ? '(EXPIRED)' : ''}
                </div>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div>
                <div style={{ color: '#64748b', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Public Key</div>
                <div style={{ color: '#e2e8f0', marginTop: '2px' }}>{selectedCert.public_key_algorithm} ({selectedCert.key_size} bits)</div>
              </div>
              <div>
                <div style={{ color: '#64748b', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Signature Algorithm</div>
                <div style={{ color: '#e2e8f0', marginTop: '2px' }}>{selectedCert.signature_algorithm}</div>
              </div>
            </div>

            {selectedCert.subject_alternative_names && selectedCert.subject_alternative_names.length > 0 && (
              <div>
                <div style={{ color: '#64748b', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Subject Alternative Names (SAN)</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '4px' }}>
                  {selectedCert.subject_alternative_names.map((san, idx) => (
                    <span key={idx} style={{
                      backgroundColor: 'rgba(99, 102, 241, 0.15)',
                      color: '#a5b4fc',
                      fontSize: '11px',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontFamily: 'monospace'
                    }}>
                      {san}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {selectedCert.extended_key_usages && selectedCert.extended_key_usages.length > 0 && (
              <div>
                <div style={{ color: '#64748b', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Extended Key Usage (EKU)</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '4px' }}>
                  {selectedCert.extended_key_usages.map((eku, idx) => (
                    <span key={idx} style={{
                      backgroundColor: eku === 'serverAuth' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(255, 255, 255, 0.06)',
                      color: eku === 'serverAuth' ? '#34d399' : '#e2e8f0',
                      fontSize: '11px',
                      padding: '2px 8px',
                      borderRadius: '4px'
                    }}>
                      {eku}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {selectedCert.subject_key_identifier && (
              <div>
                <div style={{ color: '#64748b', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Subject Key Identifier (SKI)</div>
                <div style={{ color: '#94a3b8', fontFamily: 'monospace', fontSize: '11px', wordBreak: 'break-all', marginTop: '2px' }}>
                  {selectedCert.subject_key_identifier}
                </div>
              </div>
            )}

            {selectedCert.authority_key_identifier && (
              <div>
                <div style={{ color: '#64748b', fontSize: '11px', textTransform: 'uppercase', fontWeight: 600 }}>Authority Key Identifier (AKI)</div>
                <div style={{ color: '#94a3b8', fontFamily: 'monospace', fontSize: '11px', wordBreak: 'break-all', marginTop: '2px' }}>
                  {selectedCert.authority_key_identifier}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

    </div>
  );
}
