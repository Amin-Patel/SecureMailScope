import React from 'react';

const SEVERITY_ORDER = {
  CRITICAL: 1,
  HIGH: 2,
  MEDIUM: 3,
  LOW: 4,
};

export function PrintableReport({ results }) {
  if (!results) return null;

  const captureId = results.capture_id || 'unknown';
  const timestamp = results.upload_timestamp
    ? new Date(results.upload_timestamp).toLocaleString()
    : new Date().toLocaleString();

  const summary = results.summary || {};
  const risk = results.risk || {};
  const findings = results.findings || [];
  const sessions = results.sessions || [];
  const certificates = results.certificates || [];
  const aiSummary = results.ai_summary || '';

  // Calculate risk statistics
  const score = risk.risk_score ?? summary.risk_score ?? 0;
  const level = risk.risk_level ?? summary.risk_level ?? 'UNKNOWN';

  // Sort findings by severity
  const sortedFindings = [...findings].sort((a, b) => {
    const rankA = SEVERITY_ORDER[(a.severity || '').toUpperCase()] || 99;
    const rankB = SEVERITY_ORDER[(b.severity || '').toUpperCase()] || 99;
    return rankA - rankB;
  });

  // Fallback AI briefing if ai_summary is missing
  const getFallbackExecutiveSummary = () => {
    if (findings.length === 0) {
      return "All email communication streams evaluated in this packet capture meet secure cryptographic requirements. No vulnerabilities or unencrypted protocols were detected.";
    }
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    findings.forEach(f => {
      const sev = (f.severity || '').toUpperCase();
      if (counts[sev] !== undefined) counts[sev]++;
    });
    return `Security analysis completed with a risk score of ${score}/100 (${level} Risk). A total of ${findings.length} findings were identified, including ${counts.CRITICAL} Critical, ${counts.HIGH} High, ${counts.MEDIUM} Medium, and ${counts.LOW} Low severity issues. Secure SMTP, IMAP or POP3 encapsulation is missing or weak configurations (e.g. SSL 3.0) are present, exposing traffic to potential interception.`;
  };

  return (
    <div className="print-only" style={{ display: 'none', width: '100%', fontFamily: '"Helvetica Neue", Helvetica, Arial, sans-serif', color: '#111827', backgroundColor: '#ffffff', padding: '0px' }}>
      
      {/* Self-contained Print Stylesheet */}
      <style dangerouslySetInnerHTML={{ __html: `
        @media print {
          /* Hide all application elements */
          body, html {
            background: #ffffff !important;
            color: #111827 !important;
          }
          .page {
            position: static !important;
            display: block !important;
            padding: 0 !important;
            min-height: auto !important;
            background: transparent !important;
          }
          .no-print, header, footer, nav, aside, .bg, .bg-overlay, .dashboard-container, .workspace-container, .toast-container, .drawer-backdrop, .drawer {
            display: none !important;
          }
          /* Show only the report */
          .print-only {
            display: block !important;
          }
          /* Page size and margins */
          @page {
            size: letter;
            margin: 20mm;
          }
          h1, h2, h3, h4, h5, h6 {
            page-break-after: avoid;
          }
          tr {
            page-break-inside: avoid;
          }
          pre, code {
            white-space: pre-wrap !important;
            word-wrap: break-word !important;
          }
        }
      ` }} />

      {/* HEADER */}
      <div style={{ borderBottom: '2px solid #111827', paddingBottom: '20px', marginBottom: '30px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span style={{ fontSize: '24px', fontWeight: '800', tracking: '-0.05em', color: '#111827' }}>SecureMailScope</span>
          </div>
          <div style={{ fontSize: '14px', fontWeight: '600', color: '#4b5563', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Cryptographic &amp; Email Infrastructure Forensic Assessment
          </div>
        </div>
        <div style={{ textAlign: 'right', fontSize: '12px', color: '#4b5563' }}>
          <div><strong>Timestamp:</strong> {timestamp}</div>
          <div><strong>Capture ID:</strong> {captureId}</div>
        </div>
      </div>

      {/* SECTION 1: EXECUTIVE BRIEFING & AI POSTURE ASSESSMENT */}
      <div style={{ marginBottom: '35px' }}>
        <h2 style={{ fontSize: '18px', fontWeight: '700', borderBottom: '1px solid #e5e7eb', paddingBottom: '6px', marginBottom: '12px', textTransform: 'uppercase', color: '#111827' }}>
          Section 1: Executive Briefing &amp; AI Posture Assessment
        </h2>
        
        {aiSummary ? (
          <div>
            <div style={{ background: '#f3f4f6', borderLeft: '4px solid #6366f1', padding: '12px 16px', borderRadius: '4px', marginBottom: '12px', fontSize: '13px', lineHeight: 1.5, color: '#374151' }}>
              <strong style={{ display: 'block', marginBottom: '4px', color: '#4f46e5', textTransform: 'uppercase', fontSize: '11px', letterSpacing: '0.05em' }}>
                ⚡ AI Posture Interpretation
              </strong>
              {aiSummary}
            </div>
            <p style={{ fontSize: '12px', color: '#6b7280', fontStyle: 'italic', margin: 0 }}>
              Note: The above evaluation is generated via AI interpretation of raw connection metrics. Please cross-reference with Section 3 for deterministic forensic evidence.
            </p>
          </div>
        ) : (
          <div>
            <div style={{ background: '#f3f4f6', borderLeft: '4px solid #4b5563', padding: '12px 16px', borderRadius: '4px', marginBottom: '12px', fontSize: '13px', lineHeight: 1.5, color: '#374151' }}>
              <strong style={{ display: 'block', marginBottom: '4px', color: '#4b5563', textTransform: 'uppercase', fontSize: '11px', letterSpacing: '0.05em' }}>
                🛡️ Offline Security Analysis Briefing
              </strong>
              {getFallbackExecutiveSummary()}
            </div>
            <p style={{ fontSize: '12px', color: '#6b7280', fontStyle: 'italic', margin: 0 }}>
              Note: This briefing is based on deterministic forensic rule-matching against inspected mail server traffic.
            </p>
          </div>
        )}
      </div>

      {/* SECTION 2: SECURITY POSTURE MATRIX */}
      <div style={{ marginBottom: '35px' }}>
        <h2 style={{ fontSize: '18px', fontWeight: '700', borderBottom: '1px solid #e5e7eb', paddingBottom: '6px', marginBottom: '12px', textTransform: 'uppercase', color: '#111827' }}>
          Section 2: Security Posture Matrix
        </h2>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', textAlign: 'left' }}>
          <tbody>
            <tr style={{ borderBottom: '1px solid #e5e7eb' }}>
              <td style={{ padding: '8px 12px', fontWeight: '600', width: '30%' }}>Risk Score</td>
              <td style={{ padding: '8px 12px' }}>
                <span style={{ fontWeight: '800', color: score >= 70 ? '#dc2626' : score >= 40 ? '#d97706' : '#16a34a' }}>
                  {score} / 100
                </span>
              </td>
              <td style={{ padding: '8px 12px', fontWeight: '600', width: '30%' }}>Risk Level</td>
              <td style={{ padding: '8px 12px', fontWeight: '700' }}>{level}</td>
            </tr>
            <tr style={{ borderBottom: '1px solid #e5e7eb' }}>
              <td style={{ padding: '8px 12px', fontWeight: '600' }}>Total Packets</td>
              <td style={{ padding: '8px 12px' }}>{summary.total_packets ?? 0}</td>
              <td style={{ padding: '8px 12px', fontWeight: '600' }}>Encryption Ratio</td>
              <td style={{ padding: '8px 12px' }}>
                {typeof summary.encryption_ratio === 'number'
                  ? `${(summary.encryption_ratio * 100).toFixed(1)}%`
                  : 'N/A'}
              </td>
            </tr>
            <tr style={{ borderBottom: '1px solid #e5e7eb' }}>
              <td style={{ padding: '8px 12px', fontWeight: '600' }}>Encrypted Packets</td>
              <td style={{ padding: '8px 12px' }}>{summary.encrypted_packets ?? 0}</td>
              <td style={{ padding: '8px 12px', fontWeight: '600' }}>Session Count</td>
              <td style={{ padding: '8px 12px' }}>{summary.session_count ?? sessions.length}</td>
            </tr>
            <tr style={{ borderBottom: '1px solid #e5e7eb' }}>
              <td style={{ padding: '8px 12px', fontWeight: '600' }}>Plaintext Packets</td>
              <td style={{ padding: '8px 12px' }}>{summary.plaintext_packets ?? 0}</td>
              <td style={{ padding: '8px 12px', fontWeight: '600' }}>Handshake Count</td>
              <td style={{ padding: '8px 12px' }}>{summary.handshake_count ?? 0}</td>
            </tr>
            <tr style={{ borderBottom: '1px solid #e5e7eb' }}>
              <td style={{ padding: '8px 12px', fontWeight: '600' }}>Certificate Count</td>
              <td style={{ padding: '8px 12px' }}>{summary.certificate_count ?? certificates.length}</td>
              <td style={{ padding: '8px 12px', fontWeight: '600' }}>-</td>
              <td style={{ padding: '8px 12px' }}>-</td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* SECTION 3: PRIORITIZED FINDINGS */}
      <div style={{ marginBottom: '35px', pageBreakBefore: 'auto' }}>
        <h2 style={{ fontSize: '18px', fontWeight: '700', borderBottom: '1px solid #e5e7eb', paddingBottom: '6px', marginBottom: '12px', textTransform: 'uppercase', color: '#111827' }}>
          Section 3: Prioritized Findings
        </h2>
        {sortedFindings.length === 0 ? (
          <p style={{ fontSize: '13px', color: '#4b5563', margin: 0 }}>
            No security findings were identified for this packet capture.
          </p>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left', tableLayout: 'fixed' }}>
            <thead>
              <tr style={{ background: '#f3f4f6', borderBottom: '2px solid #d1d5db' }}>
                <th style={{ padding: '8px', width: '12%' }}>Severity</th>
                <th style={{ padding: '8px', width: '28%' }}>Finding Title</th>
                <th style={{ padding: '8px', width: '30%' }}>Forensic Evidence</th>
                <th style={{ padding: '8px', width: '30%' }}>AI Explanation / Context</th>
              </tr>
            </thead>
            <tbody>
              {sortedFindings.map((f, idx) => {
                const sev = (f.severity || '').toUpperCase();
                const color =
                  sev === 'CRITICAL'
                    ? '#dc2626'
                    : sev === 'HIGH'
                    ? '#d97706'
                    : sev === 'MEDIUM'
                    ? '#b45309'
                    : '#16a34a';

                return (
                  <tr key={f.id || idx} style={{ borderBottom: '1px solid #e5e7eb' }}>
                    <td style={{ padding: '10px 8px', verticalAlign: 'top' }}>
                      <span style={{ fontWeight: '700', color }}>{sev}</span>
                    </td>
                    <td style={{ padding: '10px 8px', verticalAlign: 'top', fontWeight: '600' }}>
                      {f.title}
                      <span style={{ display: 'block', fontSize: '10px', color: '#6b7280', marginTop: '2px', fontWeight: 'normal' }}>
                        ID: {f.id}
                      </span>
                    </td>
                    <td style={{ padding: '10px 8px', verticalAlign: 'top', wordBreak: 'break-all' }}>
                      {f.evidence || 'N/A'}
                    </td>
                    <td style={{ padding: '10px 8px', verticalAlign: 'top' }}>
                      {f.description || 'No explanation available.'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* SECTION 4: MANDATORY REMEDIATION ACTION PLAN */}
      <div style={{ marginBottom: '35px', pageBreakInside: 'avoid' }}>
        <h2 style={{ fontSize: '18px', fontWeight: '700', borderBottom: '1px solid #e5e7eb', paddingBottom: '6px', marginBottom: '12px', textTransform: 'uppercase', color: '#111827' }}>
          Section 4: Mandatory Remediation Action Plan
        </h2>
        {sortedFindings.length === 0 ? (
          <p style={{ fontSize: '13px', color: '#4b5563', margin: 0 }}>
            No remediation actions required. The infrastructure configuration appears to follow standard security practices.
          </p>
        ) : (
          <ol style={{ paddingLeft: '20px', margin: 0 }}>
            {sortedFindings.map((f, idx) => {
              const sev = (f.severity || '').toUpperCase();
              const color =
                sev === 'CRITICAL'
                  ? '#dc2626'
                  : sev === 'HIGH'
                  ? '#d97706'
                  : sev === 'MEDIUM'
                  ? '#b45309'
                  : '#16a34a';

              // Format remediation text into commands and guidance if matching monospace patterns
              const remediationText = f.remediation || 'No remediation details supplied.';
              
              return (
                <li key={f.id || idx} style={{ marginBottom: '14px', fontSize: '13px', lineHeight: 1.4 }}>
                  <div style={{ fontWeight: '700', marginBottom: '4px' }}>
                    <span style={{ color }}>[{sev}]</span> {f.title}
                  </div>
                  <div style={{ color: '#374151', whiteSpace: 'pre-line' }}>
                    {remediationText}
                  </div>
                </li>
              );
            })}
          </ol>
        )}
      </div>

      {/* SECTION 5: X.509 CERTIFICATE & HANDSHAKE INVENTORY */}
      <div style={{ marginBottom: '30px', pageBreakInside: 'avoid' }}>
        <h2 style={{ fontSize: '18px', fontWeight: '700', borderBottom: '1px solid #e5e7eb', paddingBottom: '6px', marginBottom: '12px', textTransform: 'uppercase', color: '#111827' }}>
          Section 5: X.509 Certificate &amp; Handshake Inventory
        </h2>

        {/* Certificates Inventory */}
        <h3 style={{ fontSize: '14px', fontWeight: '700', color: '#374151', marginBottom: '8px', textTransform: 'uppercase' }}>
          Detected Certificates ({certificates.length})
        </h3>
        {certificates.length === 0 ? (
          <div style={{ background: '#f9fafb', border: '1px solid #e5e7eb', padding: '12px', borderRadius: '4px', fontSize: '13px', color: '#4b5563', marginBottom: '20px' }}>
            No X.509 certificates were detected in this capture.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '20px' }}>
            {certificates.map((cert, idx) => (
              <div key={cert.serial || idx} style={{ border: '1px solid #e5e7eb', borderRadius: '6px', padding: '12px', fontSize: '12px' }}>
                <div style={{ fontWeight: '700', borderBottom: '1px solid #f3f4f6', paddingBottom: '4px', marginBottom: '8px', color: '#111827' }}>
                  Certificate CN: {cert.subject_cn || cert.subject || 'Unknown Subject'}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 12px' }}>
                  <div><strong>Issuer:</strong> {cert.issuer || 'N/A'}</div>
                  <div><strong>Serial:</strong> {cert.serial || 'N/A'}</div>
                  <div><strong>Validity:</strong> {cert.valid_from ? `${cert.valid_from} to ${cert.valid_to}` : 'N/A'}</div>
                  <div><strong>Algorithm:</strong> {cert.signature_algorithm || 'N/A'}</div>
                  <div style={{ gridColumn: 'span 2' }}>
                    <strong>Fingerprint (SHA-256):</strong> <span style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{cert.fingerprint || cert.sha256 || 'N/A'}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* TLS Handshakes Inventory */}
        <h3 style={{ fontSize: '14px', fontWeight: '700', color: '#374151', marginBottom: '8px', textTransform: 'uppercase' }}>
          TLS Handshake / Protocol Inventory
        </h3>
        {sessions.filter(s => s.encrypted).length === 0 ? (
          <div style={{ background: '#f9fafb', border: '1px solid #e5e7eb', padding: '12px', borderRadius: '4px', fontSize: '13px', color: '#4b5563' }}>
            No TLS handshakes were detected in this capture.
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
            <thead>
              <tr style={{ background: '#f9fafb', borderBottom: '1px solid #e5e7eb' }}>
                <th style={{ padding: '6px 8px' }}>Session</th>
                <th style={{ padding: '6px 8px' }}>Protocol</th>
                <th style={{ padding: '6px 8px' }}>Endpoints</th>
                <th style={{ padding: '6px 8px' }}>TLS Version(s)</th>
              </tr>
            </thead>
            <tbody>
              {sessions.filter(s => s.encrypted).map((s, idx) => (
                <tr key={s.id || idx} style={{ borderBottom: '1px solid #e5e7eb' }}>
                  <td style={{ padding: '6px 8px' }}>#{s.id}</td>
                  <td style={{ padding: '6px 8px', fontWeight: '600' }}>{s.protocol}</td>
                  <td style={{ padding: '6px 8px' }}>{s.src} → {s.dst}</td>
                  <td style={{ padding: '6px 8px' }}>
                    {Array.isArray(s.tls_versions) && s.tls_versions.length > 0
                      ? s.tls_versions.join(', ')
                      : 'TLS (Encrypted)'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

    </div>
  );
}

export default PrintableReport;
