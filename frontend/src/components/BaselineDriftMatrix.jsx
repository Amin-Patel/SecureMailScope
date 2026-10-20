import React, { useState, useEffect } from 'react';
import { getBaselines, createBaseline, compareDrift, getDriftHistory, downloadDriftReportPdf } from '../utils/api';

export function BaselineDriftMatrix({ analysisData }) {
  const [baselines, setBaselines] = useState([]);
  const [selectedBaselineId, setSelectedBaselineId] = useState('nist_sp800_52r2');
  const [comparison, setComparison] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [comparing, setComparing] = useState(false);
  const [exportingPdf, setExportingPdf] = useState(false);

  // Modal / Form state for creating custom baseline
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newBaselineName, setNewBaselineName] = useState('');
  const [newBaselineDesc, setNewBaselineDesc] = useState('');
  const [creating, setCreating] = useState(false);

  const captureId = analysisData?.capture_id;

  // Load baselines & history
  useEffect(() => {
    setLoading(true);
    Promise.all([
      getBaselines(),
      captureId ? getDriftHistory(captureId) : Promise.resolve({ comparisons: [] })
    ])
      .then(([bRes, hRes]) => {
        const bList = bRes.baselines || [];
        setBaselines(bList);
        if (bList.length > 0 && !selectedBaselineId) {
          setSelectedBaselineId(bList[0].baseline_id);
        }
        const hList = hRes.comparisons || [];
        setHistory(hList);
        setLoading(false);
      })
      .catch(err => {
        console.error('Error fetching baselines:', err);
        setLoading(false);
      });
  }, [captureId]);

  const handleRunComparison = async (baselineIdToUse) => {
    const bId = baselineIdToUse || selectedBaselineId;
    if (!captureId || !bId) return;

    try {
      setComparing(true);
      const res = await compareDrift({
        capture_id: captureId,
        baseline_id: bId
      });
      setComparison(res);

      // Refresh history
      const hRes = await getDriftHistory(captureId);
      setHistory(hRes.comparisons || []);
    } catch (err) {
      console.error('Drift comparison failed:', err);
      alert('Drift comparison failed: ' + (err.message || 'Unknown error'));
    } finally {
      setComparing(false);
    }
  };

  const handleCreateBaseline = async (e) => {
    e.preventDefault();
    if (!captureId || !newBaselineName.trim()) return;

    try {
      setCreating(true);
      const created = await createBaseline({
        capture_id: captureId,
        name: newBaselineName.trim(),
        description: newBaselineDesc.trim() || `Empirical baseline established from ${analysisData.original_filename || captureId}`
      });

      // Refresh baseline list and select new baseline
      const bRes = await getBaselines();
      setBaselines(bRes.baselines || []);
      setSelectedBaselineId(created.baseline_id);
      setShowCreateModal(false);
      setNewBaselineName('');
      setNewBaselineDesc('');

      // Auto run comparison against newly created baseline
      handleRunComparison(created.baseline_id);
    } catch (err) {
      console.error('Failed to create baseline:', err);
      alert('Failed to create baseline: ' + (err.message || 'Unknown error'));
    } finally {
      setCreating(false);
    }
  };

  const handleExportDriftPdf = async (cmpId) => {
    const targetCmpId = cmpId || comparison?.comparison_id;
    if (!targetCmpId) return;

    try {
      setExportingPdf(true);
      await downloadDriftReportPdf(targetCmpId);
    } catch (err) {
      console.error('Failed to export drift report PDF:', err);
      alert('Failed to export drift report: ' + (err.message || 'Unknown error'));
    } finally {
      setExportingPdf(false);
    }
  };

  const selectedBaseline = baselines.find(b => b.baseline_id === selectedBaselineId);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Banner */}
      <div className="glass-card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{
              background: 'rgba(245, 158, 11, 0.2)',
              border: '1px solid rgba(245, 158, 11, 0.4)',
              color: '#fcd34d',
              fontSize: '11px',
              fontWeight: 800,
              padding: '3px 8px',
              borderRadius: '6px',
              letterSpacing: '0.05em'
            }}>DRIFT AUDIT</span>
            <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#ffffff', margin: 0 }}>
              Cryptographic Drift &amp; Baseline Analysis
            </h3>
          </div>
          <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.65)', margin: '6px 0 0 0' }}>
            Compare observed email cryptography against RFC/NIST security baselines or previous captures to detect configuration degradation and policy regressions.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <button
            onClick={() => setShowCreateModal(true)}
            className="btn-action btn-secondary"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '9px 16px',
              borderRadius: '999px',
              fontSize: '12px',
              fontWeight: 600
            }}
          >
            <i className="fa-solid fa-plus" />
            <span>Create Baseline from Capture</span>
          </button>
        </div>
      </div>

      {/* Baseline Selector Bar */}
      <div className="glass-card" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1, minWidth: '280px' }}>
          <label style={{ fontSize: '13px', fontWeight: 600, color: '#cbd5e1', whiteSpace: 'nowrap' }}>
            Reference Baseline:
          </label>
          <select
            value={selectedBaselineId}
            onChange={(e) => setSelectedBaselineId(e.target.value)}
            style={{
              padding: '8px 12px',
              borderRadius: '8px',
              background: 'rgba(15, 23, 42, 0.8)',
              border: '1px solid rgba(255,255,255,0.15)',
              color: '#ffffff',
              fontSize: '13px',
              fontWeight: 600,
              flex: 1,
              maxWidth: '400px'
            }}
          >
            {baselines.map(b => (
              <option key={b.baseline_id} value={b.baseline_id}>
                {b.name} (v{b.version}) &bull; {b.baseline_type === 'SECURITY_POLICY' ? 'Policy' : 'Empirical'}
              </option>
            ))}
          </select>
        </div>

        <button
          onClick={() => handleRunComparison()}
          disabled={comparing}
          className="btn-action"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '9px 20px',
            borderRadius: '999px',
            background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)',
            color: '#ffffff',
            fontWeight: 700,
            fontSize: '13px',
            border: 'none',
            cursor: comparing ? 'not-allowed' : 'pointer',
            boxShadow: '0 4px 14px rgba(245,158,11,0.3)'
          }}
        >
          <i className={comparing ? "fa-solid fa-spinner fa-spin" : "fa-solid fa-arrows-split-up-and-left"} />
          <span>{comparing ? "Comparing Properties…" : "Run Drift Comparison"}</span>
        </button>
      </div>

      {/* Selected Baseline Description Note */}
      {selectedBaseline && (
        <div style={{
          background: 'rgba(255,255,255,0.03)',
          border: '1px solid rgba(255,255,255,0.06)',
          borderRadius: '8px',
          padding: '10px 16px',
          fontSize: '12px',
          color: '#94a3b8'
        }}>
          <strong style={{ color: '#e2e8f0' }}>Target Baseline Rationale:</strong> {selectedBaseline.description}
        </div>
      )}

      {/* Active Comparison Results */}
      {comparison ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Status & Metrics Card */}
          <div className="glass-card" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px', marginBottom: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{
                    background: `${comparison.badge_color || '#10b981'}26`,
                    border: `1.5px solid ${comparison.badge_color || '#10b981'}`,
                    color: comparison.badge_color || '#10b981',
                    fontSize: '12px',
                    fontWeight: 800,
                    padding: '4px 12px',
                    borderRadius: '999px'
                  }}>
                    {comparison.overall_status?.replace(/_/g, ' ')}
                  </span>
                  <span style={{ fontSize: '13px', color: 'rgba(255,255,255,0.4)', fontFamily: 'monospace' }}>
                    #{comparison.comparison_id}
                  </span>
                </div>
                <p style={{ fontSize: '14px', color: '#e2e8f0', margin: '8px 0 0 0', fontWeight: 600 }}>
                  {comparison.summary_description}
                </p>
              </div>

              <button
                onClick={() => handleExportDriftPdf()}
                disabled={exportingPdf}
                className="btn-action"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '9px 18px',
                  borderRadius: '999px',
                  background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                  color: '#ffffff',
                  fontWeight: 700,
                  fontSize: '12px',
                  border: 'none',
                  cursor: exportingPdf ? 'not-allowed' : 'pointer'
                }}
              >
                <i className={exportingPdf ? "fa-solid fa-spinner fa-spin" : "fa-solid fa-file-pdf"} />
                <span>{exportingPdf ? "Generating PDF…" : "Export Drift Report (PDF)"}</span>
              </button>
            </div>

            {/* Metrics Breakdown */}
            <div className="metrics-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)' }}>
              <div className="metric-box">
                <div className="metric-value">{comparison.metrics?.total_properties ?? 0}</div>
                <div className="metric-label">Properties Evaluated</div>
              </div>
              <div className="metric-box">
                <div className="metric-value" style={{ color: '#10b981' }}>{comparison.metrics?.unchanged_count ?? 0}</div>
                <div className="metric-label">Unchanged / Adherent</div>
              </div>
              <div className="metric-box">
                <div className="metric-value" style={{ color: '#f59e0b' }}>{comparison.metrics?.changed_count ?? 0}</div>
                <div className="metric-label">Changed Properties</div>
              </div>
              <div className="metric-box">
                <div className="metric-value" style={{ color: '#ef4444' }}>{comparison.metrics?.weakened_count ?? 0}</div>
                <div className="metric-label">Weakened / Violations</div>
              </div>
              <div className="metric-box">
                <div className="metric-value" style={{ color: '#38bdf8' }}>{comparison.metrics?.strengthened_count ?? 0}</div>
                <div className="metric-label">Strengthened Posture</div>
              </div>
            </div>
          </div>

          {/* Property-by-Property Diff Table */}
          <div className="glass-card" style={{ padding: '20px' }}>
            <h4 style={{ fontSize: '15px', fontWeight: 700, color: '#ffffff', marginBottom: '14px' }}>
              Granular Cryptographic Drift Matrix
            </h4>

            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)', textAlign: 'left', color: '#94a3b8' }}>
                    <th style={{ padding: '10px 12px' }}>Property</th>
                    <th style={{ padding: '10px 12px' }}>Baseline Expected</th>
                    <th style={{ padding: '10px 12px' }}>Observed in Capture</th>
                    <th style={{ padding: '10px 12px' }}>Classification</th>
                    <th style={{ padding: '10px 12px' }}>Security Significance</th>
                    <th style={{ padding: '10px 12px' }}>Evidentiary Explanation</th>
                  </tr>
                </thead>
                <tbody>
                  {(comparison.property_diffs || []).map((diff, idx) => {
                    const sig = diff.security_significance;
                    const sigColor = (sig === 'POLICY_VIOLATION' || sig === 'POTENTIALLY_WEAKENED')
                      ? '#ef4444'
                      : (sig === 'POLICY_COMPLIANT' || sig === 'POTENTIALLY_STRENGTHENED')
                        ? '#10b981'
                        : '#f59e0b';

                    return (
                      <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                        <td style={{ padding: '12px', fontWeight: 600, color: '#ffffff' }}>
                          {diff.property}
                        </td>
                        <td style={{ padding: '12px', color: '#cbd5e1', fontFamily: 'monospace', fontSize: '12px' }}>
                          {Array.isArray(diff.baseline_value) ? diff.baseline_value.join(', ') : String(diff.baseline_value ?? 'N/A')}
                        </td>
                        <td style={{ padding: '12px', color: '#cbd5e1', fontFamily: 'monospace', fontSize: '12px' }}>
                          {Array.isArray(diff.current_value) ? diff.current_value.join(', ') : String(diff.current_value ?? 'N/A')}
                        </td>
                        <td style={{ padding: '12px' }}>
                          <span style={{
                            padding: '2px 8px',
                            borderRadius: '4px',
                            fontSize: '11px',
                            fontWeight: 700,
                            background: diff.diff_type === 'UNCHANGED' ? 'rgba(16,185,129,0.15)' : 'rgba(245,158,11,0.15)',
                            color: diff.diff_type === 'UNCHANGED' ? '#34d399' : '#fbbf24'
                          }}>
                            {diff.diff_type}
                          </span>
                        </td>
                        <td style={{ padding: '12px' }}>
                          <span style={{
                            padding: '2px 8px',
                            borderRadius: '4px',
                            fontSize: '11px',
                            fontWeight: 700,
                            background: `${sigColor}22`,
                            color: sigColor
                          }}>
                            {sig?.replace(/_/g, ' ')}
                          </span>
                        </td>
                        <td style={{ padding: '12px', color: '#94a3b8', fontSize: '12px', lineHeight: 1.4 }}>
                          {diff.explanation}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : (
        <div className="glass-card" style={{ padding: '40px', textAlign: 'center', color: '#94a3b8' }}>
          <i className="fa-solid fa-scale-balanced" style={{ fontSize: '32px', color: '#f59e0b', marginBottom: '14px' }} />
          <div style={{ fontSize: '15px', fontWeight: 600, color: '#ffffff' }}>No Drift Comparison Executed Yet</div>
          <p style={{ fontSize: '13px', color: '#94a3b8', marginTop: '6px', maxWidth: '480px', margin: '6px auto 16px' }}>
            Select a reference baseline above and click <strong>Run Drift Comparison</strong> to detect configuration changes, cryptographic degradations, and policy non-compliances.
          </p>
          <button
            onClick={() => handleRunComparison()}
            disabled={comparing}
            className="btn-action"
            style={{ padding: '8px 20px', borderRadius: '999px', fontSize: '13px' }}
          >
            <i className="fa-solid fa-play" /> Run Immediate Comparison
          </button>
        </div>
      )}

      {/* Comparison History */}
      {history.length > 0 && (
        <div className="glass-card" style={{ padding: '20px' }}>
          <h4 style={{ fontSize: '14px', fontWeight: 700, color: '#ffffff', marginBottom: '12px' }}>
            Comparison History for This Capture ({history.length} Run{history.length > 1 ? 's' : ''})
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {history.map(item => (
              <div
                key={item.comparison_id}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  background: 'rgba(255,255,255,0.02)',
                  padding: '10px 14px',
                  borderRadius: '8px',
                  border: '1px solid rgba(255,255,255,0.05)',
                  fontSize: '12px'
                }}
              >
                <div>
                  <strong style={{ color: '#ffffff' }}>{item.baseline_name}</strong>
                  <span style={{ color: '#94a3b8', marginLeft: '10px' }}>
                    Compared: {item.compared_at ? item.compared_at.replace('T', ' ').substring(0, 19) : ''}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ color: item.badge_color || '#10b981', fontWeight: 700 }}>
                    {item.overall_status?.replace(/_/g, ' ')}
                  </span>
                  <button
                    onClick={() => handleExportDriftPdf(item.comparison_id)}
                    className="btn-action btn-secondary"
                    style={{ padding: '4px 10px', fontSize: '11px', borderRadius: '6px' }}
                  >
                    <i className="fa-solid fa-file-pdf" /> PDF
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Modal: Create Baseline */}
      {showCreateModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0,0,0,0.7)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '20px'
        }}>
          <div style={{
            background: '#0f172a',
            border: '1px solid rgba(255,255,255,0.15)',
            borderRadius: '16px',
            maxWidth: '500px',
            width: '100%',
            padding: '24px',
            boxShadow: '0 20px 40px rgba(0,0,0,0.5)'
          }}>
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#ffffff', margin: '0 0 8px 0' }}>
              Create Empirical Baseline
            </h3>
            <p style={{ fontSize: '13px', color: '#94a3b8', margin: '0 0 16px 0' }}>
              Snapshot current capture's TLS versions, cipher suites, key lengths, and certificates as an authoritative baseline for future drift detection.
            </p>

            <form onSubmit={handleCreateBaseline} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#cbd5e1', marginBottom: '6px' }}>
                  Baseline Name *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Q4 Mail Production Cluster Baseline"
                  value={newBaselineName}
                  onChange={(e) => setNewBaselineName(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: '8px',
                    background: 'rgba(255,255,255,0.05)',
                    border: '1px solid rgba(255,255,255,0.15)',
                    color: '#ffffff',
                    fontSize: '13px',
                    boxSizing: 'border-box'
                  }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: '#cbd5e1', marginBottom: '6px' }}>
                  Description (Optional)
                </label>
                <textarea
                  rows={3}
                  placeholder="Notes on the infrastructure or policy scope..."
                  value={newBaselineDesc}
                  onChange={(e) => setNewBaselineDesc(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: '8px',
                    background: 'rgba(255,255,255,0.05)',
                    border: '1px solid rgba(255,255,255,0.15)',
                    color: '#ffffff',
                    fontSize: '13px',
                    boxSizing: 'border-box'
                  }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  style={{
                    padding: '8px 16px',
                    borderRadius: '8px',
                    background: 'transparent',
                    border: '1px solid rgba(255,255,255,0.2)',
                    color: '#cbd5e1',
                    fontSize: '13px',
                    cursor: 'pointer'
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="btn-action"
                  style={{
                    padding: '8px 18px',
                    borderRadius: '8px',
                    fontSize: '13px'
                  }}
                >
                  {creating ? "Saving Baseline…" : "Save Baseline"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
