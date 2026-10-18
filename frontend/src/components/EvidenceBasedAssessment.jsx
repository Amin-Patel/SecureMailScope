import React, { useState } from 'react';
import { Link } from 'react-router-dom';

/**
 * EvidenceBasedAssessment Component (USP 5)
 *
 * Systematically separates and visualizes:
 * 1. Observed Evidence (wire telemetry from PCAP)
 * 2. Expected Requirements (RFC/NIST standards, baselines)
 * 3. Assessment Outcomes (Satisfied, Violated, Indeterminate, N/A, Undefined Expectation, Evaluation Error)
 * 4. Explicit Uncertainty & Missing Evidence Handling
 * 5. Direct links to the Evidence Provenance Graph
 */
export function EvidenceBasedAssessment({ assessment, captureId }) {
  const [filterOutcome, setFilterOutcome] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedItems, setExpandedItems] = useState({});

  if (!assessment) {
    return (
      <div className="glass-card" style={{ marginTop: '24px', padding: '24px' }}>
        <h3 className="drawer-section-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <i className="fa-solid fa-scale-balanced" style={{ color: '#38bdf8' }} />
          Evidence-Based Assessment (Observed / Expected / Unknown)
        </h3>
        <div style={{ padding: '20px', textAlign: 'center', color: '#94a3b8', fontSize: '13px' }}>
          <i className="fa-solid fa-circle-notch fa-spin" style={{ marginRight: '8px' }} />
          Loading evidence-based assessment data...
        </div>
      </div>
    );
  }

  const {
    assessments = [],
    metrics = {},
    evaluated_at,
    engine_version
  } = assessment;

  const toggleExpand = (id) => {
    setExpandedItems(prev => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  const getOutcomeCardClass = (outcome) => {
    switch (outcome) {
      case 'Satisfied':
        return 'analysis-card-satisfied';
      case 'Violated':
        return 'analysis-card-violated';
      case 'Indeterminate':
        return 'analysis-card-warning';
      default:
        return 'analysis-card-neutral';
    }
  };

  const getOutcomeBadgeStyle = (outcome) => {
    switch (outcome) {
      case 'Satisfied':
        return { background: 'rgba(16, 185, 129, 0.15)', color: '#34d399', border: '1px solid rgba(16, 185, 129, 0.35)' };
      case 'Violated':
        return { background: 'rgba(239, 68, 68, 0.15)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.35)' };
      case 'Indeterminate':
        return { background: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', border: '1px solid rgba(245, 158, 11, 0.35)' };
      case 'Not Applicable':
        return { background: 'rgba(148, 163, 184, 0.12)', color: '#94a3b8', border: '1px solid rgba(148, 163, 184, 0.25)' };
      case 'Undefined Expectation':
        return { background: 'rgba(148, 163, 184, 0.12)', color: '#cbd5e1', border: '1px solid rgba(148, 163, 184, 0.25)' };
      case 'Evaluation Error':
        return { background: 'rgba(100, 116, 139, 0.15)', color: '#cbd5e1', border: '1px solid rgba(100, 116, 139, 0.3)' };
      default:
        return { background: 'rgba(255, 255, 255, 0.08)', color: '#e2e8f0', border: '1px solid rgba(255, 255, 255, 0.15)' };
    }
  };

  const getEvidenceStatusBadgeStyle = (status) => {
    switch (status) {
      case 'Observed':
        return { background: 'rgba(16, 185, 129, 0.12)', color: '#34d399', border: '1px solid rgba(16, 185, 129, 0.3)' };
      case 'Not Observed':
        return { background: 'rgba(244, 63, 94, 0.12)', color: '#fb7185', border: '1px solid rgba(244, 63, 94, 0.3)' };
      case 'Unknown':
      case 'Unavailable':
        return { background: 'rgba(245, 158, 11, 0.12)', color: '#fbbf24', border: '1px solid rgba(245, 158, 11, 0.3)' };
      case 'Not Applicable':
        return { background: 'rgba(100, 116, 139, 0.15)', color: '#94a3b8', border: '1px solid rgba(100, 116, 139, 0.25)' };
      default:
        return { background: 'rgba(148, 163, 184, 0.12)', color: '#cbd5e1', border: '1px solid rgba(148, 163, 184, 0.25)' };
    }
  };

  const filteredAssessments = assessments.filter(item => {
    if (filterOutcome !== 'ALL' && item.outcome !== filterOutcome) {
      return false;
    }
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      const matchName = (item.property_name || '').toLowerCase().includes(q);
      const matchId = (item.id || '').toLowerCase().includes(q);
      const matchCat = (item.category || '').toLowerCase().includes(q);
      const matchSource = (item.policy_source || '').toLowerCase().includes(q);
      const matchObs = (item.observed_value || '').toLowerCase().includes(q);
      if (!matchName && !matchId && !matchCat && !matchSource && !matchObs) {
        return false;
      }
    }
    return true;
  });

  return (
    <div
      className="glass-card evidence-assessment-card"
      style={{
        marginTop: '24px',
        marginBottom: '24px',
      }}
    >
      {/* ── 1. HEADER & ASSESSMENT TITLE ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '18px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
            <h3 style={{ fontSize: '20px', fontWeight: 800, color: '#ffffff', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <i className="fa-solid fa-scale-balanced" style={{ color: '#e2e8f0' }} />
              Evidence-Based Assessment (Observed / Expected / Unknown)
            </h3>
          </div>
          <p style={{ margin: 0, fontSize: '13px', color: '#94a3b8', maxWidth: '780px', lineHeight: 1.5 }}>
            Separates empirical wire observations from formal cryptographic policies, distinguishing verified failures from unverified conditions and explicit observation boundaries.
          </p>
        </div>

        <Link
          to={`/provenance?job=${encodeURIComponent(captureId)}`}
          className="btn-action btn-secondary"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '8px 16px',
            borderRadius: '999px',
            fontSize: '13px',
            fontWeight: 600,
            textDecoration: 'none',
            transition: 'all 0.2s ease'
          }}
          title="View full evidence lineage in Evidence Provenance Graph"
        >
          <i className="fa-solid fa-diagram-project" />
          <span>Lineage in Provenance Graph</span>
        </Link>
      </div>

      {/* ── 2. METRICS COUNTER BAR ── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
        gap: '10px',
        marginBottom: '20px',
        background: 'rgba(255, 255, 255, 0.025)',
        padding: '14px',
        borderRadius: '12px',
        border: '1px solid rgba(255, 255, 255, 0.07)'
      }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '20px', fontWeight: 800, color: '#ffffff' }}>{metrics.total_assessed || 0}</div>
          <div style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Properties</div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '20px', fontWeight: 800, color: '#34d399' }}>{metrics.satisfied_count || 0}</div>
          <div style={{ fontSize: '11px', color: '#34d399', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Satisfied</div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '20px', fontWeight: 800, color: '#f87171' }}>{metrics.violated_count || 0}</div>
          <div style={{ fontSize: '11px', color: '#f87171', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Violated</div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '20px', fontWeight: 800, color: '#fbbf24' }}>{metrics.indeterminate_count || 0}</div>
          <div style={{ fontSize: '11px', color: '#fbbf24', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Indeterminate</div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '20px', fontWeight: 800, color: '#94a3b8' }}>{metrics.undefined_expectation_count || 0}</div>
          <div style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Undefined Exp.</div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '20px', fontWeight: 800, color: '#94a3b8' }}>{metrics.not_applicable_count || 0}</div>
          <div style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>N/A</div>
        </div>
      </div>

      {/* ── 3. FILTER TABS & SEARCH INPUT ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          {[
            { id: 'ALL', label: `All (${assessments.length})` },
            { id: 'Satisfied', label: `Satisfied (${metrics.satisfied_count || 0})` },
            { id: 'Violated', label: `Violated (${metrics.violated_count || 0})` },
            { id: 'Indeterminate', label: `Indeterminate (${metrics.indeterminate_count || 0})` },
            { id: 'Undefined Expectation', label: `Undefined (${metrics.undefined_expectation_count || 0})` },
            { id: 'Not Applicable', label: `N/A (${metrics.not_applicable_count || 0})` },
          ].map(f => {
            const isSelected = filterOutcome === f.id;
            return (
              <button
                key={f.id}
                onClick={() => setFilterOutcome(f.id)}
                style={{
                  padding: '6px 12px',
                  borderRadius: '999px',
                  border: isSelected ? '1px solid rgba(255, 255, 255, 0.28)' : '1px solid rgba(255, 255, 255, 0.08)',
                  background: isSelected ? 'rgba(255, 255, 255, 0.14)' : 'rgba(255, 255, 255, 0.03)',
                  color: isSelected ? '#ffffff' : 'rgba(255, 255, 255, 0.65)',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  transition: 'all 0.15s ease'
                }}
              >
                {f.label}
              </button>
            );
          })}
        </div>

        <div style={{ position: 'relative', minWidth: '220px' }}>
          <i className="fa-solid fa-magnifying-glass" style={{ position: 'absolute', left: '10px', top: '10px', color: '#64748b', fontSize: '12px' }} />
          <input
            type="text"
            placeholder="Search property or RFC..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              width: '100%',
              padding: '6px 12px 6px 30px',
              borderRadius: '8px',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              background: 'rgba(15, 15, 25, 0.85)',
              color: '#ffffff',
              fontSize: '12px',
              outline: 'none'
            }}
          />
        </div>
      </div>

      {/* ── 4. ASSESSMENTS LIST ── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {filteredAssessments.length === 0 ? (
          <div style={{ padding: '32px', textAlign: 'center', color: '#94a3b8', fontSize: '13px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '12px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
            No assessments match the selected filter criteria.
          </div>
        ) : (
          filteredAssessments.map((item) => {
            const isExpanded = expandedItems[item.id] || false;
            const outcomeStyle = getOutcomeBadgeStyle(item.outcome);
            const statusStyle = getEvidenceStatusBadgeStyle(item.evidence_status);
            const cardClass = getOutcomeCardClass(item.outcome);

            return (
              <div
                key={item.id}
                className={cardClass}
                style={{
                  padding: '16px',
                  borderRadius: '12px',
                }}
              >
                {/* Header row: ID, Category, Scope, Outcome */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <span className="analysis-property-id">
                      {item.id}
                    </span>
                    <span style={{
                      fontSize: '11px',
                      fontWeight: 600,
                      background: 'rgba(255, 255, 255, 0.05)',
                      color: '#cbd5e1',
                      padding: '3px 8px',
                      borderRadius: '6px',
                      border: '1px solid rgba(255, 255, 255, 0.08)'
                    }}>
                      {item.category}
                    </span>
                    {item.connection_scope && item.connection_scope !== 'N/A' && (
                      <span style={{
                        fontSize: '11px',
                        color: '#94a3b8',
                        background: 'rgba(255, 255, 255, 0.03)',
                        padding: '3px 8px',
                        borderRadius: '6px',
                        border: '1px solid rgba(255, 255, 255, 0.05)'
                      }}>
                        <i className="fa-solid fa-network-wired" style={{ marginRight: '5px', fontSize: '10px' }} />
                        {item.connection_scope}
                      </span>
                    )}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{
                      padding: '4px 10px',
                      borderRadius: '999px',
                      fontSize: '12px',
                      fontWeight: 700,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '6px',
                      ...outcomeStyle
                    }}>
                      {item.outcome === 'Satisfied' && <i className="fa-solid fa-circle-check" />}
                      {item.outcome === 'Violated' && <i className="fa-solid fa-circle-xmark" />}
                      {item.outcome === 'Indeterminate' && <i className="fa-solid fa-triangle-exclamation" />}
                      {item.outcome === 'Undefined Expectation' && <i className="fa-solid fa-circle-minus" />}
                      {item.outcome === 'Not Applicable' && <i className="fa-solid fa-ban" />}
                      {item.outcome}
                    </span>
                  </div>
                </div>

                {/* Property Name */}
                <h4 style={{ fontSize: '15px', fontWeight: 700, color: '#ffffff', margin: '0 0 12px 0' }}>
                  {item.property_name}
                </h4>

                {/* 3-Column Tri-State Comparison Grid */}
                <div style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                  gap: '12px',
                  marginBottom: '12px'
                }}>
                  {/* Column 1: Observed Wire Telemetry */}
                  <div style={{
                    background: 'rgba(255, 255, 255, 0.025)',
                    padding: '12px',
                    borderRadius: '8px',
                    border: '1px solid rgba(255, 255, 255, 0.06)'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                      <span style={{ fontSize: '11px', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        Observed Wire Facts
                      </span>
                      <span style={{
                        padding: '2px 7px',
                        borderRadius: '999px',
                        fontSize: '10px',
                        fontWeight: 700,
                        ...statusStyle
                      }}>
                        {item.evidence_status}
                      </span>
                    </div>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: '#f8fafc', marginBottom: '4px' }}>
                      {item.observed_value}
                    </div>
                    <div style={{ fontSize: '11px', color: '#94a3b8', lineHeight: 1.4 }}>
                      {item.observed_details}
                    </div>
                    {item.extraction_source && (
                      <div style={{ fontSize: '10px', color: '#64748b', marginTop: '6px' }}>
                        Source: {item.extraction_source}
                      </div>
                    )}
                  </div>

                  {/* Column 2: Expected Policy / RFC Standard */}
                  <div style={{
                    background: 'rgba(255, 255, 255, 0.025)',
                    padding: '12px',
                    borderRadius: '8px',
                    border: '1px solid rgba(255, 255, 255, 0.06)'
                  }}>
                    <div style={{ fontSize: '11px', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>
                      Expected Requirement
                    </div>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: '#ffffff', marginBottom: '4px' }}>
                      {item.expected_value}
                    </div>
                    <div style={{ fontSize: '11px', color: '#94a3b8', lineHeight: 1.4, marginBottom: '6px' }}>
                      Standard: <strong style={{ color: '#cbd5e1' }}>{item.policy_source}</strong>
                    </div>
                    {item.comparison_rule && (
                      <div style={{
                        fontFamily: 'monospace',
                        fontSize: '10px',
                        background: 'rgba(255, 255, 255, 0.05)',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        padding: '3px 6px',
                        borderRadius: '4px',
                        color: '#cbd5e1',
                        display: 'inline-block'
                      }}>
                        Rule: {item.comparison_rule}
                      </div>
                    )}
                  </div>

                  {/* Column 3: Comparison Outcome & Summary */}
                  <div style={{
                    background: 'rgba(255, 255, 255, 0.025)',
                    padding: '12px',
                    borderRadius: '8px',
                    border: `1px solid ${item.outcome === 'Violated' ? 'rgba(239, 68, 68, 0.2)' : item.outcome === 'Satisfied' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(255, 255, 255, 0.06)'}`
                  }}>
                    <div style={{ fontSize: '11px', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>
                      Assessment Outcome
                    </div>
                    <div style={{ fontSize: '12px', color: '#cbd5e1', lineHeight: 1.4, marginBottom: '6px' }}>
                      {item.explanation}
                    </div>
                    {item.unknown_reason && (
                      <div style={{
                        marginTop: '6px',
                        padding: '6px 8px',
                        borderRadius: '6px',
                        background: 'rgba(245, 158, 11, 0.1)',
                        border: '1px solid rgba(245, 158, 11, 0.25)',
                        fontSize: '11px',
                        color: '#fbbf24',
                        lineHeight: 1.3
                      }}>
                        <i className="fa-solid fa-triangle-exclamation" style={{ marginRight: '5px' }} />
                        {item.unknown_reason}
                      </div>
                    )}
                  </div>
                </div>

                {/* Bottom Bar: Evidence Reference Tags & Expand Button */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px', paddingTop: '8px', borderTop: '1px solid rgba(255, 255, 255, 0.06)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                    <span style={{ fontSize: '11px', color: '#64748b' }}>Evidence Refs:</span>
                    {item.evidence_refs && item.evidence_refs.length > 0 ? (
                      item.evidence_refs.map((ref, idx) => (
                        <Link
                          key={idx}
                          to={`/provenance?job=${encodeURIComponent(captureId)}&node=${encodeURIComponent(ref)}`}
                          className="analysis-evidence-tag"
                          title={`Click to trace ${ref} in Evidence Provenance Graph`}
                        >
                          <i className="fa-solid fa-arrow-up-right-from-square" style={{ fontSize: '9px' }} />
                          {ref}
                        </Link>
                      ))
                    ) : (
                      <span style={{ fontSize: '11px', color: '#64748b', fontStyle: 'italic' }}>
                        None (Inferred or Absent)
                      </span>
                    )}
                  </div>

                  <button
                    onClick={() => toggleExpand(item.id)}
                    style={{
                      background: 'transparent',
                      border: 'none',
                      color: 'rgba(255, 255, 255, 0.7)',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '5px',
                      padding: '4px 8px',
                      transition: 'color 0.15s ease'
                    }}
                    onMouseEnter={e => e.currentTarget.style.color = '#ffffff'}
                    onMouseLeave={e => e.currentTarget.style.color = 'rgba(255, 255, 255, 0.7)'}
                  >
                    <span>{isExpanded ? 'Hide Details' : 'Why this result?'}</span>
                    <i className={`fa-solid ${isExpanded ? 'fa-chevron-up' : 'fa-chevron-down'}`} style={{ fontSize: '10px' }} />
                  </button>
                </div>

                {/* Expandable Reasoning Details */}
                {isExpanded && (
                  <div style={{
                    marginTop: '12px',
                    padding: '14px',
                    background: 'rgba(0, 0, 0, 0.35)',
                    borderRadius: '8px',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    animation: 'fadeIn 0.2s ease'
                  }}>
                    <h5 style={{ fontSize: '13px', fontWeight: 700, color: '#ffffff', margin: '0 0 8px 0', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <i className="fa-solid fa-magnifying-glass-chart" style={{ color: '#94a3b8' }} />
                      Assessment Rationale & Boundary Analysis
                    </h5>
                    <p style={{ fontSize: '12px', color: '#cbd5e1', lineHeight: 1.5, margin: '0 0 10px 0' }}>
                      {item.explanation}
                    </p>

                    {item.missing_prerequisites && item.missing_prerequisites.length > 0 && (
                      <div style={{ marginBottom: '10px' }}>
                        <span style={{ fontSize: '11px', fontWeight: 700, color: '#fbbf24', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                          Missing Prerequisites:
                        </span>
                        <ul style={{ margin: '4px 0 0 18px', padding: 0, fontSize: '12px', color: '#cbd5e1' }}>
                          {item.missing_prerequisites.map((p, pIdx) => (
                            <li key={pIdx}>{p}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '10px' }}>
                      <Link
                        to={`/provenance?job=${encodeURIComponent(captureId)}`}
                        style={{
                          fontSize: '11px',
                          color: '#e2e8f0',
                          textDecoration: 'none',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '6px',
                          fontWeight: 600
                        }}
                      >
                        <span>Open Evidence Provenance Graph for this capture</span>
                        <i className="fa-solid fa-arrow-right" />
                      </Link>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* ── 5. FOOTER INFO ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px', marginTop: '16px', paddingTop: '12px', borderTop: '1px solid rgba(255, 255, 255, 0.05)', fontSize: '11px', color: '#64748b' }}>
        <div>
          Engine: <strong>{engine_version || '1.0.0-evidence-assessment'}</strong> &bull; Scoped strictly to Capture #{captureId}
        </div>
        {evaluated_at && (
          <div>
            Evaluated: {new Date(evaluated_at).toLocaleString()}
          </div>
        )}
      </div>
    </div>
  );
}
