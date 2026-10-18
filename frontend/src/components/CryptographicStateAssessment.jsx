import React, { useState } from 'react';
import { Link } from 'react-router-dom';

/**
 * CryptographicStateAssessment Component (USP 2)
 *
 * Displays unified cryptographic state reasoning, normalized 10-rule outcomes,
 * cross-property forensic insights, and expandable explanation details.
 */
export function CryptographicStateAssessment({ assessment, captureId }) {
  const [expanded, setExpanded] = useState(false);
  const [filterStatus, setFilterStatus] = useState('ALL');

  if (!assessment) {
    return (
      <div className="glass-card" style={{ marginTop: '24px', padding: '24px' }}>
        <h3 className="drawer-section-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <i className="fa-solid fa-shield-halved" style={{ color: '#818cf8' }} />
          Cryptographic State Assessment
        </h3>
        <div style={{ padding: '20px', textAlign: 'center', color: '#94a3b8', fontSize: '13px' }}>
          <i className="fa-solid fa-circle-notch fa-spin" style={{ marginRight: '8px' }} />
          Loading unified cryptographic state evaluation...
        </div>
      </div>
    );
  }

  const {
    overall_state,
    overall_state_label,
    state_description,
    badge_color = '#6366f1',
    evidence_completeness = 'Complete',
    normalized_rules = [],
    cross_property_insights = [],
    unresolved_conditions = [],
    explanation = {},
    metrics = {}
  } = assessment;

  // Filter rules
  const filteredRules = normalized_rules.filter(r => {
    if (filterStatus === 'ALL') return true;
    return r.status === filterStatus;
  });

  const getRuleCardClass = (status) => {
    switch (status) {
      case 'SATISFIED':
        return 'analysis-card-satisfied';
      case 'VIOLATED':
        return 'analysis-card-violated';
      case 'UNKNOWN':
        return 'analysis-card-warning';
      default:
        return 'analysis-card-neutral';
    }
  };

  const getStatusBadgeStyle = (status) => {
    switch (status) {
      case 'SATISFIED':
        return { background: 'rgba(16, 185, 129, 0.15)', color: '#34d399', border: '1px solid rgba(16, 185, 129, 0.35)' };
      case 'VIOLATED':
        return { background: 'rgba(239, 68, 68, 0.15)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.35)' };
      case 'UNKNOWN':
        return { background: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', border: '1px solid rgba(245, 158, 11, 0.35)' };
      case 'NOT_APPLICABLE':
        return { background: 'rgba(148, 163, 184, 0.12)', color: '#94a3b8', border: '1px solid rgba(148, 163, 184, 0.25)' };
      default:
        return { background: 'rgba(255, 255, 255, 0.08)', color: '#e2e8f0', border: '1px solid rgba(255, 255, 255, 0.15)' };
    }
  };

  const getSeverityBadgeStyle = (sev) => {
    switch (sev) {
      case 'CRITICAL':
        return { background: 'rgba(239, 68, 68, 0.2)', color: '#fca5a5', border: '1px solid rgba(239, 68, 68, 0.35)' };
      case 'HIGH':
        return { background: 'rgba(249, 115, 22, 0.2)', color: '#fdba74', border: '1px solid rgba(249, 115, 22, 0.35)' };
      case 'MEDIUM':
        return { background: 'rgba(234, 179, 8, 0.2)', color: '#fde047', border: '1px solid rgba(234, 179, 8, 0.35)' };
      default:
        return { background: 'rgba(148, 163, 184, 0.15)', color: '#cbd5e1', border: '1px solid rgba(148, 163, 184, 0.25)' };
    }
  };

  return (
    <div className="glass-card crypto-state-card" style={{
      marginTop: '24px',
      marginBottom: '24px',
      borderTop: `2px solid ${badge_color}`,
    }}>
      {/* ── 1. HEADER & OVERALL STATE ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '18px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
            <h3 style={{ fontSize: '20px', fontWeight: 800, color: '#ffffff', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <i className="fa-solid fa-shield-halved" style={{ color: badge_color }} />
              Cryptographic State Assessment
            </h3>
          </div>
          <p style={{ fontSize: '13px', color: '#94a3b8', margin: 0 }}>
            Unified cross-property reasoning engine &bull; Evaluates 10 cryptographic standards against wire evidence
          </p>
        </div>

        {/* State Badge & Evidence Completeness */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '8px 16px',
            borderRadius: '999px',
            background: `rgba(${badge_color === '#10b981' ? '16, 185, 129' : badge_color === '#ef4444' ? '239, 68, 68' : badge_color === '#f59e0b' ? '245, 158, 11' : '148, 163, 184'}, 0.15)`,
            border: `1.5px solid ${badge_color}`,
            color: '#ffffff',
            fontWeight: 800,
            fontSize: '14px',
            boxShadow: `0 0 16px ${badge_color}33`
          }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: badge_color, boxShadow: `0 0 8px ${badge_color}` }} />
            {overall_state_label}
          </div>

          <span style={{
            fontSize: '11px',
            fontWeight: 700,
            padding: '6px 14px',
            borderRadius: '999px',
            background: evidence_completeness === 'Complete' ? 'rgba(16, 185, 129, 0.12)' : 'rgba(245, 158, 11, 0.12)',
            color: evidence_completeness === 'Complete' ? '#34d399' : '#fbbf24',
            border: `1px solid ${evidence_completeness === 'Complete' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`
          }}>
            Evidence: {evidence_completeness}
          </span>
        </div>
      </div>

      {/* ── 2. SUMMARY RATIONALE & KEY DRIVERS ── */}
      <div style={{
        background: 'rgba(255, 255, 255, 0.025)',
        border: '1px solid rgba(255, 255, 255, 0.07)',
        borderRadius: '12px',
        padding: '16px 20px',
        marginBottom: '20px'
      }}>
        <div style={{ fontSize: '14px', lineHeight: 1.6, color: '#f1f5f9', fontWeight: 500, marginBottom: '12px' }}>
          <i className="fa-solid fa-quote-left" style={{ color: badge_color, marginRight: '10px', opacity: 0.8 }} />
          {explanation.summary_rationale || state_description}
        </div>

        {explanation.state_drivers && explanation.state_drivers.length > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', paddingTop: '10px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
            <span style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#94a3b8', fontWeight: 700 }}>
              Primary Drivers:
            </span>
            {explanation.state_drivers.map((d, idx) => (
              <span key={idx} style={{
                fontSize: '12px',
                padding: '3px 10px',
                borderRadius: '6px',
                background: 'rgba(255, 255, 255, 0.05)',
                color: '#e2e8f0',
                border: '1px solid rgba(255, 255, 255, 0.08)'
              }}>
                {d}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* ── 3. METRICS PILLS ── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px', marginBottom: '20px' }}>
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          {[
            { id: 'ALL', label: `All 10 Rules (${metrics.total_rules || 10})`, activeStyle: { background: 'rgba(255, 255, 255, 0.14)', border: '1px solid rgba(255, 255, 255, 0.28)', color: '#ffffff' }, color: 'rgba(255, 255, 255, 0.65)' },
            { id: 'SATISFIED', label: `Satisfied (${metrics.satisfied_count ?? 0})`, activeStyle: { background: 'rgba(16, 185, 129, 0.2)', border: '1px solid rgba(16, 185, 129, 0.45)', color: '#34d399' }, color: '#34d399' },
            { id: 'VIOLATED', label: `Violated (${metrics.violated_count ?? 0})`, activeStyle: { background: 'rgba(239, 68, 68, 0.2)', border: '1px solid rgba(239, 68, 68, 0.45)', color: '#f87171' }, color: '#f87171' },
            { id: 'UNKNOWN', label: `Unknown (${metrics.unknown_count ?? 0})`, activeStyle: { background: 'rgba(245, 158, 11, 0.2)', border: '1px solid rgba(245, 158, 11, 0.45)', color: '#fbbf24' }, color: '#fbbf24' },
            { id: 'NOT_APPLICABLE', label: `N/A (${metrics.not_applicable_count ?? 0})`, activeStyle: { background: 'rgba(148, 163, 184, 0.18)', border: '1px solid rgba(148, 163, 184, 0.35)', color: '#cbd5e1' }, color: '#94a3b8' },
          ].map(btn => {
            const isSelected = filterStatus === btn.id;
            return (
              <button
                key={btn.id}
                onClick={() => setFilterStatus(btn.id)}
                style={{
                  padding: '6px 14px',
                  borderRadius: '999px',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  ...(isSelected
                    ? btn.activeStyle
                    : {
                        background: 'rgba(255, 255, 255, 0.03)',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        color: btn.color
                      })
                }}
              >
                {btn.label}
              </button>
            );
          })}
        </div>

        {/* Toggle Reasoning Deep-Dive */}
        <button
          onClick={() => setExpanded(!expanded)}
          className="btn-action btn-secondary"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '7px 16px',
            borderRadius: '999px',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
            transition: 'all 0.2s ease'
          }}
        >
          <i className={`fa-solid ${expanded ? 'fa-chevron-up' : 'fa-brain'}`} style={{ color: '#cbd5e1' }} />
          <span>{expanded ? 'Hide Reasoning Details' : 'Why this state? (Reasoning Details)'}</span>
        </button>
      </div>

      {/* ── 4. EXPANDABLE CROSS-PROPERTY REASONING DRAWER ── */}
      {expanded && (
        <div style={{
          background: 'rgba(12, 14, 20, 0.95)',
          borderRadius: '12px',
          border: '1px solid rgba(255, 255, 255, 0.12)',
          padding: '20px',
          marginBottom: '20px',
          animation: 'fadeIn 0.2s ease'
        }}>
          <h4 style={{ fontSize: '15px', fontWeight: 800, color: '#e2e8f0', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <i className="fa-solid fa-network-wired" style={{ color: '#cbd5e1' }} />
            Cross-Property Dependency Evaluation & Evidence Boundaries
          </h4>

          {/* Cross-Property Insights */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px', marginBottom: '16px' }}>
            {cross_property_insights.map((insight, i) => (
              <div key={i} style={{
                background: 'rgba(255, 255, 255, 0.03)',
                padding: '14px',
                borderRadius: '8px',
                border: '1px solid rgba(255, 255, 255, 0.06)'
              }}>
                <div style={{ fontSize: '11px', fontWeight: 800, color: '#cbd5e1', textTransform: 'uppercase', marginBottom: '4px' }}>
                  {insight.id}: {insight.relationship}
                </div>
                <div style={{ fontSize: '13px', fontWeight: 700, color: '#ffffff', marginBottom: '6px' }}>
                  {insight.finding}
                </div>
                <div style={{ fontSize: '12px', color: '#cbd5e1', lineHeight: 1.5, marginBottom: '6px' }}>
                  {insight.reasoning}
                </div>
                <div style={{ fontSize: '11px', color: '#94a3b8', fontStyle: 'italic' }}>
                  Impact: {insight.impact}
                </div>
              </div>
            ))}
          </div>

          {/* Unresolved conditions & boundaries */}
          <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', paddingTop: '12px', borderTop: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <div style={{ flex: 1, minWidth: '240px' }}>
              <div style={{ fontSize: '12px', fontWeight: 700, color: '#fbbf24', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <i className="fa-solid fa-circle-question" />
                Unresolved Forensic Conditions
              </div>
              <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12px', color: '#cbd5e1', lineHeight: 1.5 }}>
                {unresolved_conditions.length > 0 ? (
                  unresolved_conditions.map((u, i) => <li key={i}>{u}</li>)
                ) : (
                  <li>No unresolved conditions; sufficient wire evidence captured.</li>
                )}
              </ul>
            </div>

            <div style={{ flex: 1, minWidth: '240px' }}>
              <div style={{ fontSize: '12px', fontWeight: 700, color: '#94a3b8', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <i className="fa-solid fa-triangle-exclamation" />
                Scope & Wire Observation Limitations
              </div>
              <p style={{ margin: 0, fontSize: '12px', color: '#94a3b8', lineHeight: 1.5 }}>
                {explanation.scope_limitations || 'Forensic reasoning is strictly bounded by captured network packets. Client-side root trust stores and unobserved relay hops cannot be evaluated from PCAP data alone.'}
              </p>
            </div>
          </div>

          {/* Link to Provenance Graph */}
          {captureId && (
            <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'flex-end' }}>
              <Link
                to={`/provenance?job=${encodeURIComponent(captureId)}`}
                className="btn-action btn-secondary"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '8px 16px',
                  borderRadius: '999px',
                  fontSize: '12px',
                  fontWeight: 600,
                  textDecoration: 'none'
                }}
              >
                <i className="fa-solid fa-diagram-project" />
                Trace in Evidence Provenance Graph
              </Link>
            </div>
          )}
        </div>
      )}

      {/* ── 5. NORMALIZED 10-RULE BREAKDOWN GRID ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '12px' }}>
        {filteredRules.map((rule) => {
          const statusStyle = getStatusBadgeStyle(rule.status);
          const sevStyle = getSeverityBadgeStyle(rule.severity);
          const cardClass = getRuleCardClass(rule.status);

          return (
            <div
              key={rule.rule_id}
              className={cardClass}
              style={{
                padding: '14px',
                borderRadius: '12px',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                opacity: rule.status === 'NOT_APPLICABLE' ? 0.82 : 1
              }}
            >
              <div>
                {/* Rule Header */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '8px', marginBottom: '8px' }}>
                  <div>
                    <span style={{ fontSize: '10px', color: 'var(--muted)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      {rule.rule_id} &bull; {rule.standard}
                    </span>
                    <h5 style={{ fontSize: '13px', fontWeight: 700, color: '#f8fafc', margin: '2px 0 0 0' }}>
                      {rule.property_name}
                    </h5>
                  </div>
                  <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                    <span style={{
                      fontSize: '10px', fontWeight: 800, padding: '2px 7px', borderRadius: '999px',
                      ...sevStyle
                    }}>
                      {rule.severity}
                    </span>
                    <span style={{
                      fontSize: '10px', fontWeight: 800, padding: '2px 7px', borderRadius: '999px',
                      ...statusStyle
                    }}>
                      {rule.status}
                    </span>
                  </div>
                </div>

                {/* Explanation */}
                <p style={{ fontSize: '12px', color: '#cbd5e1', lineHeight: 1.45, margin: '6px 0 10px 0' }}>
                  {rule.explanation}
                </p>

                {/* Observed vs Expected */}
                <div style={{ fontSize: '11px', background: 'rgba(0, 0, 0, 0.25)', borderRadius: '6px', padding: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                  <div style={{ color: '#94a3b8', marginBottom: '3px' }}>
                    <strong style={{ color: '#e2e8f0' }}>Observed:</strong> {rule.observed_value}
                  </div>
                  <div style={{ color: '#94a3b8' }}>
                    <strong style={{ color: '#e2e8f0' }}>Expected:</strong> {rule.expected_value}
                  </div>
                </div>

                {/* Evidence References */}
                {rule.evidence_refs && rule.evidence_refs.length > 0 && (
                  <div style={{ marginTop: '8px', display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                    <span style={{ fontSize: '10px', color: '#64748b', fontWeight: 600 }}>Evidence:</span>
                    {rule.evidence_refs.map((ref, idx) => (
                      <Link
                        key={idx}
                        to={`/provenance?job=${encodeURIComponent(captureId)}&node=${encodeURIComponent(ref)}`}
                        className="analysis-evidence-tag"
                        title={`Click to trace ${ref} in Evidence Provenance Graph`}
                      >
                        <i className="fa-solid fa-arrow-up-right-from-square" style={{ fontSize: '8px' }} />
                        {ref}
                      </Link>
                    ))}
                  </div>
                )}
              </div>

              {/* Footer contribution & Graph link */}
              <div style={{ marginTop: '10px', paddingTop: '8px', borderTop: '1px solid rgba(255, 255, 255, 0.06)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '11px', color: '#64748b' }}>
                  Contribution: <span style={{
                    fontWeight: 600,
                    color: rule.contribution.includes('Driver') ? '#f87171' : rule.contribution.includes('Factor') ? '#fdba74' : rule.contribution.includes('Passing') ? '#34d399' : '#94a3b8'
                  }}>
                    {rule.contribution}
                  </span>
                </span>

                <Link
                  to={`/provenance?job=${encodeURIComponent(captureId)}&node=${encodeURIComponent(rule.rule_id)}`}
                  style={{
                    fontSize: '11px',
                    color: '#e2e8f0',
                    textDecoration: 'none',
                    fontWeight: 600,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px'
                  }}
                  title={`Trace rule ${rule.rule_id} in Evidence Provenance Graph`}
                >
                  <i className="fa-solid fa-diagram-project" style={{ fontSize: '10px' }} />
                  <span>Trace Node</span>
                </Link>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
