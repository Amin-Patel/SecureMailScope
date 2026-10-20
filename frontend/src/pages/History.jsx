import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { getAnalyses, deleteAnalysis, deleteAnalysesBatch } from '../utils/api';

/** Normalise backend analysis item into the shape HistoryCard expects */
function normaliseAnalysis(item) {
  const ts = item.timestamp ? new Date(item.timestamp) : null;
  const dateStr = ts && !isNaN(ts.getTime())
    ? ts.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
    : '--';
  const timeStr = ts && !isNaN(ts.getTime())
    ? ts.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
    : '--';
  const score = item.risk_score ?? 0;
  return {
    id: item.capture_id || 'unknown',
    name: item.filename || 'Unknown File',
    date: dateStr,
    time: timeStr,
    findings: item.findings_count ?? 0,
    sessions: item.session_count ?? 0,
    score,
    riskLevel: item.risk_level || 'UNKNOWN',
  };
}

function getRiskConfig(score) {
  if (score >= 75) return { color: '#ef4444', glow: 'rgba(239,68,68,0.35)', bg: 'rgba(239,68,68,0.1)', border: 'rgba(239,68,68,0.3)', label: 'HIGH' };
  if (score >= 40) return { color: '#f59e0b', glow: 'rgba(245,158,11,0.35)', bg: 'rgba(245,158,11,0.1)', border: 'rgba(245,158,11,0.3)', label: 'MED' };
  return { color: '#10b981', glow: 'rgba(16,185,129,0.35)', bg: 'rgba(16,185,129,0.1)', border: 'rgba(16,185,129,0.3)', label: 'LOW' };
}

function ScoreRing({ score }) {
  const { color, glow } = getRiskConfig(score);
  const deg = Math.round((score / 100) * 360);
  return (
    <div style={{
      width: 58, height: 58, borderRadius: '50%', flexShrink: 0,
      background: `conic-gradient(${color} 0deg ${deg}deg, rgba(255,255,255,0.06) ${deg}deg)`,
      boxShadow: `0 0 16px ${glow}`,
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      position: 'relative',
    }}>
      {/* Inner dark circle */}
      <div style={{
        position: 'absolute', inset: 5, borderRadius: '50%',
        background: 'rgba(10,10,18,0.9)',
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      }}>
        <span style={{ fontSize: 15, fontWeight: 800, color, lineHeight: 1 }}>{score}</span>
        <span style={{ fontSize: 7.5, color: 'rgba(255,255,255,0.4)', letterSpacing: '0.04em' }}>/100</span>
      </div>
    </div>
  );
}

function HistoryCard({ entry, isSelected, onToggleSelect, onDeleteSingle }) {
  const { color, bg, border, label } = getRiskConfig(entry.score);
  const fileExt = entry.name.split('.').pop().toUpperCase();

  return (
    <div
      style={{
        background: isSelected ? 'rgba(99,102,241,0.12)' : 'rgba(10,10,18,0.65)',
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)',
        border: isSelected ? '1px solid rgba(99,102,241,0.45)' : '1px solid rgba(255,255,255,0.1)',
        borderRadius: 16,
        padding: '18px 22px',
        display: 'flex',
        alignItems: 'center',
        gap: 16,
        transition: 'transform 0.2s ease, box-shadow 0.2s ease, background 0.2s ease, border-color 0.2s ease',
        cursor: 'default',
        boxShadow: isSelected ? '0 0 20px rgba(99,102,241,0.15)' : 'none',
      }}
      onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = '0 8px 32px rgba(0,0,0,0.5)'; }}
      onMouseLeave={e => { e.currentTarget.style.transform = ''; e.currentTarget.style.boxShadow = isSelected ? '0 0 20px rgba(99,102,241,0.15)' : ''; }}
    >
      {/* Checkbox for selective deletion */}
      <div
        onClick={() => onToggleSelect(entry.id)}
        style={{
          width: 22, height: 22, borderRadius: 6, flexShrink: 0,
          border: isSelected ? '2px solid #818cf8' : '2px solid rgba(255,255,255,0.25)',
          backgroundColor: isSelected ? '#6366f1' : 'rgba(255,255,255,0.04)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          cursor: 'pointer', transition: 'all 0.2s ease',
        }}
        title="Select for deletion"
      >
        {isSelected && <i className="fa-solid fa-check" style={{ color: '#ffffff', fontSize: 12 }}></i>}
      </div>

      {/* File type icon */}
      <div style={{
        width: 44, height: 44, borderRadius: 12, flexShrink: 0,
        background: 'rgba(99,102,241,0.15)',
        border: '1px solid rgba(99,102,241,0.25)',
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      }}>
        <i className="fa-solid fa-file-lines" style={{ color: '#818cf8', fontSize: 15 }}></i>
        <span style={{ fontSize: 7, color: '#818cf8', fontWeight: 700, marginTop: 2, letterSpacing: '0.04em' }}>{fileExt}</span>
      </div>

      {/* File info */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{
          fontSize: 14, fontWeight: 600, color: '#fff',
          whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
          marginBottom: 6,
        }}>
          {entry.name}
        </div>
        <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.45)', display: 'flex', alignItems: 'center', gap: 5 }}>
            <i className="fa-solid fa-hashtag" style={{ opacity: 0.6, fontSize: 9 }}></i>
            Job #{entry.id}
          </span>
          <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.45)', display: 'flex', alignItems: 'center', gap: 5 }}>
            <i className="fa-solid fa-calendar" style={{ opacity: 0.6, fontSize: 9 }}></i>
            {entry.date} · {entry.time}
          </span>
          <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.45)', display: 'flex', alignItems: 'center', gap: 5 }}>
            <i className="fa-solid fa-network-wired" style={{ opacity: 0.6, fontSize: 9 }}></i>
            {entry.sessions} session{entry.sessions !== 1 ? 's' : ''}
          </span>
          <span style={{
            fontSize: 11, fontWeight: 600,
            color: entry.findings > 0 ? '#f87171' : '#34d399',
            display: 'flex', alignItems: 'center', gap: 5,
          }}>
            <i className={`fa-solid ${entry.findings > 0 ? 'fa-triangle-exclamation' : 'fa-circle-check'}`} style={{ fontSize: 9 }}></i>
            {entry.findings} finding{entry.findings !== 1 ? 's' : ''}
          </span>
        </div>
      </div>

      {/* Risk badge */}
      <div style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, flexShrink: 0,
      }}>
        <ScoreRing score={entry.score} />
        <span style={{
          fontSize: 8.5, fontWeight: 700, color, letterSpacing: '0.08em',
          padding: '2px 7px', borderRadius: 999,
          background: bg, border: `1px solid ${border}`,
        }}>
          {label} RISK
        </span>
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
        <Link
          to={`/analysis?job=${entry.id}`}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '8px 14px', borderRadius: 10,
            background: 'rgba(99,102,241,0.2)', border: '1px solid rgba(99,102,241,0.35)',
            color: '#a5b4fc', fontSize: 12, fontWeight: 600, textDecoration: 'none',
            transition: 'background 0.2s ease',
            whiteSpace: 'nowrap',
          }}
          onMouseEnter={e => e.currentTarget.style.background = 'rgba(99,102,241,0.35)'}
          onMouseLeave={e => e.currentTarget.style.background = 'rgba(99,102,241,0.2)'}
        >
          <i className="fa-solid fa-magnifying-glass" style={{ fontSize: 10 }}></i>
          Open
        </Link>
        <Link
          to={`/analysis?job=${entry.id}&tab=report`}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '8px 14px', borderRadius: 10,
            background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)',
            color: 'rgba(255,255,255,0.65)', fontSize: 12, fontWeight: 600, textDecoration: 'none',
            transition: 'background 0.2s ease',
            whiteSpace: 'nowrap',
          }}
          onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.1)'}
          onMouseLeave={e => e.currentTarget.style.background = 'rgba(255,255,255,0.05)'}
        >
          <i className="fa-solid fa-file-export" style={{ fontSize: 10 }}></i>
          Report
        </Link>
        {/* Single Item Delete Trash Button */}
        <button
          onClick={() => onDeleteSingle(entry)}
          title="Delete this analysis"
          style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            width: 34, height: 34, borderRadius: 10,
            background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)',
            color: '#f87171', fontSize: 12, cursor: 'pointer',
            transition: 'all 0.2s ease',
          }}
          onMouseEnter={e => { e.currentTarget.style.background = 'rgba(239,68,68,0.25)'; e.currentTarget.style.transform = 'scale(1.05)'; }}
          onMouseLeave={e => { e.currentTarget.style.background = 'rgba(239,68,68,0.1)'; e.currentTarget.style.transform = 'scale(1)'; }}
        >
          <i className="fa-solid fa-trash-can"></i>
        </button>
      </div>
    </div>
  );
}

export function History() {
  const [analyses, setAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');

  // Selective deletion state
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [deleteModal, setDeleteModal] = useState({ open: false, targets: [] });
  const [deleting, setDeleting] = useState(false);
  const [notification, setNotification] = useState(null);

  const loadData = () => {
    setLoading(true);
    setError(null);
    getAnalyses()
      .then(res => {
        const list = res.analyses || [];
        setAnalyses(list.map(normaliseAnalysis));
        setSelectedIds(new Set());
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setError('Unable to load analysis history. Ensure backend server is running.');
        setLoading(false);
      });
  };

  useEffect(() => {
    loadData();
  }, []);

  const filtered = analyses.filter(e =>
    (e.name || '').toLowerCase().includes(search.toLowerCase()) ||
    (e.id || '').toLowerCase().includes(search.toLowerCase())
  );

  // Selection handlers
  const handleToggleSelect = (id) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const handleToggleSelectAll = () => {
    if (selectedIds.size === filtered.length && filtered.length > 0) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filtered.map(item => item.id)));
    }
  };

  // Open deletion modal for single entry
  const handlePromptDeleteSingle = (entry) => {
    setDeleteModal({
      open: true,
      targets: [entry]
    });
  };

  // Open deletion modal for batch selected entries
  const handlePromptDeleteBatch = () => {
    const targets = analyses.filter(a => selectedIds.has(a.id));
    if (targets.length === 0) return;
    setDeleteModal({
      open: true,
      targets
    });
  };

  // Perform backend deletion upon user confirmation in modal
  const handleConfirmDelete = async () => {
    if (deleteModal.targets.length === 0) return;
    setDeleting(true);
    const targetIds = deleteModal.targets.map(t => t.id);

    try {
      if (targetIds.length === 1) {
        await deleteAnalysis(targetIds[0]);
      } else {
        await deleteAnalysesBatch(targetIds);
      }

      // Update local state by filtering out deleted IDs
      setAnalyses(prev => prev.filter(item => !targetIds.includes(item.id)));
      setSelectedIds(prev => {
        const next = new Set(prev);
        targetIds.forEach(id => next.delete(id));
        return next;
      });

      setDeleteModal({ open: false, targets: [] });
      setNotification(`Deleted ${targetIds.length} analysis record${targetIds.length !== 1 ? 's' : ''}.`);
      setTimeout(() => setNotification(null), 4000);
    } catch (err) {
      console.error(err);
      alert(err.message || 'Failed to delete analysis record(s).');
    } finally {
      setDeleting(false);
    }
  };

  const isAllSelected = filtered.length > 0 && selectedIds.size === filtered.length;

  return (
    <main style={{ width: '100%', maxWidth: 940, margin: '0 auto', padding: '0 16px', position: 'relative', zIndex: 5 }}>
      {/* Toast Notification */}
      {notification && (
        <div style={{
          position: 'fixed',
          bottom: 24,
          right: 24,
          backgroundColor: '#10b981',
          color: '#ffffff',
          padding: '12px 20px',
          borderRadius: 12,
          fontWeight: 600,
          fontSize: 13,
          boxShadow: '0 8px 24px rgba(16,185,129,0.3)',
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          zIndex: 99999,
        }}>
          <i className="fa-solid fa-circle-check"></i>
          <span>{notification}</span>
        </div>
      )}

      {/* Title bar */}
      <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h2 style={{
            background: 'linear-gradient(135deg, #ffffff 0%, #a5b4fc 100%)',
            WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
            backgroundClip: 'text',
            fontSize: 'clamp(22px, 3vw, 32px)', fontWeight: 800, letterSpacing: '-0.03em',
            marginBottom: 6,
          }}>
            Analysis History
          </h2>
          <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.45)' }}>
            {loading ? 'Fetching historical captures…' : `${analyses.length} capture${analyses.length !== 1 ? 's' : ''} analysed`}
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {/* Delete Selected Batch Button */}
          {selectedIds.size > 0 && (
            <button
              onClick={handlePromptDeleteBatch}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 8,
                padding: '9px 18px', borderRadius: 10,
                background: 'rgba(239,68,68,0.2)', border: '1px solid rgba(239,68,68,0.4)',
                color: '#f87171', fontSize: 13, fontWeight: 700, cursor: 'pointer',
                boxShadow: '0 0 16px rgba(239,68,68,0.25)',
                transition: 'all 0.2s ease',
              }}
            >
              <i className="fa-solid fa-trash-can" style={{ fontSize: 12 }} />
              Delete Selected ({selectedIds.size})
            </button>
          )}

          <Link
            to="/workspace"
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 8,
              padding: '9px 18px', borderRadius: 10,
              background: '#ffffff', color: '#000000',
              fontSize: 13, fontWeight: 700, textDecoration: 'none',
              boxShadow: '0 0 16px rgba(255,255,255,0.2)',
            }}
          >
            <i className="fa-solid fa-plus" style={{ fontSize: 11 }} />
            New Analysis
          </Link>
        </div>
      </div>

      {/* Controls & Search Toolbar */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap', alignItems: 'center' }}>
        {/* Master Select All Toggle */}
        {!loading && filtered.length > 0 && (
          <button
            onClick={handleToggleSelectAll}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 8,
              padding: '11px 16px', borderRadius: 12,
              background: isAllSelected ? 'rgba(99,102,241,0.2)' : 'rgba(10,10,18,0.65)',
              backdropFilter: 'blur(12px)',
              border: isAllSelected ? '1px solid rgba(99,102,241,0.4)' : '1px solid rgba(255,255,255,0.1)',
              color: isAllSelected ? '#a5b4fc' : 'rgba(255,255,255,0.7)',
              fontSize: 13, fontWeight: 600, cursor: 'pointer',
              transition: 'all 0.2s ease',
            }}
          >
            <div style={{
              width: 16, height: 16, borderRadius: 4,
              border: isAllSelected ? '2px solid #818cf8' : '2px solid rgba(255,255,255,0.3)',
              backgroundColor: isAllSelected ? '#6366f1' : 'transparent',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              {isAllSelected && <i className="fa-solid fa-check" style={{ color: '#fff', fontSize: 10 }}></i>}
            </div>
            <span>{isAllSelected ? 'Deselect All' : 'Select All'}</span>
          </button>
        )}

        {/* Search input */}
        <div style={{ flex: 1, minWidth: 240, position: 'relative' }}>
          <i className="fa-solid fa-magnifying-glass" style={{
            position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)',
            color: 'rgba(255,255,255,0.35)', fontSize: 13, pointerEvents: 'none',
          }}></i>
          <input
            type="text"
            placeholder="Search by filename or Job ID…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{
              width: '100%', padding: '11px 16px 11px 40px', borderRadius: 12,
              background: 'rgba(10,10,18,0.65)', backdropFilter: 'blur(12px)',
              border: '1px solid rgba(255,255,255,0.1)', color: '#fff',
              fontSize: 13, outline: 'none', boxSizing: 'border-box',
            }}
          />
        </div>
      </div>

      {/* Loading state */}
      {loading && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {[1, 2, 3].map(i => (
            <div key={i} className="glass-card" style={{ padding: '20px 24px', display: 'flex', gap: 16, alignItems: 'center' }}>
              <div className="skeleton" style={{ width: 48, height: 48, borderRadius: 12 }} />
              <div style={{ flex: 1 }}>
                <div className="skeleton" style={{ height: 16, width: '40%', marginBottom: 8 }} />
                <div className="skeleton" style={{ height: 12, width: '70%' }} />
              </div>
              <div className="skeleton" style={{ width: 64, height: 64, borderRadius: '50%' }} />
            </div>
          ))}
        </div>
      )}

      {/* Error state */}
      {!loading && error && (
        <div className="glass-card" style={{ textAlign: 'center', padding: '40px 20px', color: '#ef4444' }}>
          <i className="fa-solid fa-triangle-exclamation" style={{ fontSize: 32, marginBottom: 12, display: 'block' }}></i>
          <p style={{ fontSize: 14, marginBottom: 16 }}>{error}</p>
          <button
            onClick={loadData}
            style={{
              padding: '8px 18px', borderRadius: 8,
              background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.3)',
              color: '#f87171', fontWeight: 600, fontSize: 13, cursor: 'pointer',
            }}
          >
            Retry Connection
          </button>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && filtered.length === 0 && (
        <div className="glass-card" style={{
          textAlign: 'center', padding: '60px 20px', color: 'rgba(255,255,255,0.4)',
        }}>
          <i className="fa-solid fa-box-open" style={{ fontSize: 36, marginBottom: 16, display: 'block', color: 'rgba(255,255,255,0.2)' }}></i>
          <h3 style={{ fontSize: 16, fontWeight: 600, color: '#ffffff', marginBottom: 6 }}>
            {search ? 'No matching analyses found' : 'No analyses yet'}
          </h3>
          <p style={{ fontSize: 13, maxWidth: 360, margin: '0 auto 20px', lineHeight: 1.5 }}>
            {search
              ? `No results match "${search}". Try checking for typos or clear your search.`
              : 'Upload a network packet capture file to start evaluating email security risks.'}
          </p>
          {!search && (
            <Link
              to="/workspace"
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 8,
                padding: '10px 22px', borderRadius: 999,
                background: '#ffffff', color: '#000000',
                fontWeight: 700, fontSize: 13, textDecoration: 'none',
              }}
            >
              <i className="fa-solid fa-upload" style={{ fontSize: 11 }} />
              Upload PCAP Now
            </Link>
          )}
        </div>
      )}

      {/* Card List */}
      {!loading && !error && filtered.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {filtered.map(entry => (
            <HistoryCard
              key={entry.id}
              entry={entry}
              isSelected={selectedIds.has(entry.id)}
              onToggleSelect={handleToggleSelect}
              onDeleteSingle={handlePromptDeleteSingle}
            />
          ))}
        </div>
      )}

      {/* Confirmation Modal */}
      {deleteModal.open && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 9999,
          backgroundColor: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(8px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          padding: 16,
        }}>
          <div style={{
            width: '100%', maxWidth: 460,
            backgroundColor: '#0f0f18', border: '1px solid rgba(239,68,68,0.3)',
            borderRadius: 20, padding: 28,
            boxShadow: '0 20px 50px rgba(0,0,0,0.8), 0 0 30px rgba(239,68,68,0.15)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 16 }}>
              <div style={{
                width: 44, height: 44, borderRadius: 12,
                backgroundColor: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.3)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: '#f87171', fontSize: 18, flexShrink: 0,
              }}>
                <i className="fa-solid fa-triangle-exclamation"></i>
              </div>
              <div>
                <h3 style={{ fontSize: 18, fontWeight: 700, color: '#ffffff', marginBottom: 2 }}>
                  Delete {deleteModal.targets.length} Analysis Record{deleteModal.targets.length !== 1 ? 's' : ''}?
                </h3>
                <p style={{ fontSize: 12, color: 'rgba(255,255,255,0.5)' }}>
                  This action cannot be undone.
                </p>
              </div>
            </div>

            <div style={{
              backgroundColor: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)',
              borderRadius: 12, padding: 12, maxHeight: 160, overflowY: 'auto',
              marginBottom: 24, display: 'flex', flexDirection: 'column', gap: 8,
            }}>
              {deleteModal.targets.map(item => (
                <div key={item.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12.5, color: '#fff' }}>
                  <span style={{ fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '70%' }}>
                    {item.name}
                  </span>
                  <span style={{ color: 'rgba(255,255,255,0.4)', fontFamily: 'monospace', fontSize: 11 }}>
                    #{item.id}
                  </span>
                </div>
              ))}
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
              <button
                onClick={() => setDeleteModal({ open: false, targets: [] })}
                disabled={deleting}
                style={{
                  padding: '10px 18px', borderRadius: 10,
                  backgroundColor: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)',
                  color: 'rgba(255,255,255,0.7)', fontSize: 13, fontWeight: 600, cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmDelete}
                disabled={deleting}
                style={{
                  padding: '10px 20px', borderRadius: 10,
                  backgroundColor: '#ef4444', border: 'none',
                  color: '#ffffff', fontSize: 13, fontWeight: 700, cursor: 'pointer',
                  boxShadow: '0 0 20px rgba(239,68,68,0.4)',
                  display: 'flex', alignItems: 'center', gap: 8,
                }}
              >
                {deleting ? (
                  <>
                    <i className="fa-solid fa-circle-notch fa-spin"></i>
                    <span>Deleting…</span>
                  </>
                ) : (
                  <>
                    <i className="fa-solid fa-trash-can"></i>
                    <span>Confirm Delete</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

