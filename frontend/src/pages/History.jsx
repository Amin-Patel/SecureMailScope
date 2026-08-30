import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { getAnalyses } from '../utils/api';

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
      width: 64, height: 64, borderRadius: '50%', flexShrink: 0,
      background: `conic-gradient(${color} 0deg ${deg}deg, rgba(255,255,255,0.06) ${deg}deg)`,
      boxShadow: `0 0 18px ${glow}`,
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      position: 'relative',
    }}>
      {/* Inner dark circle */}
      <div style={{
        position: 'absolute', inset: 6, borderRadius: '50%',
        background: 'rgba(10,10,18,0.9)',
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      }}>
        <span style={{ fontSize: 16, fontWeight: 800, color, lineHeight: 1 }}>{score}</span>
        <span style={{ fontSize: 8, color: 'rgba(255,255,255,0.4)', letterSpacing: '0.04em' }}>/100</span>
      </div>
    </div>
  );
}

function HistoryCard({ entry }) {
  const { color, bg, border, label } = getRiskConfig(entry.score);
  const fileExt = entry.name.split('.').pop().toUpperCase();

  return (
    <div style={{
      background: 'rgba(10,10,18,0.65)',
      backdropFilter: 'blur(16px)',
      WebkitBackdropFilter: 'blur(16px)',
      border: '1px solid rgba(255,255,255,0.1)',
      borderRadius: 16,
      padding: '20px 24px',
      display: 'flex',
      alignItems: 'center',
      gap: 20,
      transition: 'transform 0.2s ease, box-shadow 0.2s ease',
      cursor: 'default',
    }}
      onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = '0 8px 32px rgba(0,0,0,0.5)'; }}
      onMouseLeave={e => { e.currentTarget.style.transform = ''; e.currentTarget.style.boxShadow = ''; }}
    >
      {/* File type icon */}
      <div style={{
        width: 48, height: 48, borderRadius: 12, flexShrink: 0,
        background: 'rgba(99,102,241,0.15)',
        border: '1px solid rgba(99,102,241,0.25)',
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      }}>
        <i className="fa-solid fa-file-lines" style={{ color: '#818cf8', fontSize: 16 }}></i>
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
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
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
          fontSize: 9, fontWeight: 700, color, letterSpacing: '0.1em',
          padding: '2px 8px', borderRadius: 999,
          background: bg, border: `1px solid ${border}`,
        }}>
          {label} RISK
        </span>
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, flexShrink: 0 }}>
        <Link
          to={`/analysis?job=${entry.id}`}
          style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '8px 16px', borderRadius: 10,
            background: 'rgba(99,102,241,0.2)', border: '1px solid rgba(99,102,241,0.35)',
            color: '#a5b4fc', fontSize: 12, fontWeight: 600, textDecoration: 'none',
            transition: 'background 0.2s ease',
            whiteSpace: 'nowrap',
          }}
          onMouseEnter={e => e.currentTarget.style.background = 'rgba(99,102,241,0.35)'}
          onMouseLeave={e => e.currentTarget.style.background = 'rgba(99,102,241,0.2)'}
        >
          <i className="fa-solid fa-magnifying-glass" style={{ fontSize: 10 }}></i>
          Open Workspace
        </Link>
        <Link
          to={`/analysis?job=${entry.id}&tab=report`}
          style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '8px 16px', borderRadius: 10,
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
      </div>
    </div>
  );
}

export function History() {
  const [analyses, setAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');

  const loadData = () => {
    setLoading(true);
    setError(null);
    getAnalyses()
      .then(res => {
        const list = res.analyses || [];
        setAnalyses(list.map(normaliseAnalysis));
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

  return (
    <main style={{ width: '100%', maxWidth: 900, margin: '0 auto', padding: '0 16px', position: 'relative', zIndex: 5 }}>
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

      {/* Search bar */}
      <div style={{ marginBottom: 20, position: 'relative' }}>
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

      {/* List */}
      {!loading && !error && filtered.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {filtered.map(entry => <HistoryCard key={entry.id} entry={entry} />)}
        </div>
      )}
    </main>
  );
}

