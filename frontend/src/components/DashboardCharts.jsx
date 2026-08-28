import React, { useEffect, useState, useRef, useCallback } from 'react';
import { getAnalysis } from '../utils/api';
import { Pie, Bar, Line, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  LineElement,
  PointElement,
  Filler,
} from 'chart.js';

ChartJS.register(
  ArcElement, Tooltip, Legend,
  CategoryScale, LinearScale,
  BarElement, LineElement, PointElement, Filler,
);

// ── Palettes ─────────────────────────────────────────────────────────────────
const COLORS = [
  { solid: '#6366f1', glow: 'rgba(99,102,241,0.6)',  fill: 'rgba(99,102,241,0.15)' },
  { solid: '#10b981', glow: 'rgba(16,185,129,0.6)',  fill: 'rgba(16,185,129,0.15)' },
  { solid: '#ef4444', glow: 'rgba(239,68,68,0.6)',   fill: 'rgba(239,68,68,0.15)'  },
  { solid: '#f59e0b', glow: 'rgba(245,158,11,0.6)',  fill: 'rgba(245,158,11,0.15)' },
  { solid: '#a855f7', glow: 'rgba(168,85,247,0.6)',  fill: 'rgba(168,85,247,0.15)' },
  { solid: '#06b6d4', glow: 'rgba(6,182,212,0.6)',   fill: 'rgba(6,182,212,0.15)'  },
];

// ── Shared tooltip config ─────────────────────────────────────────────────────
const TOOLTIP = {
  backgroundColor: 'rgba(8, 8, 18, 0.95)',
  borderColor: 'rgba(99,102,241,0.6)',
  borderWidth: 1,
  titleColor: '#ffffff',
  bodyColor: 'rgba(255,255,255,0.75)',
  padding: 14,
  cornerRadius: 12,
  titleFont: { weight: '700', size: 13, family: 'Inter, system-ui' },
  bodyFont: { size: 12, family: 'Inter, system-ui' },
  displayColors: true,
  boxPadding: 4,
};

// ── ChartCard wrapper ─────────────────────────────────────────────────────────
function ChartCard({ title, icon, accentColor = '#6366f1', children, badge }) {
  return (
    <div
      className="chart-card"
      style={{ '--accent': accentColor }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{
            fontSize: '18px',
            width: '34px', height: '34px',
            borderRadius: '9px',
            background: `rgba(${hexToRgb(accentColor)}, 0.18)`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            border: `1px solid rgba(${hexToRgb(accentColor)}, 0.3)`,
          }}>
            {icon}
          </span>
          <span style={{
            fontSize: '13px', fontWeight: '700',
            color: 'rgba(255,255,255,0.9)',
            textTransform: 'uppercase', letterSpacing: '0.07em',
          }}>
            {title}
          </span>
        </div>
        {badge && (
          <span style={{
            fontSize: '11px', fontWeight: '600',
            color: accentColor,
            background: `rgba(${hexToRgb(accentColor)}, 0.15)`,
            border: `1px solid rgba(${hexToRgb(accentColor)}, 0.3)`,
            borderRadius: '999px', padding: '2px 10px',
          }}>
            {badge}
          </span>
        )}
      </div>
      {children}
    </div>
  );
}

function hexToRgb(hex) {
  const r = parseInt(hex.slice(1,3), 16);
  const g = parseInt(hex.slice(3,5), 16);
  const b = parseInt(hex.slice(5,7), 16);
  return `${r},${g},${b}`;
}

// ── Animated stat number ──────────────────────────────────────────────────────
function AnimatedStat({ value, label, color }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let start = 0;
    const step = Math.ceil(value / 24);
    const timer = setInterval(() => {
      start = Math.min(start + step, value);
      setDisplay(start);
      if (start >= value) clearInterval(timer);
    }, 35);
    return () => clearInterval(timer);
  }, [value]);

  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      padding: '12px 8px',
      background: `rgba(${hexToRgb(color)}, 0.08)`,
      border: `1px solid rgba(${hexToRgb(color)}, 0.2)`,
      borderRadius: '12px',
      flex: 1, minWidth: '70px',
    }}>
      <span style={{
        fontSize: '28px', fontWeight: '800', color,
        fontVariantNumeric: 'tabular-nums',
        textShadow: `0 0 20px rgba(${hexToRgb(color)}, 0.6)`,
        lineHeight: 1,
      }}>
        {display}
      </span>
      <span style={{ fontSize: '10px', color: 'rgba(255,255,255,0.5)', marginTop: '4px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
        {label}
      </span>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export function DashboardCharts({ jobId }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  // Toggle between chart view modes
  const [protocolView, setProtocolView] = useState('bar'); // 'bar' | 'pie'
  const [hoveredSegment, setHoveredSegment] = useState(null);

  useEffect(() => {
    if (!jobId) { setAnalysis(null); setLoading(false); return; }
    setLoading(true);
    getAnalysis(jobId)
      .then(data => { setAnalysis(data); setLoading(false); })
      .catch(err => { console.error(err); setError('Failed to load chart data'); setLoading(false); });
  }, [jobId]);

  if (loading) return (
    <div className="chart-card" style={{ minHeight: 120, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#6366f1', animation: 'pulse 1s ease infinite' }} />
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981', animation: 'pulse 1s ease 0.2s infinite' }} />
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#06b6d4', animation: 'pulse 1s ease 0.4s infinite' }} />
        <span style={{ color: 'rgba(255,255,255,0.4)', fontSize: 13, marginLeft: 8 }}>Loading charts…</span>
      </div>
    </div>
  );

  if (error) return (
    <div className="chart-card" style={{ minHeight: 80, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <span style={{ color: '#ef4444', fontSize: 13 }}>⚠ {error}</span>
    </div>
  );

  if (!analysis) return null;

  // ── Build data ──────────────────────────────────────────────────────────────
  const protocolCounts = {};
  const encryptionCounts = { Plaintext: 0, Encrypted: 0 };
  const tlsVersionCounts = {};

  (analysis.sessions || []).forEach(s => {
    protocolCounts[s.protocol] = (protocolCounts[s.protocol] || 0) + 1;
    if (s.tlsVer && s.tlsVer.toLowerCase() === 'plaintext') {
      encryptionCounts.Plaintext += 1;
    } else {
      encryptionCounts.Encrypted += 1;
    }
    const k = s.tlsVer || 'Unknown';
    tlsVersionCounts[k] = (tlsVersionCounts[k] || 0) + 1;
  });

  const totalSessions = (analysis.sessions || []).length;
  const protocolLabels = Object.keys(protocolCounts);
  const protocolValues = Object.values(protocolCounts);
  const tlsLabels = Object.keys(tlsVersionCounts);
  const tlsValues = Object.values(tlsVersionCounts);

  // ── Protocol — horizontal bar ───────────────────────────────────────────────
  const barData = {
    labels: protocolLabels,
    datasets: [{
      label: 'Sessions',
      data: protocolValues,
      backgroundColor: protocolLabels.map((_, i) => COLORS[i % COLORS.length].solid + 'cc'),
      hoverBackgroundColor: protocolLabels.map((_, i) => COLORS[i % COLORS.length].solid),
      borderColor: 'transparent',
      borderRadius: 8,
      borderSkipped: false,
    }],
  };
  const barOptions = {
    animation: { duration: 800, easing: 'easeOutQuart' },
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: true,
    plugins: {
      tooltip: { ...TOOLTIP },
      legend: { display: false },
    },
    scales: {
      x: {
        beginAtZero: true,
        ticks: { color: 'rgba(255,255,255,0.55)', font: { size: 11 }, stepSize: 1 },
        grid: { color: 'rgba(255,255,255,0.05)', lineWidth: 1 },
        border: { display: false },
      },
      y: {
        ticks: { color: 'rgba(255,255,255,0.85)', font: { size: 12, weight: '600' } },
        grid: { display: false },
        border: { display: false },
      },
    },
  };

  // ── Protocol — pie view ─────────────────────────────────────────────────────
  const pieData = {
    labels: protocolLabels,
    datasets: [{
      data: protocolValues,
      backgroundColor: protocolLabels.map((_, i) => COLORS[i % COLORS.length].solid + 'cc'),
      hoverBackgroundColor: protocolLabels.map((_, i) => COLORS[i % COLORS.length].solid),
      borderColor: 'rgba(10,10,18,0.8)',
      borderWidth: 3,
      hoverBorderWidth: 2,
      hoverOffset: 8,
    }],
  };
  const pieOptions = {
    animation: { duration: 900, easing: 'easeOutBack' },
    responsive: true,
    maintainAspectRatio: true,
    cutout: '55%',
    plugins: {
      tooltip: { ...TOOLTIP },
      legend: {
        display: true,
        position: 'bottom',
        labels: {
          color: 'rgba(255,255,255,0.75)', font: { size: 11 },
          padding: 14, usePointStyle: true, pointStyleWidth: 8,
        },
      },
    },
  };

  // ── Encryption doughnut ─────────────────────────────────────────────────────
  const encPct = totalSessions > 0 ? Math.round((encryptionCounts.Encrypted / totalSessions) * 100) : 0;
  const encData = {
    labels: ['Plaintext ⚠', 'Encrypted ✓'],
    datasets: [{
      data: [encryptionCounts.Plaintext, encryptionCounts.Encrypted],
      backgroundColor: ['rgba(239,68,68,0.85)', 'rgba(16,185,129,0.85)'],
      hoverBackgroundColor: ['#ef4444', '#10b981'],
      borderColor: 'rgba(10,10,18,0.9)',
      borderWidth: 3,
      hoverBorderWidth: 2,
      hoverOffset: 10,
    }],
  };
  const encOptions = {
    animation: { duration: 900, easing: 'easeOutBack' },
    responsive: true,
    maintainAspectRatio: true,
    cutout: '68%',
    plugins: {
      tooltip: { ...TOOLTIP },
      legend: {
        display: true, position: 'bottom',
        labels: {
          color: 'rgba(255,255,255,0.75)', font: { size: 11 },
          padding: 16, usePointStyle: true, pointStyleWidth: 8,
        },
      },
    },
  };

  // ── TLS line with gradient fill ─────────────────────────────────────────────
  const tlsData = {
    labels: tlsLabels,
    datasets: [{
      label: 'Sessions',
      data: tlsValues,
      borderColor: '#06b6d4',
      backgroundColor: ctx => {
        if (!ctx?.chart?.chartArea) return 'rgba(6,182,212,0.15)';
        const { ctx: c, chartArea: { top, bottom } } = ctx.chart;
        const g = c.createLinearGradient(0, top, 0, bottom);
        g.addColorStop(0, 'rgba(6,182,212,0.5)');
        g.addColorStop(1, 'rgba(6,182,212,0.02)');
        return g;
      },
      fill: true,
      tension: 0.45,
      borderWidth: 2.5,
      pointBackgroundColor: '#06b6d4',
      pointBorderColor: '#ffffff',
      pointBorderWidth: 2,
      pointRadius: 5,
      pointHoverRadius: 8,
      pointHoverBackgroundColor: '#ffffff',
      pointHoverBorderColor: '#06b6d4',
      pointHoverBorderWidth: 3,
    }],
  };
  const tlsOptions = {
    animation: { duration: 1000, easing: 'easeOutCubic' },
    responsive: true,
    maintainAspectRatio: true,
    plugins: {
      tooltip: { ...TOOLTIP },
      legend: { display: false },
    },
    scales: {
      x: {
        ticks: { color: 'rgba(255,255,255,0.6)', font: { size: 11 } },
        grid: { color: 'rgba(255,255,255,0.04)' },
        border: { display: false },
      },
      y: {
        beginAtZero: true,
        ticks: { color: 'rgba(255,255,255,0.6)', font: { size: 11 }, stepSize: 1 },
        grid: { color: 'rgba(255,255,255,0.04)' },
        border: { display: false },
      },
    },
  };

  // ── Inline toggle button ────────────────────────────────────────────────────
  const ToggleBtn = ({ active, label, onClick }) => (
    <button
      onClick={onClick}
      style={{
        padding: '3px 10px', borderRadius: '6px', border: 'none', cursor: 'pointer',
        fontSize: '11px', fontWeight: '600',
        background: active ? 'rgba(99,102,241,0.35)' : 'rgba(255,255,255,0.07)',
        color: active ? '#a5b4fc' : 'rgba(255,255,255,0.45)',
        transition: 'all 0.2s ease',
      }}
    >
      {label}
    </button>
  );

  return (
    <>
      {/* ── Row 1: Summary stats ─────────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: '10px', marginBottom: '20px', flexWrap: 'wrap' }}>
        <AnimatedStat value={totalSessions}               label="Total"     color="#6366f1" />
        <AnimatedStat value={encryptionCounts.Encrypted}  label="Encrypted" color="#10b981" />
        <AnimatedStat value={encryptionCounts.Plaintext}  label="Plaintext" color="#ef4444" />
        <AnimatedStat value={tlsLabels.length}            label="TLS Types" color="#06b6d4" />
      </div>

      {/* ── Row 2: Charts grid ───────────────────────────────────────────── */}
      <div className="dashboard-charts-container">

        {/* Protocol Distribution — togglable */}
        <ChartCard
          title="Protocol Distribution"
          icon="📊"
          accentColor="#6366f1"
          badge={`${protocolLabels.length} types`}
        >
          <div style={{ display: 'flex', gap: '6px', marginBottom: '12px' }}>
            <ToggleBtn active={protocolView === 'bar'} label="Bar"  onClick={() => setProtocolView('bar')} />
            <ToggleBtn active={protocolView === 'pie'} label="Ring" onClick={() => setProtocolView('pie')} />
          </div>
          {protocolView === 'bar'
            ? <Bar  data={barData} options={barOptions} />
            : <Doughnut data={pieData} options={pieOptions} />
          }
        </ChartCard>

        {/* Encryption Status — doughnut with center label */}
        <ChartCard
          title="Encryption Status"
          icon="🔐"
          accentColor={encPct >= 80 ? '#10b981' : '#ef4444'}
          badge={`${encPct}% secure`}
        >
          {/* Center % overlay */}
          <div style={{ position: 'relative' }}>
            <Doughnut data={encData} options={encOptions} />
            <div style={{
              position: 'absolute', top: '50%', left: '50%',
              transform: 'translate(-50%, -62%)',
              textAlign: 'center', pointerEvents: 'none',
            }}>
              <div style={{
                fontSize: '26px', fontWeight: '800',
                color: encPct >= 80 ? '#10b981' : '#ef4444',
                textShadow: `0 0 16px ${encPct >= 80 ? 'rgba(16,185,129,0.7)' : 'rgba(239,68,68,0.7)'}`,
                lineHeight: 1,
              }}>{encPct}%</div>
              <div style={{ fontSize: '9px', color: 'rgba(255,255,255,0.4)', letterSpacing: '0.06em' }}>SECURE</div>
            </div>
          </div>
        </ChartCard>

        {/* TLS Version Breakdown — line */}
        <ChartCard
          title="TLS Version Breakdown"
          icon="🔒"
          accentColor="#06b6d4"
          badge={`${tlsLabels.length} versions`}
        >
          <Line data={tlsData} options={tlsOptions} />
        </ChartCard>

      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.4; transform: scale(0.75); }
        }
        .chart-card {
          transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .chart-card:hover {
          transform: translateY(-3px);
          box-shadow: 0 8px 36px rgba(0,0,0,0.55), 0 0 0 1px rgba(99,102,241,0.25);
        }
      `}</style>
    </>
  );
}
