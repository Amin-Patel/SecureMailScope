import React, { useEffect, useState } from 'react';
import { getAnalysis } from '../utils/api';
import { Pie, Bar, Line } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, LineElement, PointElement, LineController } from 'chart.js';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, LineElement, PointElement, LineController);

export function DashboardCharts({ jobId }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [analysis, setAnalysis] = useState(null);

  // Load analysis data when a job ID is provided
  useEffect(() => {
    if (!jobId) {
      // No job selected – clear state and stop loading
      setAnalysis(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    getAnalysis(jobId)
      .then((data) => {
        setAnalysis(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error(err);
        setError('Failed to load chart data');
        setLoading(false);
      });
  }, [jobId]);

  if (loading) return <div className="chart-loading" style={{ color: '#fff' }}>Loading charts...</div>;
  if (error) return <div className="chart-error" style={{ color: 'red' }}>{error}</div>;
  if (!analysis) return null;

  // Prepare data for charts
  const protocolCounts = {};
  const encryptionCounts = { Plaintext: 0, Encrypted: 0 };
  const tlsVersionCounts = {};

  analysis.sessions.forEach((s) => {
    // Protocol distribution
    protocolCounts[s.protocol] = (protocolCounts[s.protocol] || 0) + 1;
    // Encryption status
    if (s.tlsVer && s.tlsVer.toLowerCase() === 'plaintext') {
      encryptionCounts.Plaintext += 1;
    } else {
      encryptionCounts.Encrypted += 1;
    }
    // TLS versions
    const tlsKey = s.tlsVer || 'Unknown';
    tlsVersionCounts[tlsKey] = (tlsVersionCounts[tlsKey] || 0) + 1;
  });

  const protocolData = {
    labels: Object.keys(protocolCounts),
    datasets: [{
      label: 'Protocol Distribution',
      data: Object.values(protocolCounts),
      backgroundColor: ['#ef4444', '#10b981', '#3b82f6', '#f59e0b', '#8b5cf6'],
      borderColor: '#fff',
      borderWidth: 1,
    }],
  };

  const encryptionData = {
    labels: Object.keys(encryptionCounts),
    datasets: [{
      label: 'Encryption Status',
      data: Object.values(encryptionCounts),
      backgroundColor: ['#ef4444', '#10b981'],
      borderColor: '#fff',
      borderWidth: 1,
    }],
  };

  const tlsVersionData = {
  labels: Object.keys(tlsVersionCounts),
  datasets: [{
    label: 'TLS Versions',
    data: Object.values(tlsVersionCounts),
    borderColor: '#3b82f6',
    backgroundColor: 'rgba(59,130,246,0.2)',
    fill: false,
    tension: 0.2,
    pointBackgroundColor: '#3b82f6',
    pointBorderColor: '#fff'
  }]
};

  return (
      <div className="dashboard-charts-container" style={{ display: 'grid', gap: '24px', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))' }}>
        <div className="chart-card glass-card" style={{ height: '300px' }}>
          <h3 className="chart-title" style={{ color: '#ffffff', marginBottom: '8px' }}>Protocol Distribution</h3>
          <Bar data={protocolData} options={{
            indexAxis: 'y',
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              x: { beginAtZero: true, ticks: { color: '#fff' } },
              y: { ticks: { color: '#fff' } }
            }
          }} />
        </div>
        <div className="chart-card glass-card" style={{ height: '300px' }}>
          <h3 className="chart-title" style={{ color: '#ffffff', marginBottom: '8px' }}>Encryption Status</h3>
          <Pie data={encryptionData} options={{ maintainAspectRatio: false, plugins: { legend: { display: true, labels: { color: '#fff' } } } }} />
        </div>
        <div className="chart-card glass-card" style={{ height: '300px' }}>
          <h3 className="chart-title" style={{ color: '#ffffff', marginBottom: '8px' }}>TLS Versions</h3>
          <Line data={tlsVersionData} options={{
              maintainAspectRatio: false,
              plugins: { legend: { display: true, labels: { color: '#fff' } } },
              scales: {
                x: { ticks: { color: '#fff' } },
                y: { beginAtZero: true, ticks: { color: '#fff' } }
              }
            }} />
        </div>
    </div>
  );
}
