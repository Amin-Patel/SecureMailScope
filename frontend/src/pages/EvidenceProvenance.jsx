import React, { useState, useEffect } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { getAnalyses, getProvenanceGraph, loadDemo } from '../utils/api';
import { ProvenanceGraph } from '../components/ProvenanceGraph';
import './EvidenceProvenance.css';

export function EvidenceProvenance() {
  const [searchParams, setSearchParams] = useSearchParams();
  const captureIdParam = searchParams.get('job');
  // Accept standard query parameters: node, highlight, focus, or evidence
  const targetNodeParam = searchParams.get('node') || searchParams.get('highlight') || searchParams.get('focus') || searchParams.get('evidence');

  const [availableAnalyses, setAvailableAnalyses] = useState([]);
  const [selectedCaptureId, setSelectedCaptureId] = useState(captureIdParam || '');
  const [graphData, setGraphData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [loadingDemo, setLoadingDemo] = useState(false);

  // Fetch analyses list helper
  const fetchAnalysesList = () => {
    return getAnalyses()
      .then(res => {
        const list = res.analyses || [];
        setAvailableAnalyses(list);
        if (!selectedCaptureId && list.length > 0) {
          const firstId = list[0].capture_id;
          setSelectedCaptureId(firstId);
          setSearchParams({ job: firstId });
        }
        return list;
      })
      .catch(err => {
        console.error('Failed to load analyses list:', err);
      });
  };

  // Load list of available analyses on mount
  useEffect(() => {
    fetchAnalysesList();
  }, []);

  // Update selected capture if URL search params change
  useEffect(() => {
    if (captureIdParam && captureIdParam !== selectedCaptureId) {
      setSelectedCaptureId(captureIdParam);
    }
  }, [captureIdParam]);

  // Fetch provenance graph when selected capture changes (with race-condition and stale-data guards)
  useEffect(() => {
    let isCurrent = true;
    if (!selectedCaptureId) {
      setLoading(false);
      setGraphData(null);
      return;
    }

    setLoading(true);
    setError(null);
    setGraphData(null); // Clear previous graph to prevent stale data display

    getProvenanceGraph(selectedCaptureId)
      .then(data => {
        if (!isCurrent) return;
        setGraphData(data);
        setLoading(false);
      })
      .catch(err => {
        if (!isCurrent) return;
        console.error('Failed to load provenance graph:', err);
        setError(err.message || 'Failed to generate provenance graph for this capture.');
        setLoading(false);
      });

    return () => {
      isCurrent = false;
    };
  }, [selectedCaptureId]);

  const handleSelectAnalysis = (e) => {
    const newId = e.target.value;
    setSelectedCaptureId(newId);
    setSearchParams({ job: newId });
  };

  const handleLoadDemo = async (sampleKey) => {
    try {
      setLoadingDemo(true);
      const res = await loadDemo(sampleKey);
      if (res && res.capture_id) {
        await fetchAnalysesList();
        setSelectedCaptureId(res.capture_id);
        setSearchParams({ job: res.capture_id });
      }
    } catch (err) {
      alert('Failed to load demo scenario: ' + err.message);
    } finally {
      setLoadingDemo(false);
    }
  };

  const metrics = graphData?.metrics || {};

  return (
    <main className="provenance-page-container">
      {/* Top Header & Selector */}
      <div className="provenance-header-row">
        <div>
          <div className="provenance-tag">
            <i className="fa-solid fa-diagram-project" />
            <span>Forensic Evidence Provenance Engine</span>
          </div>
          <h1 className="provenance-title">Evidence Provenance Graph</h1>
          <p className="provenance-subtitle">
            Trace the full cryptographic and protocol chain: Captured PCAP Artifact → Session Stream → TLS Handshake & Certificate → Security Rule → Security Finding.
          </p>
        </div>

        {/* Analysis Selector Dropdown */}
        <div className="provenance-controls-box">
          <label className="provenance-select-label" htmlFor="select-pcap-analysis">
            Select PCAP / Analysis
          </label>
          <div className="provenance-select-wrapper">
            <select
              id="select-pcap-analysis"
              className="provenance-select"
              value={selectedCaptureId}
              onChange={handleSelectAnalysis}
              disabled={loading || loadingDemo}
              aria-label="Select PCAP / Analysis"
            >
              {availableAnalyses.length === 0 ? (
                <option value="">No analyses available</option>
              ) : (
                availableAnalyses.map(a => {
                  const shortId = a.capture_id ? a.capture_id.slice(-6) : '';
                  const timeStr = a.timestamp
                    ? new Date(a.timestamp).toLocaleString([], {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })
                    : 'Recent';
                  const fileName = a.filename || a.capture_id;
                  return (
                    <option key={a.capture_id} value={a.capture_id}>
                      {fileName} [#{shortId}] — {timeStr} ({a.findings_count} findings, Risk: {a.risk_score ?? '--'}/100)
                    </option>
                  );
                })
              )}
            </select>
          </div>

          <div style={{ display: 'flex', gap: '8px', marginTop: '6px' }}>
            <Link
              to={`/analysis?job=${selectedCaptureId}`}
              className="provenance-action-link"
              title="View Forensic Results Table"
            >
              <i className="fa-solid fa-table-list" />
              <span>Results Table</span>
            </Link>
            <Link
              to={`/dashboard/${selectedCaptureId}`}
              className="provenance-action-link"
              title="Open Executive Dashboard"
            >
              <i className="fa-solid fa-gauge-high" />
              <span>Dashboard</span>
            </Link>
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      {graphData && (
        <div className="provenance-metrics-grid">
          <div className="provenance-metric-card">
            <div className="metric-icon-box" style={{ background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8' }}>
              <i className="fa-solid fa-cube" />
            </div>
            <div>
              <div className="metric-val">{metrics.evidence_entities ?? '--'}</div>
              <div className="metric-lbl">Evidence Entities (Packets/Streams/Certs)</div>
            </div>
          </div>

          <div className="provenance-metric-card">
            <div className="metric-icon-box" style={{ background: 'rgba(99, 102, 241, 0.15)', color: '#818cf8' }}>
              <i className="fa-solid fa-code-branch" />
            </div>
            <div>
              <div className="metric-val">{metrics.total_edges ?? '--'}</div>
              <div className="metric-lbl">Provenance Relationships</div>
            </div>
          </div>

          <div className="provenance-metric-card">
            <div className="metric-icon-box" style={{ background: 'rgba(239, 68, 68, 0.15)', color: '#f87171' }}>
              <i className="fa-solid fa-link" />
            </div>
            <div>
              <div className="metric-val" style={{ color: '#f87171' }}>{metrics.findings_linked ?? 0}</div>
              <div className="metric-lbl">Findings Backed by Real Evidence</div>
            </div>
          </div>

          <div className="provenance-metric-card">
            <div className="metric-icon-box" style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#34d399' }}>
              <i className="fa-solid fa-shield-check" />
            </div>
            <div>
              <div className="metric-val">{metrics.analysis_operations ?? '--'}</div>
              <div className="metric-lbl">RFC Rules Evaluated</div>
            </div>
          </div>

          <div className="provenance-metric-card">
            <div className="metric-icon-box" style={{ background: 'rgba(234, 179, 8, 0.15)', color: '#facc15' }}>
              <i className="fa-solid fa-circle-question" />
            </div>
            <div>
              <div className="metric-val" style={{ color: '#facc15' }}>{metrics.unknown_or_unverified_records ?? 0}</div>
              <div className="metric-lbl">Documented Unknown / Limits</div>
            </div>
          </div>
        </div>
      )}

      {/* Main Content Area */}
      {loading ? (
        <div className="provenance-loading-card">
          <i className="fa-solid fa-circle-notch fa-spin" style={{ fontSize: '32px', color: '#818cf8' }} />
          <h3>Constructing Evidence Provenance Graph…</h3>
          <p>Extracting network packet entities, TLS handshakes, X.509 certificates, and building deterministic causal relationships.</p>
        </div>
      ) : error ? (
        <div className="provenance-error-card">
          <i className="fa-solid fa-triangle-exclamation" style={{ fontSize: '36px', color: '#f87171', marginBottom: '12px' }} />
          <h2>Provenance Graph Unavailable</h2>
          <p>{error}</p>
          <div style={{ display: 'flex', gap: '12px', marginTop: '16px', flexWrap: 'wrap', justifyContent: 'center' }}>
            <button
              onClick={() => handleLoadDemo('sih_comprehensive')}
              className="provenance-btn-primary"
              disabled={loadingDemo}
            >
              <i className="fa-solid fa-bolt" />
              <span>Load Comprehensive Demo</span>
            </button>
            <Link to="/workspace" className="provenance-btn-secondary">
              <i className="fa-solid fa-upload" />
              <span>Upload New PCAP</span>
            </Link>
          </div>
        </div>
      ) : !selectedCaptureId ? (
        <div className="provenance-empty-card">
          <i className="fa-solid fa-network-wired" style={{ fontSize: '42px', color: '#64748b', marginBottom: '16px' }} />
          <h2>No Analysis Selected</h2>
          <p>Select a completed analysis record from the dropdown above or launch a pre-packaged forensic scenario.</p>
          <div style={{ display: 'flex', gap: '12px', marginTop: '20px', flexWrap: 'wrap', justifyContent: 'center' }}>
            <button
              onClick={() => handleLoadDemo('sih_comprehensive')}
              className="provenance-btn-primary"
              disabled={loadingDemo}
            >
              <i className="fa-solid fa-bolt" />
              <span>Load Multi-Protocol SIH Demo</span>
            </button>
            <button
              onClick={() => handleLoadDemo('vulnerable_smtp')}
              className="provenance-btn-secondary"
              disabled={loadingDemo}
            >
              <i className="fa-solid fa-envelope-open" />
              <span>Load Cleartext SMTP Demo</span>
            </button>
          </div>
        </div>
      ) : (
        <div className="provenance-graph-container">
          <ProvenanceGraph
            graphData={graphData}
            initialFocusId={targetNodeParam}
            height="760px"
            onNodeSelect={(node) => {
              if (node && node.id) {
                setSearchParams({ job: selectedCaptureId, node: node.id }, { replace: true });
              } else {
                setSearchParams({ job: selectedCaptureId }, { replace: true });
              }
            }}
          />
        </div>
      )}
    </main>
  );
}
