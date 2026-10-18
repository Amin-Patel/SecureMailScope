import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import {
  ArtifactNode,
  SessionNode,
  HandshakeNode,
  CertificateNode,
  OperationNode,
  BaselineNode,
  FindingNode,
} from './ProvenanceCustomNodes';
import { ProvenanceDetailsDrawer } from './ProvenanceDetailsDrawer';

const NODE_TYPES = {
  source_artifact: ArtifactNode,
  session: SessionNode,
  handshake: HandshakeNode,
  certificate: CertificateNode,
  analysis_operation: OperationNode,
  baseline: BaselineNode,
  finding: FindingNode,
};

// Layer definition for organized hierarchical layout
const LAYER_CONFIG = {
  source_artifact: 0,
  session: 1,
  handshake: 2,
  certificate: 2,
  baseline: 3,
  analysis_operation: 3,
  finding: 4,
};

const X_SPACING = 340;
const Y_SPACING = 130;

import { resolveGraphNode } from '../utils/resolveGraphNode';
export { resolveGraphNode };

export function ProvenanceGraph({
  graphData,
  initialFocusId = null,
  height = '720px',
  onNodeSelect = null,
}) {
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [unresolvedTarget, setUnresolvedTarget] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [drawerOpen, setDrawerOpen] = useState(true);
  const reactFlowInstanceRef = React.useRef(null);

  // Compute hierarchical positions for nodes
  const initialNodes = useMemo(() => {
    if (!graphData || !graphData.nodes) return [];

    const layerCounters = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 };
    return graphData.nodes.map(n => {
      const layer = LAYER_CONFIG[n.type] ?? 2;
      const count = layerCounters[layer]++;
      const x = 50 + layer * X_SPACING;
      const y = 60 + count * Y_SPACING;

      return {
        id: n.id,
        type: n.type,
        position: { x, y },
        data: {
          ...n,
          label: n.label,
          metadata: n.metadata,
          assessment: n.assessment,
          source_ref: n.source_ref,
          isHighlighted: false,
          isDimmed: false,
        },
      };
    });
  }, [graphData]);

  // Compute formatted edges
  const initialEdges = useMemo(() => {
    if (!graphData || !graphData.edges) return [];

    return graphData.edges.map(e => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label,
      type: 'default',
      animated: false,
      style: {
        stroke: 'rgba(148, 163, 184, 0.35)',
        strokeWidth: 1.5,
      },
      labelStyle: {
        fill: '#94a3b8',
        fontSize: 9,
        fontWeight: 600,
      },
      labelBgStyle: {
        fill: '#0f172a',
        fillOpacity: 0.8,
      },
      labelBgPadding: [4, 2],
      labelBgBorderRadius: 4,
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: 'rgba(148, 163, 184, 0.45)',
        width: 14,
        height: 14,
      },
    }));
  }, [graphData]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Sync state if graphData changes
  useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
  }, [initialNodes, initialEdges, setNodes, setEdges]);

  // Trace upstream: all reachable ancestors
  const computeUpstreamIds = useCallback((startId) => {
    const upstream = new Set([startId]);
    const queue = [startId];
    const incomingMap = {};
    (graphData?.edges || []).forEach(e => {
      if (!incomingMap[e.target]) incomingMap[e.target] = [];
      incomingMap[e.target].push(e.source);
    });

    while (queue.length > 0) {
      const curr = queue.shift();
      const parents = incomingMap[curr] || [];
      for (const p of parents) {
        if (!upstream.has(p)) {
          upstream.add(p);
          queue.push(p);
        }
      }
    }
    return upstream;
  }, [graphData]);

  // Trace downstream: all reachable descendants
  const computeDownstreamIds = useCallback((startId) => {
    const downstream = new Set([startId]);
    const queue = [startId];
    const outgoingMap = {};
    (graphData?.edges || []).forEach(e => {
      if (!outgoingMap[e.source]) outgoingMap[e.source] = [];
      outgoingMap[e.source].push(e.target);
    });

    while (queue.length > 0) {
      const curr = queue.shift();
      const children = outgoingMap[curr] || [];
      for (const c of children) {
        if (!downstream.has(c)) {
          downstream.add(c);
          queue.push(c);
        }
      }
    }
    return downstream;
  }, [graphData]);

  // Handle node selection & highlighting
  const handleSelectNode = useCallback((nodeId, mode = 'bidirectional') => {
    if (!nodeId) {
      setSelectedNodeId(null);
      setNodes(prev => prev.map(n => ({
        ...n,
        selected: false,
        data: { ...n.data, isHighlighted: false, isDimmed: false }
      })));
      setEdges(prev => prev.map(e => ({
        ...e,
        animated: false,
        style: { stroke: 'rgba(148, 163, 184, 0.35)', strokeWidth: 1.5 },
        markerEnd: { ...e.markerEnd, color: 'rgba(148, 163, 184, 0.45)' }
      })));
      return;
    }

    setSelectedNodeId(nodeId);
    setDrawerOpen(true);

    let activeNodeIds = new Set();
    if (mode === 'upstream') {
      activeNodeIds = computeUpstreamIds(nodeId);
    } else if (mode === 'downstream') {
      activeNodeIds = computeDownstreamIds(nodeId);
    } else {
      const up = computeUpstreamIds(nodeId);
      const down = computeDownstreamIds(nodeId);
      activeNodeIds = new Set([...up, ...down]);
    }

    // Update nodes styling
    setNodes(prev => prev.map(n => {
      const isSelf = n.id === nodeId;
      const isInPath = activeNodeIds.has(n.id);
      return {
        ...n,
        selected: isSelf,
        data: {
          ...n.data,
          isHighlighted: isInPath && !isSelf,
          isDimmed: !isInPath,
        },
      };
    }));

    // Update edges styling
    setEdges(prev => prev.map(e => {
      const isPathEdge = activeNodeIds.has(e.source) && activeNodeIds.has(e.target);
      return {
        ...e,
        animated: isPathEdge,
        style: isPathEdge
          ? { stroke: '#38bdf8', strokeWidth: 2.5 }
          : { stroke: 'rgba(148, 163, 184, 0.1)', strokeWidth: 1 },
        markerEnd: {
          ...e.markerEnd,
          color: isPathEdge ? '#38bdf8' : 'rgba(148, 163, 184, 0.15)',
        },
      };
    }));

    if (onNodeSelect) {
      const nObj = (graphData?.nodes || []).find(n => n.id === nodeId);
      onNodeSelect(nObj || null);
    }
  }, [computeUpstreamIds, computeDownstreamIds, graphData, onNodeSelect, setNodes, setEdges]);

  // Viewport centering helper using ReactFlow fitView
  const centerOnNode = useCallback((nodeId) => {
    if (!nodeId || !reactFlowInstanceRef.current) return;
    try {
      reactFlowInstanceRef.current.fitView({
        nodes: [{ id: nodeId }],
        duration: 500,
        padding: 0.5,
        maxZoom: 1.2,
      });
    } catch (e) {
      console.debug('fitView error:', e);
    }
  }, []);

  // Initial focus handler (resolves canonical target, centers viewport, or honestly reports unresolvable)
  useEffect(() => {
    if (!graphData?.nodes || graphData.nodes.length === 0) {
      setUnresolvedTarget(null);
      return;
    }

    if (initialFocusId) {
      const matched = resolveGraphNode(initialFocusId, graphData.nodes);
      if (matched) {
        setUnresolvedTarget(null);
        handleSelectNode(matched.id);
        setTimeout(() => {
          centerOnNode(matched.id);
        }, 100);
      } else {
        // Honest missing evidence handling: Do NOT silently select an arbitrary fallback node
        setUnresolvedTarget(initialFocusId);
        handleSelectNode(null);
      }
    } else {
      setUnresolvedTarget(null);
    }
  }, [initialFocusId, graphData, handleSelectNode, centerOnNode]);

  // Filter application
  useEffect(() => {
    if (!searchQuery && typeFilter === 'all' && severityFilter === 'all') {
      // No filter active, ensure nodes are visible unless dimmed by selection
      if (!selectedNodeId) {
        setNodes(prev => prev.map(n => ({
          ...n,
          data: { ...n.data, isDimmed: false }
        })));
      }
      return;
    }

    const q = searchQuery.toLowerCase();
    setNodes(prev => prev.map(n => {
      const meta = n.data?.metadata || {};
      const matchesSearch = !q
        || (n.data?.label || '').toLowerCase().includes(q)
        || (meta.filename || '').toLowerCase().includes(q)
        || (meta.title || '').toLowerCase().includes(q)
        || (meta.id || '').toLowerCase().includes(q)
        || (meta.src || '').toLowerCase().includes(q)
        || (meta.dst || '').toLowerCase().includes(q)
        || (meta.subject || '').toLowerCase().includes(q);

      const matchesType = typeFilter === 'all' || n.type === typeFilter;
      const sev = (meta.severity || n.data?.assessment?.status || '').toLowerCase();
      const matchesSev = severityFilter === 'all' || sev === severityFilter.toLowerCase();

      const isVisible = matchesSearch && matchesType && matchesSev;
      return {
        ...n,
        data: {
          ...n.data,
          isDimmed: !isVisible,
        },
      };
    }));
  }, [searchQuery, typeFilter, severityFilter, selectedNodeId, setNodes]);

  // Reset view & filters
  const handleResetFilters = () => {
    setSearchQuery('');
    setTypeFilter('all');
    setSeverityFilter('all');
    handleSelectNode(null);
  };

  const selectedNode = useMemo(() => {
    return nodes.find(n => n.id === selectedNodeId) || null;
  }, [nodes, selectedNodeId]);

  return (
    <div style={{ position: 'relative', width: '100%', height, display: 'flex', flexDirection: 'column', background: '#0a0d17', borderRadius: '14px', overflow: 'hidden', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
      {/* Top Filter Bar */}
      <div
        style={{
          padding: '12px 18px',
          background: 'rgba(15, 23, 42, 0.85)',
          backdropFilter: 'blur(16px)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          display: 'flex',
          gap: '12px',
          alignItems: 'center',
          flexWrap: 'wrap',
          zIndex: 10,
        }}
      >
        {/* Search */}
        <div style={{ position: 'relative', flex: '1 1 200px', maxWidth: '300px' }}>
          <i className="fa-solid fa-magnifying-glass" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: '#64748b', fontSize: '12px' }} />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search evidence, IPs, findings…"
            style={{
              width: '100%',
              padding: '8px 12px 8px 34px',
              borderRadius: '8px',
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              color: '#ffffff',
              fontSize: '12px',
              outline: 'none',
            }}
          />
        </div>

        {/* Type Filter */}
        <select
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value)}
          style={{
            padding: '8px 12px',
            borderRadius: '8px',
            background: 'rgba(255, 255, 255, 0.05)',
            border: '1px solid rgba(255, 255, 255, 0.12)',
            color: '#cbd5e1',
            fontSize: '12px',
            cursor: 'pointer',
            outline: 'none',
          }}
        >
          <option value="all">All Entity Types</option>
          <option value="source_artifact">Source Artifacts</option>
          <option value="session">Network Sessions</option>
          <option value="handshake">TLS Handshakes</option>
          <option value="certificate">X.509 Certificates</option>
          <option value="analysis_operation">Analysis Rules</option>
          <option value="finding">Security Findings</option>
        </select>

        {/* Severity Filter */}
        <select
          value={severityFilter}
          onChange={e => setSeverityFilter(e.target.value)}
          style={{
            padding: '8px 12px',
            borderRadius: '8px',
            background: 'rgba(255, 255, 255, 0.05)',
            border: '1px solid rgba(255, 255, 255, 0.12)',
            color: '#cbd5e1',
            fontSize: '12px',
            cursor: 'pointer',
            outline: 'none',
          }}
        >
          <option value="all">All Assessment Statuses</option>
          <option value="critical">Critical Findings</option>
          <option value="high">High Findings</option>
          <option value="medium">Medium Findings</option>
          <option value="compliant">Compliant / Valid</option>
          <option value="unsecured">Unsecured</option>
          <option value="deprecated">Deprecated Protocols</option>
        </select>

        {/* Reset Filter Button */}
        <button
          onClick={handleResetFilters}
          style={{
            padding: '8px 14px',
            borderRadius: '8px',
            background: 'rgba(255, 255, 255, 0.05)',
            border: '1px solid rgba(255, 255, 255, 0.12)',
            color: '#94a3b8',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <i className="fa-solid fa-arrow-rotate-left" style={{ fontSize: '11px' }} />
          <span>Reset Filters</span>
        </button>

        {/* Legend */}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '12px', alignItems: 'center', fontSize: '11px', color: '#94a3b8' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#38bdf8' }} /> Artifact
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#10b981' }} /> Compliant
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#f97316' }} /> Deprecated
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#ef4444' }} /> Critical
          </span>
        </div>
      </div>

      {/* Main Graph Canvas Area */}
      <div style={{ flex: 1, position: 'relative', display: 'flex', minHeight: 0, minWidth: 0, overflow: 'hidden', height: '100%' }}>
        {/* Unresolved Evidence Alert Banner (Requirement B8) */}
        {unresolvedTarget && (
          <div
            style={{
              position: 'absolute',
              top: '16px',
              left: '50%',
              transform: 'translateX(-50%)',
              zIndex: 40,
              background: 'rgba(239, 68, 68, 0.95)',
              backdropFilter: 'blur(16px)',
              border: '1px solid rgba(255, 255, 255, 0.2)',
              borderRadius: '10px',
              padding: '10px 18px',
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5)',
              color: '#ffffff',
              fontSize: '12px',
              fontWeight: 600,
              maxWidth: '90%'
            }}
          >
            <i className="fa-solid fa-triangle-exclamation" style={{ fontSize: '15px', color: '#fef08a' }} />
            <div>
              Requested evidence item <code style={{ background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px' }}>"{unresolvedTarget}"</code> could not be located in this analysis graph.
            </div>
            <button
              onClick={() => setUnresolvedTarget(null)}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#ffffff',
                cursor: 'pointer',
                fontSize: '14px',
                padding: '0 4px',
                opacity: 0.8
              }}
              title="Dismiss Notification"
            >
              <i className="fa-solid fa-xmark" />
            </button>
          </div>
        )}

        <div style={{ flex: 1, height: '100%', minWidth: 0, minHeight: 0 }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onInit={(instance) => {
              reactFlowInstanceRef.current = instance;
            }}
            onNodeClick={(_, node) => {
              setUnresolvedTarget(null);
              handleSelectNode(node.id);
            }}
            onPaneClick={() => {
              setUnresolvedTarget(null);
              handleSelectNode(null);
            }}
            nodeTypes={NODE_TYPES}
            fitView
            attributionPosition="bottom-left"
            minZoom={0.2}
            maxZoom={1.8}
            defaultViewport={{ x: 0, y: 0, zoom: 0.75 }}
          >
            <Background color="#1e293b" gap={24} size={1} />
            <Controls
              style={{
                background: 'rgba(15, 23, 42, 0.9)',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                borderRadius: '8px',
                overflow: 'hidden',
              }}
            />
            <MiniMap
              nodeColor={n => {
                if (n.type === 'finding') return '#ef4444';
                if (n.type === 'source_artifact') return '#38bdf8';
                if (n.type === 'session') return '#10b981';
                if (n.type === 'handshake') return '#f97316';
                if (n.type === 'certificate') return '#eab308';
                return '#818cf8';
              }}
              style={{
                background: 'rgba(15, 23, 42, 0.9)',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                borderRadius: '8px',
              }}
            />
          </ReactFlow>
        </div>

        {/* Slide-over details drawer */}
        {selectedNode && drawerOpen && (
          <ProvenanceDetailsDrawer
            selectedNode={selectedNode}
            onClose={() => setDrawerOpen(false)}
            onFocusNode={id => handleSelectNode(id)}
            onTraceUpstream={id => handleSelectNode(id, 'upstream')}
            onTraceDownstream={id => handleSelectNode(id, 'downstream')}
            rawGraph={graphData}
          />
        )}
      </div>
    </div>
  );
}
