import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveGraphNode } from '../src/utils/resolveGraphNode.js';

// Sample mock graph nodes representing realistic SecureMailScope provenance output
const mockNodesRunA = [
  {
    id: 'artifact:run_a',
    type: 'source_artifact',
    label: 'Capture: enterprise_mail.pcap',
    source_ref: 'enterprise_mail.pcap',
    metadata: { capture_id: 'run_a', filename: 'enterprise_mail.pcap', total_packets: 150 }
  },
  {
    id: 'session:session_1',
    type: 'session',
    label: 'SMTP Session (192.168.1.10 → 192.168.1.25)',
    source_ref: 'Stream session_1',
    metadata: { session_id: 'session_1', protocol: 'SMTP', src: '192.168.1.10', dst: '192.168.1.25', encrypted: false }
  },
  {
    id: 'session:session_2',
    type: 'session',
    label: 'IMAPS Session (192.168.1.10 → 192.168.1.25)',
    source_ref: 'Stream session_2',
    metadata: { session_id: 'session_2', protocol: 'IMAP', src: '192.168.1.10', dst: '192.168.1.25', encrypted: true }
  },
  {
    id: 'handshake:frame_6',
    type: 'handshake',
    label: 'TLS TLS 1.0 Handshake (Frame #6)',
    source_ref: 'Packet Frame #6',
    metadata: { frame: 6, tls_version: 'TLS 1.0', cipher_suites: ['0x000a', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'] }
  },
  {
    id: 'handshake:frame_18',
    type: 'handshake',
    label: 'TLS TLS 1.2 Handshake (Frame #18)',
    source_ref: 'Packet Frame #18',
    metadata: { frame: 18, tls_version: 'TLS 1.2', cipher_suites: ['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'] }
  },
  {
    id: 'cert:frame_6_0',
    type: 'certificate',
    label: 'X.509 Cert: mail.insecure.corp',
    source_ref: 'Certificate Frame #6',
    metadata: { frame: 6, subject: 'CN=mail.insecure.corp', issuer: 'CN=Insecure Local CA', key_size: 1024, is_expired: true }
  },
  {
    id: 'operation:RULE-RFC8996-DEPRECATED-TLS',
    type: 'analysis_operation',
    label: 'RFC 8996 Deprecated TLS Protocol Audit',
    source_ref: 'RFC 8996',
    metadata: { rule_id: 'RULE-RFC8996-DEPRECATED-TLS', standard: 'RFC 8996 / PCI DSS 3.2+' }
  },
  {
    id: 'operation:RULE-RFC8314-PLAINTEXT',
    type: 'analysis_operation',
    label: 'RFC 8314 Cleartext Transport Check',
    source_ref: 'RFC 8314',
    metadata: { rule_id: 'RULE-RFC8314-PLAINTEXT', standard: 'RFC 8314' }
  },
  {
    id: 'finding:SMS-001',
    type: 'finding',
    label: '[CRITICAL] Deprecated TLS 1.0 Protocol Negotiated',
    source_ref: 'SMS-001',
    metadata: { finding_id: 'SMS-001', severity: 'CRITICAL', title: 'Deprecated TLS 1.0 Protocol Negotiated' }
  },
  {
    id: 'finding:SMS-002',
    type: 'finding',
    label: '[HIGH] Plaintext SMTP Transmission Detected',
    source_ref: 'SMS-002',
    metadata: { finding_id: 'SMS-002', severity: 'HIGH', title: 'Plaintext SMTP Transmission Detected' }
  }
];

const mockNodesRunB = [
  {
    id: 'artifact:run_b',
    type: 'source_artifact',
    label: 'Capture: second_pcap.pcap',
    source_ref: 'second_pcap.pcap',
    metadata: { capture_id: 'run_b', filename: 'second_pcap.pcap' }
  },
  {
    id: 'session:session_99',
    type: 'session',
    label: 'POP3 Session (10.0.0.5 → 10.0.0.1)',
    source_ref: 'Stream session_99',
    metadata: { session_id: 'session_99', protocol: 'POP3' }
  },
  {
    id: 'handshake:frame_6',
    type: 'handshake',
    label: 'TLS TLS 1.3 Handshake (Frame #6)',
    source_ref: 'Packet Frame #6',
    metadata: { frame: 6, tls_version: 'TLS 1.3' }
  }
];

test('Scenario 1 — Packet selected from Evidence-Based Assessment resolves exact handshake / packet frame', () => {
  // Test direct handshake frame reference: 'handshake:frame_6'
  const res1 = resolveGraphNode('handshake:frame_6', mockNodesRunA);
  assert.ok(res1, 'Should resolve handshake:frame_6');
  assert.equal(res1.id, 'handshake:frame_6');
  assert.equal(res1.metadata.frame, 6);

  // Test frame-only reference: 'frame_6'
  const res2 = resolveGraphNode('frame_6', mockNodesRunA);
  assert.ok(res2, 'Should resolve frame_6');
  assert.equal(res2.id, 'handshake:frame_6');

  // Test packet reference: 'packet:18'
  const res3 = resolveGraphNode('packet:18', mockNodesRunA);
  assert.ok(res3, 'Should resolve packet:18 to Frame #18 handshake');
  assert.equal(res3.id, 'handshake:frame_18');

  // Test index reference: 'handshake:0'
  const res4 = resolveGraphNode('handshake:0', mockNodesRunA);
  assert.ok(res4, 'Should resolve handshake:0 index to first handshake');
  assert.equal(res4.id, 'handshake:frame_6');
});

test('Scenario 2 — Stream selected from assessment resolves exact session node', () => {
  // Direct node ID: 'session:session_1'
  const res1 = resolveGraphNode('session:session_1', mockNodesRunA);
  assert.ok(res1, 'Should resolve session:session_1');
  assert.equal(res1.id, 'session:session_1');
  assert.equal(res1.metadata.protocol, 'SMTP');

  // Bare session ID: 'session_2'
  const res2 = resolveGraphNode('session_2', mockNodesRunA);
  assert.ok(res2, 'Should resolve bare session_2');
  assert.equal(res2.id, 'session:session_2');

  // Stream alias: 'stream_1'
  const res3 = resolveGraphNode('stream_1', mockNodesRunA);
  assert.ok(res3, 'Should resolve stream_1');
  assert.equal(res3.id, 'session:session_1');

  // Direct session ref: 'session:session_2'
  const res4 = resolveGraphNode('session:session_2', mockNodesRunA);
  assert.ok(res4, 'Should resolve session:session_2 to second session');
  assert.equal(res4.id, 'session:session_2');

  // Index-based: 'session:0'
  const res5 = resolveGraphNode('session:0', mockNodesRunA);
  assert.ok(res5, 'Should resolve session:0 to first session');
  assert.equal(res5.id, 'session:session_1');
});

test('Scenario 3 — Asynchronous graph loading simulation', () => {
  const targetToResolve = 'handshake:frame_6';

  // Initially empty graph
  const beforeLoaded = resolveGraphNode(targetToResolve, []);
  assert.equal(beforeLoaded, null, 'Must return null before graph nodes are loaded');

  // Graph resolves once nodes arrive
  const afterLoaded = resolveGraphNode(targetToResolve, mockNodesRunA);
  assert.ok(afterLoaded, 'Resolves once graph is ready');
  assert.equal(afterLoaded.id, 'handshake:frame_6');
});

test('Scenario 4 — Multiple analysis runs separation (no cross-capture contamination)', () => {
  // Both captures have a node with frame 6, but Run A is TLS 1.0 and Run B is TLS 1.3
  const nodeRunA = resolveGraphNode('handshake:frame_6', mockNodesRunA);
  const nodeRunB = resolveGraphNode('handshake:frame_6', mockNodesRunB);

  assert.equal(nodeRunA.metadata.tls_version, 'TLS 1.0', 'Run A must have TLS 1.0');
  assert.equal(nodeRunB.metadata.tls_version, 'TLS 1.3', 'Run B must have TLS 1.3');

  // Requesting session_99 from Run A must return null (it belongs only to Run B)
  const leakCheck = resolveGraphNode('session:session_99', mockNodesRunA);
  assert.equal(leakCheck, null, 'Run A must not resolve Run B session');
});

test('Scenario 5 — Different evidence items resolved in succession', () => {
  const item1 = resolveGraphNode('SMS-001', mockNodesRunA);
  assert.equal(item1.id, 'finding:SMS-001');

  const item2 = resolveGraphNode('session:session_2', mockNodesRunA);
  assert.equal(item2.id, 'session:session_2');
  assert.notEqual(item1.id, item2.id, 'Successive items must resolve independently');

  const item3 = resolveGraphNode('RULE-RFC8314-PLAINTEXT', mockNodesRunA);
  assert.equal(item3.id, 'operation:RULE-RFC8314-PLAINTEXT');
});

test('Scenario 6 — Missing evidence handled honestly without selecting arbitrary fallback', () => {
  // Completely missing node
  const missing1 = resolveGraphNode('packet:99999', mockNodesRunA);
  assert.equal(missing1, null, 'Must return null for non-existent packet');

  const missing2 = resolveGraphNode('session:session_unknown_404', mockNodesRunA);
  assert.equal(missing2, null, 'Must return null for non-existent session');

  const missing3 = resolveGraphNode('INVALID-RULE-999', mockNodesRunA);
  assert.equal(missing3, null, 'Must return null for non-existent rule');

  // Ensure it never returns the first node (node 0 is artifact:run_a)
  assert.notEqual(missing1, mockNodesRunA[0], 'Must not fall back to node 0');
});

test('Scenario 7 — Direct route entry / query parameter parsing', () => {
  // Simulates reading ?job=run_a&node=SMS-002
  const queryParam = 'SMS-002';
  const resolved = resolveGraphNode(queryParam, mockNodesRunA);
  assert.ok(resolved, 'Should resolve from URL parameter');
  assert.equal(resolved.id, 'finding:SMS-002');
  assert.equal(resolved.metadata.severity, 'HIGH');
});

test('Scenario 8 — Certificate evidence node resolution', () => {
  // Direct cert frame reference: 'cert:frame_6_0'
  const res1 = resolveGraphNode('cert:frame_6_0', mockNodesRunA);
  assert.ok(res1, 'Should resolve cert:frame_6_0');
  assert.equal(res1.id, 'cert:frame_6_0');
  assert.equal(res1.metadata.subject, 'CN=mail.insecure.corp');

  // Cert index: 'cert:0'
  const res2 = resolveGraphNode('cert:0', mockNodesRunA);
  assert.ok(res2, 'Should resolve cert:0 index');
  assert.equal(res2.id, 'cert:frame_6_0');
});

test('Scenario 9 — Security Operation Rule resolution', () => {
  // Rule ID: 'RULE-RFC8996-DEPRECATED-TLS'
  const res1 = resolveGraphNode('RULE-RFC8996-DEPRECATED-TLS', mockNodesRunA);
  assert.ok(res1, 'Should resolve rule by ID');
  assert.equal(res1.id, 'operation:RULE-RFC8996-DEPRECATED-TLS');

  // Full node ID: 'operation:RULE-RFC8314-PLAINTEXT'
  const res2 = resolveGraphNode('operation:RULE-RFC8314-PLAINTEXT', mockNodesRunA);
  assert.ok(res2, 'Should resolve rule by full node ID');
  assert.equal(res2.id, 'operation:RULE-RFC8314-PLAINTEXT');
});
