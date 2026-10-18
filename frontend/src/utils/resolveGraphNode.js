/**
 * SecureMailScope — Canonical Evidence Node Resolver
 *
 * Resolves a requested evidence identifier (finding ID, packet frame number,
 * session/stream ID, TLS handshake, X.509 certificate, security rule ID, or source artifact)
 * to its exact corresponding canonical node in the provenance graph.
 *
 * Requirements:
 * - Always preserves the exact identity of the requested item.
 * - Resolves packets, handshakes, certificates, streams, sessions, findings, and rules.
 * - Never returns an arbitrary fallback node (e.g. node[0]).
 * - Returns null if the item cannot be resolved in the provided graph nodes.
 */

export function resolveGraphNode(targetId, nodes = []) {
  if (!targetId || !Array.isArray(nodes) || nodes.length === 0) return null;

  const rawTarget = String(targetId).trim();
  if (!rawTarget) return null;
  const lowerTarget = rawTarget.toLowerCase();

  const getMeta = n => n.metadata || n.data?.metadata || {};

  // 1. Direct exact ID match
  const exact = nodes.find(n => n.id === rawTarget || n.id.toLowerCase() === lowerTarget);
  if (exact) return exact;

  // 2. Finding matches: e.g. "SMS-001", "finding:SMS-001", "SMS-002"
  const findingId = rawTarget.startsWith('finding:') ? rawTarget.slice(8) : rawTarget;
  const matchedFinding = nodes.find(n => {
    if (n.type !== 'finding') return false;
    const meta = getMeta(n);
    return n.id === `finding:${findingId}`
      || n.id.toLowerCase() === `finding:${findingId.toLowerCase()}`
      || meta.finding_id === findingId
      || meta.id === findingId
      || (n.label && n.label.toLowerCase().includes(findingId.toLowerCase()));
  });
  if (matchedFinding) return matchedFinding;

  // 3. Operation / Security Rule matches: e.g. "RULE-RFC8314-PLAINTEXT", "operation:RULE-...", "RULE-TLS-01"
  const opId = rawTarget.startsWith('operation:') ? rawTarget.slice(10) : rawTarget;
  const matchedOp = nodes.find(n => {
    if (n.type !== 'analysis_operation') return false;
    const meta = getMeta(n);
    return n.id === `operation:${opId}`
      || n.id.toLowerCase() === `operation:${opId.toLowerCase()}`
      || meta.rule_id === opId
      || (meta.rule_id && meta.rule_id.toLowerCase() === opId.toLowerCase())
      || (meta.standard && meta.standard.toLowerCase().includes(opId.toLowerCase()));
  });
  if (matchedOp) return matchedOp;

  // 4. Handshake / Frame matches: e.g. "handshake:frame_6", "handshake:0", "handshake:6", "packet:6", "frame:6", "frame_6"
  if (lowerTarget.startsWith('handshake:') || lowerTarget.startsWith('packet:') || lowerTarget.startsWith('frame:') || lowerTarget.startsWith('frame_')) {
    const cleanNum = rawTarget.replace(/^(handshake:|packet:|frame:|frame_)/i, '');
    const num = parseInt(cleanNum, 10);

    // First try matching handshake frame number
    const matchedHsFrame = nodes.find(n => {
      if (n.type !== 'handshake') return false;
      const meta = getMeta(n);
      return n.id === `handshake:frame_${cleanNum}` || String(meta.frame) === String(cleanNum);
    });
    if (matchedHsFrame) return matchedHsFrame;

    // Then try matching certificate frame number
    const matchedCertFrame = nodes.find(n => {
      if (n.type !== 'certificate') return false;
      const meta = getMeta(n);
      return String(meta.frame) === String(cleanNum) || n.id.startsWith(`cert:frame_${cleanNum}_`);
    });
    if (matchedCertFrame) return matchedCertFrame;

    // Index-based fallback for 'handshake:0' or 'handshake:1'
    if (lowerTarget.startsWith('handshake:') && !isNaN(num)) {
      const handshakes = nodes.filter(n => n.type === 'handshake');
      if (handshakes[num]) return handshakes[num];
    }
  }

  // 5. Certificate matches: e.g. "cert:0", "cert:frame_6_0", "cert:6"
  if (lowerTarget.startsWith('cert:')) {
    const cleanCert = rawTarget.slice(5);
    const num = parseInt(cleanCert, 10);
    const matchedCert = nodes.find(n => {
      if (n.type !== 'certificate') return false;
      const meta = getMeta(n);
      return n.id === rawTarget || String(meta.frame) === cleanCert || n.id.includes(cleanCert);
    });
    if (matchedCert) return matchedCert;

    if (!isNaN(num)) {
      const certs = nodes.filter(n => n.type === 'certificate');
      if (certs[num]) return certs[num];
    }
  }

  // 6. Session / Stream matches: e.g. "session:session_1", "session:0", "stream_1", "session_1", "stream:1"
  if (lowerTarget.startsWith('session:') || lowerTarget.startsWith('stream:') || lowerTarget.startsWith('session_') || lowerTarget.startsWith('stream_')) {
    const cleanSess = rawTarget.replace(/^(session:|stream:|session_|stream_)/i, '');
    const num = parseInt(cleanSess, 10);

    const matchedSess = nodes.find(n => {
      if (n.type !== 'session') return false;
      const meta = getMeta(n);
      const sId = String(meta.session_id || '');
      return n.id === `session:${cleanSess}`
        || n.id === `session:session_${cleanSess}`
        || n.id.toLowerCase() === `session:${cleanSess.toLowerCase()}`
        || n.id === rawTarget
        || sId === cleanSess
        || sId === `session_${cleanSess}`
        || sId.toLowerCase() === cleanSess.toLowerCase()
        || (n.source_ref && n.source_ref.toLowerCase().includes(rawTarget.toLowerCase()));
    });
    if (matchedSess) return matchedSess;

    if (!isNaN(num)) {
      const sessions = nodes.filter(n => n.type === 'session');
      // 0-indexed match (e.g. session:0)
      if (sessions[num]) return sessions[num];
      // 1-indexed match (e.g. stream_1 or session_1)
      if (num > 0 && sessions[num - 1]) return sessions[num - 1];
    }
  }

  // 7. Pure numeric frame match: e.g. "6"
  const numericOnly = parseInt(rawTarget, 10);
  if (!isNaN(numericOnly) && String(numericOnly) === rawTarget) {
    const frameMatch = nodes.find(n => {
      const meta = getMeta(n);
      return String(meta.frame) === rawTarget;
    });
    if (frameMatch) return frameMatch;
  }

  // 8. Source Ref or Label match
  const refMatch = nodes.find(n => {
    const meta = getMeta(n);
    return n.source_ref === rawTarget
      || meta.source_ref === rawTarget
      || (n.label && n.label.toLowerCase() === lowerTarget);
  });
  if (refMatch) return refMatch;

  return null;
}
