"""
SecureMailScope — Evidence Provenance Service
Constructs deterministic, evidence-backed provenance graphs linking captured network
evidence (PCAP artifacts, packets/streams, TLS handshakes, X.509 certificates)
through deterministic analysis rules and baselines to final security findings.
"""

import os
import re
import hashlib

try:
    from app.core.cipher_suites import lookup as lookup_cipher_suite
except ImportError:  # pragma: no cover - import style depends on entry point
    from core.cipher_suites import lookup as lookup_cipher_suite
from pathlib import Path
from typing import Dict, List, Any, Optional, Set


class ProvenanceGraphBuilder:
    """
    Constructs an interactive Evidence Provenance Graph from analysis result data.
    Ensures complete, bidirectional traceability:
    Source Artifact → Session/Stream → Crypto/Certificate → Analysis Operation → Baseline → Finding.
    """

    # Standard rule definitions mapped to finding types
    RULE_DEFINITIONS = {
        'plaintext_protocol': {
            'rule_id': 'RULE-RFC8314-PLAINTEXT',
            'label': 'RFC 8314 Cleartext Transport Check',
            'standard': 'RFC 8314 (Section 3) / NIST SP 800-45',
            'description': 'Validates that sensitive email protocols (SMTP, IMAP, POP3) enforce TLS encryption.',
            'category': 'protocol_rule'
        },
        'deprecated_protocol': {
            'rule_id': 'RULE-RFC8996-DEPRECATED-TLS',
            'label': 'RFC 8996 Deprecated TLS Protocol Audit',
            'standard': 'RFC 7568 (SSL 3.0) / RFC 8996 (TLS 1.0 & 1.1) / PCI DSS 3.2+',
            'description': 'Audits negotiated TLS protocol versions and flags obsolete versions vulnerable to POODLE/BEAST.',
            'category': 'cryptographic_rule'
        },
        'weak_cipher': {
            'rule_id': 'RULE-NIST-SP800-52R2-CIPHER',
            'label': 'NIST SP 800-52r2 Cipher Suite Policy Audit',
            'standard': 'NIST Special Publication 800-52 Revision 2',
            'description': 'Screens negotiated and offered cipher suites for broken primitives (RC4, 3DES, CBC mode).',
            'category': 'cryptographic_rule'
        },
        'weak_signature': {
            'rule_id': 'RULE-RFC5280-SIG-ALGO',
            'label': 'RFC 5280 Certificate Signature Strength Audit',
            'standard': 'RFC 5280 / CA/B Forum Baseline Requirements',
            'description': 'Checks X.509 certificate signatures against collision-compromised hash algorithms (MD5, SHA-1).',
            'category': 'pki_rule'
        },
        'insufficient_key_size': {
            'rule_id': 'RULE-NIST-SP800-57-KEYLEN',
            'label': 'NIST SP 800-57 Asymmetric Key Length Audit',
            'standard': 'NIST SP 800-57 Part 1 Rev. 5',
            'description': 'Verifies public key modulus sizes (RSA >= 2048-bit, ECC >= 256-bit) against factorization risks.',
            'category': 'pki_rule'
        },
        'expired_certificate': {
            'rule_id': 'RULE-RFC5280-VALIDITY',
            'label': 'RFC 5280 Certificate Validity Period Audit',
            'standard': 'RFC 5280 (Section 4.1.2.5)',
            'description': 'Compares certificate notBefore and notAfter timestamps against evaluation time to detect expired trust.',
            'category': 'pki_rule'
        },
        'self_signed_certificate': {
            'rule_id': 'RULE-WEB-PKI-TRUST',
            'label': 'WebPKI / CA Trust Verification Audit',
            'standard': 'RFC 5280 / CA/B Forum WebTrust Principles',
            'description': 'Identifies self-signed certificates lacking a verifiable trust chain to a recognized Root Certificate Authority.',
            'category': 'pki_rule'
        },
        'missing_starttls': {
            'rule_id': 'RULE-RFC3207-STARTTLS',
            'label': 'RFC 3207 / RFC 8314 Opportunistic TLS Enforcement',
            'standard': 'RFC 3207 (SMTP STARTTLS) / RFC 8314',
            'description': 'Detects cleartext SMTP sessions lacking STARTTLS command negotiation.',
            'category': 'protocol_rule'
        }
    }

    def __init__(self, analysis_data: Dict[str, Any], file_path: Optional[Path] = None):
        self.data = analysis_data
        self.file_path = file_path
        self.nodes = []
        self.edges = []
        self.node_ids: Set[str] = set()
        self.edge_ids: Set[str] = set()
        self.unknown_count = 0
        self.evidence_count = 0
        self.linked_findings = set()
        self.unlinked_findings = set()
        
        # Upstream and downstream traceability indices
        self.finding_to_evidence: Dict[str, List[str]] = {}
        self.evidence_to_findings: Dict[str, List[str]] = {}

    def _add_node(self, node: Dict[str, Any]):
        node_id = node['id']
        if node_id not in self.node_ids:
            self.node_ids.add(node_id)
            self.nodes.append(node)
            if node['type'] in ('source_artifact', 'session', 'handshake', 'certificate'):
                self.evidence_count += 1
            if node.get('assessment', {}).get('unknown'):
                self.unknown_count += len(node['assessment']['unknown'])

    def _add_edge(self, source_id: str, target_id: str, edge_type: str,
                  label: str, is_direct: bool = True, metadata: Optional[Dict] = None):
        if source_id not in self.node_ids or target_id not in self.node_ids:
            return  # Prevent dangling edges
        edge_id = f"edge__{source_id}__{target_id}__{edge_type}"
        if edge_id not in self.edge_ids:
            self.edge_ids.add(edge_id)
            self.edges.append({
                'id': edge_id,
                'source': source_id,
                'target': target_id,
                'type': edge_type,
                'label': label,
                'is_direct': is_direct,
                'metadata': metadata or {}
            })

    @staticmethod
    def _extract_cn(subject: str) -> str:
        """Pull the Common Name out of a distinguished name, or '' if absent."""
        if subject and 'CN=' in subject:
            return subject.split('CN=')[-1].split(',')[0].strip()
        return ''

    def _compute_file_hash(self, filename: str) -> Dict[str, Any]:
        """Attempt to locate capture file and compute real SHA-256 hash."""
        base_dir = Path(__file__).resolve().parent.parent.parent
        candidate_paths = [
            self.file_path,
            Path("uploads") / filename,
            Path("test-data") / filename,
            Path("backend/test-data") / filename,
            base_dir / "test-data" / filename,
            base_dir / "uploads" / filename,
            Path("uploads") / f"{self.data.get('capture_id')}{Path(filename).suffix if filename else '.pcap'}"
        ]
        for p in candidate_paths:
            if p and isinstance(p, Path) and p.exists() and p.is_file():
                try:
                    hasher = hashlib.sha256()
                    with open(p, "rb") as f:
                        for chunk in iter(lambda: f.read(65536), b""):
                            hasher.update(chunk)
                    return {
                        'sha256': hasher.hexdigest(),
                        'verified_on_disk': True,
                        'file_path': str(p.name)
                    }
                except Exception:
                    pass
        # If file not on disk (e.g., cleared upload), return honest unknown status
        return {
            'sha256': None,
            'verified_on_disk': False,
            'status': 'file_archived_or_removed'
        }

    def build_graph(self) -> Dict[str, Any]:
        """Construct the complete provenance graph (alias for build)."""
        return self.build()

    def build(self) -> Dict[str, Any]:
        """Construct the complete provenance graph with nodes and relationships."""
        capture_id = self.data.get('capture_id', 'unknown_capture')
        filename = self.data.get('original_filename') or self.data.get('filename') or f"{capture_id}.pcap"
        summary = self.data.get('summary', {})
        findings = self.data.get('findings', [])
        sessions = self.data.get('sessions', [])
        certificates = self.data.get('certificates', [])
        handshakes = self.data.get('tls_handshakes', []) or self.data.get('handshakes', [])

        # ── 1. SOURCE ARTIFACT NODE ──
        artifact_id = f"artifact:{capture_id}"
        hash_info = self._compute_file_hash(filename)
        
        artifact_unknowns = []
        if not hash_info.get('verified_on_disk'):
            artifact_unknowns.append("Original PCAP file binary is no longer present on local disk for direct hash verification")

        self._add_node({
            'id': artifact_id,
            'type': 'source_artifact',
            'label': f"Capture: {filename}",
            'category': 'artifact',
            'source_ref': filename,
            'metadata': {
                'capture_id': capture_id,
                'filename': filename,
                'file_size': self.data.get('file_size', 0),
                'total_packets': summary.get('total_packets', 0),
                'upload_timestamp': self.data.get('upload_timestamp', 'Unknown'),
                'sha256_hash': hash_info.get('sha256') or 'Unavailable (Archived)',
                'encryption_ratio': summary.get('encryption_ratio', 0),
                'protocols_detected': summary.get('protocols_detected', [])
            },
            'assessment': {
                'observed': {
                    'total_packets': summary.get('total_packets', 0),
                    'encrypted_packets': summary.get('encrypted_packets', 0),
                    'plaintext_packets': summary.get('plaintext_packets', 0),
                    'encryption_ratio': f"{round(summary.get('encryption_ratio', 0) * 100, 1)}%",
                    'protocols': summary.get('protocols_detected', [])
                },
                'expected': {
                    'encryption_ratio': '100% Encrypted per RFC 8314',
                    'plaintext_packets': 0
                },
                'unknown': artifact_unknowns,
                'status': 'non_compliant' if summary.get('plaintext_packets', 0) > 0 else 'compliant'
            }
        })

        # ── 2. BASELINE NODE ──
        baseline_id = "baseline:nist_rfc_enterprise"
        self._add_node({
            'id': baseline_id,
            'type': 'baseline',
            'label': 'Organizational Cryptographic Baseline',
            'category': 'baseline',
            'source_ref': 'NIST SP 800-52r2 / RFC 8314 Policy',
            'metadata': {
                'baseline_id': 'SMS-SEC-BASELINE-v1',
                'title': 'Strict Enterprise Email Cryptographic Posture',
                'enforced_standards': [
                    'RFC 8314 Cleartext Email Deprecation',
                    'RFC 8996 Deprecation of SSLv3, TLS 1.0, TLS 1.1',
                    'NIST SP 800-52 Rev 2 Mandatory TLS 1.2/1.3',
                    'NIST SP 800-57 RSA >= 2048-bit / ECC >= 256-bit',
                    'RFC 5280 Valid Non-Expired Public CA Chain'
                ]
            },
            'assessment': {
                'observed': 'Assessed against network packet evidence',
                'expected': 'Zero cleartext packets, TLS 1.2+ only, AEAD ciphers',
                'unknown': ['Custom tenant override baseline not configured; using strict RFC/NIST default'],
                'status': 'baseline_drift_detected' if findings else 'baseline_adherent'
            }
        })

        # ── 3. SESSION NODES ──
        session_map = {}
        for s in sessions:
            s_id = s.get('id') or f"session_{len(session_map)+1}"
            node_id = f"session:{s_id}"
            session_map[s_id] = node_id

            is_enc = s.get('encrypted', False)
            tls_vers = s.get('tls_versions', [])
            proto = s.get('protocol', 'Unknown')
            src = s.get('src', '0.0.0.0')
            dst = s.get('dst', '0.0.0.0')

            sess_unknowns = []
            if is_enc:
                sess_unknowns.append("Full session application payload unparsed (encrypted TLS stream requires private key to inspect)")
            else:
                sess_unknowns.append("STARTTLS negotiation attempt not observed in cleartext frames")

            self._add_node({
                'id': node_id,
                'type': 'session',
                'label': f"{proto} Session ({src} → {dst})",
                'category': 'network_session',
                'source_ref': f"Stream {s_id} ({src} → {dst})",
                'metadata': {
                    'session_id': s_id,
                    'protocol': proto,
                    'src': src,
                    'dst': dst,
                    'packet_count': s.get('packet_count', 0),
                    'encrypted': is_enc,
                    'tls_versions': tls_vers
                },
                'assessment': {
                    'observed': {
                        'protocol': proto,
                        'transport_security': 'Encrypted' if is_enc else 'Cleartext (Plaintext)',
                        'tls_versions': tls_vers if tls_vers else 'None',
                        'packet_volume': s.get('packet_count', 0)
                    },
                    'expected': {
                        'transport_security': 'TLS Encrypted (RFC 8314)',
                        'recommended_protocol': f"{proto}S (Implicit TLS)" if proto in ['SMTP', 'IMAP', 'POP3'] else proto
                    },
                    'unknown': sess_unknowns,
                    'status': 'compliant' if is_enc else 'unsecured'
                }
            })

            # Edge: Capture -> Session
            self._add_edge(artifact_id, node_id, 'RECONSTRUCTED_FROM', 'reconstructed from', is_direct=True)

        # ── 4. TLS HANDSHAKE NODES ──
        handshake_map = {}
        for i, hs in enumerate(handshakes):
            frame = hs.get('frame', i + 1)
            hs_id = f"handshake:frame_{frame}"
            handshake_map[frame] = hs_id

            tls_ver = hs.get('tls_version', 'Unknown')
            ciphers = hs.get('cipher_suites', [])
            sni = hs.get('sni')
            hs_type = hs.get('handshake_type', 'Handshake')
            src = hs.get('src', '')
            dst = hs.get('dst', '')

            hs_unknowns = []
            if not sni:
                hs_unknowns.append("Server Name Indication (SNI) extension absent in ClientHello")

            status = 'compliant'
            if tls_ver in ['SSL 3.0', 'TLS 1.0', 'TLS 1.1']:
                status = 'deprecated'
            elif any(c in ['0x0004', '0x0005', '0x000a', '0x0009', '0x0016'] or 'RC4' in c.upper() or '3DES' in c.upper() for c in ciphers):
                status = 'weak_cipher'

            self._add_node({
                'id': hs_id,
                'type': 'handshake',
                'label': f"TLS {tls_ver} Handshake (Frame #{frame})",
                'category': 'crypto_handshake',
                'source_ref': f"Packet Frame #{frame}",
                'metadata': {
                    'frame': frame,
                    'timestamp': hs.get('timestamp', ''),
                    'src': f"{src}:{hs.get('src_port', '')}",
                    'dst': f"{dst}:{hs.get('dst_port', '')}",
                    'tls_version': tls_ver,
                    'handshake_type': hs_type,
                    'cipher_suites': ciphers,
                    'sni': sni or 'Not Provided'
                },
                'assessment': {
                    'observed': {
                        'negotiated_protocol': tls_ver,
                        'cipher_suites_count': len(ciphers),
                        'ciphers': ciphers[:4],
                        'sni_hostname': sni or 'Absent (None)'
                    },
                    'expected': {
                        'negotiated_protocol': 'TLS 1.2 or TLS 1.3 per RFC 8996',
                        'cipher_suite': 'AEAD (AES-GCM / ChaCha20-Poly1305)'
                    },
                    'unknown': hs_unknowns,
                    'status': status
                }
            })

            # Correlate handshake to session based on IP and port matching
            matched_session_id = None
            hs_src_port = str(hs.get('src_port') or '')
            hs_dst_port = str(hs.get('dst_port') or '')
            candidate_id = None

            for s_k, s_val in session_map.items():
                s_obj = next((item for item in sessions if (item.get('id') or f"session_{sessions.index(item)+1}") == s_k), None)
                if s_obj and src and dst:
                    s_src_parts = s_obj.get('src', '').split(':')
                    s_dst_parts = s_obj.get('dst', '').split(':')
                    s_src_ip = s_src_parts[0]
                    s_dst_ip = s_dst_parts[0]
                    s_src_p = s_src_parts[1] if len(s_src_parts) > 1 else ''
                    s_dst_p = s_dst_parts[1] if len(s_dst_parts) > 1 else ''

                    ip_match = (src == s_src_ip and dst == s_dst_ip) or (src == s_dst_ip and dst == s_src_ip)
                    if ip_match:
                        # 1. Exact port match takes highest priority
                        if hs_src_port and hs_dst_port and s_src_p and s_dst_p:
                            port_match = (hs_src_port == s_src_p and hs_dst_port == s_dst_p) or (hs_src_port == s_dst_p and hs_dst_port == s_src_p)
                            if port_match:
                                matched_session_id = s_val
                                break
                        # 2. Prefer encrypted session for TLS handshake
                        if s_obj.get('encrypted'):
                            candidate_id = s_val
                        elif not candidate_id:
                            candidate_id = s_val

            if not matched_session_id and candidate_id:
                matched_session_id = candidate_id
            
            if matched_session_id:
                self._add_edge(matched_session_id, hs_id, 'NEGOTIATES', 'negotiates TLS', is_direct=True)
            else:
                self._add_edge(artifact_id, hs_id, 'OBSERVED_IN', 'observed in capture', is_direct=True)

        # ── 5. CERTIFICATE NODES ──
        cert_map = {}
        for i, cert in enumerate(certificates):
            # The analysis pipeline emits certificates with 'frame_number'; accept
            # either key so provenance nodes cite the real capture frame rather
            # than falling back to the list index.
            c_frame = cert.get('frame') or cert.get('frame_number') or (i + 1)
            c_id = f"cert:frame_{c_frame}_{i}"
            cert_map[i] = c_id

            subject = cert.get('subject', 'Unknown Subject')
            issuer = cert.get('issuer', 'Unknown Issuer')
            sig_algo = cert.get('signature_algorithm', 'Unknown')
            key_size = cert.get('key_size', 0)
            is_self = cert.get('is_self_signed', False)
            is_exp = cert.get('is_expired', False)

            cert_unknowns = []
            cert_unknowns.append("Online Certificate Status Protocol (OCSP) / CRL revocation check not present in capture stream")
            if not is_self and 'snakeoil' not in issuer.lower():
                cert_unknowns.append("Local operating system trust store verification requires external PKI validation")

            c_status = 'valid'
            if is_exp:
                c_status = 'expired'
            elif is_self:
                c_status = 'self_signed'
            elif key_size and key_size < 2048:
                c_status = 'insufficient_key'
            elif any(w in sig_algo.lower() for w in ['md5', 'sha1', 'sha-1']):
                c_status = 'weak_signature'

            # Human-friendly label
            cn = 'Unknown'
            if 'CN=' in subject:
                cn = subject.split('CN=')[-1].split(',')[0].strip()
            elif subject:
                cn = subject[:30]

            self._add_node({
                'id': c_id,
                'type': 'certificate',
                'label': f"X.509 Cert: {cn}",
                'category': 'x509_certificate',
                'source_ref': f"Certificate Frame #{c_frame}",
                'metadata': {
                    'frame': c_frame,
                    'subject': subject,
                    'issuer': issuer,
                    'serial': cert.get('serial', 'N/A'),
                    'not_before': cert.get('not_before', 'N/A'),
                    'not_after': cert.get('not_after', 'N/A'),
                    'signature_algorithm': sig_algo,
                    'public_key_algorithm': cert.get('public_key_algorithm', 'RSA'),
                    'key_size': key_size,
                    'is_self_signed': is_self,
                    'is_expired': is_exp
                },
                'assessment': {
                    'observed': {
                        'subject_dn': subject,
                        'issuer_dn': issuer,
                        'key_length': f"{key_size} bits" if key_size else "Unknown",
                        'signature_algorithm': sig_algo,
                        'self_signed': is_self,
                        'expired': is_exp
                    },
                    'expected': {
                        'min_rsa_key_size': '2048 bits (NIST SP 800-57)',
                        'min_signature_algorithm': 'SHA-256 or stronger (RFC 5280)',
                        'trust_anchor': 'Recognized CA Trust Store',
                        'validity_status': 'Current (Not Expired)'
                    },
                    'unknown': cert_unknowns,
                    'status': c_status
                }
            })

            # Edge to corresponding handshake or session
            matched_hs = handshake_map.get(c_frame)
            if matched_hs:
                self._add_edge(matched_hs, c_id, 'PRESENTS_CERTIFICATE', 'presents certificate', is_direct=True)
            elif session_map:
                # Link to first session as fallback
                self._add_edge(list(session_map.values())[0], c_id, 'PRESENTS_CERTIFICATE', 'presents certificate', is_direct=False)
            else:
                self._add_edge(artifact_id, c_id, 'OBSERVED_IN', 'observed in capture', is_direct=True)

        # ── 6. ANALYSIS OPERATION NODES & FINDINGS ──
        # Track which rules actually executed
        executed_rules = {}

        for finding in findings:
            f_type = finding.get('type', 'generic_violation')
            f_id = finding.get('id', f"SMS-{len(self.nodes):03d}")
            finding_node_id = f"finding:{f_id}"

            # Retrieve rule definition
            rule_info = self.RULE_DEFINITIONS.get(f_type, {
                'rule_id': f"RULE-{f_type.upper().replace('_', '-')}",
                'label': f"Security Rule: {f_type.replace('_', ' ').title()}",
                'standard': 'RFC / Security Baseline',
                'description': finding.get('description', ''),
                'category': 'security_rule'
            })
            rule_node_id = f"operation:{rule_info['rule_id']}"

            # Create rule node if not already created
            if rule_node_id not in executed_rules:
                executed_rules[rule_node_id] = True
                self._add_node({
                    'id': rule_node_id,
                    'type': 'analysis_operation',
                    'label': rule_info['label'],
                    'category': 'rule_operation',
                    'source_ref': rule_info['standard'],
                    'metadata': {
                        'rule_id': rule_info['rule_id'],
                        'standard': rule_info['standard'],
                        'description': rule_info['description'],
                        'evaluation_engine': 'SecureMailScope Deterministic Security Engine',
                        'evaluation_status': 'VIOLATION_CONFIRMED'
                    },
                    'assessment': {
                        'observed': 'Security non-compliance detected in captured artifacts',
                        'expected': 'Full compliance with RFC / NIST standard',
                        'unknown': ['Heuristic anomaly confidence not evaluated; check is 100% deterministic'],
                        'status': 'rule_triggered'
                    }
                })
                # Link rule to baseline
                self._add_edge(baseline_id, rule_node_id, 'COMPARED_AGAINST', 'evaluates policy', is_direct=True)

            # Create Finding Node
            severity = finding.get('severity', 'MEDIUM')
            self._add_node({
                'id': finding_node_id,
                'type': 'finding',
                'label': f"[{severity}] {finding.get('title', 'Security Finding')}",
                'category': 'security_finding',
                'source_ref': f_id,
                'metadata': {
                    'finding_id': f_id,
                    'severity': severity,
                    'type': f_type,
                    'title': finding.get('title', ''),
                    'description': finding.get('description', ''),
                    'evidence_snippet': finding.get('evidence', ''),
                    'remediation': finding.get('remediation', ''),
                    'ai_explanation': finding.get('ai_explanation', ''),
                    'ai_confidence': finding.get('ai_confidence', 'DETERMINISTIC_BASELINE')
                },
                'assessment': {
                    'observed': finding.get('evidence', ''),
                    'expected': 'Clean audit / No vulnerability',
                    'unknown': ['Active exploitation status on client host unverified (network passive evidence only)'],
                    'status': severity.lower()
                }
            })

            # Edge: Rule -> Finding
            self._add_edge(rule_node_id, finding_node_id, 'SUPPORTS_FINDING', 'generates finding', is_direct=True)

            # ── 7. LINK EVIDENCE TO RULE AND FINDING ──
            # Determine specific supporting evidence nodes based on finding type
            evidence_linked_for_this_finding = []

            if f_type == 'plaintext_protocol' or f_type == 'missing_starttls':
                # Link all unencrypted sessions
                for s in sessions:
                    if not s.get('encrypted'):
                        s_node = session_map.get(s.get('id'))
                        if s_node:
                            self._add_edge(s_node, rule_node_id, 'EVALUATED_BY', 'evaluated by rule', is_direct=True)
                            self._add_edge(s_node, finding_node_id, 'SUPPORTS_FINDING', 'proves plaintext traffic', is_direct=True)
                            evidence_linked_for_this_finding.append(s_node)

            elif f_type == 'deprecated_protocol':
                # Link handshakes with SSL 3.0 / TLS 1.0 / TLS 1.1
                for i, hs in enumerate(handshakes):
                    if hs.get('tls_version') in ['SSL 3.0', 'TLS 1.0', 'TLS 1.1']:
                        hs_node = handshake_map.get(hs.get('frame', i + 1))
                        if hs_node:
                            self._add_edge(hs_node, rule_node_id, 'EVALUATED_BY', 'evaluated by rule', is_direct=True)
                            self._add_edge(hs_node, finding_node_id, 'SUPPORTS_FINDING', 'exhibits deprecated protocol', is_direct=True)
                            evidence_linked_for_this_finding.append(hs_node)

            elif f_type == 'weak_cipher':
                # Link only the ServerHellos that actually negotiated a weak
                # suite, decided by the same IANA registry the security engine
                # uses. Matching every handshake against a hardcoded code list
                # would cite a ClientHello's offer list as proof of negotiation,
                # which is the defect F37 describes.
                for i, hs in enumerate(handshakes):
                    if hs.get('handshake_type') != 'ServerHello':
                        continue
                    for c in hs.get('cipher_suites', []):
                        info = lookup_cipher_suite(c)
                        if info and info['weak']:
                            hs_node = handshake_map.get(hs.get('frame', i + 1))
                            if hs_node:
                                self._add_edge(hs_node, rule_node_id, 'EVALUATED_BY', 'evaluated by rule', is_direct=True)
                                self._add_edge(hs_node, finding_node_id, 'SUPPORTS_FINDING', 'negotiates weak cipher', is_direct=True)
                                evidence_linked_for_this_finding.append(hs_node)
                            break

            elif f_type in ['weak_signature', 'insufficient_key_size', 'expired_certificate', 'self_signed_certificate']:
                # Link matching certificate nodes
                for i, cert in enumerate(certificates):
                    match = False
                    if f_type == 'weak_signature' and any(w in cert.get('signature_algorithm', '').lower() for w in ['md5', 'sha1']):
                        match = True
                    elif f_type == 'insufficient_key_size' and cert.get('key_size', 0) and cert.get('key_size', 0) < 2048:
                        match = True
                    elif f_type == 'expired_certificate' and cert.get('is_expired'):
                        match = True
                    elif f_type == 'self_signed_certificate' and cert.get('is_self_signed'):
                        match = True

                    if match:
                        c_node = cert_map.get(i)
                        if c_node:
                            self._add_edge(c_node, rule_node_id, 'EVALUATED_BY', 'evaluated by rule', is_direct=True)
                            self._add_edge(c_node, finding_node_id, 'SUPPORTS_FINDING', 'violates PKI policy', is_direct=True)
                            evidence_linked_for_this_finding.append(c_node)

            elif f_type == 'certificate_pki':
                # The analysis pipeline consolidates per-certificate PKI findings
                # (expiry, not-yet-valid, self-signed, untrusted chain) under one
                # type and names the certificate in the title/evidence. Resolve
                # the exact certificate by cited frame number, else by subject CN.
                text = f"{finding.get('title', '')} {finding.get('evidence', '')}"
                cited_frames = {int(m) for m in re.findall(r'[Ff]rame\s+(\d+)', text)}
                matched_indices = [
                    i for i, cert in enumerate(certificates)
                    if (cert.get('frame') or cert.get('frame_number')) in cited_frames
                ]
                if not matched_indices:
                    # The cited frame may be a re-presentation of an already
                    # de-duplicated certificate; fall back to the subject CN.
                    matched_indices = [
                        i for i, cert in enumerate(certificates)
                        if self._extract_cn(cert.get('subject', ''))
                        and self._extract_cn(cert.get('subject', '')) in text
                    ]
                for i in matched_indices:
                    c_node = cert_map.get(i)
                    if c_node:
                        self._add_edge(c_node, rule_node_id, 'EVALUATED_BY', 'evaluated by rule', is_direct=True)
                        self._add_edge(c_node, finding_node_id, 'SUPPORTS_FINDING', 'violates PKI policy', is_direct=True)
                        evidence_linked_for_this_finding.append(c_node)

            elif f_type == 'no_forward_secrecy':
                # Mirror check_forward_secrecy exactly: ServerHello only, TLS 1.3
                # skipped (it mandates ephemeral key exchange), and the verdict
                # taken from the registry's forward_secret flag rather than from
                # the text of a cipher name. tshark reports cipher suites as hex
                # codes, so any string test for "DHE" matches nothing and would
                # link every handshake, ECDHE ones included.
                for i, hs in enumerate(handshakes):
                    if hs.get('handshake_type') != 'ServerHello':
                        continue
                    if hs.get('tls_version') == 'TLS 1.3':
                        continue
                    for c in hs.get('cipher_suites', []):
                        info = lookup_cipher_suite(c)
                        if info and not info['forward_secret']:
                            hs_node = handshake_map.get(hs.get('frame', i + 1))
                            if hs_node:
                                self._add_edge(hs_node, rule_node_id, 'EVALUATED_BY', 'evaluated by rule', is_direct=True)
                                self._add_edge(hs_node, finding_node_id, 'SUPPORTS_FINDING', 'static key exchange, no forward secrecy', is_direct=True)
                                evidence_linked_for_this_finding.append(hs_node)
                            break

            elif f_type in ['email_authentication', 'missing_dkim', 'missing_spf', 'missing_dmarc']:
                # Email-authentication findings cite the stream each message was
                # observed on; sessions are keyed by that same stream id.
                cited_streams = set(re.findall(r'stream\s+(\w+)', str(finding.get('evidence', '')), re.IGNORECASE))
                for s in sessions:
                    # Sessions carry the TCP stream id the finding cites, which is
                    # distinct from the session's own id.
                    if {str(s.get('stream_id')), str(s.get('id'))} & cited_streams:
                        s_node = session_map.get(s.get('id'))
                        if s_node:
                            self._add_edge(s_node, rule_node_id, 'EVALUATED_BY', 'evaluated by rule', is_direct=True)
                            self._add_edge(s_node, finding_node_id, 'SUPPORTS_FINDING', 'carries the assessed message', is_direct=True)
                            evidence_linked_for_this_finding.append(s_node)

            # Record in traceability index
            if evidence_linked_for_this_finding:
                self.linked_findings.add(f_id)
                self.finding_to_evidence[f_id] = [rule_node_id] + evidence_linked_for_this_finding
                for ev in evidence_linked_for_this_finding:
                    if ev not in self.evidence_to_findings:
                        self.evidence_to_findings[ev] = []
                    self.evidence_to_findings[ev].append(f_id)
            else:
                self.unlinked_findings.add(f_id)
                self.finding_to_evidence[f_id] = [rule_node_id]

        # ── 8. PASSING RULES (When no findings or clean checks) ──
        # If there are no findings, add passing baseline validation rules
        if not findings:
            pass_rule_id = "operation:RULE-RFC8314-COMPLIANCE-PASS"
            self._add_node({
                'id': pass_rule_id,
                'type': 'analysis_operation',
                'label': 'RFC 8314 / TLS 1.3 Security Validation',
                'category': 'rule_operation',
                'source_ref': 'RFC 8314 Compliant Posture',
                'metadata': {
                    'rule_id': 'RULE-COMPLIANCE-PASS',
                    'standard': 'RFC 8314 / NIST SP 800-52r2',
                    'description': 'Verified all captured email streams utilize modern cryptographic transport security.',
                    'evaluation_status': 'CLEAN_VERIFIED'
                },
                'assessment': {
                    'observed': '100% Encrypted Sessions, Valid TLS Handshakes',
                    'expected': 'Compliant Transport Encryption',
                    'unknown': [],
                    'status': 'passed'
                }
            })
            self._add_edge(baseline_id, pass_rule_id, 'COMPARED_AGAINST', 'conforms to baseline', is_direct=True)
            for s_node in session_map.values():
                self._add_edge(s_node, pass_rule_id, 'EVALUATED_BY', 'satisfies requirements', is_direct=True)

        return {
            'success': True,
            'capture_id': capture_id,
            'filename': filename,
            'metrics': {
                'total_nodes': len(self.nodes),
                'total_edges': len(self.edges),
                'evidence_entities': self.evidence_count,
                'analysis_operations': len(executed_rules) or 1,
                'findings_linked': len(self.linked_findings),
                'findings_unlinked': len(self.unlinked_findings),
                'unknown_or_unverified_records': self.unknown_count
            },
            'nodes': self.nodes,
            'edges': self.edges,
            'traceability_index': {
                'finding_to_evidence': self.finding_to_evidence,
                'evidence_to_findings': self.evidence_to_findings
            }
        }
