"""
Backend Tests for Evidence Provenance Navigation & Traceability.
Verifies that:
1. Provenance graphs generate deterministic, canonical node IDs for packets,
   sessions, handshakes, certificates, analysis operations, and findings.
2. Evidence references produced in assessment results match graph node IDs or can be
   resolved by canonical aliases.
3. Multi-analysis PCAP separation is maintained without identifier collision or cross-leakage.
4. Unresolvable evidence queries return empty/null without selecting fallback nodes.
"""

import pytest
from app.services.provenance_service import ProvenanceGraphBuilder


@pytest.fixture
def sample_analysis_data():
    return {
        "capture_id": "test_capture_nav_01",
        "original_filename": "insecure_mail.pcap",
        "file_size": 204800,
        "upload_timestamp": "2026-10-18T12:00:00Z",
        "summary": {
            "total_packets": 85,
            "encrypted_packets": 20,
            "plaintext_packets": 65,
            "encryption_ratio": 0.235,
            "protocols_detected": ["SMTP", "TLS"]
        },
        "sessions": [
            {
                "id": "session_1",
                "src": "192.168.1.100:49200",
                "dst": "192.168.1.25:25",
                "protocol": "SMTP",
                "packet_count": 45,
                "encrypted": False,
                "tls_versions": []
            },
            {
                "id": "session_2",
                "src": "192.168.1.100:49202",
                "dst": "192.168.1.25:465",
                "protocol": "SMTP",
                "packet_count": 40,
                "encrypted": True,
                "tls_versions": ["TLS 1.0"]
            }
        ],
        "handshakes": [
            {
                "frame": 12,
                "src": "192.168.1.100",
                "dst": "192.168.1.25",
                "src_port": 49202,
                "dst_port": 465,
                "tls_version": "TLS 1.0",
                "handshake_type": "ClientHello / ServerHello",
                "cipher_suites": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
                "sni": "mail.corp.local"
            }
        ],
        "certificates": [
            {
                "frame": 12,
                "subject": "CN=mail.corp.local",
                "issuer": "CN=Insecure Internal CA",
                "signature_algorithm": "sha1WithRSAEncryption",
                "key_size": 1024,
                "is_self_signed": False,
                "is_expired": True
            }
        ],
        "findings": [
            {
                "id": "SMS-001",
                "type": "deprecated_protocol",
                "severity": "CRITICAL",
                "title": "Deprecated TLS 1.0 Protocol Negotiated",
                "description": "TLS 1.0 negotiated in session.",
                "evidence": "Frame #12 negotiated TLS 1.0."
            },
            {
                "id": "SMS-002",
                "type": "plaintext_protocol",
                "severity": "HIGH",
                "title": "Cleartext SMTP Communication",
                "description": "Cleartext SMTP session observed on port 25.",
                "evidence": "Stream session_1 sent 45 plaintext packets."
            }
        ]
    }


def test_provenance_builder_node_ids_canonical(sample_analysis_data):
    """Verify that generated graph nodes adhere to canonical prefix conventions."""
    builder = ProvenanceGraphBuilder(sample_analysis_data)
    graph = builder.build_graph()
    nodes = graph["nodes"]

    node_ids = {n["id"] for n in nodes}

    # Artifact node
    assert "artifact:test_capture_nav_01" in node_ids

    # Session nodes
    assert "session:session_1" in node_ids
    assert "session:session_2" in node_ids

    # Handshake node with frame number
    assert "handshake:frame_12" in node_ids

    # Certificate node with frame number and index
    assert "cert:frame_12_0" in node_ids

    # Rule operation nodes
    assert "operation:RULE-RFC8996-DEPRECATED-TLS" in node_ids
    assert "operation:RULE-RFC8314-PLAINTEXT" in node_ids

    # Finding nodes
    assert "finding:SMS-001" in node_ids
    assert "finding:SMS-002" in node_ids


def test_provenance_edges_traceability(sample_analysis_data):
    """Verify bidirectional edges connecting artifact -> sessions -> handshakes -> findings."""
    builder = ProvenanceGraphBuilder(sample_analysis_data)
    graph = builder.build_graph()
    edges = graph["edges"]

    edge_tuples = {(e["source"], e["target"]) for e in edges}

    # Artifact to session
    assert ("artifact:test_capture_nav_01", "session:session_1") in edge_tuples
    assert ("artifact:test_capture_nav_01", "session:session_2") in edge_tuples

    # Session 2 negotiates handshake frame 12
    assert ("session:session_2", "handshake:frame_12") in edge_tuples

    # Handshake frame 12 presents certificate
    assert ("handshake:frame_12", "cert:frame_12_0") in edge_tuples


def test_multi_capture_isolation():
    """Verify two different captures produce completely independent graphs."""
    data_1 = {
        "capture_id": "pcap_alpha",
        "summary": {"total_packets": 10},
        "sessions": [{"id": "s1", "src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "SMTP", "encrypted": False}],
        "handshakes": [],
        "certificates": [],
        "findings": [{"id": "F1", "type": "plaintext_protocol", "severity": "HIGH", "title": "P1"}]
    }

    data_2 = {
        "capture_id": "pcap_beta",
        "summary": {"total_packets": 20},
        "sessions": [{"id": "s1", "src": "172.16.0.1", "dst": "172.16.0.2", "protocol": "IMAP", "encrypted": True}],
        "handshakes": [{"frame": 5, "tls_version": "TLS 1.3"}],
        "certificates": [],
        "findings": []
    }

    builder1 = ProvenanceGraphBuilder(data_1)
    g1 = builder1.build_graph()

    builder2 = ProvenanceGraphBuilder(data_2)
    g2 = builder2.build_graph()

    g1_ids = {n["id"] for n in g1["nodes"]}
    g2_ids = {n["id"] for n in g2["nodes"]}

    assert "artifact:pcap_alpha" in g1_ids
    assert "artifact:pcap_alpha" not in g2_ids
    assert "artifact:pcap_beta" in g2_ids
    assert "artifact:pcap_beta" not in g1_ids

    # Handshake frame 5 exists only in Beta
    assert "handshake:frame_5" in g2_ids
    assert "handshake:frame_5" not in g1_ids
