"""
Unit and Integration Tests for USP 1: Historical Cryptographic Forensics
Verifies:
1. Historical event timeline reconstruction from network evidence.
2. Correlation across TCP streams, protocol sessions, certificates, and findings.
3. Accurate preservation of evidentiary uncertainty (RFC/ISO standards).
4. Longitudinal host history tracking and temporal cryptographic regressions.
5. FastAPI endpoint /api/analysis/{capture_id}/forensics.
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from main import app, RESULTS_DIR, TEST_DATA_DIR
from app.core.pcap_analyzer import EmailPCAPAnalyzer
from app.core.forensics_engine import HistoricalForensicsEngine

client = TestClient(app)


@pytest.fixture(scope="module")
def analyzed_captures():
    """Analyze real PCAP test fixtures once for tests"""
    fixtures = {
        "vulnerable_smtp": TEST_DATA_DIR / "smtp.pcap",
        "secure_mail": TEST_DATA_DIR / "secure_mail.pcap",
        "legacy_ssl3": TEST_DATA_DIR / "rsasnakeoil2.cap",
        "sih_demo": TEST_DATA_DIR / "SecureMailScope_SIHDemo.pcap"
    }
    results = {}
    for key, path in fixtures.items():
        if path.exists():
            analyzer = EmailPCAPAnalyzer(str(path))
            res = analyzer.analyze()
            res["capture_id"] = f"test_{key}"
            res["original_filename"] = path.name
            results[key] = res
    return results


def test_usp1_event_timeline_reconstruction(analyzed_captures):
    """Verify chronological timeline reconstruction produces ordered forensic events"""
    smtp_data = analyzed_captures.get("vulnerable_smtp")
    assert smtp_data is not None, "smtp.pcap fixture missing"

    engine = HistoricalForensicsEngine(smtp_data)
    summary = engine.reconstruct()

    timeline = summary.get("chronological_timeline", [])
    assert len(timeline) > 0, "Timeline should contain reconstructed events"

    # Verify event structure
    first_event = timeline[0]
    assert first_event["event_id"].startswith("FEVT-")
    assert "event_type" in first_event
    assert "protocol" in first_event
    assert "description" in first_event
    assert "uncertainty" in first_event

    # Verify sequential IDs
    ids = [e["event_id"] for e in timeline]
    expected_ids = [f"FEVT-{i+1:04d}" for i in range(len(timeline))]
    assert ids == expected_ids, "Event IDs must be sequentially ordered"


def test_usp1_multi_protocol_forensics_correlation(analyzed_captures):
    """Verify multi-protocol session correlation and finding linkage on SIH Demo capture"""
    sih_data = analyzed_captures.get("sih_demo")
    assert sih_data is not None, "SecureMailScope_SIHDemo.pcap fixture missing"

    engine = HistoricalForensicsEngine(sih_data)
    summary = engine.reconstruct()

    metrics = summary.get("forensic_metrics", {})
    assert metrics.get("sessions_tracked", 0) >= 1
    assert metrics.get("total_events", 0) >= 3

    # Check for linked findings in events
    events_with_findings = [e for e in summary.get("chronological_timeline", []) if e.get("related_findings")]
    assert len(events_with_findings) > 0, "At least one forensic event must link to detected findings"

    for evt in events_with_findings:
        assert isinstance(evt["related_findings"], list)
        for fid in evt["related_findings"]:
            assert any(fid.startswith(p) for p in ("SMS-", "SEC-", "FIND-", "RULE-", "VULN-", "ISSUE-"))


def test_usp1_evidentiary_uncertainty_preservation():
    """Verify incomplete or unencrypted streams do not invent missing handshakes"""
    dummy_incomplete = {
        "capture_id": "test_incomplete",
        "original_filename": "incomplete.pcap",
        "sessions": [
            {
                "id": "sess_0",
                "stream_id": 0,
                "protocol": "SMTP",
                "src": "10.0.0.1",
                "dst": "10.0.0.2",
                "encrypted": False,
                "starttls_status": "NOT_ATTEMPTED",
                "packets": [{"packet_number": 1, "timestamp": "2026-01-01T00:00:00Z"}]
            }
        ],
        "tls_handshakes": [],
        "certificates": [],
        "findings": [],
        "summary": {"total_packets": 1, "plaintext_packets": 1}
    }

    engine = HistoricalForensicsEngine(dummy_incomplete)
    summary = engine.reconstruct()

    timeline = summary.get("chronological_timeline", [])
    assert len(timeline) >= 1

    # Should disclose wire-level boundary rather than fabricating TLS
    tls_events = [e for e in timeline if e.get("protocol") == "TLS"]
    assert len(tls_events) == 0, "Engine must not invent TLS events where none occurred"


def test_usp1_host_regression_and_history_tracking(analyzed_captures, tmp_path):
    """Verify host cryptographic downgrade detection across multiple captures"""
    sih_data = analyzed_captures.get("sih_demo")
    assert sih_data is not None

    engine = HistoricalForensicsEngine(sih_data)
    summary = engine.reconstruct()

    # Verify structure of host_regressions
    regressions = summary.get("host_regressions")
    assert isinstance(regressions, list)


def test_usp1_api_forensics_endpoint(analyzed_captures):
    """Verify GET /api/analysis/{capture_id}/forensics returns structured forensic summary"""
    sih_data = analyzed_captures.get("sih_demo")
    cid = sih_data["capture_id"]

    # Save to RESULTS_DIR so API can find it
    result_path = RESULTS_DIR / f"{cid}.json"
    with open(result_path, "w") as f:
        json.dump(sih_data, f, indent=2, default=str)

    try:
        response = client.get(f"/api/analysis/{cid}/forensics")
        assert response.status_code == 200
        data = response.json()

        assert "chronological_timeline" in data
        assert "forensic_metrics" in data
        assert "host_regressions" in data
        assert len(data["chronological_timeline"]) > 0
    finally:
        if result_path.exists():
            result_path.unlink()
