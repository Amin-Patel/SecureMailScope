"""
Unit and Integration Tests for USP 6: Cryptographic Drift & Baseline Analysis
Verifies:
1. Baseline management: Creation, versioning, persistence, and retrieval.
2. Multi-property drift comparison with granular diff classification.
3. Security significance evaluation (Weakened vs Strengthened vs Policy Violation vs Benign).
4. Drift history recording and temporal trend tracking.
5. FastAPI endpoints (/api/baselines, /api/drift/compare, /api/drift/history).
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from main import app, RESULTS_DIR, TEST_DATA_DIR
from app.core.pcap_analyzer import EmailPCAPAnalyzer
from app.core.baseline_drift_engine import (
    BaselineDriftEngine,
    DiffClassification,
    SecuritySignificance
)

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


def test_usp6_default_baselines_seeded():
    """Verify standard pre-seeded baselines exist upon engine initialization"""
    engine = BaselineDriftEngine()
    baselines = engine.list_baselines()
    ids = [b["baseline_id"] for b in baselines]

    assert "nist_sp800_52r2" in ids, "NIST SP 800-52r2 baseline must be pre-seeded"
    assert "secure_enterprise_default" in ids, "Enterprise baseline must be pre-seeded"


def test_usp6_create_baseline_from_analysis(analyzed_captures):
    """Verify empirical baseline creation from real capture analysis"""
    sec_data = analyzed_captures.get("secure_mail")
    assert sec_data is not None

    engine = BaselineDriftEngine()
    baseline = engine.create_baseline_from_analysis(
        analysis_data=sec_data,
        name="Test Production Mail Baseline",
        description="Empirical baseline created for test suite",
        target_endpoint="mail.secure.local:465"
    )

    try:
        assert baseline["baseline_id"].startswith("baseline_")
        assert baseline["name"] == "Test Production Mail Baseline"
        assert baseline["version"] == "1.0"
        assert baseline["baseline_type"] == "OBSERVED_TRAFFIC"
        assert "properties" in baseline

        # Verify persistent retrieval
        retrieved = engine.get_baseline(baseline["baseline_id"])
        assert retrieved is not None
        assert retrieved["baseline_id"] == baseline["baseline_id"]
    finally:
        # Cleanup
        engine.delete_baseline(baseline["baseline_id"])


def test_usp6_baseline_versioning_and_history():
    """Verify updating a baseline archives previous version in version_history"""
    engine = BaselineDriftEngine()
    dummy_analysis = {
        "capture_id": "test_versioning",
        "original_filename": "dummy.pcap",
        "sessions": [],
        "tls_handshakes": [],
        "certificates": [],
        "summary": {}
    }
    baseline = engine.create_baseline_from_analysis(
        analysis_data=dummy_analysis,
        name="Versioned Baseline",
        description="Version 1.0 initial",
        target_endpoint="192.168.1.100:25"
    )
    b_id = baseline["baseline_id"]

    try:
        updated = engine.update_baseline(
            baseline_id=b_id,
            name="Versioned Baseline (Updated)",
            description="Version 1.1 updated properties",
            properties={"min_rsa_key_size": 3072}
        )

        assert updated["version"] == "1.1"
        assert len(updated["version_history"]) == 1
        assert updated["version_history"][0]["version"] == "1.0"
        assert updated["properties"]["min_rsa_key_size"] == 3072
    finally:
        engine.delete_baseline(b_id)


def test_usp6_drift_comparison_vulnerable_smtp_against_nist(analyzed_captures):
    """Verify drift detection flags plaintext SMTP as policy violation against NIST SP 800-52r2"""
    smtp_data = analyzed_captures.get("vulnerable_smtp")
    assert smtp_data is not None

    engine = BaselineDriftEngine()
    comp = engine.compare_analysis_against_baseline(
        analysis_data=smtp_data,
        baseline_id="nist_sp800_52r2"
    )

    assert comp["overall_status"] == "SECURITY_DEGRADATION_DRIFT"
    assert comp["metrics"]["weakened_count"] > 0
    assert len(comp["property_diffs"]) > 0

    # Look for STARTTLS and TLS Protocol Version violations
    props = {d["property"]: d for d in comp["property_diffs"]}
    assert "TLS Protocol Versions" in props
    assert props["TLS Protocol Versions"]["security_significance"] == SecuritySignificance.POLICY_VIOLATION


def test_usp6_drift_comparison_legacy_ssl3_against_nist(analyzed_captures):
    """Verify drift detection flags deprecated SSL 3.0 as critical regression"""
    ssl3_data = analyzed_captures.get("legacy_ssl3")
    assert ssl3_data is not None

    engine = BaselineDriftEngine()
    comp = engine.compare_analysis_against_baseline(
        analysis_data=ssl3_data,
        baseline_id="nist_sp800_52r2"
    )

    assert comp["overall_status"] == "SECURITY_DEGRADATION_DRIFT"
    props = {d["property"]: d for d in comp["property_diffs"]}

    tls_diff = props.get("TLS Protocol Versions")
    assert tls_diff is not None
    assert tls_diff["diff_type"] == DiffClassification.CHANGED
    assert tls_diff["security_significance"] == SecuritySignificance.POLICY_VIOLATION


def test_usp6_drift_history_persistence(analyzed_captures):
    """Verify drift comparison records are saved and retrievable via history"""
    sec_data = analyzed_captures.get("secure_mail")
    assert sec_data is not None

    engine = BaselineDriftEngine()
    comp = engine.compare_analysis_against_baseline(
        analysis_data=sec_data,
        baseline_id="nist_sp800_52r2"
    )
    cmp_id = comp["comparison_id"]

    retrieved = engine.get_comparison(cmp_id)
    assert retrieved is not None
    assert retrieved["comparison_id"] == cmp_id
    assert retrieved["baseline_id"] == "nist_sp800_52r2"

    history = engine.list_comparisons(capture_id=sec_data["capture_id"])
    hist_ids = [c["comparison_id"] for c in history]
    assert cmp_id in hist_ids


def test_usp6_api_baseline_and_drift_endpoints(analyzed_captures):
    """Verify FastAPI baseline & drift routes integration"""
    sih_data = analyzed_captures.get("sih_demo")
    cid = sih_data["capture_id"]

    # Save to RESULTS_DIR for API retrieval
    result_path = RESULTS_DIR / f"{cid}.json"
    with open(result_path, "w") as f:
        json.dump(sih_data, f, indent=2, default=str)

    try:
        # 1. GET /api/baselines
        b_res = client.get("/api/baselines")
        assert b_res.status_code == 200
        assert "baselines" in b_res.json()

        # 2. POST /api/drift/compare
        cmp_res = client.post("/api/drift/compare", json={
            "capture_id": cid,
            "baseline_id": "nist_sp800_52r2"
        })
        assert cmp_res.status_code == 200
        cmp_data = cmp_res.json()
        assert "comparison_id" in cmp_data
        assert "property_diffs" in cmp_data

        cmp_id = cmp_data["comparison_id"]

        # 3. GET /api/drift/comparison/{id}
        det_res = client.get(f"/api/drift/comparison/{cmp_id}")
        assert det_res.status_code == 200
        assert det_res.json()["comparison_id"] == cmp_id

        # 4. GET /api/drift/history
        hist_res = client.get(f"/api/drift/history?capture_id={cid}")
        assert hist_res.status_code == 200
        assert len(hist_res.json()["comparisons"]) >= 1
    finally:
        if result_path.exists():
            result_path.unlink()
