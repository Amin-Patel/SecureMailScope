"""
Unit and Integration Tests for Evidence-Based Assessment (Observed / Expected / Unknown) (USP 5)

Tests:
- Evidence normalization & property separation
- Defined vs Undefined expectations (REQ-EXP-POSTQUANTUM)
- Assessment outcomes: Satisfied, Violated, Indeterminate, Not Applicable
- Explicit uncertainty handling & passive wire observation limitation (REQ-PKI-CLIENTTRUST)
- Evidence references & analysis-run isolation
- Real PCAP integration via FastAPI endpoints
"""

import pytest
import json
from pathlib import Path
from fastapi.testclient import TestClient
import sys

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from main import app
from app.core.evidence_assessment_engine import (
    EvidenceAssessmentEngine,
    EvidenceStatus,
    AssessmentOutcome
)

client = TestClient(app)


# ─── 1. FIXTURE BUILDERS ───

def build_empty_analysis_data():
    return {
        "capture_id": "test_empty_capture",
        "summary": {"total_packets": 0, "plaintext_packets": 0, "protocols_detected": []},
        "sessions": [],
        "tls_handshakes": [],
        "certificates": [],
        "findings": []
    }

def build_secure_analysis_data():
    return {
        "capture_id": "test_secure_capture",
        "summary": {
            "total_packets": 120,
            "plaintext_packets": 0,
            "protocols_detected": ["SMTPS", "IMAPS"],
            "tls_versions": {"TLS 1.3": 2}
        },
        "sessions": [
            {"id": "s_1", "protocol": "SMTPS", "encrypted": True, "port": 465},
            {"id": "s_2", "protocol": "IMAPS", "encrypted": True, "port": 993}
        ],
        "tls_handshakes": [
            {"id": "hs_1", "version": "TLS 1.3", "cipher_suites": ["TLS_AES_256_GCM_SHA384"]}
        ],
        "certificates": [
            {
                "id": "c_1",
                "subject": "CN=mail.enterprise.corp",
                "signature_algorithm": "sha256WithRSAEncryption",
                "public_key_algorithm": "rsaEncryption",
                "key_size": 2048,
                "is_expired": False,
                "is_self_signed": False
            }
        ],
        "findings": []
    }

def build_vulnerable_analysis_data():
    return {
        "capture_id": "test_vulnerable_capture",
        "summary": {
            "total_packets": 57,
            "plaintext_packets": 57,
            "protocols_detected": ["SMTP"],
            "tls_versions": {}
        },
        "sessions": [
            {"id": "s_plain_1", "protocol": "SMTP", "encrypted": False, "port": 25},
            {"id": "s_plain_2", "protocol": "SMTP", "encrypted": False, "port": 25}
        ],
        "tls_handshakes": [],
        "certificates": [],
        "findings": []
    }


# ─── 2. UNIT TESTS: EVIDENCE & EXPECTATION SEPARATION ───

def test_t28_observed_evidence_normalization():
    """T28 — Verify evidence normalization and separation of observed values from expectations"""
    data = build_secure_analysis_data()
    engine = EvidenceAssessmentEngine(data)
    res = engine.evaluate()

    assert res["success"] is True
    assert res["capture_id"] == "test_secure_capture"
    assessments = res["assessments"]
    assert len(assessments) == 11

    for item in assessments:
        # Must have distinct observed and expected fields
        assert "observed_value" in item
        assert "expected_value" in item
        assert "policy_source" in item
        assert "comparison_rule" in item
        assert "evidence_status" in item
        assert "outcome" in item
        assert "outcome_badge_color" in item
        assert "explanation" in item
        assert isinstance(item["evidence_refs"], list)


def test_t29_defined_vs_undefined_expectations():
    """T29 — Verify system distinguishes defined policy expectations from undefined expectations"""
    data = build_secure_analysis_data()
    engine = EvidenceAssessmentEngine(data)
    res = engine.evaluate()

    # Post-quantum key exchange is observed or classical, but enterprise policy is undefined
    pq_item = next(a for a in res["assessments"] if a["id"] == "REQ-EXP-POSTQUANTUM")
    assert pq_item["outcome"] == AssessmentOutcome.UNDEFINED_EXPECTATION
    assert "[Undefined Expectation]" in pq_item["expected_value"]
    assert "undefined expectation" in pq_item["explanation"].lower()


def test_t30_satisfied_violated_indeterminate_outcomes():
    """T30 — Verify distinct Satisfied, Violated, Indeterminate, and N/A outcomes"""
    # 1. Secure capture has Satisfied outcomes
    sec_data = build_secure_analysis_data()
    sec_res = EvidenceAssessmentEngine(sec_data).evaluate()
    assert sec_res["metrics"]["satisfied_count"] >= 5

    enc_item = next(a for a in sec_res["assessments"] if a["id"] == "REQ-RFC8314-ENCRYPT")
    assert enc_item["outcome"] == AssessmentOutcome.SATISFIED

    # 2. Vulnerable capture has Violated outcomes
    vuln_data = build_vulnerable_analysis_data()
    vuln_res = EvidenceAssessmentEngine(vuln_data).evaluate()
    assert vuln_res["metrics"]["violated_count"] >= 1

    vuln_enc = next(a for a in vuln_res["assessments"] if a["id"] == "REQ-RFC8314-ENCRYPT")
    assert vuln_enc["outcome"] == AssessmentOutcome.VIOLATED
    assert vuln_enc["evidence_status"] == EvidenceStatus.OBSERVED

    # 3. Not applicable checks in vulnerable capture (e.g. TLS version not applicable to plaintext)
    vuln_tls = next(a for a in vuln_res["assessments"] if a["id"] == "REQ-RFC8996-TLSVER")
    assert vuln_tls["outcome"] == AssessmentOutcome.NOT_APPLICABLE
    assert vuln_tls["evidence_status"] == EvidenceStatus.NOT_APPLICABLE


def test_t31_uncertainty_handling_client_trust_boundary():
    """T31 — Verify REQ-PKI-CLIENTTRUST: wire cert observation does not prove client trust acceptance"""
    data = build_secure_analysis_data()
    engine = EvidenceAssessmentEngine(data)
    res = engine.evaluate()

    trust_item = next(a for a in res["assessments"] if a["id"] == "REQ-PKI-CLIENTTRUST")
    assert trust_item["outcome"] == AssessmentOutcome.INDETERMINATE
    assert trust_item["evidence_status"] == EvidenceStatus.UNKNOWN
    assert "passive network capture boundary" in trust_item["unknown_reason"].lower()
    assert len(trust_item["missing_prerequisites"]) >= 1


def test_t32_empty_capture_uncertainty():
    """T32 — Incomplete capture yields Indeterminate without registering false security violations"""
    empty_data = build_empty_analysis_data()
    engine = EvidenceAssessmentEngine(empty_data)
    res = engine.evaluate()

    assert res["metrics"]["violated_count"] == 0
    enc_item = next(a for a in res["assessments"] if a["id"] == "REQ-RFC8314-ENCRYPT")
    assert enc_item["outcome"] == AssessmentOutcome.INDETERMINATE
    assert enc_item["evidence_status"] == EvidenceStatus.UNKNOWN


def test_t33_evidence_references_integrity():
    """T33 — Evidence references map to genuine session, handshake, and cert IDs"""
    data = build_secure_analysis_data()
    engine = EvidenceAssessmentEngine(data)
    res = engine.evaluate()

    enc_item = next(a for a in res["assessments"] if a["id"] == "REQ-RFC8314-ENCRYPT")
    assert "session:s_1" in enc_item["evidence_refs"]

    key_item = next(a for a in res["assessments"] if a["id"] == "REQ-NIST57-KEYLEN")
    assert "cert:c_1" in key_item["evidence_refs"]


# ─── 3. INTEGRATION TESTS: REAL ANALYSIS ENDPOINTS ───

def test_t34_integration_demo_captures():
    """T34 — Integration: Verify evidence-based assessment payload in demo results"""
    # 1. Secure Enterprise Demo
    res_clean = client.post("/api/demo/load/secure_enterprise")
    assert res_clean.status_code == 200
    clean_id = res_clean.json()["capture_id"]

    res_clean_get = client.get(f"/api/analysis/{clean_id}/results")
    assert res_clean_get.status_code == 200
    clean_data = res_clean_get.json()
    assert "evidence_based_assessment" in clean_data
    ev_clean = clean_data["evidence_based_assessment"]
    assert ev_clean["metrics"]["total_assessed"] == 11
    assert ev_clean["metrics"]["satisfied_count"] >= 4

    # 2. Vulnerable SMTP Demo
    res_smtp = client.post("/api/demo/load/vulnerable_smtp")
    assert res_smtp.status_code == 200
    smtp_id = res_smtp.json()["capture_id"]

    res_smtp_get = client.get(f"/api/analysis/{smtp_id}/results")
    assert res_smtp_get.status_code == 200
    smtp_data = res_smtp_get.json()
    assert "evidence_based_assessment" in smtp_data
    ev_smtp = smtp_data["evidence_based_assessment"]
    assert ev_smtp["metrics"]["violated_count"] >= 1
