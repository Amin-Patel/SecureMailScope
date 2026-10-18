"""
Unit and Integration Tests for Cryptographic State Reasoning (USP 2)

Tests:
- Unified state vocabulary & 7 discrete states
- 10 normalized rule outcomes (Satisfied, Violated, Unknown, Not Applicable, Error)
- Precedence ladder & deterministic aggregation
- Cross-property reasoning rules (CPR-01 through CPR-05)
- Evidence sufficiency & uncertainty handling (incomplete != failed)
- Explanation generation & driver attribution
- Real PCAP pipeline integration and API endpoints
"""

import pytest
import json
from pathlib import Path
from fastapi.testclient import TestClient
import sys

# Ensure backend root is in sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from main import app
from app.core.crypto_state_engine import (
    CryptographicStateEngine,
    CryptoState,
    RuleStatus
)

client = TestClient(app)


# ─── 1. FIXTURE BUILDERS ───

def build_empty_analysis_data():
    return {
        "summary": {"total_packets": 0, "plaintext_packets": 0, "protocols_detected": []},
        "sessions": [],
        "tls_handshakes": [],
        "certificates": [],
        "findings": []
    }

def build_secure_analysis_data():
    return {
        "summary": {
            "total_packets": 150,
            "plaintext_packets": 0,
            "protocols_detected": ["SMTPS", "IMAPS"],
            "tls_versions": {"TLS 1.3": 2}
        },
        "sessions": [
            {"id": "sess_1", "protocol": "SMTPS", "encrypted": True, "port": 465},
            {"id": "sess_2", "protocol": "IMAPS", "encrypted": True, "port": 993}
        ],
        "tls_handshakes": [
            {"id": "hs_1", "version": "TLS 1.3", "cipher_suites": ["TLS_AES_256_GCM_SHA384"]}
        ],
        "certificates": [
            {
                "id": "cert_1",
                "subject": "CN=mail.enterprise.com",
                "signature_algorithm": "sha256WithRSAEncryption",
                "public_key_algorithm": "rsaEncryption",
                "key_size": 4096,
                "is_expired": False,
                "is_self_signed": False
            }
        ],
        "findings": []
    }

def build_poodle_analysis_data():
    return {
        "summary": {
            "total_packets": 80,
            "plaintext_packets": 0,
            "protocols_detected": ["SMTPS"],
            "tls_versions": {"SSL 3.0": 1}
        },
        "sessions": [
            {"id": "sess_1", "protocol": "SMTPS", "encrypted": True, "port": 465}
        ],
        "tls_handshakes": [
            {"id": "hs_1", "version": "SSL 3.0", "cipher_suites": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]}
        ],
        "certificates": [
            {
                "id": "cert_1",
                "subject": "CN=legacy.target.com",
                "signature_algorithm": "sha1WithRSAEncryption",
                "public_key_algorithm": "rsaEncryption",
                "key_size": 1024,
                "is_expired": True,
                "is_self_signed": True
            }
        ],
        "findings": []
    }


# ─── 2. UNIT TESTS: STATE VOCABULARY & AGGREGATION ───

def test_t06_unified_state_vocabulary_completeness():
    """T06 — Verify all 7 formal cryptographic states exist with labels and descriptions"""
    expected_states = [
        CryptoState.SECURE_WITHIN_OBSERVED_SCOPE,
        CryptoState.ACCEPTABLE_WITH_LIMITATIONS,
        CryptoState.CRYPTOGRAPHIC_VALIDATION_CONCERN,
        CryptoState.CRYPTOGRAPHICALLY_WEAK,
        CryptoState.CRYPTOGRAPHIC_FAILURE,
        CryptoState.INSUFFICIENT_EVIDENCE,
        CryptoState.ANALYSIS_ERROR
    ]
    for state in expected_states:
        assert state in CryptoState.LABELS
        assert state in CryptoState.DESCRIPTIONS
        assert state in CryptoState.BADGE_COLORS
        assert len(CryptoState.DESCRIPTIONS[state]) > 20


def test_t07_normalized_rule_statuses():
    """T07 — Verify that all 10 rules produce structured normalized outcomes"""
    data = build_secure_analysis_data()
    engine = CryptographicStateEngine(data)
    assessment = engine.evaluate()

    rules = assessment["normalized_rules"]
    assert len(rules) == 10
    expected_rule_ids = [
        'RULE-RFC8314-PLAINTEXT',
        'RULE-RFC7568-SSL3',
        'RULE-RFC8996-TLS10',
        'RULE-RFC8996-TLS11',
        'RULE-NIST-SP800-52R2-CIPHER',
        'RULE-RFC5280-SIG-ALGO',
        'RULE-NIST-SP800-57-KEYLEN',
        'RULE-RFC5280-VALIDITY',
        'RULE-WEB-PKI-TRUST',
        'RULE-RFC3207-STARTTLS'
    ]
    actual_rule_ids = [r["rule_id"] for r in rules]
    assert actual_rule_ids == expected_rule_ids

    for r in rules:
        assert r["status"] in [RuleStatus.SATISFIED, RuleStatus.VIOLATED, RuleStatus.UNKNOWN, RuleStatus.NOT_APPLICABLE, RuleStatus.ERROR]
        assert "observed_value" in r
        assert "expected_value" in r
        assert "explanation" in r
        assert "contribution" in r


def test_t08_deterministic_state_aggregation_secure():
    """T08 — Verify clean modern TLS traffic maps to SECURE_WITHIN_OBSERVED_SCOPE"""
    data = build_secure_analysis_data()
    engine = CryptographicStateEngine(data)
    res = engine.evaluate()

    assert res["overall_state"] == CryptoState.SECURE_WITHIN_OBSERVED_SCOPE
    assert res["metrics"]["violated_count"] == 0
    assert res["metrics"]["satisfied_count"] >= 8
    assert res["evidence_completeness"] == "Complete"


def test_t09_uncertainty_and_incomplete_evidence_handling():
    """T09 — Verify incomplete evidence maps to INSUFFICIENT_EVIDENCE without false failures"""
    empty_data = build_empty_analysis_data()
    engine = CryptographicStateEngine(empty_data)
    res = engine.evaluate()

    assert res["overall_state"] == CryptoState.INSUFFICIENT_EVIDENCE
    assert res["evidence_completeness"] == "Insufficient"
    # An empty capture must NOT register cryptographic violations
    assert res["metrics"]["violated_count"] == 0
    assert len(res["unresolved_conditions"]) >= 1


def test_t10_critical_violation_precedence():
    """T10 — Verify a single CRITICAL violation dominates multiple passing rules"""
    data = build_secure_analysis_data()
    # Inject a single critical violation: SSL 3.0
    data["summary"]["tls_versions"]["SSL 3.0"] = 1
    engine = CryptographicStateEngine(data)
    res = engine.evaluate()

    assert res["overall_state"] == CryptoState.CRYPTOGRAPHIC_FAILURE
    assert res["metrics"]["violated_count"] >= 1
    # Even though 8+ rules passed, failure dominates
    assert "SSL 3.0" in res["explanation"]["summary_rationale"]


# ─── 3. UNIT TESTS: CROSS-PROPERTY REASONING ───

def test_t11_t12_cross_property_cpr01_client_trust_limitation():
    """T11-T13 — Verify CPR-01: wire presence of certificate does NOT imply client trust validation"""
    data = build_secure_analysis_data()
    engine = CryptographicStateEngine(data)
    res = engine.evaluate()

    cpr_ids = [c["id"] for c in res["cross_property_insights"]]
    assert "CPR-01" in cpr_ids
    cpr01 = next(c for c in res["cross_property_insights"] if c["id"] == "CPR-01")
    assert "Wire Presence Does Not Guarantee Client Trust" in cpr01["finding"]
    assert "local trust store" in cpr01["reasoning"]


def test_t13_t14_handshake_truncation_not_attack():
    """T13-T14 — Incomplete handshake is treated as evidence limitation, not a malicious attack"""
    data = build_secure_analysis_data()
    # Handshake with missing version / unparsed ciphers
    data["tls_handshakes"] = [{"id": "hs_truncated"}]
    data["summary"]["tls_versions"] = {}
    engine = CryptographicStateEngine(data)
    res = engine.evaluate()

    # Must NOT jump to failure
    assert res["overall_state"] in [CryptoState.ACCEPTABLE_WITH_LIMITATIONS, CryptoState.INSUFFICIENT_EVIDENCE, CryptoState.CRYPTOGRAPHIC_VALIDATION_CONCERN]
    assert res["overall_state"] != CryptoState.CRYPTOGRAPHIC_FAILURE


def test_t15_explanation_generation_structure():
    """T15 — Verify explanation contains structured rationale, drivers, and scope limitations"""
    data = build_poodle_analysis_data()
    engine = CryptographicStateEngine(data)
    res = engine.evaluate()

    exp = res["explanation"]
    assert "summary_rationale" in exp
    assert len(exp["state_drivers"]) >= 1
    assert "scope_limitations" in exp
    assert len(exp["violated_conditions"]) >= 1


# ─── 4. INTEGRATION TESTS: REAL SCENARIOS & API ───

def test_t26_scenario_normal_tls_demo():
    """T26 — Integration: Test secure enterprise demo (secure_mail.pcap)"""
    res = client.post("/api/demo/load/secure_enterprise")
    assert res.status_code == 200
    capture_id = res.json()["capture_id"]

    # Fetch stored results
    res_get = client.get(f"/api/analysis/{capture_id}/results")
    assert res_get.status_code == 200
    result_data = res_get.json()

    assert "cryptographic_state_assessment" in result_data
    assessment = result_data["cryptographic_state_assessment"]
    assert assessment["overall_state"] in [CryptoState.SECURE_WITHIN_OBSERVED_SCOPE, CryptoState.ACCEPTABLE_WITH_LIMITATIONS]
    assert assessment["overall_state_label"] in ["Secure Within Observed Scope", "Acceptable With Limitations"]
    assert len(assessment["normalized_rules"]) == 10


def test_t27_scenario_poodle_weakness_demo():
    """T27 — Integration: Test legacy SSL 3.0 demo (rsasnakeoil2.cap)"""
    res = client.post("/api/demo/load/legacy_ssl3")
    assert res.status_code == 200
    capture_id = res.json()["capture_id"]

    res_get = client.get(f"/api/analysis/{capture_id}/results")
    assert res_get.status_code == 200
    result_data = res_get.json()

    assessment = result_data["cryptographic_state_assessment"]
    assert assessment["overall_state"] == CryptoState.CRYPTOGRAPHIC_FAILURE
    assert any("SSL 3.0" in v or "POODLE" in v for v in assessment["explanation"]["violated_conditions"])


def test_t28_scenario_incomplete_or_empty_capture():
    """T28 — Scenario: Test capture with zero packets"""
    engine = CryptographicStateEngine({"summary": {"total_packets": 0}, "sessions": []})
    res = engine.evaluate()
    assert res["overall_state"] == CryptoState.INSUFFICIENT_EVIDENCE
    assert res["evidence_completeness"] == "Insufficient"


def test_t29_scenario_mixed_observations():
    """T29 — Scenario: Multi-session with 1 secure TLS 1.3 and 1 cleartext SMTP"""
    data = {
        "summary": {
            "total_packets": 100,
            "plaintext_packets": 40,
            "protocols_detected": ["SMTP", "SMTPS"],
            "tls_versions": {"TLS 1.3": 1}
        },
        "sessions": [
            {"id": "sess_enc", "protocol": "SMTPS", "encrypted": True, "port": 465},
            {"id": "sess_plain", "protocol": "SMTP", "encrypted": False, "port": 25}
        ],
        "tls_handshakes": [
            {"id": "hs_1", "version": "TLS 1.3", "cipher_suites": ["TLS_AES_256_GCM_SHA384"]}
        ],
        "certificates": [
            {
                "id": "c1",
                "subject": "CN=mail.example.com",
                "signature_algorithm": "sha256WithRSAEncryption",
                "public_key_algorithm": "rsaEncryption",
                "key_size": 2048,
                "is_expired": False,
                "is_self_signed": False
            }
        ]
    }
    engine = CryptographicStateEngine(data)
    res = engine.evaluate()

    # Plaintext SMTP triggers CRITICAL -> Cryptographic Failure
    assert res["overall_state"] == CryptoState.CRYPTOGRAPHIC_FAILURE
    cpr05 = next((c for c in res["cross_property_insights"] if c["id"] == "CPR-05"), None)
    assert cpr05 is not None
    assert "Coexistence of Secure and Vulnerable Channels" in cpr05["finding"]


def test_t31_deterministic_repeatability():
    """T31 — Repeated evaluations on identical data produce identical deterministic results"""
    data = build_secure_analysis_data()
    res1 = CryptographicStateEngine(data).evaluate()
    res2 = CryptographicStateEngine(data).evaluate()

    assert res1["overall_state"] == res2["overall_state"]
    assert res1["metrics"] == res2["metrics"]
    assert res1["explanation"]["summary_rationale"] == res2["explanation"]["summary_rationale"]
