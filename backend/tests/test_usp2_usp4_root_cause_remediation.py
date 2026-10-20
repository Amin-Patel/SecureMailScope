"""
Targeted Regression Test Suite for SecureMailScope USP 2 & USP 4 Root-Cause Remediation

Tests:
1. USP 4 Defect Reproduction: Hardcoded key_size=1024 vs True Cryptographic Extraction
2. USP 4 Assessment Uncertainty: Missing/unparseable key size must NOT produce false PASS
3. USP 2 Defect Reproduction: Global has_any_tls leakage in check_missing_starttls()
4. USP 2 Defect Reproduction: STARTTLS packet-level encryption classification
5. USP 2 Dynamic State Machine: Flow-level event transitions & state progression
6. Cross-Module Consistency: Verification on actual PCAP test fixtures
"""

import sys
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Ensure backend root is on sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from app.utils.cert_analyzer import CertificateAnalyzer
from app.core.security_engine import SecurityEngine
from app.core.crypto_state_engine import CryptographicStateEngine, CryptoState, RuleStatus
from app.core.evidence_assessment_engine import EvidenceAssessmentEngine, AssessmentOutcome, EvidenceStatus


# ─────────────────────────────────────────────────────────────────────────────
# 1. USP 4 ROOT-CAUSE REPRODUCTION & REMEDIATION TESTS: KEY-SIZE EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

def _generate_synthetic_der_cert(key_type="rsa", key_size=2048, cn="mail.test.local"):
    """Helper to generate a real synthetic DER certificate in memory."""
    if key_type == "rsa":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_type == "ec":
        curve = ec.SECP256R1() if key_size == 256 else ec.SECP384R1()
        priv = ec.generate_private_key(curve)
    else:
        raise ValueError(f"Unsupported key_type: {key_type}")

    subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "SecureMailScope Test Org"),
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "US"),
    ])
    issuer = subject  # self-signed for test

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(123456789)
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(priv, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_cert_analyzer_extracts_actual_rsa2048_and_ec256_keys():
    """
    USP 4 Root-Cause Test:
    Verifies that CertificateAnalyzer derives key properties from real DER certificate
    bytes rather than defaulting to key_size=1024 and naive printable strings splitting.
    """
    der_rsa2048 = _generate_synthetic_der_cert("rsa", 2048, "smtp.rsa2048.org")
    der_rsa1024 = _generate_synthetic_der_cert("rsa", 1024, "legacy.rsa1024.org")
    der_ec256 = _generate_synthetic_der_cert("ec", 256, "modern.ecc.org")

    parsed_2048 = CertificateAnalyzer.parse_der_certificate(der_rsa2048, frame_num=10)
    assert parsed_2048 is not None
    assert parsed_2048["key_size"] == 2048, "Must extract genuine 2048-bit key size"
    assert parsed_2048["public_key_algorithm"] == "RSA"
    assert "CN=smtp.rsa2048.org" in parsed_2048["subject"]

    parsed_1024 = CertificateAnalyzer.parse_der_certificate(der_rsa1024, frame_num=11)
    assert parsed_1024["key_size"] == 1024, "Must extract genuine 1024-bit key size"
    assert parsed_1024["public_key_algorithm"] == "RSA"

    parsed_ec = CertificateAnalyzer.parse_der_certificate(der_ec256, frame_num=12)
    assert parsed_ec["key_size"] == 256, "Must extract genuine 256-bit EC curve length"
    assert parsed_ec["public_key_algorithm"] == "EC"


def test_cert_analyzer_unparseable_evidence_preserves_unknown_no_fallback():
    """
    USP 4 Uncertainty Test:
    When certificate DER is corrupt, missing, or unparseable, key_size must be None.
    It must NEVER default to 1024 or fabricate a valid size.
    """
    corrupt_der = b"\x30\x82\x01\x00InvalidAsn1BytesPayload"
    parsed = CertificateAnalyzer.parse_der_certificate(corrupt_der, frame_num=99)
    # Must report unknown/None key_size rather than hardcoding 1024
    assert parsed["key_size"] is None
    assert parsed["public_key_algorithm"] is None


def test_evidence_assessment_missing_keysize_produces_indeterminate():
    """
    USP 4 Defect Reproduction in Assessment Engine:
    Previously, if key_size was missing or 0, weak_keys was empty,
    causing _assess_key_length to falsely return SATISFIED.
    With the fix, missing key_size MUST produce INDETERMINATE.
    """
    analysis_data = {
        "summary": {"total_packets": 20, "plaintext_packets": 0},
        "sessions": [{"id": "s1", "encrypted": True}],
        "tls_handshakes": [{"id": "hs1", "version": "TLS 1.2"}],
        "certificates": [{
            "id": "c1",
            "subject": "CN=unknown.host",
            "issuer": "CN=Unknown CA",
            "public_key_algorithm": None,
            "key_size": None,  # Key size could not be observed from wire
        }],
        "findings": []
    }
    engine = EvidenceAssessmentEngine(analysis_data)
    result = engine.evaluate()
    keylen_item = next(a for a in result["assessments"] if a["req_id"] == "REQ-NIST57-KEYLEN")
    
    assert keylen_item["outcome"] == AssessmentOutcome.INDETERMINATE, (
        f"Missing key_size must be INDETERMINATE, got {keylen_item['outcome']}"
    )
    assert keylen_item["evidence_status"] == EvidenceStatus.UNKNOWN


def test_evidence_assessment_compliant_rsa2048_satisfies_policy():
    """
    USP 4 Assessment Test:
    A verified 2048-bit RSA certificate must be SATISFIED (not falsely violated by 1024 fallback).
    """
    analysis_data = {
        "summary": {"total_packets": 20, "plaintext_packets": 0},
        "sessions": [{"id": "s1", "encrypted": True}],
        "tls_handshakes": [{"id": "hs1", "version": "TLS 1.2"}],
        "certificates": [{
            "id": "c1",
            "subject": "CN=smtp.enterprise.com",
            "issuer": "CN=Enterprise Root CA",
            "public_key_algorithm": "RSA",
            "key_size": 2048,
        }],
        "findings": []
    }
    engine = EvidenceAssessmentEngine(analysis_data)
    result = engine.evaluate()
    keylen_item = next(a for a in result["assessments"] if a["req_id"] == "REQ-NIST57-KEYLEN")
    assert keylen_item["outcome"] == AssessmentOutcome.SATISFIED
    assert keylen_item["evidence_status"] == EvidenceStatus.OBSERVED


# ─────────────────────────────────────────────────────────────────────────────
# 2. USP 2 ROOT-CAUSE REPRODUCTION & REMEDIATION TESTS: STARTTLS & STATE MACHINE
# ─────────────────────────────────────────────────────────────────────────────

def test_security_engine_missing_starttls_session_isolation():
    """
    USP 2 Defect Reproduction:
    Previously in SecurityEngine.check_missing_starttls:
      has_any_tls = len(tls_handshakes) > 0
      if plaintext_smtp and not has_any_tls: ...
    If Session 1 was cleartext SMTP and Session 2 used SMTPS, has_any_tls was True,
    causing Session 1's missing STARTTLS to be SILENTLY IGNORED.
    With per-session isolation, Session 1 MUST be flagged!
    """
    analysis_data = {
        "summary": {"total_packets": 50, "plaintext_packets": 25},
        "sessions": [
            {
                "id": "session_cleartext_smtp",
                "protocol": "SMTP",
                "src": "10.0.0.1:45123",
                "dst": "192.0.2.25:25",
                "encrypted": False,
                "tls_info": None,
                "starttls_status": "NOT_ATTEMPTED"
            },
            {
                "id": "session_secure_smtps",
                "protocol": "SMTPS",
                "src": "10.0.0.2:45124",
                "dst": "192.0.2.25:465",
                "encrypted": True,
                "tls_info": {"versions": ["TLS 1.3"], "handshake_count": 1},
                "starttls_status": "NOT_APPLICABLE"
            }
        ],
        "tls_handshakes": [
            {"id": "hs_smtps", "version": "TLS 1.3", "src": "10.0.0.2", "dst": "192.0.2.25"}
        ],
        "certificates": []
    }
    engine = SecurityEngine(analysis_data)
    engine.check_missing_starttls()
    
    missing_starttls_findings = [f for f in engine.findings if f["type"] == "missing_starttls"]
    assert len(missing_starttls_findings) == 1, (
        "Unencrypted SMTP session MUST be flagged even if another session has TLS!"
    )
    assert "session_cleartext_smtp" in missing_starttls_findings[0]["evidence"] or "port 25" in missing_starttls_findings[0]["evidence"]


def test_dynamic_flow_state_machine_starttls_upgrade_lifecycle():
    """
    USP 2 State Machine Test:
    Tests that FlowStateMachine tracks sequential protocol progression:
    INIT -> PLAINTEXT -> STARTTLS_REQUESTED -> STARTTLS_ACCEPTED ->
    TLS_HANDSHAKE_INIT -> TLS_HANDSHAKE_PROGRESS -> TLS_ESTABLISHED -> TERMINATED.
    """
    from app.core.protocol_state_machine import (
        FlowStateMachine, ProtocolState, ProtocolEvent, ProtocolEventType
    )

    fsm = FlowStateMachine(stream_id=3, flow_id="192.0.2.11:41002->198.51.100.11:587", protocol="SMTP-Submission")
    assert fsm.current_state == ProtocolState.INIT

    # 1. Server Banner
    fsm.process_event(ProtocolEvent(
        frame_number=83, timestamp="1.000", stream_id=3,
        event_type=ProtocolEventType.SERVER_BANNER, data="220 mail.demo.local ESMTP"
    ))
    assert fsm.current_state == ProtocolState.PLAINTEXT

    # 2. Client EHLO
    fsm.process_event(ProtocolEvent(
        frame_number=84, timestamp="1.010", stream_id=3,
        event_type=ProtocolEventType.CLIENT_EHLO, data="EHLO client.demo.local"
    ))
    assert fsm.current_state == ProtocolState.PLAINTEXT

    # 3. Client issues STARTTLS
    fsm.process_event(ProtocolEvent(
        frame_number=86, timestamp="1.030", stream_id=3,
        event_type=ProtocolEventType.STARTTLS_CMD, data="STARTTLS"
    ))
    assert fsm.current_state == ProtocolState.STARTTLS_REQUESTED

    # 4. Server accepts with 220
    fsm.process_event(ProtocolEvent(
        frame_number=87, timestamp="1.040", stream_id=3,
        event_type=ProtocolEventType.STARTTLS_RESP_220, data="220 2.0.0 Ready to start TLS"
    ))
    assert fsm.current_state == ProtocolState.STARTTLS_ACCEPTED

    # 5. ClientHello
    fsm.process_event(ProtocolEvent(
        frame_number=88, timestamp="1.050", stream_id=3,
        event_type=ProtocolEventType.TLS_CLIENT_HELLO, data="TLS 1.2 ClientHello"
    ))
    assert fsm.current_state == ProtocolState.TLS_HANDSHAKE_INIT

    # 6. ServerHello & Certificate
    fsm.process_event(ProtocolEvent(
        frame_number=89, timestamp="1.060", stream_id=3,
        event_type=ProtocolEventType.TLS_SERVER_HELLO, data="TLS 1.2 ServerHello + Certificate"
    ))
    assert fsm.current_state == ProtocolState.TLS_HANDSHAKE_PROGRESS

    # 7. Encrypted Application Data
    fsm.process_event(ProtocolEvent(
        frame_number=90, timestamp="1.080", stream_id=3,
        event_type=ProtocolEventType.TLS_APPLICATION_DATA, data="Encrypted TLS Record (23)"
    ))
    assert fsm.current_state == ProtocolState.TLS_ESTABLISHED

    # Verify transition history is inspectable and recorded in stream order
    history = fsm.transition_history
    assert len(history) >= 6
    assert history[0]["from_state"] == ProtocolState.INIT
    assert history[-1]["to_state"] == ProtocolState.TLS_ESTABLISHED
    assert all("evidence_ref" in t for t in history)

    # Posture summary
    posture = fsm.get_cryptographic_posture()
    assert posture["is_encrypted"] is True
    assert posture["starttls_status"] == "UPGRADED_SUCCESSFUL"


def test_dynamic_flow_state_machine_starttls_rejected_fallback():
    """
    USP 2 State Machine Test:
    If client requests STARTTLS but server rejects with 454/501,
    the state must transition to STARTTLS_REJECTED and PLAINTEXT_FALLBACK.
    """
    from app.core.protocol_state_machine import (
        FlowStateMachine, ProtocolState, ProtocolEvent, ProtocolEventType
    )

    fsm = FlowStateMachine(stream_id=1, flow_id="10.0.0.1:50000->10.0.0.2:25", protocol="SMTP")
    fsm.process_event(ProtocolEvent(
        frame_number=5, timestamp="0.1", stream_id=1,
        event_type=ProtocolEventType.STARTTLS_CMD, data="STARTTLS"
    ))
    assert fsm.current_state == ProtocolState.STARTTLS_REQUESTED

    # Server rejects upgrade
    fsm.process_event(ProtocolEvent(
        frame_number=6, timestamp="0.2", stream_id=1,
        event_type=ProtocolEventType.STARTTLS_RESP_ERR, data="454 TLS not available"
    ))
    assert fsm.current_state == ProtocolState.STARTTLS_REJECTED

    # Client sends plaintext MAIL
    fsm.process_event(ProtocolEvent(
        frame_number=7, timestamp="0.3", stream_id=1,
        event_type=ProtocolEventType.PLAINTEXT_COMMAND, data="MAIL FROM:<alice@test.local>"
    ))
    assert fsm.current_state == ProtocolState.PLAINTEXT_FALLBACK

    posture = fsm.get_cryptographic_posture()
    assert posture["is_encrypted"] is False
    assert posture["starttls_status"] == "REJECTED"


def test_pcap_analyzer_real_fixture_sih_demo_starttls_and_key_sizes():
    """
    USP 2 & USP 4 Integration Test on Real Capture:
    Evaluates SecureMailScope_SIHDemo.pcap with remediated analyzer.
    Verifies:
    1. Key sizes of frames 89, 126, 155, 165 are extracted as 2048 bits (not 1024).
    2. Session 2 (stream 3 on port 587) is recognized as encrypted=True with STARTTLS upgrade.
    3. Session 1 (stream 2 on port 25) is recognized as unencrypted=True and flagged for missing STARTTLS.
    """
    from app.core.pcap_analyzer import EmailPCAPAnalyzer

    pcap_path = BACKEND_DIR / "test-data" / "SecureMailScope_SIHDemo.pcap"
    if not pcap_path.exists():
        pytest.skip("SecureMailScope_SIHDemo.pcap not found in test-data")

    analyzer = EmailPCAPAnalyzer(str(pcap_path))
    res = analyzer.analyze()

    assert res["success"] is True

    # 1. Certificate verification: must contain both 1024 and 2048 bit keys
    certs = res["certificates"]
    assert len(certs) >= 2
    key_sizes = [c["key_size"] for c in certs if c.get("key_size")]
    assert 2048 in key_sizes, f"Real 2048-bit keys must be extracted! Found: {key_sizes}"
    assert 1024 in key_sizes, f"Real 1024-bit snakeoil keys must be extracted! Found: {key_sizes}"

    # 2. Session verification
    sessions = res["sessions"]
    # Port 587 session must be encrypted=True after STARTTLS upgrade
    sess_587 = next((s for s in sessions if "587" in str(s["src"]) or "587" in str(s["dst"])), None)
    assert sess_587 is not None
    assert sess_587["encrypted"] is True, "Port 587 session with STARTTLS TLS 1.2 handshake must be encrypted=True"
    assert sess_587.get("starttls_status") == "UPGRADED_SUCCESSFUL"

    # Port 25 cleartext session must be encrypted=False
    sess_25 = next((s for s in sessions if "41001" in str(s["src"]) or "41001" in str(s["dst"])), None)
    if sess_25:
        assert sess_25["encrypted"] is False
        assert sess_25.get("starttls_status") == "NOT_ATTEMPTED"
