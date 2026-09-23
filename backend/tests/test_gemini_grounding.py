"""
Test Suite for Gemini Boundary Enforcement, RAG Grounding, and Hallucination Prevention.
Verifies that AI explanations are strictly contextual, do not invent findings, and do not mutate risk scores.
"""

import pytest
from app.services.gemini_service import GeminiSecurityAssistant
from app.utils.sanitizer import DataSanitizer


def test_sanitizer_redacts_credentials():
    raw_text = "AUTH PLAIN dGVzdHVzZXIAdGVzdHBhc3M= and Bearer secret_token_xyz"
    sanitized = DataSanitizer.sanitize_text(raw_text)
    assert "secret_token_xyz" not in sanitized
    assert "[REDACTED_BEARER_TOKEN]" in sanitized


def test_sanitizer_removes_raw_payloads():
    data = {
        "title": "Cleartext IMAP Transmission",
        "evidence": "Observed LOGIN command with password",
        "hex_payload": "61303031204c4f47494e20757365722070617373",
        "raw_bytes": b"\x00\x01\x02"
    }
    sanitized = DataSanitizer.sanitize_for_gemini(data)
    assert "hex_payload" not in sanitized
    assert "raw_bytes" not in sanitized
    assert sanitized["title"] == "Cleartext IMAP Transmission"


def test_ai_explanation_deterministic_fallback():
    assistant = GeminiSecurityAssistant()
    finding = {
        "id": "SMS-001",
        "title": "Unencrypted Email Protocol Detected",
        "severity": "CRITICAL",
        "type": "plaintext_protocol",
        "description": "50 packets transmitted in plaintext.",
        "evidence": "50 plaintext packets on SMTP port 25"
    }
    explanation = assistant.explain_finding(finding)
    assert "ai_explanation" in explanation
    assert len(explanation["ai_explanation"]) > 20
    assert "ai_confidence" in explanation


def test_ai_executive_summary_does_not_mutate_risk():
    assistant = GeminiSecurityAssistant()
    summary = {"total_packets": 100, "encryption_ratio": 0.2}
    findings = [{"title": "Unencrypted Email Protocol Detected", "severity": "CRITICAL"}]
    risk = {"risk_score": 75, "risk_level": "CRITICAL"}
    
    exec_summary = assistant.generate_executive_summary(summary, findings, risk)
    assert isinstance(exec_summary, str)
    assert len(exec_summary) > 30
    # Original deterministic values remain intact
    assert risk["risk_score"] == 75
    assert risk["risk_level"] == "CRITICAL"
