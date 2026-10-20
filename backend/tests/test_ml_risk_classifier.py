"""
Comprehensive Unit Tests for SecureMailScope ML Risk Classifier and Anomaly Detector
Validates feature extraction, model loading, advisory predictions, and raise-only risk fusion.
"""

import pytest
from pathlib import Path
import sys

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))
sys.path.insert(0, str(backend_dir / "app"))

from app.ml.feature_extractor import (
    extract_session_features,
    features_to_vector,
    effective_tls_version,
    FEATURE_NAMES,
)
from app.ml.risk_classifier import get_risk_classifier, RiskClassifier
from app.ml.anomaly_detector import get_anomaly_detector, AnomalyDetector
from app.services.ml_risk_service import assess_sessions, fuse_risk_level


def test_feature_extractor_dimension_and_names():
    """Verify feature extractor produces exactly 24 features with correct keys."""
    features = extract_session_features(
        tls_version="TLS 1.3",
        cipher_code="0x1302",
        certificate=None,
        starttls_used=False,
    )
    assert len(features) == 24
    assert set(features.keys()) == set(FEATURE_NAMES)
    assert features["tls_version_tls13"] == 1.0
    assert features["tls_version_ssl3"] == 0.0
    assert features["cipher_aead"] == 1.0
    assert features["cipher_weak"] == 0.0

    vector = features_to_vector(features)
    assert len(vector) == 24
    assert isinstance(vector, list)


def test_effective_tls_version_rfc8446_correction():
    """Verify effective_tls_version identifies TLS 1.3 even when record layer claims TLS 1.2."""
    assert effective_tls_version("TLS 1.2", "0x1301") == "TLS 1.3"
    assert effective_tls_version("TLS 1.2", "0x1302") == "TLS 1.3"
    assert effective_tls_version("TLS 1.2", "0xc02f") == "TLS 1.2"
    assert effective_tls_version("SSL 3.0", "0x000a") == "SSL 3.0"


def test_risk_classifier_model_loading_and_prediction():
    """Verify pre-trained RandomForest model loads from disk and predicts valid risk labels."""
    clf = get_risk_classifier()
    assert clf is not None, "Trained risk classifier joblib should exist and load successfully"

    # 1. Critical scenario: SSL 3.0 + weak cipher
    crit_features = extract_session_features(
        tls_version="SSL 3.0",
        cipher_code="0x000a", # 3DES
        certificate={"is_expired": True, "is_self_signed": True, "key_size": 1024, "public_key_algorithm": "rsa"},
    )
    pred_crit = clf.predict(crit_features)
    assert pred_crit["ml_risk_label"] in ["CRITICAL", "HIGH"]
    assert 0.0 <= pred_crit["ml_confidence"] <= 1.0

    # 2. Modern TLS 1.3 scenario
    secure_features = extract_session_features(
        tls_version="TLS 1.3",
        cipher_code="0x1302",
        certificate={"is_expired": False, "is_self_signed": False, "key_size": 2048, "public_key_algorithm": "rsa"},
    )
    pred_secure = clf.predict(secure_features)
    assert pred_secure["ml_risk_label"] in ["LOW", "MEDIUM"]
    assert 0.0 <= pred_secure["ml_confidence"] <= 1.0


def test_anomaly_detector_model_loading_and_prediction():
    """Verify pre-trained IsolationForest anomaly detector loads and scores sessions."""
    det = get_anomaly_detector()
    assert det is not None, "Trained anomaly detector joblib should exist and load successfully"

    features = extract_session_features(
        tls_version="TLS 1.2",
        cipher_code="0xc030",
        certificate={"is_expired": False, "is_self_signed": False, "key_size": 2048, "public_key_algorithm": "rsa"},
    )
    pred = det.predict(features)
    assert "is_anomaly" in pred
    assert "anomaly_score" in pred
    assert isinstance(pred["is_anomaly"], bool)
    assert isinstance(pred["anomaly_score"], float)


def test_ml_risk_service_raise_only_fusion_rule():
    """Verify raise-only fusion rule: ML can elevate risk, but NEVER lowers a rule-confirmed finding."""
    # Scenario A: Deterministic is LOW, ML predicts CRITICAL -> Fused should be CRITICAL, ml_elevated = True
    deterministic_low = {"risk_score": 10, "risk_level": "LOW", "risk_grade": "A"}
    ml_critical = {
        "sessions": [
            {"ml_risk_label": "CRITICAL", "ml_confidence": 0.95, "is_anomaly": True}
        ]
    }
    fused_a = fuse_risk_level(deterministic_low, ml_critical)
    assert fused_a["fused_risk_level"] == "CRITICAL"
    assert fused_a["ml_elevated"] is True
    assert fused_a["ml_anomaly_session_count"] == 1

    # Scenario B: Deterministic is CRITICAL, ML predicts LOW -> Fused MUST STAY CRITICAL
    deterministic_crit = {"risk_score": 90, "risk_level": "CRITICAL", "risk_grade": "F"}
    ml_low = {
        "sessions": [
            {"ml_risk_label": "LOW", "ml_confidence": 0.98, "is_anomaly": False}
        ]
    }
    fused_b = fuse_risk_level(deterministic_crit, ml_low)
    assert fused_b["fused_risk_level"] == "CRITICAL"
    assert fused_b["ml_elevated"] is False


def test_assess_sessions_pipeline():
    """Verify assess_sessions extracts features and runs both models across handshakes."""
    handshakes = [
        {
            "handshake_type": "ServerHello",
            "src": "192.168.1.10",
            "dst": "192.168.1.25",
            "tls_version": "TLS 1.2",
            "cipher_suites": ["0xc030"],
        }
    ]
    certificates = [
        {
            "is_expired": False,
            "is_self_signed": False,
            "key_size": 2048,
            "public_key_algorithm": "rsa",
        }
    ]

    result = assess_sessions(handshakes, certificates)
    assert result is not None
    assert result["model_available"] is True
    assert len(result["sessions"]) == 1
    session = result["sessions"][0]
    assert "ml_risk_label" in session
    assert "ml_confidence" in session
    assert "is_anomaly" in session
