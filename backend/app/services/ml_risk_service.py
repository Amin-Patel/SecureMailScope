"""
ML risk assessment service for SecureMailScope.

Deliberately kept separate from security_engine.py: the rule engine stays
100% deterministic and auditable on its own, and this layer sits alongside
it as an independent, advisory second opinion -- the architectural split
several other SIH26159 teams converged on independently (deterministic
rules / unsupervised anomaly detection / supervised risk classification
as three separate concerns, not one tangled module).

Fusion rule: the ML classifier's assessment may only ever *raise* the
overall risk level the deterministic engine already computed, never lower
or suppress it. A rule-confirmed CRITICAL finding stays CRITICAL regardless
of what the model predicts -- the model exists to catch what the rules
might have missed, not to second-guess what they found.
"""

from typing import Dict, List, Optional

from ml.feature_extractor import extract_session_features, effective_tls_version
from core.security_engine import LEVEL_MIN_GRADE
from ml.risk_classifier import get_risk_classifier
from ml.anomaly_detector import get_anomaly_detector

_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def assess_sessions(
    tls_handshakes: List[Dict], certificates: List[Dict], certificate_chains: Optional[List[Dict]] = None
) -> Optional[Dict]:
    """
    Run the ML risk classifier and anomaly detector over every negotiated
    TLS session in this capture. Returns None (not an empty result) if no
    trained model is available, so callers can distinguish "ran and found
    nothing" from "couldn't run at all" -- the frontend and report should
    say "ML assessment unavailable," not silently show a clean result.
    """
    classifier = get_risk_classifier()
    detector = get_anomaly_detector()
    if classifier is None and detector is None:
        return None

    certificate = certificates[0] if certificates else None
    pki_findings = (certificate_chains or [{}])[0].get("pki_findings") if certificate_chains else None
    session_assessments = []

    for hs in tls_handshakes:
        if hs.get("handshake_type") != "ServerHello":
            continue
        ciphers = hs.get("cipher_suites") or []
        cipher_code = ciphers[0] if ciphers else None
        features = extract_session_features(
            hs.get("tls_version"), cipher_code, certificate, starttls_used=False, pki_findings=pki_findings
        )

        assessment = {
            "src": hs.get("src"),
            "dst": hs.get("dst"),
            "tls_version": effective_tls_version(hs.get("tls_version"), cipher_code),
        }
        if classifier is not None:
            assessment.update(classifier.predict(features))
        if detector is not None:
            assessment.update(detector.predict(features))
        session_assessments.append(assessment)

    return {
        "model_available": True,
        "classifier_available": classifier is not None,
        "anomaly_detector_available": detector is not None,
        "sessions": session_assessments,
    }


def fuse_risk_level(deterministic_risk: Dict, ml_assessment: Optional[Dict]) -> Dict:
    """
    Apply the raise-only fusion rule. Returns the deterministic risk dict
    augmented with ml_risk_level (the highest label the model assigned any
    session, if any) and fused_risk_level (never lower than the
    deterministic level).
    """
    result = dict(deterministic_risk)
    deterministic_level = deterministic_risk.get("risk_level", "LOW")

    if not ml_assessment or not ml_assessment.get("sessions"):
        result["ml_risk_level"] = None
        result["fused_risk_level"] = deterministic_level
        result["ml_elevated"] = False
        return result

    ml_labels = [s["ml_risk_label"] for s in ml_assessment["sessions"] if "ml_risk_label" in s]
    if not ml_labels:
        result["ml_risk_level"] = None
        result["fused_risk_level"] = deterministic_level
        result["ml_elevated"] = False
        return result

    highest_ml_label = max(ml_labels, key=lambda l: _SEVERITY_RANK.get(l, 0))
    deterministic_rank = _SEVERITY_RANK.get(deterministic_level, 0)
    ml_rank = _SEVERITY_RANK.get(highest_ml_label, 0)

    result["ml_risk_level"] = highest_ml_label
    if ml_rank > deterministic_rank:
        result["fused_risk_level"] = highest_ml_label
        result["ml_elevated"] = True
        floor = LEVEL_MIN_GRADE.get(highest_ml_label)
        if floor and floor > result.get("risk_grade", "A"):  # letters sort A<F; worse grade wins
            result["risk_grade"] = floor
    else:
        result["fused_risk_level"] = deterministic_level
        result["ml_elevated"] = False

    anomaly_count = sum(1 for s in ml_assessment["sessions"] if s.get("is_anomaly"))
    result["ml_anomaly_session_count"] = anomaly_count

    return result
