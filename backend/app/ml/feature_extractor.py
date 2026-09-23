"""
Session-level feature extraction for the ML risk classifier and anomaly
detector.

Converts the same signals SecurityEngine's deterministic rules already look
at (negotiated TLS version, cipher suite properties, certificate validity/
key-size/signature) into a fixed-order numeric feature vector. Reuses the
existing cipher-suite registry and weak-signature/key-size constants rather
than re-deriving them, so the ML layer and the rule engine can never
disagree about what "weak" or "forward-secret" means for the same cipher.
"""

from typing import Dict, List, Optional

from core.cipher_suites import lookup as lookup_cipher_suite
from core.security_engine import WEAK_SIG_ALGOS, MIN_KEY_SIZES

FEATURE_NAMES: List[str] = [
    "tls_version_ssl3",
    "tls_version_tls10",
    "tls_version_tls11",
    "tls_version_tls12",
    "tls_version_tls13",
    "tls_version_none",
    "cipher_weak",
    "cipher_forward_secret",
    "cipher_aead",
    "cipher_unknown",
    "has_certificate",
    "cert_expired",
    "cert_self_signed",
    "cert_key_size_adequate",
    "cert_signature_weak",
    "cert_not_yet_valid",
    "cert_hostname_mismatch",
    "cert_signature_invalid",
    "cert_chain_order_invalid",
    "cert_untrusted_ca",
    "cert_invalid_eku",
    "cert_invalid_basic_constraints",
    "starttls_used",
    "plaintext_session",
]

_AEAD_MARKERS = ("GCM", "CHACHA20", "CCM")

# Maps cert_analyzer.py's _evaluate_pki_rules() rule_ids to the feature they
# set. CERT_EXPIRED and CERT_SELF_SIGNED are deliberately excluded -- those
# are already covered by cert_expired/cert_self_signed above, sourced
# directly from the certificate dict rather than from a chain-level finding.
_PKI_RULE_TO_FEATURE = {
    "CERT_NOT_YET_VALID": "cert_not_yet_valid",
    "CERT_HOSTNAME_MISMATCH": "cert_hostname_mismatch",
    "CERT_SIGNATURE_INVALID": "cert_signature_invalid",
    "CERT_INVALID_CHAIN_ORDER": "cert_chain_order_invalid",
    "CERT_UNTRUSTED_CA": "cert_untrusted_ca",
    "CERT_INVALID_EKU": "cert_invalid_eku",
    "CERT_INVALID_BASIC_CONSTRAINTS": "cert_invalid_basic_constraints",
}

_TLS_VERSION_FEATURE = {
    "SSL 3.0": "tls_version_ssl3",
    "TLS 1.0": "tls_version_tls10",
    "TLS 1.1": "tls_version_tls11",
    "TLS 1.2": "tls_version_tls12",
    "TLS 1.3": "tls_version_tls13",
}


def _cert_key_size_adequate(certificate: Optional[Dict]) -> float:
    if not certificate:
        return 0.0
    key_algo = (certificate.get("public_key_algorithm") or "").lower()
    key_size = certificate.get("key_size") or 0
    if not key_size:
        return 0.0
    for algo, min_size in MIN_KEY_SIZES.items():
        if algo in key_algo:
            return 1.0 if key_size >= min_size else 0.0
    # Unknown key algorithm: don't guess -- treat as not-confirmed-adequate.
    return 0.0


def _cert_signature_weak(certificate: Optional[Dict]) -> float:
    if not certificate:
        return 0.0
    sig_algo = (certificate.get("signature_algorithm") or "").lower()
    return 1.0 if any(weak in sig_algo for weak in WEAK_SIG_ALGOS) else 0.0


def effective_tls_version(tls_version: Optional[str], cipher_code: Optional[str]) -> Optional[str]:
    """The TLS version this session actually negotiated, correcting for
    tshark_helper.py reading the record-layer version (frozen at "TLS 1.2"
    for TLS 1.3 per RFC 8446) rather than the real negotiated version.
    Exposed separately so callers displaying the version get the same
    corrected value the feature vector was built from."""
    info = lookup_cipher_suite(cipher_code) if cipher_code else None
    if info and info["kex"] == "TLS1.3":
        return "TLS 1.3"
    return tls_version


def extract_session_features(
    tls_version: Optional[str],
    cipher_code: Optional[str],
    certificate: Optional[Dict] = None,
    starttls_used: bool = False,
    pki_findings: Optional[List[Dict]] = None,
) -> Dict[str, float]:
    """
    Build one session's feature vector.

    tls_version: one of "SSL 3.0"/"TLS 1.0"/"TLS 1.1"/"TLS 1.2"/"TLS 1.3",
        or None/anything else for a session with no TLS at all.
    cipher_code: the raw tshark hex cipher-suite code from the negotiated
        ServerHello (e.g. "0x1302"), or None if no TLS was negotiated.
    certificate: the matched certificate dict for this session (same shape
        cert_analyzer.py produces), or None if no certificate was observed.
    starttls_used: whether an explicit STARTTLS upgrade was observed for
        this session (as opposed to implicit TLS or no encryption at all).
    pki_findings: the matched certificate chain's 'pki_findings' list (same
        shape CertificateAnalyzer._evaluate_pki_rules() produces), or None
        if no chain was analyzed. Only meaningful alongside a certificate --
        a chain-level finding can't exist without a presented chain.
    """
    features = {name: 0.0 for name in FEATURE_NAMES}

    cipher_info = lookup_cipher_suite(cipher_code) if cipher_code else None
    corrected_version = effective_tls_version(tls_version, cipher_code)

    version_feature = _TLS_VERSION_FEATURE.get(corrected_version or "")
    if version_feature:
        features[version_feature] = 1.0
    else:
        features["tls_version_none"] = 1.0
        features["plaintext_session"] = 1.0

    if cipher_code:
        if cipher_info:
            features["cipher_weak"] = 1.0 if cipher_info["weak"] else 0.0
            features["cipher_forward_secret"] = 1.0 if cipher_info["forward_secret"] else 0.0
            features["cipher_aead"] = 1.0 if any(m in cipher_info["name"].upper() for m in _AEAD_MARKERS) else 0.0
        else:
            features["cipher_unknown"] = 1.0

    if certificate:
        features["has_certificate"] = 1.0
        features["cert_expired"] = 1.0 if certificate.get("is_expired") else 0.0
        features["cert_self_signed"] = 1.0 if certificate.get("is_self_signed") else 0.0
        features["cert_key_size_adequate"] = _cert_key_size_adequate(certificate)
        features["cert_signature_weak"] = _cert_signature_weak(certificate)

        for finding in (pki_findings or []):
            feature_name = _PKI_RULE_TO_FEATURE.get(finding.get("rule_id"))
            if feature_name:
                features[feature_name] = 1.0

    features["starttls_used"] = 1.0 if starttls_used else 0.0

    return features


def features_to_vector(features: Dict[str, float]) -> List[float]:
    """Convert a feature dict to an ordered vector matching FEATURE_NAMES."""
    return [features[name] for name in FEATURE_NAMES]
