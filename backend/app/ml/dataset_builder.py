"""
Training-data generation for the ML risk classifier and anomaly detector.

There is no publicly labeled "is this TLS session cryptographically risky"
dataset -- every team that built this for SIH26159 either hand-labeled a
handful of examples or distilled their own rule engine. We do the latter:
generate synthetic sessions spanning the feature space, label each one by
what SecurityEngine's own rules would conclude (max-severity-wins, same
severity levels the rule engine already uses), then train a classifier to
reproduce and generalize that decision boundary.

This also exposes a path to fold in *real* captures: extract_real_sessions()
takes the same tls_handshakes/certificates lists pcap_analyzer.py already
produces and runs them through the identical feature extractor + labeling
function, so real PCAPs (our own demo captures today, ISCXTor2016 email
traffic later if access comes through) slot in with zero rework -- they
just become more rows in the same dataset.
"""

import itertools
from typing import Dict, List, Optional, Tuple

from core.cipher_suites import CIPHER_SUITE_REGISTRY
from ml.feature_extractor import extract_session_features, features_to_vector, FEATURE_NAMES

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
RANK_TO_SEVERITY = {v: k for k, v in SEVERITY_RANK.items()}


def label_session(features: Dict[str, float]) -> str:
    """
    Distill a session's overall risk label from the same rules
    SecurityEngine uses, at max-severity-wins granularity: a session's
    label is its single worst finding, not a summed/bucketed score --
    "your posture is only as strong as your weakest link," and it avoids
    having to recalibrate score thresholds for per-session vs per-capture
    granularity.
    """
    active: List[str] = []

    if features["plaintext_session"]:
        active.append("CRITICAL")  # plaintext_protocol
    if features["tls_version_ssl3"]:
        active.append("CRITICAL")  # deprecated_protocol (SSL 3.0 / POODLE)
    if features["tls_version_tls10"]:
        active.append("CRITICAL")  # deprecated_protocol (TLS 1.0)
    if features["tls_version_tls11"]:
        active.append("HIGH")      # deprecated_protocol (TLS 1.1)
    if features["cipher_weak"]:
        active.append("CRITICAL")  # weak_cipher
    if features["cert_signature_weak"]:
        active.append("HIGH")      # weak_signature
    if features["has_certificate"] and not features["cert_key_size_adequate"]:
        active.append("HIGH")      # insufficient_key_size
    if features["cert_expired"]:
        active.append("HIGH")      # expired_certificate / CERT_EXPIRED
    if features["cert_self_signed"]:
        active.append("MEDIUM")    # self_signed_certificate
    if features["cert_not_yet_valid"]:
        active.append("HIGH")      # CERT_NOT_YET_VALID
    if features["cert_hostname_mismatch"]:
        active.append("HIGH")      # CERT_HOSTNAME_MISMATCH
    if features["cert_signature_invalid"]:
        active.append("CRITICAL")  # CERT_SIGNATURE_INVALID
    if features["cert_chain_order_invalid"]:
        active.append("MEDIUM")    # CERT_INVALID_CHAIN_ORDER
    if features["cert_untrusted_ca"]:
        active.append("HIGH")      # CERT_UNTRUSTED_CA
    if features["cert_invalid_eku"]:
        active.append("MEDIUM")    # CERT_INVALID_EKU
    if features["cert_invalid_basic_constraints"]:
        active.append("CRITICAL")  # CERT_INVALID_BASIC_CONSTRAINTS
    if (
        not features["tls_version_tls13"]
        and not features["plaintext_session"]
        and features["cipher_weak"] == 0.0  # weak-cipher sessions are already CRITICAL
        and features["cipher_unknown"] == 0.0  # matches check_forward_secrecy: unknown ciphers are skipped, not guessed at
        and features["cipher_forward_secret"] == 0.0
    ):
        active.append("HIGH")      # no_forward_secrecy (TLS 1.3 is exempt -- always ephemeral)

    if not active:
        return "LOW"
    best_rank = max(SEVERITY_RANK[s] for s in active)
    return RANK_TO_SEVERITY[best_rank]


# ─── SYNTHETIC CERTIFICATE VARIANTS ───
# Representative, not exhaustive -- covers every individual cert-related
# rule condition and a couple of realistic combinations, rather than the
# full combinatorial cross product of every flag.
_SYNTHETIC_CERTS: List[Optional[Dict]] = [
    None,
    {"is_expired": False, "is_self_signed": False, "key_size": 2048, "public_key_algorithm": "rsaEncryption", "signature_algorithm": "sha256"},
    {"is_expired": False, "is_self_signed": False, "key_size": 256, "public_key_algorithm": "ecPublicKey", "signature_algorithm": "sha384"},
    {"is_expired": True, "is_self_signed": False, "key_size": 2048, "public_key_algorithm": "rsaEncryption", "signature_algorithm": "sha256"},
    {"is_expired": False, "is_self_signed": True, "key_size": 2048, "public_key_algorithm": "rsaEncryption", "signature_algorithm": "sha256"},
    {"is_expired": False, "is_self_signed": False, "key_size": 1024, "public_key_algorithm": "rsaEncryption", "signature_algorithm": "sha256"},
    {"is_expired": False, "is_self_signed": False, "key_size": 2048, "public_key_algorithm": "rsaEncryption", "signature_algorithm": "md5WithRSAEncryption"},
    {"is_expired": True, "is_self_signed": True, "key_size": 1024, "public_key_algorithm": "rsaEncryption", "signature_algorithm": "md5WithRSAEncryption"},
]

# ─── SYNTHETIC PKI FINDINGS VARIANTS ───
# One representative example per chain-level rule cert_analyzer.py can
# raise (excluding CERT_EXPIRED/CERT_SELF_SIGNED, which are already driven
# directly off the certificate dict above, not off a chain finding).
_PKI_FINDING_RULE_IDS = [
    "CERT_NOT_YET_VALID",
    "CERT_HOSTNAME_MISMATCH",
    "CERT_SIGNATURE_INVALID",
    "CERT_INVALID_CHAIN_ORDER",
    "CERT_UNTRUSTED_CA",
    "CERT_INVALID_EKU",
    "CERT_INVALID_BASIC_CONSTRAINTS",
]
_SYNTHETIC_PKI_FINDINGS: List[Optional[List[Dict]]] = [None] + [
    [{"rule_id": rule_id}] for rule_id in _PKI_FINDING_RULE_IDS
]

# Cross every certificate variant against every PKI-findings variant --
# a chain-level finding only makes sense alongside a presented certificate,
# so the None-certificate case only ever pairs with no findings.
_SYNTHETIC_CERT_PKI_PAIRS: List[Tuple[Optional[Dict], Optional[List[Dict]]]] = [(None, None)] + [
    (cert, pki_findings)
    for cert in _SYNTHETIC_CERTS[1:]
    for pki_findings in _SYNTHETIC_PKI_FINDINGS
]

_TLS_VERSIONS = ["SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]

# Sentinel codes deliberately absent from CIPHER_SUITE_REGISTRY, so the
# dataset includes real examples of "cipher observed but not recognized"
# rather than leaving that feature state entirely untrained-on.
_UNKNOWN_CIPHER_CODES = ["0xfafa", "0x9999"]


def generate_synthetic_dataset() -> Tuple[List[List[float]], List[str]]:
    """
    Cross every TLS version (and no-TLS/plaintext) against every registered
    cipher suite, every synthetic certificate x PKI-findings pairing, and
    STARTTLS state. Deduplicated, since many combinations collapse to the
    same feature vector (e.g. no-TLS sessions are identical regardless of
    which cipher "would have" been picked -- there isn't one).
    """
    seen: Dict[Tuple[float, ...], str] = {}

    # Plaintext / no-TLS sessions: no cipher, but certificate and STARTTLS
    # state still vary (a session can present no TLS yet still be probed
    # for a cert in other checks -- keep the space consistent).
    for (cert, pki_findings), starttls in itertools.product(_SYNTHETIC_CERT_PKI_PAIRS, (True, False)):
        features = extract_session_features(None, None, cert, starttls, pki_findings)
        vector = tuple(features_to_vector(features))
        seen[vector] = label_session(features)

    for tls_version, cipher_code, (cert, pki_findings), starttls in itertools.product(
        _TLS_VERSIONS, CIPHER_SUITE_REGISTRY.keys(), _SYNTHETIC_CERT_PKI_PAIRS, (True, False)
    ):
        features = extract_session_features(tls_version, cipher_code, cert, starttls, pki_findings)
        vector = tuple(features_to_vector(features))
        seen[vector] = label_session(features)

    # Unrecognized-cipher examples: a session with a cipher code that isn't
    # in our registry should still be trainable-on, not an untested state.
    for tls_version, cipher_code, (cert, pki_findings), starttls in itertools.product(
        _TLS_VERSIONS, _UNKNOWN_CIPHER_CODES, _SYNTHETIC_CERT_PKI_PAIRS, (True, False)
    ):
        features = extract_session_features(tls_version, cipher_code, cert, starttls, pki_findings)
        vector = tuple(features_to_vector(features))
        seen[vector] = label_session(features)

    vectors = [list(v) for v in seen.keys()]
    labels = list(seen.values())
    return vectors, labels


def extract_real_sessions(
    tls_handshakes: List[Dict], certificates: List[Dict], certificate_chains: Optional[List[Dict]] = None
) -> Tuple[List[List[float]], List[str]]:
    """
    Build (feature_vector, label) pairs from a real analyzed capture's
    negotiated ServerHello sessions, matched to the nearest certificate and
    chain by presence (the same coarse matching the rest of the pipeline
    uses -- certificates/chains aren't currently linked to a specific
    handshake by frame). Real PCAPs (our demo captures today, external
    corpora later) become more rows in the same dataset through this one
    function.
    """
    vectors: List[List[float]] = []
    labels: List[str] = []
    cert = certificates[0] if certificates else None
    pki_findings = (certificate_chains or [{}])[0].get("pki_findings") if certificate_chains else None

    for hs in tls_handshakes:
        if hs.get("handshake_type") != "ServerHello":
            continue
        ciphers = hs.get("cipher_suites") or []
        cipher_code = ciphers[0] if ciphers else None
        features = extract_session_features(
            hs.get("tls_version"), cipher_code, cert, starttls_used=False, pki_findings=pki_findings
        )
        vectors.append(features_to_vector(features))
        labels.append(label_session(features))

    return vectors, labels
