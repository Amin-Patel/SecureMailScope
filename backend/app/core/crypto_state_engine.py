"""
Cryptographic State Reasoning Engine for SecureMailScope (USP 2)

Transforms individual rule outputs and packet capture telemetry into a unified,
evidence-backed, cross-property cryptographic state assessment with explicit
uncertainty quantification, explainable rationales, and connection-level forensic isolation.
"""

from typing import List, Dict, Any, Optional, Set
from datetime import datetime


# ─── 1. CONSTANTS & DOMAIN MODELS ───

class CryptoState:
    """Explicit 7-state cryptographic state vocabulary"""
    SECURE_WITHIN_OBSERVED_SCOPE = "SECURE_WITHIN_OBSERVED_SCOPE"
    ACCEPTABLE_WITH_LIMITATIONS = "ACCEPTABLE_WITH_LIMITATIONS"
    CRYPTOGRAPHIC_VALIDATION_CONCERN = "CRYPTOGRAPHIC_VALIDATION_CONCERN"
    CRYPTOGRAPHICALLY_WEAK = "CRYPTOGRAPHICALLY_WEAK"
    CRYPTOGRAPHIC_FAILURE = "CRYPTOGRAPHIC_FAILURE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    ANALYSIS_ERROR = "ANALYSIS_ERROR"

    LABELS = {
        SECURE_WITHIN_OBSERVED_SCOPE: "Secure Within Observed Scope",
        ACCEPTABLE_WITH_LIMITATIONS: "Acceptable With Limitations",
        CRYPTOGRAPHIC_VALIDATION_CONCERN: "Cryptographic Validation Concern",
        CRYPTOGRAPHICALLY_WEAK: "Cryptographically Weak",
        CRYPTOGRAPHIC_FAILURE: "Cryptographic Failure",
        INSUFFICIENT_EVIDENCE: "Insufficient Evidence",
        ANALYSIS_ERROR: "Analysis Error"
    }

    DESCRIPTIONS = {
        SECURE_WITHIN_OBSERVED_SCOPE: (
            "All observed cryptographic properties satisfy modern security standards (TLS 1.2+, AEAD ciphers, "
            "valid CA-signed certificates). Evidence is sufficient to establish transport integrity within observed packet scope."
        ),
        ACCEPTABLE_WITH_LIMITATIONS: (
            "Observed cryptographic properties meet baseline standards, but non-critical unknowns remain (e.g., client-side trust "
            "store validation or OCSP revocation status cannot be conclusively established purely from network wire data)."
        ),
        CRYPTOGRAPHIC_VALIDATION_CONCERN: (
            "Material validation issue or unverified prerequisite detected (e.g., self-signed certificates, unconfirmed STARTTLS "
            "completion, or borderline key configurations that require forensic scrutiny)."
        ),
        CRYPTOGRAPHICALLY_WEAK: (
            "Cryptographic weaknesses identified per RFC/NIST specifications (e.g., deprecated TLS 1.0/1.1 protocols, weak SHA-1 "
            "signatures, or sub-2048-bit RSA keys)."
        ),
        CRYPTOGRAPHIC_FAILURE: (
            "Critical cryptographic failure or vulnerability identified (e.g., unencrypted plaintext email transmissions, "
            "SSL 3.0 POODLE vulnerability, expired active certificates, or broken NULL/EXPORT/RC4/DES ciphers)."
        ),
        INSUFFICIENT_EVIDENCE: (
            "Capture contains insufficient packet volume, truncated handshakes, or absent cryptographic exchanges, preventing a "
            "defensible security conclusion."
        ),
        ANALYSIS_ERROR: (
            "Evaluation encountered an internal processing exception or corrupted capture payload."
        )
    }

    BADGE_COLORS = {
        SECURE_WITHIN_OBSERVED_SCOPE: "#10b981",       # Emerald Green
        ACCEPTABLE_WITH_LIMITATIONS: "#3b82f6",        # Blue
        CRYPTOGRAPHIC_VALIDATION_CONCERN: "#f59e0b",   # Amber / Orange
        CRYPTOGRAPHICALLY_WEAK: "#f97316",             # Vivid Orange
        CRYPTOGRAPHIC_FAILURE: "#ef4444",              # Red
        INSUFFICIENT_EVIDENCE: "#8b5cf6",              # Violet
        ANALYSIS_ERROR: "#6b7280"                      # Gray
    }


class RuleStatus:
    """Normalized rule evaluation status"""
    SATISFIED = "SATISFIED"
    VIOLATED = "VIOLATED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


# Weak cipher reference sets (matching security_engine.py)
WEAK_CIPHERS = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon', 'MD5']
WEAK_CIPHER_CODES = {
    '0X0000', '0X0001', '0X0002', '0X0003', '0X0004', '0X0005',
    '0X0006', '0X0007', '0X0008', '0X0009', '0X000A', '0X000B',
    '0X000C', '0X000D', '0X000E', '0X000F', '0X0010', '0X0011',
    '0X0012', '0X0013', '0X0014', '0X0015', '0X0016', '0X0017',
    '0X0018', '0X0019', '0X001A', '0X001B',
}
WEAK_SIG_ALGOS = ['md5', 'sha1', 'md2']
MIN_KEY_SIZES = {
    'rsa': 2048,
    'rsaencryption': 2048,
    'ec': 224,
    'ecdsa': 224,
    'dh': 2048,
    'dhe': 2048,
}


# ─── 2. ENGINE CLASS ───

class CryptographicStateEngine:
    """
    Evidence-driven Cryptographic State Reasoning Engine.
    Evaluates 10 normalized rules, executes cross-property dependency checks,
    determines evidence sufficiency, and derives an explainable unified state.
    """

    RULE_METADATA = {
        'RULE-RFC8314-PLAINTEXT': {
            'name': 'Transport Encryption Enforcement',
            'standard': 'RFC 8314 Section 3',
            'severity': 'CRITICAL',
            'target': 'Traffic Transport'
        },
        'RULE-RFC7568-SSL3': {
            'name': 'SSL 3.0 POODLE Immunity',
            'standard': 'RFC 7568 (CVE-2014-3566)',
            'severity': 'CRITICAL',
            'target': 'Protocol Negotiation'
        },
        'RULE-RFC8996-TLS10': {
            'name': 'TLS 1.0 Deprecation Compliance',
            'standard': 'RFC 8996 / PCI DSS 3.2+',
            'severity': 'CRITICAL',
            'target': 'Protocol Negotiation'
        },
        'RULE-RFC8996-TLS11': {
            'name': 'TLS 1.1 Deprecation Compliance',
            'standard': 'RFC 8996',
            'severity': 'HIGH',
            'target': 'Protocol Negotiation'
        },
        'RULE-NIST-SP800-52R2-CIPHER': {
            'name': 'Modern Cryptographic Cipher Suites',
            'standard': 'NIST SP 800-52 Rev 2',
            'severity': 'CRITICAL',
            'target': 'Cipher Suite Negotiation'
        },
        'RULE-RFC5280-SIG-ALGO': {
            'name': 'Certificate Signature Algorithm Strength',
            'standard': 'RFC 5280 Section 4.1.2.3',
            'severity': 'HIGH',
            'target': 'X.509 PKI'
        },
        'RULE-NIST-SP800-57-KEYLEN': {
            'name': 'Asymmetric Key Length Adequacy',
            'standard': 'NIST SP 800-57 Part 1',
            'severity': 'HIGH',
            'target': 'X.509 PKI'
        },
        'RULE-RFC5280-VALIDITY': {
            'name': 'Certificate Validity & Expiration',
            'standard': 'RFC 5280 Section 4.1.2.5',
            'severity': 'HIGH',
            'target': 'X.509 PKI'
        },
        'RULE-WEB-PKI-TRUST': {
            'name': 'Public CA Trust & PKI Authenticity',
            'standard': 'CAB Forum Baseline Requirements',
            'severity': 'MEDIUM',
            'target': 'X.509 PKI'
        },
        'RULE-RFC3207-STARTTLS': {
            'name': 'STARTTLS Upgrade Negotiation',
            'standard': 'RFC 3207 Section 4',
            'severity': 'HIGH',
            'target': 'Protocol Transition'
        }
    }

    def __init__(self, analysis_data: Dict[str, Any]):
        """
        Initialize with analysis payload containing summary, sessions,
        tls_handshakes, certificates, and findings.
        """
        self.data = analysis_data or {}
        self.summary = self.data.get('summary', {})
        self.sessions = self.data.get('sessions', [])
        self.handshakes = self.data.get('tls_handshakes', [])
        self.certificates = self.data.get('certificates', [])
        self.findings = self.data.get('findings', [])

        self.normalized_rules: List[Dict[str, Any]] = []
        self.cross_property_insights: List[Dict[str, Any]] = []
        self.unresolved_conditions: List[str] = []
        self.evidence_completeness: str = "Complete"
        self.overall_state: str = CryptoState.INSUFFICIENT_EVIDENCE
        self.explanation: Dict[str, Any] = {}

    def evaluate(self) -> Dict[str, Any]:
        """
        Execute full reasoning lifecycle:
        1. Evaluate 10 normalized rules.
        2. Evaluate cross-property dependencies.
        3. Evaluate evidence sufficiency and uncertainty.
        4. Derive unified cryptographic state.
        5. Generate explainable rationale.
        """
        try:
            self._evaluate_normalized_rules()
            self._evaluate_cross_property_reasoning()
            self._evaluate_evidence_sufficiency()
            self._derive_overall_state()
            self._generate_explanation()

            return {
                "overall_state": self.overall_state,
                "overall_state_label": CryptoState.LABELS.get(self.overall_state, self.overall_state),
                "state_description": CryptoState.DESCRIPTIONS.get(self.overall_state, ""),
                "badge_color": CryptoState.BADGE_COLORS.get(self.overall_state, "#6b7280"),
                "evidence_completeness": self.evidence_completeness,
                "normalized_rules": self.normalized_rules,
                "cross_property_insights": self.cross_property_insights,
                "unresolved_conditions": self.unresolved_conditions,
                "explanation": self.explanation,
                "metrics": {
                    "total_rules": len(self.normalized_rules),
                    "satisfied_count": sum(1 for r in self.normalized_rules if r['status'] == RuleStatus.SATISFIED),
                    "violated_count": sum(1 for r in self.normalized_rules if r['status'] == RuleStatus.VIOLATED),
                    "unknown_count": sum(1 for r in self.normalized_rules if r['status'] == RuleStatus.UNKNOWN),
                    "not_applicable_count": sum(1 for r in self.normalized_rules if r['status'] == RuleStatus.NOT_APPLICABLE),
                    "error_count": sum(1 for r in self.normalized_rules if r['status'] == RuleStatus.ERROR),
                },
                "evaluated_at": datetime.now().isoformat(),
                "engine_version": "2.0.0-state-reasoner"
            }
        except Exception as e:
            # Catch processing errors gracefully without crashing the whole pipeline
            return {
                "overall_state": CryptoState.ANALYSIS_ERROR,
                "overall_state_label": CryptoState.LABELS[CryptoState.ANALYSIS_ERROR],
                "state_description": f"Internal evaluation error: {str(e)}",
                "badge_color": CryptoState.BADGE_COLORS[CryptoState.ANALYSIS_ERROR],
                "evidence_completeness": "Insufficient",
                "normalized_rules": [],
                "cross_property_insights": [],
                "unresolved_conditions": [f"Evaluation aborted: {str(e)}"],
                "explanation": {
                    "summary_rationale": f"Cryptographic state reasoning could not complete due to an analysis exception: {str(e)}",
                    "state_drivers": ["Analysis Exception"],
                    "supporting_observations": [],
                    "violated_conditions": [],
                    "unresolved_conditions": [str(e)],
                    "scope_limitations": "Assessment incomplete due to processing failure."
                },
                "metrics": {"total_rules": 0, "satisfied_count": 0, "violated_count": 0, "unknown_count": 0, "not_applicable_count": 0, "error_count": 1},
                "evaluated_at": datetime.now().isoformat(),
                "engine_version": "2.0.0-state-reasoner"
            }

    # ─── 3. NORMALIZED RULE EVALUATORS ───

    def _evaluate_normalized_rules(self):
        """Evaluate each of the 10 rules into a structured outcome"""
        self.normalized_rules = [
            self._eval_rule_plaintext(),
            self._eval_rule_ssl3(),
            self._eval_rule_tls10(),
            self._eval_rule_tls11(),
            self._eval_rule_weak_ciphers(),
            self._eval_rule_weak_signatures(),
            self._eval_rule_key_sizes(),
            self._eval_rule_expired_certs(),
            self._eval_rule_self_signed_certs(),
            self._eval_rule_missing_starttls(),
        ]

    # Rule 1: Plaintext Protocols
    def _eval_rule_plaintext(self) -> Dict[str, Any]:
        rule_id = 'RULE-RFC8314-PLAINTEXT'
        meta = self.RULE_METADATA[rule_id]
        total = self.summary.get('total_packets', 0)
        plaintext = self.summary.get('plaintext_packets', 0)
        protocols = self.summary.get('protocols_detected', [])

        if total == 0:
            return self._build_rule_result(
                rule_id, meta, RuleStatus.UNKNOWN,
                observed="0 packets captured", expected="Captured packet stream",
                explanation="No email packets observed to determine encryption status.",
                missing_prereqs=["Packet capture stream"]
            )

        plaintext_protocols = [p for p in protocols if p not in ['SMTPS', 'IMAPS', 'POP3S']]
        if plaintext > 0 and plaintext_protocols:
            pct = round((plaintext / total) * 100, 1)
            return self._build_rule_result(
                rule_id, meta, RuleStatus.VIOLATED,
                observed=f"{plaintext}/{total} packets ({pct}%) unencrypted on {', '.join(plaintext_protocols)}",
                expected="100% encrypted email transport (TLS wrapper or STARTTLS)",
                explanation=f"Unencrypted email traffic detected on {', '.join(plaintext_protocols)}. Sensitive data and credentials transmitted in cleartext.",
                evidence_refs=[f"session:{s.get('id', idx)}" for idx, s in enumerate(self.sessions) if not s.get('encrypted')]
            )

        return self._build_rule_result(
            rule_id, meta, RuleStatus.SATISFIED,
            observed="0 plaintext packets; all email streams use TLS encryption",
            expected="100% encrypted email transport",
            explanation="All observed email transmissions are protected by transport-layer encryption.",
            evidence_refs=[f"session:{s.get('id', idx)}" for idx, s in enumerate(self.sessions) if s.get('encrypted')]
        )

    # Rule 2: SSL 3.0
    def _eval_rule_ssl3(self) -> Dict[str, Any]:
        rule_id = 'RULE-RFC7568-SSL3'
        meta = self.RULE_METADATA[rule_id]
        tls_versions = self.summary.get('tls_versions', {})

        if not tls_versions and not self.handshakes:
            if self.summary.get('total_packets', 0) > 0 and self.summary.get('plaintext_packets', 0) == self.summary.get('total_packets', 0):
                return self._build_rule_result(
                    rule_id, meta, RuleStatus.NOT_APPLICABLE,
                    observed="Plaintext traffic only; no TLS handshakes",
                    expected="Modern TLS (1.2 or 1.3)",
                    explanation="Rule not applicable because traffic does not utilize TLS."
                )
            return self._build_rule_result(
                rule_id, meta, RuleStatus.UNKNOWN,
                observed="No completed TLS handshake metadata",
                expected="Completed TLS handshake with negotiated version",
                explanation="TLS versions could not be determined due to missing handshake messages.",
                missing_prereqs=["TLS ServerHello / Handshake messages"]
            )

        if 'SSL 3.0' in tls_versions:
            count = tls_versions['SSL 3.0']
            return self._build_rule_result(
                rule_id, meta, RuleStatus.VIOLATED,
                observed=f"SSL 3.0 negotiated in {count} handshake(s)",
                expected="TLS 1.2 or TLS 1.3",
                explanation="SSL 3.0 is fundamentally broken and vulnerable to POODLE padding oracle attacks (CVE-2014-3566).",
                evidence_refs=[f"handshake:{hs.get('id', i)}" for i, hs in enumerate(self.handshakes) if hs.get('version') == 'SSL 3.0']
            )

        return self._build_rule_result(
            rule_id, meta, RuleStatus.SATISFIED,
            observed=f"Versions observed: {', '.join(tls_versions.keys()) or 'Modern TLS'}",
            expected="No SSL 3.0",
            explanation="SSL 3.0 was not detected in any observed TLS negotiation.",
            evidence_refs=[f"handshake:{hs.get('id', i)}" for i, hs in enumerate(self.handshakes)]
        )

    # Rule 3: TLS 1.0
    def _eval_rule_tls10(self) -> Dict[str, Any]:
        rule_id = 'RULE-RFC8996-TLS10'
        meta = self.RULE_METADATA[rule_id]
        tls_versions = self.summary.get('tls_versions', {})

        if not tls_versions and not self.handshakes:
            status = RuleStatus.NOT_APPLICABLE if self.summary.get('plaintext_packets', 0) > 0 else RuleStatus.UNKNOWN
            return self._build_rule_result(
                rule_id, meta, status,
                observed="No TLS handshakes observed", expected="TLS 1.2 or 1.3",
                explanation="TLS 1.0 check cannot be evaluated without TLS handshake evidence."
            )

        if 'TLS 1.0' in tls_versions:
            count = tls_versions['TLS 1.0']
            return self._build_rule_result(
                rule_id, meta, RuleStatus.VIOLATED,
                observed=f"TLS 1.0 negotiated in {count} handshake(s)",
                expected="TLS 1.2 or TLS 1.3 (RFC 8996 deprecated)",
                explanation="TLS 1.0 was formally deprecated in 2021 (RFC 8996) and violates PCI DSS 3.2+ requirements.",
                evidence_refs=[f"handshake:{hs.get('id', i)}" for i, hs in enumerate(self.handshakes) if hs.get('version') == 'TLS 1.0']
            )

        return self._build_rule_result(
            rule_id, meta, RuleStatus.SATISFIED,
            observed=f"Observed TLS versions: {', '.join(tls_versions.keys()) or 'TLS 1.2+'}",
            expected="TLS 1.2 or TLS 1.3",
            explanation="Deprecated protocol TLS 1.0 was not observed.",
            evidence_refs=[f"handshake:{hs.get('id', i)}" for i, hs in enumerate(self.handshakes)]
        )

    # Rule 4: TLS 1.1
    def _eval_rule_tls11(self) -> Dict[str, Any]:
        rule_id = 'RULE-RFC8996-TLS11'
        meta = self.RULE_METADATA[rule_id]
        tls_versions = self.summary.get('tls_versions', {})

        if not tls_versions and not self.handshakes:
            status = RuleStatus.NOT_APPLICABLE if self.summary.get('plaintext_packets', 0) > 0 else RuleStatus.UNKNOWN
            return self._build_rule_result(
                rule_id, meta, status,
                observed="No TLS handshakes observed", expected="TLS 1.2 or 1.3",
                explanation="TLS 1.1 check requires TLS handshake observations."
            )

        if 'TLS 1.1' in tls_versions:
            count = tls_versions['TLS 1.1']
            return self._build_rule_result(
                rule_id, meta, RuleStatus.VIOLATED,
                observed=f"TLS 1.1 negotiated in {count} handshake(s)",
                expected="TLS 1.2 or TLS 1.3 (RFC 8996 deprecated)",
                explanation="TLS 1.1 is deprecated per RFC 8996 due to weak cryptographic primitives and lack of modern AEAD support.",
                evidence_refs=[f"handshake:{hs.get('id', i)}" for i, hs in enumerate(self.handshakes) if hs.get('version') == 'TLS 1.1']
            )

        return self._build_rule_result(
            rule_id, meta, RuleStatus.SATISFIED,
            observed=f"Observed TLS versions: {', '.join(tls_versions.keys()) or 'TLS 1.2+'}",
            expected="TLS 1.2 or TLS 1.3",
            explanation="Deprecated protocol TLS 1.1 was not observed.",
            evidence_refs=[f"handshake:{hs.get('id', i)}" for i, hs in enumerate(self.handshakes)]
        )

    # Rule 5: Weak Ciphers
    def _eval_rule_weak_ciphers(self) -> Dict[str, Any]:
        rule_id = 'RULE-NIST-SP800-52R2-CIPHER'
        meta = self.RULE_METADATA[rule_id]

        if not self.handshakes:
            status = RuleStatus.NOT_APPLICABLE if self.summary.get('plaintext_packets', 0) > 0 else RuleStatus.UNKNOWN
            return self._build_rule_result(
                rule_id, meta, status,
                observed="No TLS handshakes with cipher suite records",
                expected="Modern AEAD cipher suites (GCM, ChaCha20-Poly1305)",
                explanation="Cipher suite evaluations require captured TLS handshakes."
            )

        weak_found = set()
        strong_found = set()
        ciphers_observed = []

        for hs in self.handshakes:
            for cipher in hs.get('cipher_suites', []):
                ciphers_observed.append(cipher)
                cipher_upper = cipher.upper()
                if cipher_upper in WEAK_CIPHER_CODES or any(w.upper() in cipher_upper for w in WEAK_CIPHERS):
                    weak_found.add(cipher)
                else:
                    strong_found.add(cipher)

        if not ciphers_observed:
            return self._build_rule_result(
                rule_id, meta, RuleStatus.UNKNOWN,
                observed="TLS handshakes present but cipher suites empty or unparsed",
                expected="Parsed negotiated cipher suite",
                explanation="Cipher suites could not be extracted from handshake messages.",
                missing_prereqs=["ServerHello cipher suite field"]
            )

        if weak_found:
            return self._build_rule_result(
                rule_id, meta, RuleStatus.VIOLATED,
                observed=f"Weak cipher(s) detected: {', '.join(list(weak_found)[:3])}",
                expected="Secure AEAD ciphers (AES-GCM, ChaCha20-Poly1305)",
                explanation=f"Weak or obsolete cipher suites ({', '.join(list(weak_found)[:3])}) offered or negotiated. Vulnerable to SWEET32, BEAST, or RC4 biases.",
                evidence_refs=[f"handshake:{hs.get('id', i)}" for i, hs in enumerate(self.handshakes)]
            )

        return self._build_rule_result(
            rule_id, meta, RuleStatus.SATISFIED,
            observed=f"Strong ciphers observed: {', '.join(list(strong_found)[:2]) or 'AEAD compliant'}",
            expected="No weak or export-grade ciphers",
            explanation="All observed cipher suites meet NIST SP 800-52 Rev 2 standards with no legacy/weak algorithms.",
            evidence_refs=[f"handshake:{hs.get('id', i)}" for i, hs in enumerate(self.handshakes)]
        )

    # Rule 6: Weak Signatures
    def _eval_rule_weak_signatures(self) -> Dict[str, Any]:
        rule_id = 'RULE-RFC5280-SIG-ALGO'
        meta = self.RULE_METADATA[rule_id]

        if not self.certificates:
            status = RuleStatus.NOT_APPLICABLE if not self.handshakes and self.summary.get('plaintext_packets', 0) > 0 else RuleStatus.UNKNOWN
            return self._build_rule_result(
                rule_id, meta, status,
                observed="No X.509 certificates extracted from capture",
                expected="SHA-256 or stronger signature algorithm (RFC 5280)",
                explanation="Certificate signature algorithm cannot be verified without extracted certificates.",
                missing_prereqs=["Certificate exchange messages"] if status == RuleStatus.UNKNOWN else []
            )

        weak_certs = []
        strong_algos = set()
        for c in self.certificates:
            algo = (c.get('signature_algorithm') or '').lower()
            if any(w in algo for w in WEAK_SIG_ALGOS):
                weak_certs.append(c.get('subject', 'Unknown'))
            elif algo:
                strong_algos.add(algo)

        if weak_certs:
            return self._build_rule_result(
                rule_id, meta, RuleStatus.VIOLATED,
                observed=f"Weak hash algorithm in {len(weak_certs)} cert(s) ({', '.join(weak_certs[:2])})",
                expected="SHA-256, SHA-384, or Ed25519",
                explanation="Certificates utilize collision-vulnerable signature hashes (MD5 or SHA-1), allowing potential certificate forgery.",
                evidence_refs=[f"cert:{c.get('id', i)}" for i, c in enumerate(self.certificates) if any(w in (c.get('signature_algorithm') or '').lower() for w in WEAK_SIG_ALGOS)]
            )

        return self._build_rule_result(
            rule_id, meta, RuleStatus.SATISFIED,
            observed=f"Strong signature algorithm(s): {', '.join(strong_algos) or 'SHA-256+'}",
            expected="SHA-256 or stronger",
            explanation="All examined certificates utilize secure cryptographic hash algorithms for signatures.",
            evidence_refs=[f"cert:{c.get('id', i)}" for i, c in enumerate(self.certificates)]
        )

    # Rule 7: Key Sizes
    def _eval_rule_key_sizes(self) -> Dict[str, Any]:
        rule_id = 'RULE-NIST-SP800-57-KEYLEN'
        meta = self.RULE_METADATA[rule_id]

        if not self.certificates:
            status = RuleStatus.NOT_APPLICABLE if not self.handshakes and self.summary.get('plaintext_packets', 0) > 0 else RuleStatus.UNKNOWN
            return self._build_rule_result(
                rule_id, meta, status,
                observed="No certificates observed to verify public key lengths",
                expected="RSA >= 2048-bit, EC >= 224-bit (NIST SP 800-57)",
                explanation="Key length evaluation requires extracted certificate public keys.",
                missing_prereqs=["X.509 Certificate public key"] if status == RuleStatus.UNKNOWN else []
            )

        weak_keys = []
        valid_keys = []
        unobserved_keys = []
        for c in self.certificates:
            algo = (c.get('public_key_algorithm') or '').lower()
            size = c.get('key_size')
            if size and size > 0:
                is_weak = False
                for a, min_sz in MIN_KEY_SIZES.items():
                    if a in algo and size < min_sz:
                        weak_keys.append(f"{c.get('subject', 'Cert')} ({algo} {size}-bit < {min_sz}-bit)")
                        is_weak = True
                        break
                if not is_weak:
                    valid_keys.append(f"{algo.upper()} {size}-bit")
            else:
                unobserved_keys.append(c.get('subject') or 'Unknown Cert')

        if weak_keys:
            return self._build_rule_result(
                rule_id, meta, RuleStatus.VIOLATED,
                observed=f"Insufficient key length: {', '.join(weak_keys[:2])}",
                expected="RSA >= 2048 bits, EC >= 224 bits",
                explanation="Certificate public keys do not meet NIST recommended minimum security bit strengths, risking factorisation.",
                evidence_refs=[f"cert:{c.get('id', i)}" for i, c in enumerate(self.certificates)]
            )

        if not valid_keys and unobserved_keys:
            return self._build_rule_result(
                rule_id, meta, RuleStatus.UNKNOWN,
                observed="Public key length unparsed or omitted from wire certificate",
                expected="RSA >= 2048 bits, EC >= 224 bits",
                explanation="Certificate public key sizes could not be derived from the extracted certificate evidence.",
                missing_prereqs=["Certificate SubjectPublicKeyInfo key size"]
            )

        return self._build_rule_result(
            rule_id, meta, RuleStatus.SATISFIED,
            observed=f"Compliant key sizes: {', '.join(set(valid_keys)) or '>= 2048-bit'}",
            expected="RSA >= 2048 bits, EC >= 224 bits",
            explanation="All inspected certificates meet NIST SP 800-57 minimum asymmetric key length requirements.",
            evidence_refs=[f"cert:{c.get('id', i)}" for i, c in enumerate(self.certificates)]
        )

    # Rule 8: Expired Certificates
    def _eval_rule_expired_certs(self) -> Dict[str, Any]:
        rule_id = 'RULE-RFC5280-VALIDITY'
        meta = self.RULE_METADATA[rule_id]

        if not self.certificates:
            status = RuleStatus.NOT_APPLICABLE if not self.handshakes and self.summary.get('plaintext_packets', 0) > 0 else RuleStatus.UNKNOWN
            return self._build_rule_result(
                rule_id, meta, status,
                observed="No certificates observed to verify validity dates",
                expected="Valid notBefore/notAfter time window (RFC 5280)",
                explanation="Certificate validity cannot be checked without certificate metadata.",
                missing_prereqs=["Certificate validity interval"] if status == RuleStatus.UNKNOWN else []
            )

        expired = [c for c in self.certificates if c.get('is_expired')]
        if expired:
            subjects = [c.get('subject', 'Cert') for c in expired]
            return self._build_rule_result(
                rule_id, meta, RuleStatus.VIOLATED,
                observed=f"{len(expired)} certificate(s) expired: {', '.join(subjects[:2])}",
                expected="Active certificate within validity period",
                explanation="Expired certificates invalidate the chain of trust and trigger client security rejection or transport failure.",
                evidence_refs=[f"cert:{c.get('id', i)}" for i, c in enumerate(self.certificates) if c.get('is_expired')]
            )

        return self._build_rule_result(
            rule_id, meta, RuleStatus.SATISFIED,
            observed=f"All {len(self.certificates)} certificate(s) currently valid",
            expected="Active certificate within validity window",
            explanation="All presented certificates are within their valid temporal window.",
            evidence_refs=[f"cert:{c.get('id', i)}" for i, c in enumerate(self.certificates)]
        )

    # Rule 9: Self-Signed Certificates
    def _eval_rule_self_signed_certs(self) -> Dict[str, Any]:
        rule_id = 'RULE-WEB-PKI-TRUST'
        meta = self.RULE_METADATA[rule_id]

        if not self.certificates:
            status = RuleStatus.NOT_APPLICABLE if not self.handshakes and self.summary.get('plaintext_packets', 0) > 0 else RuleStatus.UNKNOWN
            return self._build_rule_result(
                rule_id, meta, status,
                observed="No certificates observed to verify CA authority",
                expected="Trusted Certificate Authority issuer",
                explanation="Trust verification requires extracted X.509 certificates.",
                missing_prereqs=["X.509 Certificate Issuer/Subject"] if status == RuleStatus.UNKNOWN else []
            )

        self_signed = [c for c in self.certificates if c.get('is_self_signed')]
        if self_signed:
            subjects = [c.get('subject', 'Cert') for c in self_signed]
            return self._build_rule_result(
                rule_id, meta, RuleStatus.VIOLATED,
                observed=f"{len(self_signed)} self-signed certificate(s): {', '.join(subjects[:2])}",
                expected="Certificate signed by public or organizational CA",
                explanation="Self-signed certificates cannot be verified via public PKI trust roots and are vulnerable to adversary spoofing / MITM.",
                evidence_refs=[f"cert:{c.get('id', i)}" for i, c in enumerate(self.certificates) if c.get('is_signed')]
            )

        return self._build_rule_result(
            rule_id, meta, RuleStatus.SATISFIED,
            observed="Certificates issued by third-party Certificate Authorities",
            expected="CA-signed certificates",
            explanation="Certificates are signed by distinct issuing authorities, avoiding self-signed trust issues.",
            evidence_refs=[f"cert:{c.get('id', i)}" for i, c in enumerate(self.certificates)]
        )

    # Rule 10: Missing STARTTLS
    def _eval_rule_missing_starttls(self) -> Dict[str, Any]:
        rule_id = 'RULE-RFC3207-STARTTLS'
        meta = self.RULE_METADATA[rule_id]

        smtp_sessions = [
            s for s in self.sessions
            if s.get('protocol') in ['SMTP', 'SMTP-Submission', 'SMTP-Alt', 'SMTPS']
        ]

        if not smtp_sessions:
            return self._build_rule_result(
                rule_id, meta, RuleStatus.NOT_APPLICABLE,
                observed="No SMTP protocol sessions in capture",
                expected="SMTP with STARTTLS or dedicated SMTPS",
                explanation="STARTTLS is specific to SMTP submission/relay and is not applicable to non-SMTP captures."
            )

        plaintext_smtp = [
            s for s in smtp_sessions
            if not s.get('encrypted') and s.get('protocol') != 'SMTPS'
        ]
        has_any_tls = len(self.handshakes) > 0

        if plaintext_smtp and not has_any_tls:
            return self._build_rule_result(
                rule_id, meta, RuleStatus.VIOLATED,
                observed=f"{len(plaintext_smtp)} plaintext SMTP session(s) without TLS upgrade",
                expected="Explicit STARTTLS negotiation (RFC 3207) or SMTPS",
                explanation="SMTP session operated in cleartext without issuing STARTTLS command, exposing email content and authentication.",
                evidence_refs=[f"session:{s.get('id', i)}" for i, s in enumerate(self.sessions) if not s.get('encrypted')]
            )

        if plaintext_smtp and has_any_tls:
            # Partial upgrade in capture - some upgraded, some didn't
            return self._build_rule_result(
                rule_id, meta, RuleStatus.VIOLATED,
                observed=f"Mixed posture: {len(plaintext_smtp)} unencrypted session(s) despite TLS capability",
                expected="Universal STARTTLS enforcement on all SMTP ports",
                explanation="Some SMTP sessions remained unencrypted while others used TLS, indicating opportunistic fallback or missing policy enforcement.",
                evidence_refs=[f"session:{s.get('id', i)}" for i, s in enumerate(self.sessions) if not s.get('encrypted')]
            )

        return self._build_rule_result(
            rule_id, meta, RuleStatus.SATISFIED,
            observed="SMTP sessions secured via STARTTLS or dedicated SMTPS port",
            expected="STARTTLS or SMTPS encryption",
            explanation="All observed SMTP traffic successfully transitioned to or operated under TLS encryption.",
            evidence_refs=[f"session:{s.get('id', i)}" for i, s in enumerate(self.sessions) if s.get('encrypted')]
        )

    def _build_rule_result(
        self,
        rule_id: str,
        meta: Dict[str, str],
        status: str,
        observed: str,
        expected: str,
        explanation: str,
        evidence_refs: Optional[List[str]] = None,
        missing_prereqs: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Format normalized rule dictionary"""
        contribution = "Neutral / Passing"
        if status == RuleStatus.VIOLATED:
            contribution = "Primary Driver (Violation)" if meta['severity'] == 'CRITICAL' else "Contributing Factor (Weakness)"
        elif status == RuleStatus.UNKNOWN:
            contribution = "Unresolved Limiter (Unknown)"
        elif status == RuleStatus.NOT_APPLICABLE:
            contribution = "Not Applicable"

        return {
            "rule_id": rule_id,
            "property_name": meta['name'],
            "standard": meta['standard'],
            "severity": meta['severity'],
            "target": meta['target'],
            "status": status,
            "contribution": contribution,
            "observed_value": observed,
            "expected_value": expected,
            "explanation": explanation,
            "evidence_refs": evidence_refs or [],
            "missing_prerequisites": missing_prereqs or []
        }

    # ─── 4. CROSS-PROPERTY REASONING ───

    def _evaluate_cross_property_reasoning(self):
        """
        Evaluate semantic relationships and dependencies between the 10 rules.
        Prevents false conclusions and handles cross-property protocol dynamics.
        """
        self.cross_property_insights = []

        # CPR-01: Handshake Presence vs. Client Trust Verification
        has_handshake = len(self.handshakes) > 0
        has_certs = len(self.certificates) > 0
        all_certs_ca = has_certs and all(not c.get('is_self_signed') for c in self.certificates)

        if has_handshake and has_certs and all_certs_ca:
            self.cross_property_insights.append({
                "id": "CPR-01",
                "relationship": "Handshake Presence vs. Client Trust Verification",
                "finding": "Wire Presence Does Not Guarantee Client Trust",
                "reasoning": (
                    "Server presented CA-signed certificate during TLS handshake. However, network capture evidence "
                    "only establishes transmission across the wire; it cannot verify whether the client system's local "
                    "trust store accepted the certificate without warning, or if custom pinning/CT logs were evaluated."
                ),
                "impact": "Caps maximum defensible conclusion at 'Secure Within Observed Scope' with explicit wire-only boundary."
            })

        # CPR-02: STARTTLS Capability vs. Session Protection
        smtp_sessions = [s for s in self.sessions if s.get('protocol') in ['SMTP', 'SMTP-Submission', 'SMTP-Alt']]
        if smtp_sessions:
            has_plaintext = any(not s.get('encrypted') for s in smtp_sessions)
            has_encrypted = any(s.get('encrypted') for s in smtp_sessions)
            if has_plaintext and has_encrypted:
                self.cross_property_insights.append({
                    "id": "CPR-02",
                    "relationship": "STARTTLS Transition vs. Plaintext Fallback",
                    "finding": "Inconsistent STARTTLS Enforcement / Downgrade Risk",
                    "reasoning": (
                        "Both encrypted and cleartext SMTP sessions exist in the same capture. This indicates that STARTTLS "
                        "is opportunistic rather than mandatory, creating vulnerability to STARTTLS stripping (STRIPTLS) attacks."
                    ),
                    "impact": "Triggers validation concern regarding lack of MTA-STS or DANE enforcement."
                })

        # CPR-03: Handshake Truncation vs. Attack Inference
        incomplete_handshakes = [
            hs for hs in self.handshakes
            if not hs.get('version') or not hs.get('cipher_suites')
        ]
        if incomplete_handshakes and not any(r['status'] == RuleStatus.VIOLATED for r in self.normalized_rules):
            self.cross_property_insights.append({
                "id": "CPR-03",
                "relationship": "Handshake Incompleteness vs. Attack Attribution",
                "finding": "Incomplete Handshake Recorded As Evidence Limitation",
                "reasoning": (
                    f"{len(incomplete_handshakes)} handshake message(s) are incomplete. In accordance with forensic integrity "
                    "principles, packet truncation or missing ServerHello is classified as an evidence uncertainty rather "
                    "than a malicious tampering attack."
                ),
                "impact": "Prevents false-positive security findings while flagging unresolved evidence."
            })

        # CPR-04: Protocol Version & Cipher Suite Synergy
        tls_versions = self.summary.get('tls_versions', {})
        if 'SSL 3.0' in tls_versions or 'TLS 1.0' in tls_versions:
            self.cross_property_insights.append({
                "id": "CPR-04",
                "relationship": "Legacy Protocol & CBC Mode Vulnerability",
                "finding": "Structural Insecurity from Protocol Deprecation",
                "reasoning": (
                    "Deprecated protocol versions (SSL 3.0 / TLS 1.0) inherently lack modern AEAD cipher support, "
                    "enabling active eavesdropping via CBC padding oracle vulnerabilities (POODLE / BEAST)."
                ),
                "impact": "Directly drives the assessment into Cryptographic Failure or Cryptographically Weak state."
            })

        # CPR-05: Multi-Connection Cross-Contamination Guard
        if len(self.sessions) > 1:
            enc_count = sum(1 for s in self.sessions if s.get('encrypted'))
            plain_count = len(self.sessions) - enc_count
            if enc_count > 0 and plain_count > 0:
                self.cross_property_insights.append({
                    "id": "CPR-05",
                    "relationship": "Multi-Connection Forensics Isolation",
                    "finding": "Coexistence of Secure and Vulnerable Channels",
                    "reasoning": (
                        f"Capture contains {enc_count} encrypted session(s) alongside {plain_count} cleartext session(s). "
                        "A compliant session cannot sanitize or conceal an unencrypted session. The overall assessment is "
                        "governed by the least secure channel."
                    ),
                    "impact": "Ensures critical violations in one stream dominate the overall state."
                })

    # ─── 5. EVIDENCE SUFFICIENCY & UNCERTAINTY ───

    def _evaluate_evidence_sufficiency(self):
        """Evaluate whether evidence is Complete, Partial, or Insufficient"""
        self.unresolved_conditions = []
        total_packets = self.summary.get('total_packets', 0)
        has_tls = len(self.handshakes) > 0
        has_certs = len(self.certificates) > 0
        has_sessions = len(self.sessions) > 0

        # Collect missing prerequisites from rules
        for r in self.normalized_rules:
            for p in r.get('missing_prerequisites', []):
                if p not in self.unresolved_conditions:
                    self.unresolved_conditions.append(p)

        if total_packets == 0 and not has_tls and not has_certs:
            self.evidence_completeness = "Insufficient"
            self.unresolved_conditions.append("Zero network packets or cryptographic records captured")
            return

        if not has_sessions and not has_tls and not has_certs:
            self.evidence_completeness = "Insufficient"
            self.unresolved_conditions.append("Zero protocol sessions or cryptographic handshakes detected")
            return

        # If TLS was used, were certificates captured?
        if has_tls and not has_certs:
            self.evidence_completeness = "Partial"
            self.unresolved_conditions.append("TLS handshake observed but X.509 Certificate packets were truncated or missing")
        elif not has_tls and self.summary.get('plaintext_packets', 0) == total_packets and total_packets > 0:
            # 100% plaintext: evidence is complete enough to prove plaintext failure
            self.evidence_completeness = "Complete"
        elif any(r['status'] == RuleStatus.UNKNOWN for r in self.normalized_rules):
            self.evidence_completeness = "Partial"
        else:
            self.evidence_completeness = "Complete"

    # ─── 6. DETERMINISTIC STATE AGGREGATION ───

    def _derive_overall_state(self):
        """
        Deterministic aggregation ladder with strict precedence:
        1. Insufficient Evidence
        2. Critical Violations -> Cryptographic Failure
        3. High Violations -> Cryptographically Weak
        4. Medium Violations / Partial Prerequisites -> Cryptographic Validation Concern
        5. Non-critical Unknowns -> Acceptable With Limitations
        6. All Satisfied -> Secure Within Observed Scope
        """
        total_packets = self.summary.get('total_packets', 0)
        has_tls = len(self.handshakes) > 0
        has_certs = len(self.certificates) > 0
        has_sessions = len(self.sessions) > 0

        if (total_packets == 0 and not has_tls and not has_certs) or (not has_sessions and not has_tls and not has_certs):
            self.overall_state = CryptoState.INSUFFICIENT_EVIDENCE
            return

        violations = [r for r in self.normalized_rules if r['status'] == RuleStatus.VIOLATED]
        unknowns = [r for r in self.normalized_rules if r['status'] == RuleStatus.UNKNOWN]

        critical_violations = [v for v in violations if v['severity'] == 'CRITICAL']
        high_violations = [v for v in violations if v['severity'] == 'HIGH']
        medium_violations = [v for v in violations if v['severity'] == 'MEDIUM']

        # Precedence Step 1: Any CRITICAL violation -> CRYPTOGRAPHIC_FAILURE
        # (e.g. Plaintext email, SSL 3.0 POODLE, Weak Ciphers like RC4/DES/NULL, or TLS 1.0)
        if critical_violations:
            self.overall_state = CryptoState.CRYPTOGRAPHIC_FAILURE
            return

        # Precedence Step 2: Any HIGH violation -> CRYPTOGRAPHICALLY_WEAK
        # (e.g. Expired certs, Weak signatures SHA-1, Key size < 2048, or Missing STARTTLS)
        if high_violations:
            self.overall_state = CryptoState.CRYPTOGRAPHICALLY_WEAK
            return

        # Precedence Step 3: Any MEDIUM violation -> CRYPTOGRAPHIC_VALIDATION_CONCERN
        # (e.g. Self-signed certificate, TLS 1.1)
        if medium_violations:
            self.overall_state = CryptoState.CRYPTOGRAPHIC_VALIDATION_CONCERN
            return

        # Precedence Step 4: Material Unknowns with no violations
        # If critical properties could not be observed (e.g. TLS used but certs missing)
        if self.evidence_completeness == "Partial" and unknowns:
            self.overall_state = CryptoState.ACCEPTABLE_WITH_LIMITATIONS
            return

        # Precedence Step 5: All applicable properties Satisfied
        self.overall_state = CryptoState.SECURE_WITHIN_OBSERVED_SCOPE

    # ─── 7. EXPLANATION GENERATION ───

    def _generate_explanation(self):
        """Generate human-readable, evidence-derived rationale"""
        drivers = []
        violations = [r for r in self.normalized_rules if r['status'] == RuleStatus.VIOLATED]
        satisfied = [r for r in self.normalized_rules if r['status'] == RuleStatus.SATISFIED]

        for v in violations:
            drivers.append(f"{v['property_name']}: {v['observed_value']}")

        if not violations and self.overall_state in [CryptoState.SECURE_WITHIN_OBSERVED_SCOPE, CryptoState.ACCEPTABLE_WITH_LIMITATIONS]:
            drivers.append("All observed transport & cryptographic properties satisfy security baselines.")

        summary_map = {
            CryptoState.CRYPTOGRAPHIC_FAILURE: (
                f"The analysis identified critical cryptographic failure(s) that actively jeopardize email confidentiality. "
                f"Primary drivers include: {'; '.join(drivers[:2])}."
            ),
            CryptoState.CRYPTOGRAPHICALLY_WEAK: (
                f"The email traffic utilizes deprecated or sub-standard cryptographic primitives ({'; '.join(drivers[:2])}), "
                f"failing to meet current NIST and RFC security recommendations."
            ),
            CryptoState.CRYPTOGRAPHIC_VALIDATION_CONCERN: (
                f"The overall state indicates a material validation concern ({'; '.join(drivers[:2])}) that prevents an unreserved "
                f"security endorsement."
            ),
            CryptoState.ACCEPTABLE_WITH_LIMITATIONS: (
                "Observed parameters meet acceptable baseline standards. However, conclusions are strictly limited to the captured "
                "wire messages; client-side PKI trust acceptance and post-handshake state cannot be verified from PCAP data alone."
            ),
            CryptoState.SECURE_WITHIN_OBSERVED_SCOPE: (
                "All observed email streams adhere to modern cryptographic standards (TLS 1.2/1.3, AEAD ciphers, valid certificates). "
                "Transport integrity and confidentiality are properly enforced within the observed traffic scope."
            ),
            CryptoState.INSUFFICIENT_EVIDENCE: (
                "Insufficient packet volume or absence of email protocol exchanges prevents drawing a definitive cryptographic conclusion."
            ),
            CryptoState.ANALYSIS_ERROR: (
                "Cryptographic state reasoning encountered an unexpected processing error."
            )
        }

        self.explanation = {
            "overall_state": self.overall_state,
            "overall_state_label": CryptoState.LABELS.get(self.overall_state, self.overall_state),
            "summary_rationale": summary_map.get(self.overall_state, "Assessment completed."),
            "state_drivers": drivers or ["Evidence evaluation"],
            "supporting_observations": [
                f"{s['property_name']}: {s['observed_value']}"
                for s in satisfied[:4]
            ],
            "violated_conditions": [
                f"{v['property_name']}: {v['observed_value']}"
                for v in violations
            ],
            "unresolved_conditions": self.unresolved_conditions,
            "cross_property_insights": [i['finding'] for i in self.cross_property_insights],
            "scope_limitations": (
                "Forensic assessment is bounded by the captured packets. Client-side root trust stores, "
                "application-level certificate pinning, and uncaptured server-to-server relay hops cannot be evaluated."
            )
        }
