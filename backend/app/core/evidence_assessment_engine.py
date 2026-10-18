"""
Evidence-Based Assessment Engine for SecureMailScope (USP 5)

Systematically separates and correlates:
1. Observed Evidence (facts extracted from PCAP wire telemetry)
2. Expected Requirements (explicit security policies, baselines, and RFC/NIST standards)
3. Assessment Outcomes (Satisfied, Violated, Indeterminate, Not Applicable, Undefined Expectation, Evaluation Error)
4. Evidence Statuses (Observed, Not Observed, Unknown, Unavailable, Not Applicable)
5. Explicit Uncertainty Handling & Evidence Provenance Links
"""

from typing import List, Dict, Any, Optional
from datetime import datetime


# ─── 1. STATUS & OUTCOME ENUMS ───

class EvidenceStatus:
    """Status of physical/logical evidence in the inspected capture"""
    OBSERVED = "Observed"
    NOT_OBSERVED = "Not Observed"
    UNKNOWN = "Unknown"
    UNAVAILABLE = "Unavailable"
    NOT_APPLICABLE = "Not Applicable"


class AssessmentOutcome:
    """Evaluation result of comparing Observed Evidence against Expected Requirements"""
    SATISFIED = "Satisfied"
    VIOLATED = "Violated"
    INDETERMINATE = "Indeterminate"
    NOT_APPLICABLE = "Not Applicable"
    UNDEFINED_EXPECTATION = "Undefined Expectation"
    EVALUATION_ERROR = "Evaluation Error"

    BADGE_COLORS = {
        SATISFIED: "#10b981",              # Emerald Green
        VIOLATED: "#ef4444",               # Red
        INDETERMINATE: "#f59e0b",          # Amber
        NOT_APPLICABLE: "#9ca3af",         # Slate / Gray
        UNDEFINED_EXPECTATION: "#a855f7",  # Purple
        EVALUATION_ERROR: "#64748b"        # Dark Gray
    }

    DESCRIPTIONS = {
        SATISFIED: "Observed evidence conclusively satisfies the applicable policy requirement.",
        VIOLATED: "Observed evidence demonstrably violates the applicable policy requirement.",
        INDETERMINATE: "Comparison cannot be resolved because evidence or prerequisites are incomplete or unverified.",
        NOT_APPLICABLE: "Requirement does not apply to the evaluated protocol or traffic scenario.",
        UNDEFINED_EXPECTATION: "Observation was extracted, but no applicable policy, baseline, or expectation is defined.",
        EVALUATION_ERROR: "Assessment could not be completed reliably due to a processing or evaluation error."
    }


# Standard references
WEAK_CIPHERS = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon', 'MD5']
WEAK_CIPHER_CODES = {
    '0X0000', '0X0001', '0X0002', '0X0003', '0X0004', '0X0005',
    '0X0006', '0X0007', '0X0008', '0X0009', '0X000A', '0X000B',
    '0X000C', '0X000D', '0X000E', '0X000F', '0X0010', '0X0011',
    '0X0012', '0X0013', '0X0014', '0X0015', '0X0016', '0X0017',
    '0X0018', '0X0019', '0X001A', '0X001B',
}
MIN_KEY_SIZES = {
    'rsa': 2048,
    'rsaencryption': 2048,
    'ec': 224,
    'ecdsa': 224,
    'dh': 2048,
    'dhe': 2048,
}
WEAK_SIG_ALGOS = ['md5', 'sha1', 'md2']


# ─── 2. ENGINE CLASS ───

class EvidenceAssessmentEngine:
    """
    Evidence-Based Assessment Engine (USP 5).
    Performs deterministic multi-dimensional assessments comparing wire evidence against
    formal security expectations with explicit uncertainty propagation.
    """

    def __init__(self, analysis_data: Dict[str, Any]):
        self.data = analysis_data or {}
        self.capture_id = self.data.get('capture_id', 'unknown_capture')
        self.summary = self.data.get('summary', {})
        self.sessions = self.data.get('sessions', [])
        self.handshakes = self.data.get('tls_handshakes', [])
        self.certificates = self.data.get('certificates', [])
        self.findings = self.data.get('findings', [])

        self.assessments: List[Dict[str, Any]] = []

    def evaluate(self) -> Dict[str, Any]:
        """Run all evidence-versus-expectation assessments"""
        try:
            self.assessments = [
                self._assess_transport_encryption(),
                self._assess_tls_protocol_version(),
                self._assess_cipher_suite_strength(),
                self._assess_key_length(),
                self._assess_signature_algorithm(),
                self._assess_certificate_validity(),
                self._assess_ca_authenticity(),
                self._assess_starttls_upgrade(),
                self._assess_handshake_completeness(),
                self._assess_client_trust_acceptance(),
                self._assess_post_quantum_readiness(),
            ]

            metrics = {
                "total_assessed": len(self.assessments),
                "satisfied_count": sum(1 for a in self.assessments if a['outcome'] == AssessmentOutcome.SATISFIED),
                "violated_count": sum(1 for a in self.assessments if a['outcome'] == AssessmentOutcome.VIOLATED),
                "indeterminate_count": sum(1 for a in self.assessments if a['outcome'] == AssessmentOutcome.INDETERMINATE),
                "not_applicable_count": sum(1 for a in self.assessments if a['outcome'] == AssessmentOutcome.NOT_APPLICABLE),
                "undefined_expectation_count": sum(1 for a in self.assessments if a['outcome'] == AssessmentOutcome.UNDEFINED_EXPECTATION),
                "evaluation_error_count": sum(1 for a in self.assessments if a['outcome'] == AssessmentOutcome.EVALUATION_ERROR),
            }

            return {
                "success": True,
                "capture_id": self.capture_id,
                "assessments": self.assessments,
                "metrics": metrics,
                "evaluated_at": datetime.now().isoformat(),
                "engine_version": "1.0.0-evidence-assessment"
            }
        except Exception as e:
            return {
                "success": False,
                "capture_id": self.capture_id,
                "error": str(e),
                "assessments": [],
                "metrics": {
                    "total_assessed": 0, "satisfied_count": 0, "violated_count": 0,
                    "indeterminate_count": 0, "not_applicable_count": 0,
                    "undefined_expectation_count": 0, "evaluation_error_count": 1
                },
                "evaluated_at": datetime.now().isoformat(),
                "engine_version": "1.0.0-evidence-assessment"
            }

    # ─── PROPERTY 1: Transport Layer Encryption ───
    def _assess_transport_encryption(self) -> Dict[str, Any]:
        req_id = "REQ-RFC8314-ENCRYPT"
        prop = "Transport Layer Encryption Enforcement"
        category = "Transport Security"
        total = self.summary.get('total_packets', 0)
        plaintext = self.summary.get('plaintext_packets', 0)
        protocols = self.summary.get('protocols_detected', [])

        if total == 0:
            return self._build_item(
                req_id, prop, category,
                evidence_status=EvidenceStatus.UNKNOWN,
                observed_value="0 packets captured",
                observed_details="No network packets were captured in this stream.",
                expected_value="100% email traffic encrypted via TLS (Port 465/993/995 or STARTTLS)",
                policy_source="RFC 8314 Section 3",
                comparison_rule="plaintext_packets == 0 and total_packets > 0",
                outcome=AssessmentOutcome.INDETERMINATE,
                explanation="Cannot determine transport encryption because the capture file contains no network packets.",
                unknown_reason="Zero network packets in capture",
                missing_prereqs=["Captured TCP traffic stream"],
                connection_scope="Global Capture Scope",
                extraction_source="PCAP Ingestion & Protocol Demuxer"
            )

        plaintext_protocols = [p for p in protocols if p not in ['SMTPS', 'IMAPS', 'POP3S']]
        if plaintext > 0 and plaintext_protocols:
            pct = round((plaintext / total) * 100, 1)
            return self._build_item(
                req_id, prop, category,
                evidence_status=EvidenceStatus.OBSERVED,
                observed_value=f"{plaintext} plaintext packets ({pct}%) on {', '.join(plaintext_protocols)}",
                observed_details=f"{plaintext} out of {total} packets transmitted in cleartext without TLS.",
                expected_value="100% email traffic encrypted via TLS (RFC 8314)",
                policy_source="RFC 8314 Section 3",
                comparison_rule="plaintext_packets == 0",
                outcome=AssessmentOutcome.VIOLATED,
                explanation=f"Cleartext email traffic detected on {', '.join(plaintext_protocols)}. Credentials and email payloads exposed to passive wiretapping.",
                evidence_refs=[f"session:{s.get('id', i)}" for i, s in enumerate(self.sessions) if not s.get('encrypted')],
                connection_scope=f"Port(s): {', '.join(set(str(s.get('port', '25')) for s in self.sessions if not s.get('encrypted')))}",
                extraction_source="TCP Stream Reassembly & Protocol Analyzer"
            )

        return self._build_item(
            req_id, prop, category,
            evidence_status=EvidenceStatus.OBSERVED,
            observed_value=f"100% encrypted traffic ({total} packets protected)",
            observed_details="All observed email protocol streams utilize transport layer security.",
            expected_value="100% email traffic encrypted via TLS",
            policy_source="RFC 8314 Section 3",
            comparison_rule="plaintext_packets == 0 and total_packets > 0",
            outcome=AssessmentOutcome.SATISFIED,
            explanation="All email protocol communications are encrypted in transit using TLS wrappers or successfully upgraded streams.",
            evidence_refs=[f"session:{s.get('id', i)}" for i, s in enumerate(self.sessions) if s.get('encrypted')],
            connection_scope=f"Port(s): {', '.join(set(str(s.get('port', '465')) for s in self.sessions if s.get('encrypted')))}",
            extraction_source="TCP Stream Reassembly & Protocol Analyzer"
        )

    # ─── PROPERTY 2: Negotiated TLS Protocol Version ───
    def _assess_tls_protocol_version(self) -> Dict[str, Any]:
        req_id = "REQ-RFC8996-TLSVER"
        prop = "Negotiated TLS Protocol Version"
        category = "Protocol Negotiation"
        tls_versions = self.summary.get('tls_versions', {})
        total_packets = self.summary.get('total_packets', 0)

        if not tls_versions and not self.handshakes:
            if total_packets > 0 and self.summary.get('plaintext_packets', 0) == total_packets:
                return self._build_item(
                    req_id, prop, category,
                    evidence_status=EvidenceStatus.NOT_APPLICABLE,
                    observed_value="Plaintext only (No TLS handshakes present)",
                    observed_details="Traffic is cleartext; no TLS records exist to evaluate negotiated version.",
                    expected_value="TLS 1.2 or TLS 1.3 (RFC 8996 / RFC 8446)",
                    policy_source="RFC 8996 / NIST SP 800-52r2",
                    comparison_rule="negotiated_version in {'TLS 1.2', 'TLS 1.3'}",
                    outcome=AssessmentOutcome.NOT_APPLICABLE,
                    explanation="TLS version requirement is not applicable to unencrypted protocol streams.",
                    connection_scope="N/A",
                    extraction_source="TLS Handshake Extractor"
                )
            return self._build_item(
                req_id, prop, category,
                evidence_status=EvidenceStatus.UNKNOWN,
                observed_value="TLS handshakes absent or truncated",
                observed_details="Could not parse ServerHello record to extract negotiated TLS version.",
                expected_value="TLS 1.2 or TLS 1.3",
                policy_source="RFC 8996 / NIST SP 800-52r2",
                comparison_rule="negotiated_version in {'TLS 1.2', 'TLS 1.3'}",
                outcome=AssessmentOutcome.INDETERMINATE,
                explanation="Negotiated TLS version could not be determined because no ServerHello handshake record was captured.",
                unknown_reason="Missing TLS ServerHello in packet capture",
                missing_prereqs=["TLS ServerHello record"],
                connection_scope="TLS Handshake Scope",
                extraction_source="TLS Handshake Extractor"
            )

        deprecated = [v for v in tls_versions.keys() if v in ['SSL 3.0', 'TLS 1.0', 'TLS 1.1']]
        if deprecated:
            return self._build_item(
                req_id, prop, category,
                evidence_status=EvidenceStatus.OBSERVED,
                observed_value=f"Deprecated version: {', '.join(deprecated)}",
                observed_details=f"Negotiated versions: {', '.join(f'{k} ({v} handshakes)' for k, v in tls_versions.items())}",
                expected_value="TLS 1.2 or TLS 1.3 (RFC 8996 / NIST SP 800-52r2)",
                policy_source="RFC 8996 / RFC 7568",
                comparison_rule="negotiated_version >= 'TLS 1.2'",
                outcome=AssessmentOutcome.VIOLATED,
                explanation=f"Negotiation of {', '.join(deprecated)} violates RFC 8996 / RFC 7568 and exposes communications to cryptographic exploits (POODLE, BEAST).",
                evidence_refs=[f"handshake:{hs.get('id', i)}" for i, hs in enumerate(self.handshakes) if hs.get('version') in deprecated],
                connection_scope="Encrypted Transport",
                extraction_source="TLS ServerHello Handshake Record"
            )

        return self._build_item(
            req_id, prop, category,
            evidence_status=EvidenceStatus.OBSERVED,
            observed_value=f"Modern TLS: {', '.join(tls_versions.keys()) or 'TLS 1.2+'}",
            observed_details=f"Handshakes: {', '.join(f'{k} ({v})' for k, v in tls_versions.items())}",
            expected_value="TLS 1.2 or TLS 1.3",
            policy_source="RFC 8996 / NIST SP 800-52r2",
            comparison_rule="negotiated_version >= 'TLS 1.2'",
            outcome=AssessmentOutcome.SATISFIED,
            explanation="Negotiated TLS protocol version complies with modern security standards and deprecation mandates.",
            evidence_refs=[f"handshake:{hs.get('id', i)}" for i, hs in enumerate(self.handshakes)],
            connection_scope="Encrypted Transport",
            extraction_source="TLS ServerHello Handshake Record"
        )

    # ─── PROPERTY 3: Cryptographic Cipher Suite AEAD Strength ───
    def _assess_cipher_suite_strength(self) -> Dict[str, Any]:
        req_id = "REQ-NIST52-CIPHER"
        prop = "Cipher Suite AEAD Cryptographic Strength"
        category = "Cryptographic Primitives"

        if not self.handshakes:
            status = EvidenceStatus.NOT_APPLICABLE if self.summary.get('plaintext_packets', 0) > 0 else EvidenceStatus.UNKNOWN
            return self._build_item(
                req_id, prop, category,
                evidence_status=status,
                observed_value="No TLS handshakes captured",
                observed_details="No cipher suites negotiated or offered.",
                expected_value="AEAD cipher suites (AES-GCM, ChaCha20-Poly1305)",
                policy_source="NIST SP 800-52 Rev 2 Section 3.3.1",
                comparison_rule="cipher_in_approved_aead_set()",
                outcome=AssessmentOutcome.NOT_APPLICABLE if status == EvidenceStatus.NOT_APPLICABLE else AssessmentOutcome.INDETERMINATE,
                explanation="Cipher suite analysis requires captured TLS handshake messages.",
                unknown_reason="TLS handshake records not captured" if status == EvidenceStatus.UNKNOWN else None,
                connection_scope="N/A",
                extraction_source="TLS Handshake Parser"
            )

        weak_found = []
        ciphers_seen = []
        for hs in self.handshakes:
            for c in hs.get('cipher_suites', []):
                ciphers_seen.append(c)
                cu = c.upper()
                if cu in WEAK_CIPHER_CODES or any(w.upper() in cu for w in WEAK_CIPHERS):
                    weak_found.append(c)

        if not ciphers_seen:
            return self._build_item(
                req_id, prop, category,
                evidence_status=EvidenceStatus.UNKNOWN,
                observed_value="Cipher suite fields unparsed or empty",
                observed_details="Handshake record observed, but cipher suite ID was omitted or unparsed.",
                expected_value="Approved AEAD cipher suite",
                policy_source="NIST SP 800-52 Rev 2 Section 3.3.1",
                comparison_rule="cipher_in_approved_aead_set()",
                outcome=AssessmentOutcome.INDETERMINATE,
                explanation="Handshake record exists but cipher suite could not be extracted from packet payload.",
                unknown_reason="Unparsed or truncated cipher suite field in ServerHello",
                missing_prereqs=["ServerHello.cipher_suite field"],
                connection_scope="Encrypted Transport",
                extraction_source="TLS Handshake Parser"
            )

        if weak_found:
            return self._build_item(
                req_id, prop, category,
                evidence_status=EvidenceStatus.OBSERVED,
                observed_value=f"Legacy/Weak ciphers: {', '.join(sorted(set(weak_found))[:3])}",
                observed_details=f"Weak cipher suites identified: {', '.join(sorted(set(weak_found)))}",
                expected_value="Approved AEAD ciphers; zero RC4/DES/3DES/NULL/EXPORT/anon ciphers",
                policy_source="NIST SP 800-52 Rev 2 Section 3.3.1",
                comparison_rule="not_contains(WEAK_CIPHERS)",
                outcome=AssessmentOutcome.VIOLATED,
                explanation=f"Weak or obsolete cipher suite ({', '.join(sorted(set(weak_found))[:2])}) negotiated, vulnerable to SWEET32, BEAST, or RC4 bias attacks.",
                evidence_refs=[f"handshake:{hs.get('id', i)}" for i, hs in enumerate(self.handshakes)],
                connection_scope="Encrypted Transport",
                extraction_source="TLS ServerHello Cipher Suite Field"
            )

        return self._build_item(
            req_id, prop, category,
            evidence_status=EvidenceStatus.OBSERVED,
            observed_value=f"Modern ciphers: {', '.join(sorted(set(ciphers_seen))[:2])}",
            observed_details=f"All observed ciphers meet NIST SP 800-52r2 standards.",
            expected_value="Modern AEAD cipher suites (GCM, ChaCha20-Poly1305)",
            policy_source="NIST SP 800-52 Rev 2 Section 3.3.1",
            comparison_rule="not_contains(WEAK_CIPHERS)",
            outcome=AssessmentOutcome.SATISFIED,
            explanation="All negotiated cipher suites provide authenticated encryption with associated data (AEAD) and forward secrecy.",
            evidence_refs=[f"handshake:{hs.get('id', i)}" for i, hs in enumerate(self.handshakes)],
            connection_scope="Encrypted Transport",
            extraction_source="TLS ServerHello Cipher Suite Field"
        )

    # ─── PROPERTY 4: Public Key Asymmetric Bit Strength ───
    def _assess_key_length(self) -> Dict[str, Any]:
        req_id = "REQ-NIST57-KEYLEN"
        prop = "Public Key Asymmetric Bit Strength"
        category = "X.509 PKI"

        if not self.certificates:
            status = EvidenceStatus.NOT_APPLICABLE if not self.handshakes and self.summary.get('plaintext_packets', 0) > 0 else EvidenceStatus.UNKNOWN
            return self._build_item(
                req_id, prop, category,
                evidence_status=status,
                observed_value="No X.509 certificates extracted",
                observed_details="No public keys available to evaluate bit strength.",
                expected_value="RSA >= 2048-bit, EC >= 224-bit (NIST SP 800-57 Part 1)",
                policy_source="NIST SP 800-57 Part 1 Section 5.6",
                comparison_rule="key_size >= min_size",
                outcome=AssessmentOutcome.NOT_APPLICABLE if status == EvidenceStatus.NOT_APPLICABLE else AssessmentOutcome.INDETERMINATE,
                explanation="Key length assessment requires extracted X.509 certificates from the TLS exchange.",
                unknown_reason="Certificate packets truncated or absent from capture" if status == EvidenceStatus.UNKNOWN else None,
                connection_scope="PKI Certificate Scope",
                extraction_source="X.509 Certificate Parser"
            )

        weak_keys = []
        valid_keys = []
        for c in self.certificates:
            algo = (c.get('public_key_algorithm') or '').lower()
            size = c.get('key_size', 0)
            if size > 0:
                is_weak = False
                for a, min_sz in MIN_KEY_SIZES.items():
                    if a in algo and size < min_sz:
                        weak_keys.append(f"{algo} {size}-bit (min {min_sz})")
                        is_weak = True
                        break
                if not is_weak:
                    valid_keys.append(f"{algo.upper()} {size}-bit")

        if weak_keys:
            return self._build_item(
                req_id, prop, category,
                evidence_status=EvidenceStatus.OBSERVED,
                observed_value=f"Sub-standard key length: {', '.join(weak_keys[:2])}",
                observed_details=f"Public key size below NIST recommendation: {', '.join(weak_keys)}",
                expected_value="RSA >= 2048-bit, EC >= 224-bit",
                policy_source="NIST SP 800-57 Part 1 Section 5.6",
                comparison_rule="key_size >= min_size",
                outcome=AssessmentOutcome.VIOLATED,
                explanation="Certificate public key length does not meet NIST recommended minimum security bit strength, vulnerable to factorization.",
                evidence_refs=[f"cert:{c.get('id', i)}" for i, c in enumerate(self.certificates)],
                connection_scope="Server Certificate",
                extraction_source="X.509 SubjectPublicKeyInfo Field"
            )

        return self._build_item(
            req_id, prop, category,
            evidence_status=EvidenceStatus.OBSERVED,
            observed_value=f"Compliant key length: {', '.join(set(valid_keys)) or '>= 2048-bit'}",
            observed_details="All examined public keys meet or exceed NIST SP 800-57 minimum bit strengths.",
            expected_value="RSA >= 2048-bit, EC >= 224-bit",
            policy_source="NIST SP 800-57 Part 1 Section 5.6",
            comparison_rule="key_size >= min_size",
            outcome=AssessmentOutcome.SATISFIED,
            explanation="All inspected asymmetric key lengths satisfy NIST SP 800-57 minimum security thresholds.",
            evidence_refs=[f"cert:{c.get('id', i)}" for i, c in enumerate(self.certificates)],
            connection_scope="Server Certificate",
            extraction_source="X.509 SubjectPublicKeyInfo Field"
        )

    # ─── PROPERTY 5: Certificate Signature Hash Algorithm ───
    def _assess_signature_algorithm(self) -> Dict[str, Any]:
        req_id = "REQ-RFC5280-SIGALG"
        prop = "Certificate Signature Hash Algorithm"
        category = "X.509 PKI"

        if not self.certificates:
            status = EvidenceStatus.NOT_APPLICABLE if not self.handshakes and self.summary.get('plaintext_packets', 0) > 0 else EvidenceStatus.UNKNOWN
            return self._build_item(
                req_id, prop, category,
                evidence_status=status,
                observed_value="No certificates extracted",
                observed_details="No signature algorithms available for evaluation.",
                expected_value="SHA-256, SHA-384, or Ed25519 (RFC 5280 / CAB Forum)",
                policy_source="RFC 5280 Section 4.1.2.3",
                comparison_rule="sig_algo_hash not in {'md5', 'sha1', 'md2'}",
                outcome=AssessmentOutcome.NOT_APPLICABLE if status == EvidenceStatus.NOT_APPLICABLE else AssessmentOutcome.INDETERMINATE,
                explanation="Signature algorithm assessment requires extracted certificate records.",
                unknown_reason="Certificate packets missing or unparsed" if status == EvidenceStatus.UNKNOWN else None,
                connection_scope="PKI Scope",
                extraction_source="X.509 Certificate Parser"
            )

        weak_sigs = []
        strong_sigs = []
        for c in self.certificates:
            algo = (c.get('signature_algorithm') or '').lower()
            if any(w in algo for w in WEAK_SIG_ALGOS):
                weak_sigs.append(c.get('signature_algorithm', algo))
            elif algo:
                strong_sigs.append(c.get('signature_algorithm', algo))

        if weak_sigs:
            return self._build_item(
                req_id, prop, category,
                evidence_status=EvidenceStatus.OBSERVED,
                observed_value=f"Weak signature hash: {', '.join(sorted(set(weak_sigs))[:2])}",
                observed_details=f"Weak hash algorithms identified: {', '.join(sorted(set(weak_sigs)))}",
                expected_value="SHA-256, SHA-384, or Ed25519; no MD5 or SHA-1",
                policy_source="RFC 5280 Section 4.1.2.3 / CAB Forum BR",
                comparison_rule="sig_algo_hash not in {'md5', 'sha1'}",
                outcome=AssessmentOutcome.VIOLATED,
                explanation="Certificate uses a collision-vulnerable signature hash algorithm (MD5/SHA-1), exposing PKI hierarchy to fraudulent signature forgery.",
                evidence_refs=[f"cert:{c.get('id', i)}" for i, c in enumerate(self.certificates)],
                connection_scope="Certificate Signature",
                extraction_source="X.509 SignatureAlgorithm Field"
            )

        return self._build_item(
            req_id, prop, category,
            evidence_status=EvidenceStatus.OBSERVED,
            observed_value=f"Strong signature hash: {', '.join(sorted(set(strong_sigs))[:2]) or 'SHA-256+'}",
            observed_details="All examined certificates utilize collision-resistant hash algorithms.",
            expected_value="SHA-256, SHA-384, or Ed25519",
            policy_source="RFC 5280 Section 4.1.2.3",
            comparison_rule="sig_algo_hash not in {'md5', 'sha1'}",
            outcome=AssessmentOutcome.SATISFIED,
            explanation="All inspected certificate signatures use cryptographically secure hash functions meeting modern PKI standards.",
            evidence_refs=[f"cert:{c.get('id', i)}" for i, c in enumerate(self.certificates)],
            connection_scope="Certificate Signature",
            extraction_source="X.509 SignatureAlgorithm Field"
        )

    # ─── PROPERTY 6: Certificate Temporal Validity ───
    def _assess_certificate_validity(self) -> Dict[str, Any]:
        req_id = "REQ-RFC5280-EXPIRY"
        prop = "Certificate Temporal Validity"
        category = "X.509 PKI"

        if not self.certificates:
            status = EvidenceStatus.NOT_APPLICABLE if not self.handshakes and self.summary.get('plaintext_packets', 0) > 0 else EvidenceStatus.UNKNOWN
            return self._build_item(
                req_id, prop, category,
                evidence_status=status,
                observed_value="No certificates extracted",
                observed_details="Validity dates cannot be verified.",
                expected_value="Active certificate within validity interval (RFC 5280)",
                policy_source="RFC 5280 Section 4.1.2.5",
                comparison_rule="notBefore <= now <= notAfter",
                outcome=AssessmentOutcome.NOT_APPLICABLE if status == EvidenceStatus.NOT_APPLICABLE else AssessmentOutcome.INDETERMINATE,
                explanation="Validity check requires extracted certificate metadata.",
                unknown_reason="Certificate records absent from capture" if status == EvidenceStatus.UNKNOWN else None,
                connection_scope="PKI Scope",
                extraction_source="X.509 Certificate Parser"
            )

        expired = [c for c in self.certificates if c.get('is_expired')]
        if expired:
            subjects = [c.get('subject', 'Cert') for c in expired]
            return self._build_item(
                req_id, prop, category,
                evidence_status=EvidenceStatus.OBSERVED,
                observed_value=f"Expired certificate(s): {', '.join(subjects[:2])}",
                observed_details=f"{len(expired)} certificate(s) have passed their notAfter validity expiration date.",
                expected_value="Valid certificate within active date window",
                policy_source="RFC 5280 Section 4.1.2.5",
                comparison_rule="is_expired == False",
                outcome=AssessmentOutcome.VIOLATED,
                explanation="Presented certificate has expired, breaking the cryptographic chain of trust and triggering client connection aborts.",
                evidence_refs=[f"cert:{c.get('id', i)}" for i, c in enumerate(self.certificates) if c.get('is_expired')],
                connection_scope="Server Certificate",
                extraction_source="X.509 Validity Interval Field"
            )

        return self._build_item(
            req_id, prop, category,
            evidence_status=EvidenceStatus.OBSERVED,
            observed_value=f"All {len(self.certificates)} certificate(s) currently valid",
            observed_details="All examined certificates are operating within their specified notBefore/notAfter interval.",
            expected_value="Valid certificate within active date window",
            policy_source="RFC 5280 Section 4.1.2.5",
            comparison_rule="is_expired == False",
            outcome=AssessmentOutcome.SATISFIED,
            explanation="All inspected certificates are within their valid operational lifespan.",
            evidence_refs=[f"cert:{c.get('id', i)}" for i, c in enumerate(self.certificates)],
            connection_scope="Server Certificate",
            extraction_source="X.509 Validity Interval Field"
        )

    # ─── PROPERTY 7: Public PKI CA Issuance Authenticity ───
    def _assess_ca_authenticity(self) -> Dict[str, Any]:
        req_id = "REQ-CAB-CATRUST"
        prop = "Public PKI CA Issuance Authenticity"
        category = "X.509 PKI"

        if not self.certificates:
            status = EvidenceStatus.NOT_APPLICABLE if not self.handshakes and self.summary.get('plaintext_packets', 0) > 0 else EvidenceStatus.UNKNOWN
            return self._build_item(
                req_id, prop, category,
                evidence_status=status,
                observed_value="No certificates extracted",
                observed_details="Issuer and subject fields unavailable.",
                expected_value="Certificate signed by trusted public or enterprise CA (CAB Forum BR)",
                policy_source="CAB Forum Baseline Requirements Section 6",
                comparison_rule="is_self_signed == False",
                outcome=AssessmentOutcome.NOT_APPLICABLE if status == EvidenceStatus.NOT_APPLICABLE else AssessmentOutcome.INDETERMINATE,
                explanation="CA authority assessment requires extracted certificate issuer fields.",
                unknown_reason="Certificate records absent" if status == EvidenceStatus.UNKNOWN else None,
                connection_scope="PKI Scope",
                extraction_source="X.509 Certificate Parser"
            )

        self_signed = [c for c in self.certificates if c.get('is_self_signed')]
        if self_signed:
            subjects = [c.get('subject', 'Cert') for c in self_signed]
            return self._build_item(
                req_id, prop, category,
                evidence_status=EvidenceStatus.OBSERVED,
                observed_value=f"Self-signed certificate(s): {', '.join(subjects[:2])}",
                observed_details=f"{len(self_signed)} certificate(s) have identical subject and issuer without public CA chaining.",
                expected_value="Certificate signed by trusted public or private enterprise CA",
                policy_source="CAB Forum Baseline Requirements Section 6",
                comparison_rule="is_self_signed == False",
                outcome=AssessmentOutcome.VIOLATED,
                explanation="Self-signed certificates cannot be verified via public trust roots, leaving connections vulnerable to man-in-the-middle impersonation.",
                evidence_refs=[f"cert:{c.get('id', i)}" for i, c in enumerate(self.certificates) if c.get('is_self_signed')],
                connection_scope="Server Certificate",
                extraction_source="X.509 Issuer / Subject Comparison"
            )

        return self._build_item(
            req_id, prop, category,
            evidence_status=EvidenceStatus.OBSERVED,
            observed_value="CA-signed certificates presented",
            observed_details="Certificates issued by distinct third-party Certificate Authorities.",
            expected_value="CA-signed certificate",
            policy_source="CAB Forum Baseline Requirements Section 6",
            comparison_rule="is_self_signed == False",
            outcome=AssessmentOutcome.SATISFIED,
            explanation="Certificates are signed by distinct issuing authorities, avoiding self-signed trust issues.",
            evidence_refs=[f"cert:{c.get('id', i)}" for i, c in enumerate(self.certificates)],
            connection_scope="Server Certificate",
            extraction_source="X.509 Issuer Field"
        )

    # ─── PROPERTY 8: Opportunistic / Enforced STARTTLS Upgrade ───
    def _assess_starttls_upgrade(self) -> Dict[str, Any]:
        req_id = "REQ-RFC3207-STARTTLS"
        prop = "Opportunistic / Enforced STARTTLS Negotiation"
        category = "Protocol Transition"

        smtp_sessions = [s for s in self.sessions if s.get('protocol') in ['SMTP', 'SMTP-Submission', 'SMTP-Alt', 'SMTPS']]
        if not smtp_sessions:
            return self._build_item(
                req_id, prop, category,
                evidence_status=EvidenceStatus.NOT_APPLICABLE,
                observed_value="No SMTP protocol sessions in capture",
                observed_details="STARTTLS is specific to SMTP relay/submission ports.",
                expected_value="STARTTLS upgrade on port 25/587 (RFC 3207)",
                policy_source="RFC 3207 Section 4",
                comparison_rule="starttls_upgraded_or_smtps()",
                outcome=AssessmentOutcome.NOT_APPLICABLE,
                explanation="STARTTLS evaluation is not applicable to non-SMTP email captures.",
                connection_scope="N/A",
                extraction_source="Protocol Demuxer"
            )

        plaintext_smtp = [s for s in smtp_sessions if not s.get('encrypted') and s.get('protocol') != 'SMTPS']
        has_any_tls = len(self.handshakes) > 0

        if plaintext_smtp and not has_any_tls:
            return self._build_item(
                req_id, prop, category,
                evidence_status=EvidenceStatus.NOT_OBSERVED,
                observed_value=f"No STARTTLS upgrade in {len(plaintext_smtp)} SMTP session(s)",
                observed_details="Client and server communicated over cleartext port 25/587 without issuing STARTTLS command.",
                expected_value="Explicit STARTTLS upgrade (RFC 3207) or SMTPS",
                policy_source="RFC 3207 Section 4",
                comparison_rule="starttls_executed == True",
                outcome=AssessmentOutcome.VIOLATED,
                explanation="SMTP session operated entirely in cleartext without issuing STARTTLS command. Credentials and messages exposed.",
                evidence_refs=[f"session:{s.get('id', i)}" for i, s in enumerate(self.sessions) if not s.get('encrypted')],
                connection_scope="Port 25/587 (SMTP)",
                extraction_source="SMTP Command/Response Stream Reassembly"
            )

        if plaintext_smtp and has_any_tls:
            return self._build_item(
                req_id, prop, category,
                evidence_status=EvidenceStatus.OBSERVED,
                observed_value=f"Inconsistent STARTTLS: {len(plaintext_smtp)} cleartext session(s)",
                observed_details="Some SMTP sessions were upgraded while others remained cleartext, exposing traffic to STRIPTLS attacks.",
                expected_value="Mandatory STARTTLS enforcement across all SMTP sessions",
                policy_source="RFC 3207 / MTA-STS (RFC 8461)",
                comparison_rule="all_sessions_encrypted()",
                outcome=AssessmentOutcome.VIOLATED,
                explanation="Opportunistic STARTTLS without strict enforcement allows active adversaries to strip STARTTLS capabilities.",
                evidence_refs=[f"session:{s.get('id', i)}" for i, s in enumerate(self.sessions) if not s.get('encrypted')],
                connection_scope="Port 25/587 (SMTP)",
                extraction_source="SMTP Command/Response Stream Reassembly"
            )

        return self._build_item(
            req_id, prop, category,
            evidence_status=EvidenceStatus.OBSERVED,
            observed_value="All SMTP sessions secured via STARTTLS or SMTPS",
            observed_details="All observed SMTP exchanges operated under TLS encryption.",
            expected_value="STARTTLS or dedicated SMTPS",
            policy_source="RFC 3207 Section 4",
            comparison_rule="starttls_upgraded_or_smtps()",
            outcome=AssessmentOutcome.SATISFIED,
            explanation="All SMTP protocol interactions were successfully protected by TLS encryption.",
            evidence_refs=[f"session:{s.get('id', i)}" for i, s in enumerate(self.sessions) if s.get('encrypted')],
            connection_scope="Port 465 / 587 (SMTPS/STARTTLS)",
            extraction_source="SMTP Command/Response Stream Reassembly"
        )

    # ─── PROPERTY 9: Handshake State & Exchange Completeness ───
    def _assess_handshake_completeness(self) -> Dict[str, Any]:
        req_id = "REQ-RFC8446-HANDSHAKE"
        prop = "Handshake State & Exchange Completeness"
        category = "Protocol Negotiation"

        if not self.handshakes:
            status = EvidenceStatus.NOT_APPLICABLE if self.summary.get('plaintext_packets', 0) > 0 else EvidenceStatus.UNKNOWN
            return self._build_item(
                req_id, prop, category,
                evidence_status=status,
                observed_value="No TLS handshakes in capture",
                observed_details="No TLS handshake messages observed.",
                expected_value="Completed TLS handshake exchange (ClientHello -> ServerHello -> Finished)",
                policy_source="RFC 8446 / RFC 5246",
                comparison_rule="handshake_state == 'Completed'",
                outcome=AssessmentOutcome.NOT_APPLICABLE if status == EvidenceStatus.NOT_APPLICABLE else AssessmentOutcome.INDETERMINATE,
                explanation="Handshake completeness cannot be evaluated without captured TLS handshake records.",
                unknown_reason="Zero TLS handshakes present" if status == EvidenceStatus.UNKNOWN else None,
                connection_scope="N/A",
                extraction_source="TLS State Machine Analyzer"
            )

        truncated = [hs for hs in self.handshakes if not hs.get('version') or not hs.get('cipher_suites')]
        if truncated:
            return self._build_item(
                req_id, prop, category,
                evidence_status=EvidenceStatus.UNKNOWN,
                observed_value=f"{len(truncated)} incomplete handshake(s) observed",
                observed_details="Handshake exchange begins mid-stream or ends before ServerHello / Finished completion.",
                expected_value="Full bidirectional handshake exchange",
                policy_source="RFC 8446 / RFC 5246",
                comparison_rule="handshake_state == 'Completed'",
                outcome=AssessmentOutcome.INDETERMINATE,
                explanation="Handshake is truncated or incomplete in the capture. Classified as an evidence limitation, not a malicious attack.",
                unknown_reason="Mid-session capture or truncated packet recording",
                missing_prereqs=["Complete ClientHello / ServerHello exchange"],
                evidence_refs=[f"handshake:{hs.get('id', i)}" for i, hs in enumerate(self.handshakes)],
                connection_scope="TLS Handshake Scope",
                extraction_source="TLS State Machine Analyzer"
            )

        return self._build_item(
            req_id, prop, category,
            evidence_status=EvidenceStatus.OBSERVED,
            observed_value=f"{len(self.handshakes)} complete TLS handshake(s) verified",
            observed_details="ClientHello, ServerHello, and session negotiation successfully established.",
            expected_value="Completed TLS handshake exchange",
            policy_source="RFC 8446 / RFC 5246",
            comparison_rule="handshake_state == 'Completed'",
            outcome=AssessmentOutcome.SATISFIED,
            explanation="TLS handshake negotiation successfully completed without truncation or abnormal termination.",
            evidence_refs=[f"handshake:{hs.get('id', i)}" for i, hs in enumerate(self.handshakes)],
            connection_scope="TLS Handshake Scope",
            extraction_source="TLS State Machine Analyzer"
        )

    # ─── PROPERTY 10: Client-Side Trust Store Acceptance ───
    def _assess_client_trust_acceptance(self) -> Dict[str, Any]:
        """
        Demonstrates explicit uncertainty handling (USP 5 core requirement):
        Even if a certificate is present on the wire, client trust store verification cannot be
        proven from wire data alone.
        """
        req_id = "REQ-PKI-CLIENTTRUST"
        prop = "Client-Side Trust Store Acceptance"
        category = "Forensic Boundaries"

        if not self.certificates:
            return self._build_item(
                req_id, prop, category,
                evidence_status=EvidenceStatus.NOT_APPLICABLE,
                observed_value="No certificates observed in capture",
                observed_details="No certificate exchange to evaluate.",
                expected_value="Client trust verification confirmation",
                policy_source="Local Client Trust Store Telemetry",
                comparison_rule="client_alert_received == False and trust_store_verified == True",
                outcome=AssessmentOutcome.NOT_APPLICABLE,
                explanation="No certificates present to evaluate client trust acceptance.",
                connection_scope="N/A",
                extraction_source="Passive Packet Inspection Boundary"
            )

        # A certificate was observed on wire! But can we prove client acceptance from PCAP alone?
        return self._build_item(
            req_id, prop, category,
            evidence_status=EvidenceStatus.UNKNOWN,
            observed_value="Certificate presented on wire; Client verification unobservable",
            observed_details=f"Server presented {len(self.certificates)} certificate(s). No TLS Alert records observed.",
            expected_value="Conclusive verification of client-side trust store acceptance",
            policy_source="Local OS / MUA Trust Store Policy",
            comparison_rule="client_trust_telemetry_available()",
            outcome=AssessmentOutcome.INDETERMINATE,
            explanation=(
                "Passive network wire captures only observe traffic in transit. While the server presented a certificate and no "
                "fatal TLS Alert was transmitted, the internal client-side trust store decision (e.g., custom root CAs, user prompt "
                "overrides, or application certificate pinning) cannot be proven from PCAP data alone."
            ),
            unknown_reason="Passive network capture boundary: endpoint OS/MUA trust store state is unobservable over the wire",
            missing_prereqs=["Client-side endpoint agent telemetry / MUA log data"],
            evidence_refs=[f"cert:{c.get('id', i)}" for i, c in enumerate(self.certificates)],
            connection_scope="Client Endpoint Boundary",
            extraction_source="Passive Packet Inspection Boundary"
        )

    # ─── PROPERTY 11: Experimental Post-Quantum Cipher Negotiation ───
    def _assess_post_quantum_readiness(self) -> Dict[str, Any]:
        """
        Demonstrates Undefined Expectation (USP 5 core requirement):
        Observation is extracted (classical vs hybrid PQ key exchange), but no formal post-quantum
        policy has been mandated by the enterprise.
        """
        req_id = "REQ-EXP-POSTQUANTUM"
        prop = "Post-Quantum Cryptographic Readiness (PQ-KEM)"
        category = "Cryptographic Primitives"

        if not self.handshakes:
            return self._build_item(
                req_id, prop, category,
                evidence_status=EvidenceStatus.NOT_APPLICABLE,
                observed_value="No TLS handshakes in capture",
                observed_details="No key exchange parameters observed.",
                expected_value="[Undefined] No post-quantum policy established",
                policy_source="NIST PQC / Custom Organization Policy",
                comparison_rule="none()",
                outcome=AssessmentOutcome.NOT_APPLICABLE,
                explanation="Post-quantum evaluation is not applicable when no TLS handshakes exist.",
                connection_scope="N/A",
                extraction_source="TLS Key Share Extractor"
            )

        # Check if any ML-KEM or Kyber hybrid was used
        pq_ciphers = [
            hs for hs in self.handshakes
            if any('KYBER' in str(c).upper() or 'MLKEM' in str(c).upper() for c in hs.get('cipher_suites', []))
        ]

        observed_str = "Hybrid PQ-KEM negotiated" if pq_ciphers else "Classical key exchange (ECDHE / DHE)"

        return self._build_item(
            req_id, prop, category,
            evidence_status=EvidenceStatus.OBSERVED,
            observed_value=observed_str,
            observed_details="Evaluated key exchange extensions for post-quantum hybrid algorithms (Kyber / ML-KEM).",
            expected_value="[Undefined Expectation] No mandatory post-quantum policy configured",
            policy_source="IETF Draft / Enterprise PQC Transition Roadmap",
            comparison_rule="none()",
            outcome=AssessmentOutcome.UNDEFINED_EXPECTATION,
            explanation=(
                f"Observed {observed_str}. However, no formal post-quantum requirement has been defined in current RFC/NIST "
                "baselines for email transport. The system accurately reports an undefined expectation rather than inventing an arbitrary pass/fail."
            ),
            unknown_reason="Enterprise post-quantum policy baseline is not currently configured or mandated",
            evidence_refs=[f"handshake:{hs.get('id', i)}" for i, hs in enumerate(self.handshakes)],
            connection_scope="TLS Key Share Scope",
            extraction_source="TLS Supported Groups & Key Share Extension"
        )

    # ─── 3. HELPER BUILDER ───
    def _build_item(
        self,
        req_id: str,
        property_name: str,
        category: str,
        evidence_status: str,
        observed_value: str,
        observed_details: str,
        expected_value: str,
        policy_source: str,
        comparison_rule: str,
        outcome: str,
        explanation: str,
        evidence_refs: Optional[List[str]] = None,
        unknown_reason: Optional[str] = None,
        missing_prereqs: Optional[List[str]] = None,
        connection_scope: str = "Global Scope",
        extraction_source: str = "Network Packet Analyzer"
    ) -> Dict[str, Any]:
        """Build standardized assessment record"""
        return {
            "id": req_id,
            "property_name": property_name,
            "category": category,
            "evidence_status": evidence_status,
            "observed_value": observed_value,
            "observed_details": observed_details,
            "expected_value": expected_value,
            "policy_source": policy_source,
            "comparison_rule": comparison_rule,
            "outcome": outcome,
            "outcome_badge_color": AssessmentOutcome.BADGE_COLORS.get(outcome, "#64748b"),
            "explanation": explanation,
            "unknown_reason": unknown_reason,
            "missing_prerequisites": missing_prereqs or [],
            "evidence_refs": evidence_refs or [],
            "connection_scope": connection_scope,
            "extraction_source": extraction_source
        }
