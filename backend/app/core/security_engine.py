"""
Security Rule Engine for SecureMailScope
Deterministic security checks against extracted PCAP data and certificate chains.
Preserves forensic evidence references (frame, stream, SNI, endpoints).
"""

from typing import List, Dict, Optional, Any

from core.cipher_suites import lookup as lookup_cipher_suite
from services.threat_intel_feed import get_threat_intel_feed

# Known weak signature algorithms
WEAK_SIG_ALGOS = ['md5', 'sha1', 'md2']

# Minimum acceptable key sizes
MIN_KEY_SIZES = {
    'rsa': 2048,
    'rsaencryption': 2048,
    'ec': 224,
    'ecdsa': 224,
    'dh': 2048,
    'dhe': 2048,
}


# Grade boundaries align with calculate_risk_score()'s level thresholds
# (20/40/70) so a letter grade can never contradict the risk level.
GRADE_THRESHOLDS = [(70, 'F'), (55, 'E'), (40, 'D'), (20, 'C'), (10, 'B')]
# Minimum grade implied by a risk level, used when ML fusion raises the level.
LEVEL_MIN_GRADE = {'MEDIUM': 'C', 'HIGH': 'D', 'CRITICAL': 'F'}


def risk_score_to_grade(score: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return 'A'


class SecurityEngine:
    """Run deterministic security checks on PCAP analysis data and PKI chains"""

    def __init__(self, analysis_data: Dict):
        """
        analysis_data should contain:
        - summary: packet counts, protocols, TLS versions
        - sessions: reconstructed email sessions
        - tls_handshakes: TLS handshake metadata
        - certificates: extracted X.509 certificates
        - certificate_chains: multi-tier certificate chain analyses
        """
        self.data = analysis_data
        self.findings = []
        self.finding_counter = 0

    def run_all_checks(self) -> List[Dict]:
        """Run all deterministic security and PKI checks"""
        self.check_plaintext_protocols()
        self.check_ssl3()
        self.check_tls10()
        self.check_tls11()
        self.check_weak_ciphers()
        self.check_weak_signatures()
        self.check_key_sizes()
        self.check_missing_starttls()
        self.check_forward_secrecy()
        self.check_certificate_chains()
        self.check_known_malicious_certificates()
        self.check_email_authentication()

        return self.findings

    def _add_finding(self, severity: str, finding_type: str,
                     title: str, description: str,
                     evidence: str, remediation: str,
                     structured_evidence: Optional[Dict[str, Any]] = None,
                     rule_id: Optional[str] = None):
        """Add a finding to the list with machine-readable structured evidence"""
        self.finding_counter += 1
        fid = f"SMS-{self.finding_counter:03d}"
        self.findings.append({
            'id': fid,
            'rule_id': rule_id or finding_type.upper(),
            'severity': severity,
            'type': finding_type,
            'title': title,
            'description': description,
            'evidence': evidence,
            'structured_evidence': structured_evidence or {},
            'remediation': remediation
        })

    # ─── CHECK 1: PLAINTEXT PROTOCOLS ───
    def check_plaintext_protocols(self):
        summary = self.data.get('summary', {})
        plaintext_count = summary.get('plaintext_packets', 0)
        total = summary.get('total_packets', 0)
        protocols = summary.get('protocols_detected', [])

        if plaintext_count > 0 and total > 0:
            plaintext_protocols = [
                p for p in protocols
                if p not in ['SMTPS', 'IMAPS', 'POP3S']
            ]
            if plaintext_protocols:
                self._add_finding(
                    severity='CRITICAL',
                    finding_type='plaintext_protocol',
                    rule_id='PROTO_CLEARTEXT_DETECTED',
                    title='Unencrypted Email Protocol Detected',
                    description=(
                        f"{plaintext_count} out of {total} email packets "
                        f"({round(plaintext_count/total*100, 1)}%) are transmitted "
                        f"in plaintext using {', '.join(plaintext_protocols)}. "
                        f"Credentials and email content are visible to any "
                        f"network observer."
                    ),
                    evidence=(
                        f"{plaintext_count} plaintext packets detected on "
                        f"protocols: {', '.join(plaintext_protocols)}"
                    ),
                    structured_evidence={
                        'plaintext_packets': plaintext_count,
                        'total_packets': total,
                        'protocols': plaintext_protocols
                    },
                    remediation=(
                        "1. Enable TLS encryption for all email services\n"
                        "2. Use SMTPS (port 465), IMAPS (port 993), POP3S (port 995)\n"
                        "3. Enforce STARTTLS for SMTP submission (port 587)\n"
                        "4. Disable plaintext authentication"
                    )
                )

    # ─── CHECK 2: SSL 3.0 ───
    def check_ssl3(self):
        tls_versions = self.data.get('summary', {}).get('tls_versions', {})
        if 'SSL 3.0' in tls_versions:
            count = tls_versions['SSL 3.0']
            self._add_finding(
                severity='CRITICAL',
                finding_type='deprecated_protocol',
                rule_id='PROTO_SSL3_DEPRECATED',
                title='SSL 3.0 Detected (POODLE Vulnerable)',
                description=(
                    f"SSL 3.0 was detected in {count} handshake(s). "
                    f"SSL 3.0 is vulnerable to the POODLE attack (CVE-2014-3566) "
                    f"and has been deprecated since RFC 7568 (2015)."
                ),
                evidence=f"{count} TLS handshakes using SSL 3.0",
                structured_evidence={'version': 'SSL 3.0', 'count': count},
                remediation=(
                    "1. Disable SSL 3.0 on all mail servers immediately\n"
                    "2. Configure minimum TLS version to 1.2\n"
                    "3. Test with: openssl s_client -connect mail.example.com:465 -tls1_2"
                )
            )

    # ─── CHECK 3: TLS 1.0 ───
    def check_tls10(self):
        tls_versions = self.data.get('summary', {}).get('tls_versions', {})
        if 'TLS 1.0' in tls_versions:
            count = tls_versions['TLS 1.0']
            self._add_finding(
                severity='CRITICAL',
                finding_type='deprecated_protocol',
                rule_id='PROTO_TLS10_DEPRECATED',
                title='TLS 1.0 Detected (Deprecated)',
                description=(
                    f"TLS 1.0 was detected in {count} handshake(s). "
                    f"TLS 1.0 is deprecated per RFC 8996 (2021) and is "
                    f"non-compliant with PCI DSS 3.2+."
                ),
                evidence=f"{count} TLS handshakes using TLS 1.0",
                structured_evidence={'version': 'TLS 1.0', 'count': count},
                remediation=(
                    "1. Disable TLS 1.0 on all mail servers\n"
                    "2. Set minimum TLS version to 1.2\n"
                    "3. Update mail server configuration (Postfix/Dovecot/Exchange)"
                )
            )

    # ─── CHECK 4: TLS 1.1 ───
    def check_tls11(self):
        tls_versions = self.data.get('summary', {}).get('tls_versions', {})
        if 'TLS 1.1' in tls_versions:
            count = tls_versions['TLS 1.1']
            self._add_finding(
                severity='HIGH',
                finding_type='deprecated_protocol',
                rule_id='PROTO_TLS11_DEPRECATED',
                title='TLS 1.1 Detected (Deprecated)',
                description=(
                    f"TLS 1.1 was detected in {count} handshake(s). "
                    f"TLS 1.1 is deprecated per RFC 8996 (2021). "
                    f"Major browsers and mail providers have dropped support."
                ),
                evidence=f"{count} TLS handshakes using TLS 1.1",
                structured_evidence={'version': 'TLS 1.1', 'count': count},
                remediation=(
                    "1. Disable TLS 1.1 on all mail servers\n"
                    "2. Use TLS 1.2 or TLS 1.3 only\n"
                    "3. Verify with: nmap --script ssl-enum-ciphers -p 465 mail.example.com"
                )
            )

    # ─── CHECK 5: WEAK CIPHERS ───
    def check_weak_ciphers(self):
        """Flag weak cipher suites that were actually negotiated (ServerHello),
        not merely offered by the client -- a client listing a weak cipher
        among many options isn't itself a vulnerability if the server never
        selects it. tshark reports the negotiated cipher as a raw hex code
        (e.g. "0x0035"), so this looks it up in the IANA cipher-suite
        registry rather than string-matching cipher names."""
        handshakes = self.data.get('tls_handshakes', [])
        weak_found: Dict[str, str] = {}  # cipher_code -> name

        for hs in handshakes:
            if hs.get('handshake_type') != 'ServerHello':
                continue
            ciphers = hs.get('cipher_suites', [])
            if not ciphers:
                continue
            info = lookup_cipher_suite(ciphers[0])
            if info and info['weak']:
                weak_found[ciphers[0]] = f"{info['name']} ({info['weak_reason']})"

        if weak_found:
            names = list(weak_found.values())
            self._add_finding(
                severity='CRITICAL',
                finding_type='weak_cipher',
                rule_id='CIPHER_WEAK_DETECTED',
                title='Weak Cipher Suites Detected',
                description=(
                    f"The following weak cipher suite(s) were negotiated: "
                    f"{', '.join(names[:5])}. These are vulnerable to known "
                    f"attacks (BEAST, Sweet32, RC4 keystream biases, FREAK) "
                    f"or provide no encryption at all."
                ),
                evidence=f"Negotiated weak cipher(s): {', '.join(names[:5])}",
                structured_evidence={'weak_ciphers': names},
                remediation=(
                    "1. Remove all RC4, DES, 3DES, NULL, and EXPORT ciphers from the server config\n"
                    "2. Prioritize AEAD ciphers: AES-GCM, ChaCha20-Poly1305\n"
                    "3. Use TLS 1.3 which only allows strong ciphers\n"
                    "4. Test with: testssl.sh mail.example.com"
                )
            )

    # ─── CHECK 11: FORWARD SECRECY ───
    def check_forward_secrecy(self):
        """Flag TLS sessions that negotiated a static (non-ephemeral) key
        exchange -- static RSA or static (EC)DH -- instead of DHE/ECDHE.
        TLS 1.3 is skipped entirely since it mandates ephemeral key exchange
        by design and is therefore always forward-secret."""
        handshakes = self.data.get('tls_handshakes', [])
        weak_kex_sessions = []

        for hs in handshakes:
            if hs.get('handshake_type') != 'ServerHello':
                continue
            if hs.get('tls_version') == 'TLS 1.3':
                continue

            ciphers = hs.get('cipher_suites', [])
            if not ciphers:
                continue

            info = lookup_cipher_suite(ciphers[0])
            if not info:
                continue  # unrecognized cipher code -- don't guess at its properties

            if not info['forward_secret']:
                weak_kex_sessions.append({
                    'src': hs.get('src') or 'unknown',
                    'dst': hs.get('dst') or 'unknown',
                    'cipher': info['name'],
                    'tls_version': hs.get('tls_version'),
                })

        if weak_kex_sessions:
            examples = [
                f"{s['src']}→{s['dst']} ({s['cipher']}, {s['tls_version']})"
                for s in weak_kex_sessions[:3]
            ]
            self._add_finding(
                severity='HIGH',
                finding_type='no_forward_secrecy',
                rule_id='TLS_NO_FORWARD_SECRECY',
                title='TLS Session Without Forward Secrecy',
                description=(
                    f"{len(weak_kex_sessions)} TLS session(s) negotiated a static "
                    f"(non-ephemeral) key exchange -- RSA or static (EC)DH -- instead "
                    f"of DHE/ECDHE. Without forward secrecy, recording this encrypted "
                    f"traffic today and later compromising the server's private key "
                    f"would let an attacker decrypt every past session that used it, "
                    f"not just future ones."
                ),
                evidence='; '.join(examples),
                structured_evidence={'sessions': weak_kex_sessions},
                remediation=(
                    "1. Configure the server to prefer ECDHE or DHE cipher suites\n"
                    "2. Disable static RSA and static (EC)DH key-exchange cipher suites\n"
                    "3. Prefer TLS 1.3, which removes non-ephemeral key exchange entirely\n"
                    "4. Verify with: nmap --script ssl-enum-ciphers -p 465 mail.example.com"
                )
            )

    # ─── CHECK 6: WEAK SIGNATURES ───
    def check_weak_signatures(self):
        certificates = self.data.get('certificates', [])
        weak_certs = []

        for cert in certificates:
            sig_algo = cert.get('signature_algorithm', '').lower()
            for weak in WEAK_SIG_ALGOS:
                if weak in sig_algo:
                    weak_certs.append({
                        'subject': cert.get('subject', 'Unknown'),
                        'algorithm': cert.get('signature_algorithm', ''),
                        'serial': cert.get('serial_number', '')
                    })
                    break

        if weak_certs:
            subjects = [c['subject'] for c in weak_certs[:3]]
            self._add_finding(
                severity='HIGH',
                finding_type='weak_signature',
                rule_id='CERT_SIGNATURE_WEAK',
                title='Weak Certificate Signature Algorithm',
                description=(
                    f"{len(weak_certs)} certificate(s) use weak signature "
                    f"algorithms (MD5/SHA-1). These are vulnerable to "
                    f"collision attacks."
                ),
                evidence=f"Affected: {', '.join(subjects)}",
                structured_evidence={'affected_certificates': weak_certs},
                remediation=(
                    "1. Re-issue certificates with SHA-256 or stronger\n"
                    "2. Update CA signing configuration\n"
                    "3. Verify: openssl x509 -in cert.pem -text | grep 'Signature Algorithm'"
                )
            )

    # ─── CHECK 7: KEY SIZES ───
    def check_key_sizes(self):
        certificates = self.data.get('certificates', [])
        weak_keys = []

        for cert in certificates:
            key_algo = cert.get('public_key_algorithm', '').lower()
            key_size = cert.get('key_size', 0)

            if key_size > 0:
                for algo, min_size in MIN_KEY_SIZES.items():
                    if algo in key_algo and key_size < min_size:
                        weak_keys.append({
                            'subject': cert.get('subject', 'Unknown'),
                            'algorithm': cert.get('public_key_algorithm', ''),
                            'size': key_size,
                            'minimum': min_size
                        })
                        break

        if weak_keys:
            details = [
                f"{k['subject']} ({k['size']} bits, min {k['minimum']})"
                for k in weak_keys[:3]
            ]
            self._add_finding(
                severity='HIGH',
                finding_type='insufficient_key_size',
                rule_id='CERT_KEY_SIZE_INSUFFICIENT',
                title='Insufficient Certificate Key Size',
                description=(
                    f"{len(weak_keys)} certificate(s) have key sizes below "
                    f"recommended minimums. Small keys are vulnerable to "
                    f"brute-force factorization."
                ),
                evidence='; '.join(details),
                structured_evidence={'weak_keys': weak_keys},
                remediation=(
                    "1. Use RSA keys >= 2048 bits (4096 recommended)\n"
                    "2. Use ECC keys >= 256 bits\n"
                    "3. Re-issue certificates with stronger keys"
                )
            )

    # ─── CHECK 8: MISSING STARTTLS ───
    def check_missing_starttls(self):
        sessions = self.data.get('sessions', [])
        tls_handshakes = self.data.get('tls_handshakes', [])

        plaintext_smtp = [
            s for s in sessions
            if s.get('protocol') in ['SMTP', 'SMTP-Submission', 'SMTP-Alt']
            and not s.get('encrypted')
        ]

        has_any_tls = len(tls_handshakes) > 0

        if plaintext_smtp and not has_any_tls:
            self._add_finding(
                severity='HIGH',
                finding_type='missing_starttls',
                rule_id='PROTO_MISSING_STARTTLS',
                title='No STARTTLS Negotiation Detected',
                description=(
                    f"{len(plaintext_smtp)} plaintext SMTP session(s) detected "
                    f"with no TLS upgrade (STARTTLS). Email is transmitted "
                    f"entirely in cleartext."
                ),
                evidence=(
                    f"{len(plaintext_smtp)} SMTP sessions on port 25/587 "
                    f"without STARTTLS"
                ),
                structured_evidence={'plaintext_session_count': len(plaintext_smtp)},
                remediation=(
                    "1. Enable STARTTLS on SMTP server\n"
                    "2. Configure opportunistic TLS (TLS if available)\n"
                    "3. Consider MTA-STS policy for enforced TLS\n"
                    "4. Postfix: smtpd_tls_security_level = may\n"
                    "5. Dovecot: ssl = required"
                )
            )

    # ─── CHECK 9: GRANULAR CERTIFICATE CHAIN CHECKS ───
    def check_certificate_chains(self):
        """Integrates granular PKI findings from multi-tier chain analysis"""
        chains = self.data.get('certificate_chains', [])
        seen_rule_targets = set()

        for ch in chains:
            for pki_f in ch.get('pki_findings', []):
                rule_id = pki_f.get('rule_id')
                ev = pki_f.get('evidence', {})
                unique_key = (rule_id, ev.get('subject'), ev.get('frame'))
                if unique_key in seen_rule_targets:
                    continue
                seen_rule_targets.add(unique_key)

                ev_str = f"Frame {ev.get('frame', 'N/A')} (Stream {ev.get('tcp_stream', 'N/A')})"
                if ev.get('subject'):
                    ev_str += f" - {ev.get('subject')}"
                elif ev.get('sni'):
                    ev_str += f" - SNI: {ev.get('sni')}"

                self._add_finding(
                    severity=pki_f.get('severity', 'MEDIUM'),
                    finding_type='certificate_pki',
                    rule_id=rule_id,
                    title=pki_f.get('title', 'PKI Certificate Issue'),
                    description=pki_f.get('description', ''),
                    evidence=ev_str,
                    structured_evidence=ev,
                    remediation=pki_f.get('remediation', 'Renew or reconfigure certificate.')
                )

    # ─── CHECK 9: THREAT INTEL (SSLBL) ───
    def check_known_malicious_certificates(self):
        """Flags certificates matching abuse.ch's SSLBL blacklist of SHA1
        fingerprints seen on botnet C2 infrastructure. Unlike every other
        check here, this is not a property of the certificate itself --
        it's external threat intelligence, so a well-formed, validly-signed
        certificate can still trigger it."""
        certificates = self.data.get('certificates', [])
        feed = get_threat_intel_feed()
        matches = []

        for cert in certificates:
            listing = feed.lookup(cert.get('fingerprint_sha1'))
            if listing:
                matches.append({
                    'subject': cert.get('subject', 'Unknown'),
                    'fingerprint_sha1': cert.get('fingerprint_sha1', ''),
                    'listed_since': listing.get('listed_since', ''),
                    'reason': listing.get('reason', ''),
                })

        if matches:
            subjects = [m['subject'] for m in matches[:3]]
            self._add_finding(
                severity='CRITICAL',
                finding_type='known_malicious_certificate',
                rule_id='CERT_THREAT_INTEL_MATCH',
                title='Certificate Matches Known-Malicious Threat Intel',
                description=(
                    f"{len(matches)} certificate(s) match entries in the abuse.ch SSLBL "
                    f"blacklist of certificates observed on botnet command-and-control "
                    f"infrastructure. This connection is cryptographically valid but "
                    f"terminates at a host known to be malicious."
                ),
                evidence=f"Affected: {', '.join(subjects)}",
                structured_evidence={'affected_certificates': matches, 'source': 'abuse.ch SSLBL'},
                remediation=(
                    "1. Treat this host as compromised and terminate the connection\n"
                    "2. Isolate the endpoint and investigate for related C2 traffic\n"
                    "3. Block the certificate's SHA1 fingerprint and associated IP(s) at the network perimeter"
                )
            )

    # ─── CHECK 10: EMAIL AUTHENTICATION (PASSIVE SPF/DKIM/DMARC) ───
    def check_email_authentication(self):
        """Findings from SPF/DKIM/DMARC evidence found in the capture itself
        (message headers, plaintext DNS). One finding per rule, listing every
        affected message/record, so a busy capture doesn't inflate the score."""
        for issue in self.data.get('email_auth', {}).get('issues', []):
            affected = issue['affected']
            self._add_finding(
                severity=issue['severity'],
                finding_type='email_authentication',
                rule_id=issue['rule_id'],
                title=issue['title'],
                description=f"{issue['description']} ({len(affected)} occurrence(s) in this capture.)",
                evidence="; ".join(affected[:3]) + (f" (+{len(affected) - 3} more)" if len(affected) > 3 else ""),
                structured_evidence={'affected': affected, 'source': 'passive capture analysis'},
                remediation=issue['remediation'],
            )

    # ─── RISK SCORING ───
    def calculate_risk_score(self) -> Dict:
        """Calculate overall risk score (0-100)"""
        severity_weights = {
            'CRITICAL': 15,
            'HIGH': 10,
            'MEDIUM': 5,
            'LOW': 2
        }

        finding_score = sum(
            severity_weights.get(f['severity'], 0)
            for f in self.findings
        )

        summary = self.data.get('summary', {})
        total = summary.get('total_packets', 0)
        plaintext = summary.get('plaintext_packets', 0)

        encryption_penalty = 0
        if total > 0:
            encryption_penalty = (plaintext / total) * 30

        raw_score = finding_score + encryption_penalty
        risk_score = min(round(raw_score), 100)

        if risk_score >= 70:
            level = 'CRITICAL'
        elif risk_score >= 40:
            level = 'HIGH'
        elif risk_score >= 20:
            level = 'MEDIUM'
        else:
            level = 'LOW'

        return {
            'risk_score': risk_score,
            'risk_level': level,
            'risk_grade': risk_score_to_grade(risk_score),
            'finding_score': finding_score,
            'encryption_penalty': round(encryption_penalty, 1),
            'critical_count': sum(1 for f in self.findings if f['severity'] == 'CRITICAL'),
            'high_count': sum(1 for f in self.findings if f['severity'] == 'HIGH'),
            'medium_count': sum(1 for f in self.findings if f['severity'] == 'MEDIUM'),
            'low_count': sum(1 for f in self.findings if f['severity'] == 'LOW'),
        }