"""
Security Rule Engine for SecureMailScope
Deterministic security checks against extracted PCAP data
"""

from typing import List, Dict


# Known weak cipher suite keywords
WEAK_CIPHERS = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon', 'MD5']

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


class SecurityEngine:
    """Run deterministic security checks on PCAP analysis data"""

    def __init__(self, analysis_data: Dict):
        """
        analysis_data should contain:
        - summary: packet counts, protocols, TLS versions
        - sessions: reconstructed email sessions
        - tls_handshakes: TLS handshake metadata
        - certificates: extracted X.509 certificates
        """
        self.data = analysis_data
        self.findings = []
        self.finding_counter = 0

    def run_all_checks(self) -> List[Dict]:
        """Run all security checks and return findings"""
        self.check_plaintext_protocols()
        self.check_ssl3()
        self.check_tls10()
        self.check_tls11()
        self.check_weak_ciphers()
        self.check_weak_signatures()
        self.check_key_sizes()
        self.check_expired_certificates()
        self.check_self_signed_certificates()
        self.check_missing_starttls()

        return self.findings

    def _add_finding(self, severity: str, finding_type: str,
                     title: str, description: str,
                     evidence: str, remediation: str):
        """Add a finding to the list"""
        self.finding_counter += 1
        self.findings.append({
            'id': f"SMS-{self.finding_counter:03d}",
            'severity': severity,
            'type': finding_type,
            'title': title,
            'description': description,
            'evidence': evidence,
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
                title='SSL 3.0 Detected (POODLE Vulnerable)',
                description=(
                    f"SSL 3.0 was detected in {count} handshake(s). "
                    f"SSL 3.0 is vulnerable to the POODLE attack (CVE-2014-3566) "
                    f"and has been deprecated since RFC 7568 (2015)."
                ),
                evidence=f"{count} TLS handshakes using SSL 3.0",
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
                title='TLS 1.0 Detected (Deprecated)',
                description=(
                    f"TLS 1.0 was detected in {count} handshake(s). "
                    f"TLS 1.0 is deprecated per RFC 8996 (2021) and is "
                    f"non-compliant with PCI DSS 3.2+."
                ),
                evidence=f"{count} TLS handshakes using TLS 1.0",
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
                title='TLS 1.1 Detected (Deprecated)',
                description=(
                    f"TLS 1.1 was detected in {count} handshake(s). "
                    f"TLS 1.1 is deprecated per RFC 8996 (2021). "
                    f"Major browsers and mail providers have dropped support."
                ),
                evidence=f"{count} TLS handshakes using TLS 1.1",
                remediation=(
                    "1. Disable TLS 1.1 on all mail servers\n"
                    "2. Use TLS 1.2 or TLS 1.3 only\n"
                    "3. Verify with: nmap --script ssl-enum-ciphers -p 465 mail.example.com"
                )
            )

    # ─── CHECK 5: WEAK CIPHERS ───
    def check_weak_ciphers(self):
        handshakes = self.data.get('tls_handshakes', [])
        weak_found = set()

        for hs in handshakes:
            for cipher in hs.get('cipher_suites', []):
                cipher_upper = cipher.upper()
                for weak in WEAK_CIPHERS:
                    if weak.upper() in cipher_upper:
                        weak_found.add(cipher)

        if weak_found:
            self._add_finding(
                severity='CRITICAL',
                finding_type='weak_cipher',
                title='Weak Cipher Suites Detected',
                description=(
                    f"The following weak cipher suites were offered or "
                    f"selected: {', '.join(list(weak_found)[:5])}. "
                    f"These ciphers are vulnerable to known attacks "
                    f"(BEAST, SWEET32, RC4 biases)."
                ),
                evidence=f"Weak ciphers: {', '.join(list(weak_found)[:5])}",
                remediation=(
                    "1. Remove all RC4, DES, 3DES, NULL, and EXPORT ciphers\n"
                    "2. Prioritize AEAD ciphers: AES-GCM, ChaCha20-Poly1305\n"
                    "3. Use TLS 1.3 which only allows strong ciphers\n"
                    "4. Test with: testssl.sh mail.example.com"
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
                        'algorithm': cert.get('signature_algorithm', '')
                    })
                    break

        if weak_certs:
            subjects = [c['subject'] for c in weak_certs[:3]]
            self._add_finding(
                severity='HIGH',
                finding_type='weak_signature',
                title='Weak Certificate Signature Algorithm',
                description=(
                    f"{len(weak_certs)} certificate(s) use weak signature "
                    f"algorithms (MD5/SHA-1). These are vulnerable to "
                    f"collision attacks."
                ),
                evidence=f"Affected: {', '.join(subjects)}",
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
                title='Insufficient Certificate Key Size',
                description=(
                    f"{len(weak_keys)} certificate(s) have key sizes below "
                    f"recommended minimums. Small keys are vulnerable to "
                    f"brute-force factorization."
                ),
                evidence='; '.join(details),
                remediation=(
                    "1. Use RSA keys ≥ 2048 bits (4096 recommended)\n"
                    "2. Use ECC keys ≥ 256 bits\n"
                    "3. Re-issue certificates with stronger keys"
                )
            )

    # ─── CHECK 8: EXPIRED CERTIFICATES ───
    def check_expired_certificates(self):
        certificates = self.data.get('certificates', [])
        expired = [c for c in certificates if c.get('is_expired')]

        if expired:
            subjects = [c.get('subject', 'Unknown') for c in expired[:3]]
            self._add_finding(
                severity='HIGH',
                finding_type='expired_certificate',
                title='Expired Certificate Detected',
                description=(
                    f"{len(expired)} certificate(s) have expired. "
                    f"Expired certificates break trust chains and "
                    f"indicate poor certificate lifecycle management."
                ),
                evidence=f"Expired: {', '.join(subjects)}",
                remediation=(
                    "1. Renew expired certificates immediately\n"
                    "2. Implement automated certificate renewal (ACME/Let's Encrypt)\n"
                    "3. Set up expiry monitoring alerts (30 days before expiry)"
                )
            )

    # ─── CHECK 9: SELF-SIGNED CERTIFICATES ───
    def check_self_signed_certificates(self):
        certificates = self.data.get('certificates', [])
        self_signed = [c for c in certificates if c.get('is_self_signed')]

        if self_signed:
            subjects = [c.get('subject', 'Unknown') for c in self_signed[:3]]
            self._add_finding(
                severity='MEDIUM',
                finding_type='self_signed_certificate',
                title='Self-Signed Certificate Detected',
                description=(
                    f"{len(self_signed)} self-signed certificate(s) detected. "
                    f"Self-signed certificates cannot be verified by clients "
                    f"and are vulnerable to man-in-the-middle attacks."
                ),
                evidence=f"Self-signed: {', '.join(subjects)}",
                remediation=(
                    "1. Replace with certificates from a trusted CA\n"
                    "2. Use Let's Encrypt for free trusted certificates\n"
                    "3. If internal use, deploy a private CA and distribute root cert"
                )
            )

    # ─── CHECK 10: MISSING STARTTLS ───
    def check_missing_starttls(self):
        sessions = self.data.get('sessions', [])
        tls_handshakes = self.data.get('tls_handshakes', [])

        # Check for plaintext SMTP sessions without any TLS upgrade
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
                remediation=(
                    "1. Enable STARTTLS on SMTP server\n"
                    "2. Configure opportunistic TLS (TLS if available)\n"
                    "3. Consider MTA-STS policy for enforced TLS\n"
                    "4. Postfix: smtpd_tls_security_level = may\n"
                    "5. Dovecot: ssl = required"
                )
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

        # Score from findings
        finding_score = sum(
            severity_weights.get(f['severity'], 0)
            for f in self.findings
        )

        # Score from encryption ratio
        summary = self.data.get('summary', {})
        total = summary.get('total_packets', 0)
        plaintext = summary.get('plaintext_packets', 0)

        encryption_penalty = 0
        if total > 0:
            encryption_penalty = (plaintext / total) * 30

        # Calculate total
        raw_score = finding_score + encryption_penalty
        risk_score = min(round(raw_score), 100)

        # Determine level
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
            'finding_score': finding_score,
            'encryption_penalty': round(encryption_penalty, 1),
            'critical_count': sum(1 for f in self.findings if f['severity'] == 'CRITICAL'),
            'high_count': sum(1 for f in self.findings if f['severity'] == 'HIGH'),
            'medium_count': sum(1 for f in self.findings if f['severity'] == 'MEDIUM'),
            'low_count': sum(1 for f in self.findings if f['severity'] == 'LOW'),
        }