"""
Security Rule Engine for SecureMailScope
Deterministic security checks against extracted PCAP data and certificate chains.
Preserves forensic evidence references (frame, stream, SNI, endpoints) and provenance source_refs.
"""

from typing import List, Dict, Optional, Any

try:
    from app.core.cipher_suites import lookup as lookup_cipher_suite
    from app.services.threat_intel_feed import get_threat_intel_feed
except ImportError:
    try:
        from core.cipher_suites import lookup as lookup_cipher_suite
        from services.threat_intel_feed import get_threat_intel_feed
    except ImportError:
        try:
            from ..core.cipher_suites import lookup as lookup_cipher_suite
            from ..services.threat_intel_feed import get_threat_intel_feed
        except ImportError:
            lookup_cipher_suite = None
            get_threat_intel_feed = None

# Known weak cipher suite keywords
WEAK_CIPHERS = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon', 'MD5']

# Weak cipher hex codes (IANA TLS Cipher Suite Registry) - UPPERCASE for matching
WEAK_CIPHER_CODES = {
    '0X0000', '0X0001', '0X0002', '0X0003', '0X0004', '0X0005',  # NULL, RC4, RC2
    '0X0006', '0X0007', '0X0008', '0X0009', '0X000A', '0X000B',  # DES, 3DES
    '0X000C', '0X000D', '0X000E', '0X000F', '0X0010', '0X0011',  # 3DES variants
    '0X0012', '0X0013', '0X0014', '0X0015', '0X0016', '0X0017',  # DES/export
    '0X0018', '0X0019', '0X001A', '0X001B',  # anon DH
}

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
    """Run deterministic security checks on PCAP analysis data, PKI chains, and passive authentication evidence"""

    def __init__(self, analysis_data: Dict):
        """
        analysis_data should contain:
        - summary: packet counts, protocols, TLS versions
        - sessions: reconstructed email sessions
        - tls_handshakes: TLS handshake metadata
        - certificates: extracted X.509 certificates
        - certificate_chains: multi-tier certificate chain analyses
        - email_auth: passive SPF/DKIM/DMARC analysis results
        """
        self.data = analysis_data
        self.findings = []
        self.finding_counter = 0

    def run_all_checks(self) -> List[Dict]:
        """Run all deterministic security, PKI, and authentication checks"""
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
        self.check_forward_secrecy()
        self.check_certificate_chains()
        self.check_known_malicious_certificates()
        self.check_email_authentication()

        return self.findings

    def _add_finding(self, severity: str, finding_type: str,
                     title: str, description: str,
                     evidence: str, remediation: str,
                     structured_evidence: Optional[Dict[str, Any]] = None,
                     source_refs: Optional[List[str]] = None,
                     rule_id: Optional[str] = None):
        """Add a finding to the list with machine-readable structured evidence and provenance source_refs"""
        self.finding_counter += 1
        fid = f"SMS-{self.finding_counter:03d}"
        f_entry = {
            'id': fid,
            'rule_id': rule_id or finding_type.upper(),
            'severity': severity,
            'type': finding_type,
            'title': title,
            'description': description,
            'evidence': evidence,
            'structured_evidence': structured_evidence or {},
            'remediation': remediation
        }
        if source_refs:
            f_entry['source_refs'] = source_refs
        self.findings.append(f_entry)

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
                    rule_id='PROTO_PLAINTEXT_DETECTED',
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
                        'plaintext_count': plaintext_count,
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
                rule_id='TLS_SSL3_DEPRECATED',
                title='SSL 3.0 Detected (POODLE Vulnerable)',
                description=(
                    f"SSL 3.0 was detected in {count} handshake(s). "
                    f"SSL 3.0 is vulnerable to the POODLE attack (CVE-2014-3566) "
                    f"and has been deprecated since RFC 7568 (2015)."
                ),
                evidence=f"{count} TLS handshakes using SSL 3.0",
                structured_evidence={'version': 'SSL 3.0', 'handshake_count': count},
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
                rule_id='TLS_10_DEPRECATED',
                title='TLS 1.0 Detected (Deprecated)',
                description=(
                    f"TLS 1.0 was detected in {count} handshake(s). "
                    f"TLS 1.0 is deprecated per RFC 8996 (2021) and is "
                    f"non-compliant with PCI DSS 3.2+."
                ),
                evidence=f"{count} TLS handshakes using TLS 1.0",
                structured_evidence={'version': 'TLS 1.0', 'handshake_count': count},
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
                rule_id='TLS_11_DEPRECATED',
                title='TLS 1.1 Detected (Deprecated)',
                description=(
                    f"TLS 1.1 was detected in {count} handshake(s). "
                    f"TLS 1.1 is deprecated per RFC 8996 (2021)."
                ),
                evidence=f"{count} TLS handshakes using TLS 1.1",
                structured_evidence={'version': 'TLS 1.1', 'handshake_count': count},
                remediation=(
                    "1. Disable TLS 1.1 on all mail servers\n"
                    "2. Set minimum TLS version to 1.2\n"
                    "3. Migrate to TLS 1.3 where supported"
                )
            )

    # ─── CHECK 5: WEAK CIPHERS (SERVERHELLO ONLY, DETERMINISTIC ORDERING) ───
    def check_weak_ciphers(self):
        """Flag weak cipher suites that were actually negotiated (ServerHello),
        not merely offered by the client. Looks up IANA cipher-suite registry
        where available, falling back to keyword and known code matching."""
        handshakes = self.data.get('tls_handshakes', [])
        weak_found: Dict[str, str] = {}  # cipher_code -> name

        for hs in handshakes:
            if hs.get('handshake_type') != 'ServerHello':
                continue
            ciphers = hs.get('cipher_suites', [])
            if not ciphers:
                continue
            for c in ciphers:
                if lookup_cipher_suite:
                    info = lookup_cipher_suite(c)
                    if info and info['weak']:
                        weak_found[c] = f"{info['name']} ({info['weak_reason']})"
                        continue
                # Fallback to local table if lookup_cipher_suite not available or unknown
                c_clean = str(c).strip().upper()
                if c_clean in WEAK_CIPHER_CODES or any(wc.upper() in c_clean for wc in WEAK_CIPHERS):
                    weak_found[c] = f"Weak Cipher Suite {c}"

        if weak_found:
            names = [weak_found[code] for code in sorted(weak_found)]
            self._add_finding(
                severity='CRITICAL',
                finding_type='weak_cipher',
                rule_id='CIPHER_WEAK_DETECTED',
                title='Weak Cipher Suites Detected',
                description=(
                    f"The following weak cipher suite(s) were negotiated: "
                    f"{', '.join(names)}. These are vulnerable to known "
                    f"attacks (BEAST, Sweet32, RC4 keystream biases, FREAK) "
                    f"or provide no encryption at all."
                ),
                evidence=f"Negotiated in ServerHello: {', '.join(names)}",
                structured_evidence={'negotiated_weak_ciphers': sorted(weak_found.keys())},
                remediation=(
                    "1. Disable all NULL, RC4, DES, and 3DES cipher suites\n"
                    "2. Enforce modern AEAD cipher suites (GCM, Poly1305)\n"
                    "3. Recommended OpenSSL cipher string: "
                    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
                )
            )

    # ─── CHECK 6: WEAK SIGNATURES ───
    def check_weak_signatures(self):
        certificates = self.data.get('certificates', [])
        weak_certs = []

        for cert in certificates:
            sig_algo = cert.get('signature_algorithm', '').lower()
            for weak_algo in WEAK_SIG_ALGOS:
                if weak_algo in sig_algo:
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
                rule_id='CERT_WEAK_SIG_ALGO',
                title='Weak Certificate Signature Algorithm',
                description=(
                    f"{len(weak_certs)} certificate(s) use weak signature "
                    f"algorithms (MD5/SHA-1). These are vulnerable to "
                    f"collision attacks."
                ),
                evidence=f"Affected: {', '.join(subjects)}",
                structured_evidence={'weak_certs': weak_certs},
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

            if key_size and key_size > 0:
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
                rule_id='CERT_INSUFFICIENT_KEY_SIZE',
                title='Insufficient Certificate Key Size',
                description=(
                    f"{len(weak_keys)} certificate(s) have key sizes below "
                    f"recommended minimums. Small keys are vulnerable to "
                    f"brute-force factorization."
                ),
                evidence='; '.join(details),
                structured_evidence={'weak_keys': weak_keys},
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
                rule_id='CERT_EXPIRED',
                title='Expired Certificate Detected',
                description=(
                    f"{len(expired)} certificate(s) have expired. "
                    f"Expired certificates break trust chains and "
                    f"indicate poor certificate lifecycle management."
                ),
                evidence=f"Expired: {', '.join(subjects)}",
                structured_evidence={'expired_count': len(expired), 'subjects': subjects},
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
                rule_id='CERT_SELF_SIGNED',
                title='Self-Signed Certificate Detected',
                description=(
                    f"{len(self_signed)} certificate(s) are self-signed. "
                    f"Self-signed certificates cannot be verified by clients "
                    f"without explicit root trust configuration."
                ),
                evidence=f"Self-signed: {', '.join(subjects)}",
                structured_evidence={'self_signed_count': len(self_signed), 'subjects': subjects},
                remediation=(
                    "1. Replace self-signed certificates with trusted CA-signed certificates\n"
                    "2. Use Let's Encrypt for free, automated trusted certificates\n"
                    "3. For internal servers, establish an internal CA with distributed root trust"
                )
            )

    # ─── CHECK 10: MISSING STARTTLS ───
    def check_missing_starttls(self):
        sessions = self.data.get('sessions', [])
        missing_starttls = [
            s for s in sessions
            if s.get('protocol') in ['SMTP', 'SMTP-Submission', 'SMTP-Alt']
            and not s.get('starttls_offered', False)
            and not s.get('encrypted', False)
        ]

        if missing_starttls:
            server_ips = []
            for s in missing_starttls:
                srv = s.get('server', {}).get('ip')
                if not srv:
                    dst = s.get('dst', '')
                    srv = dst.split(':')[0] if ':' in str(dst) else (dst or 'Unknown')
                port = s.get('dst_port') or (str(s.get('dst', '')).split(':')[-1] if ':' in str(s.get('dst', '')) else '25')
                server_ips.append(f"{srv} (port {port})")
            unique_servers = list(dict.fromkeys(server_ips))
            session_ids = [s.get('id', '') for s in missing_starttls if s.get('id')]
            evidence_parts = [f"{len(missing_starttls)} SMTP session(s) without STARTTLS"]
            if session_ids:
                evidence_parts.append(f"[{', '.join(session_ids[:3])}]")
            evidence_parts.append(f"on servers: {', '.join(unique_servers[:3])}")
            evidence_str = " ".join(evidence_parts)

            self._add_finding(
                severity='HIGH',
                finding_type='missing_starttls',
                rule_id='STARTTLS_NOT_OFFERED',
                title='STARTTLS Not Offered on Mail Service',
                description=(
                    f"Mail servers at {', '.join(unique_servers[:3])} did not "
                    f"advertise STARTTLS in their EHLO/HELO responses. "
                    f"Clients cannot upgrade to encrypted connections."
                ),
                evidence=evidence_str,
                structured_evidence={'server_ips': unique_servers, 'session_count': len(missing_starttls), 'session_ids': session_ids},
                remediation=(
                    "1. Enable STARTTLS on SMTP server\n"
                    "2. Configure opportunistic TLS (TLS if available)\n"
                    "3. Consider MTA-STS policy for enforced TLS\n"
                    "4. Postfix: smtpd_tls_security_level = may\n"
                    "5. Dovecot: ssl = required"
                )
            )

    # ─── CHECK 11: FORWARD SECRECY ───
    def check_forward_secrecy(self):
        """Flag TLS sessions that negotiated a static (non-ephemeral) key
        exchange -- static RSA or static (EC)DH -- instead of DHE/ECDHE.
        TLS 1.3 is skipped entirely since it mandates ephemeral key exchange."""
        handshakes = self.data.get('tls_handshakes', [])
        weak_kex_sessions = []

        for hs in handshakes:
            if hs.get('handshake_type') and hs.get('handshake_type') != 'ServerHello':
                continue
            if hs.get('tls_version') == 'TLS 1.3':
                continue

            ciphers = hs.get('cipher_suites', [])
            if not ciphers:
                continue

            for c in ciphers:
                if lookup_cipher_suite:
                    info = lookup_cipher_suite(c)
                    if not info:
                        continue
                    if not info['forward_secret']:
                        weak_kex_sessions.append({
                            'src': hs.get('src') or 'unknown',
                            'dst': hs.get('dst') or 'unknown',
                            'cipher_code': c,
                            'cipher_name': info['name'],
                            'kex': info['kex'],
                            'frame': hs.get('frame'),
                            'tcp_stream': hs.get('tcp_stream'),
                        })
                        break
                else:
                    c_clean = str(c).upper()
                    if 'RSA' in c_clean and 'DHE' not in c_clean and 'ECDHE' not in c_clean:
                        weak_kex_sessions.append({
                            'src': hs.get('src') or 'unknown',
                            'dst': hs.get('dst') or 'unknown',
                            'cipher_code': c,
                            'cipher_name': str(c),
                            'kex': 'Static RSA',
                            'frame': hs.get('frame'),
                            'tcp_stream': hs.get('tcp_stream'),
                        })
                        break

        if weak_kex_sessions:
            ciphers_used = sorted({s['cipher_name'] for s in weak_kex_sessions})
            endpoints = sorted({f"{s['src']} -> {s['dst']}" for s in weak_kex_sessions})
            frames = [s['frame'] for s in weak_kex_sessions if s.get('frame')]

            self._add_finding(
                severity='HIGH',
                finding_type='no_forward_secrecy',
                rule_id='CIPHER_NO_FORWARD_SECRECY',
                title='Missing Forward Secrecy in Negotiated TLS Ciphers',
                description=(
                    f"{len(weak_kex_sessions)} session(s) negotiated static key-exchange "
                    f"ciphers ({', '.join(ciphers_used)}) that lack Forward Secrecy. "
                    f"If the server's private key is compromised in the future, past "
                    f"recorded traffic can be retroactively decrypted."
                ),
                evidence=(
                    f"Static key exchange negotiated across: {', '.join(endpoints[:3])} "
                    f"using {', '.join(ciphers_used)}"
                ),
                structured_evidence={
                    'session_count': len(weak_kex_sessions),
                    'ciphers': ciphers_used,
                    'endpoints': endpoints,
                    'frames': frames,
                },
                remediation=(
                    "1. Configure mail servers to prefer ECDHE and DHE key exchange ciphers\n"
                    "2. Disable static RSA key-exchange cipher suites\n"
                    "3. OpenSSL recommended: ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\n"
                    "4. Upgrade to TLS 1.3, which mandates forward-secret key exchange by design"
                )
            )

    # ─── CHECK 12: CERTIFICATE CHAINS (RFC 5280 MULTI-TIER AUDIT) ───
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
                    remediation=pki_f.get('remediation', '')
                )

    # ─── CHECK 13: KNOWN MALICIOUS CERTIFICATES (SSLBL FEED) ───
    def check_known_malicious_certificates(self):
        """Flags certificates matching abuse.ch's SSLBL blacklist of SHA1
        fingerprints seen on botnet C2 infrastructure."""
        if not get_threat_intel_feed:
            return

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
                title='Certificate Matches Known Threat Intel (SSLBL Blacklist)',
                description=(
                    f"{len(matches)} certificate(s) match abuse.ch's SSL Blacklist (SSLBL) "
                    f"of SHA1 fingerprints associated with malicious activity and botnet C2. "
                    f"This strongly suggests traffic to or from compromised infrastructure."
                ),
                evidence=(
                    f"Matched fingerprints: {', '.join(m['fingerprint_sha1'][:16] + '...' for m in matches)} "
                    f"({', '.join(m['reason'] for m in matches if m.get('reason'))})"
                ),
                structured_evidence={'matches': matches},
                remediation=(
                    "1. Isolate the affected host and inspect endpoints immediately\n"
                    "2. Block network traffic to the associated IPs/domains at the firewall\n"
                    "3. Rotate any credentials potentially exposed during this connection\n"
                    "4. Consult abuse.ch SSLBL listing for full malware family attribution"
                ),
            )

    # ─── CHECK 14: PASSIVE EMAIL AUTHENTICATION (SPF/DKIM/DMARC) ───
    def check_email_authentication(self):
        """Findings from SPF/DKIM/DMARC evidence found in the capture itself
        (message headers, plaintext DNS)."""
        for issue in self.data.get('email_auth', {}).get('issues', []):
            affected = issue.get('affected', [])
            self._add_finding(
                severity=issue.get('severity', 'MEDIUM'),
                finding_type='email_authentication',
                rule_id=issue.get('rule_id', 'EMAIL_AUTH_ISSUE'),
                title=issue.get('title', 'Email Authentication Finding'),
                description=f"{issue.get('description', '')} ({len(affected)} occurrence(s) in this capture.)",
                evidence="; ".join(affected[:3]) + (f" (+{len(affected) - 3} more)" if len(affected) > 3 else ""),
                structured_evidence={'affected': affected, 'source': 'passive capture analysis'},
                remediation=issue.get('remediation', ''),
            )

    # ─── RISK SCORING ───
    def calculate_risk_score(self) -> Dict:
        """Calculate overall risk score (0-100) and letter grade"""
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
            'risk_grade': risk_score_to_grade(risk_score),
            'finding_score': finding_score,
            'encryption_penalty': round(encryption_penalty, 1),
            'critical_count': sum(1 for f in self.findings if f['severity'] == 'CRITICAL'),
            'high_count': sum(1 for f in self.findings if f['severity'] == 'HIGH'),
            'medium_count': sum(1 for f in self.findings if f['severity'] == 'MEDIUM'),
            'low_count': sum(1 for f in self.findings if f['severity'] == 'LOW'),
        }