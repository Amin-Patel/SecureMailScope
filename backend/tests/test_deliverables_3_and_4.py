"""
Unit & Forensic Integration Tests for Deliverables #3 and #4:
- Bidirectional TCP Stream Reassembly & Protocol-Aware Credential Redaction
- Multi-Tier Certificate Chain Parsing & CA Trust Hierarchy Validation
"""

import unittest
from pathlib import Path
import os
import sys

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.utils.tshark_helper import TSharkHelper
from app.utils.cert_analyzer import CertificateAnalyzer
from app.core.pcap_analyzer import EmailPCAPAnalyzer
from app.core.security_engine import SecurityEngine


class TestDeliverables3And4(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_data_dir = backend_dir / "test-data"
        cls.smtp_pcap = cls.test_data_dir / "smtp.pcap"
        cls.snakeoil_pcap = cls.test_data_dir / "rsasnakeoil2.cap"
        cls.secure_pcap = cls.test_data_dir / "secure_mail.pcap"

    # ─── DELIVERABLE #3 TESTS: TCP STREAM RECONSTRUCTION ───

    def test_structured_tcp_stream_extraction_smtp(self):
        """Verify structured TCP stream extraction on plaintext SMTP capture."""
        if not self.smtp_pcap.exists():
            self.skipTest("smtp.pcap not available")

        streams = TSharkHelper.extract_structured_tcp_streams(str(self.smtp_pcap))
        self.assertGreaterEqual(len(streams), 1, "Should extract at least 1 TCP stream")

        s0 = next(iter(streams.values()))
        self.assertEqual(s0['protocol'], 'SMTP')
        self.assertIn('client', s0)
        self.assertIn('server', s0)
        self.assertGreater(s0['packet_count'], 0)
        self.assertGreater(len(s0['chunks']), 0)
        self.assertIn('direction', s0['chunks'][0])
        self.assertIn(s0['chunks'][0]['direction'], ['client_to_server', 'server_to_client'])
        self.assertIn('frame_number', s0['chunks'][0])
        self.assertIn('timestamp', s0['chunks'][0])
        self.assertIn('payload', s0['chunks'][0])

    def test_protocol_aware_credential_redaction(self):
        """Verify protocol-aware masking does NOT redact arbitrary Base64 but masks SMTP/POP3/IMAP auth."""
        # 1. Arbitrary Base64 in normal email body should remain untouched
        normal_b64 = "Subject: Test\r\nVGVzdCBtZXNzYWdl"
        redacted, count, state = TSharkHelper._redact_protocol_credentials(
            normal_b64, 'client_to_server', 'SMTP', None
        )
        self.assertEqual(count, 0, "Arbitrary Base64 should not be redacted")
        self.assertEqual(redacted, normal_b64)

        # 2. SMTP AUTH PLAIN
        auth_plain = "AUTH PLAIN dGVzdAB0ZXN0ADEyMzQ1Ng=="
        redacted, count, state = TSharkHelper._redact_protocol_credentials(
            auth_plain, 'client_to_server', 'SMTP', None
        )
        self.assertEqual(count, 1)
        self.assertIn("[REDACTED_PLAIN_CREDENTIALS]", redacted)

        # 3. POP3 PASS
        pop3_pass = "PASS secretpassword123"
        redacted, count, state = TSharkHelper._redact_protocol_credentials(
            pop3_pass, 'client_to_server', 'POP3', None
        )
        self.assertEqual(count, 1)
        self.assertIn("PASS [REDACTED_PASSWORD]", redacted)

        # 4. Bearer token
        bearer_text = "Authorization: Bearer ya29.a0AfH6SM..."
        redacted, count, state = TSharkHelper._redact_protocol_credentials(
            bearer_text, 'client_to_server', 'SMTP', None
        )
        self.assertEqual(count, 1)
        self.assertIn("[REDACTED_BEARER_TOKEN]", redacted)

    def test_encrypted_stream_graceful_handling(self):
        """Verify encrypted streams report encrypted: True with intact stream metadata."""
        if not self.secure_pcap.exists():
            self.skipTest("secure_mail.pcap not available")

        streams = TSharkHelper.extract_structured_tcp_streams(str(self.secure_pcap))
        self.assertGreaterEqual(len(streams), 1)
        s0 = next(iter(streams.values()))
        self.assertTrue(s0['encrypted'], "SMTPS / IMAPS stream should be marked encrypted")

    # ─── DELIVERABLE #4 TESTS: CERTIFICATE CHAIN & PKI VALIDATION ───

    def test_certificate_chain_extraction_and_trust_path(self):
        """Verify presented certificate chain vs built trust path on rsasnakeoil2.cap."""
        if not self.snakeoil_pcap.exists():
            self.skipTest("rsasnakeoil2.cap not available")

        chains = CertificateAnalyzer.extract_and_analyze_chains(str(self.snakeoil_pcap))
        self.assertGreaterEqual(len(chains), 1, "Should extract certificate chain from TLS handshake")

        ch0 = chains[0]
        self.assertIn('presented_chain', ch0)
        self.assertIn('built_trust_path', ch0)
        self.assertIn('leaf_certificate', ch0)
        self.assertIn('pki_findings', ch0)

        leaf = ch0['leaf_certificate']
        self.assertIn('common_name', leaf)
        self.assertIn('serial_number', leaf)
        self.assertIn('public_key_algorithm', leaf)
        self.assertIn('key_size', leaf)
        self.assertIn('signature_algorithm', leaf)
        self.assertIn('is_expired', leaf)
        self.assertTrue(leaf['is_expired'], "SnakeOil cert should be expired")

        # Machine-readable evidence attached
        finding_rule_ids = [f['rule_id'] for f in ch0['pki_findings']]
        self.assertIn('CERT_EXPIRED', finding_rule_ids)
        self.assertIn('CERT_UNTRUSTED_CA', finding_rule_ids)

        for f in ch0['pki_findings']:
            self.assertIn('evidence', f)
            self.assertIn('frame', f['evidence'])
            self.assertIn('tcp_stream', f['evidence'])

    def test_trust_store_loaded(self):
        """Verify Mozilla root CA bundle loads from certifi."""
        trust_store = CertificateAnalyzer.get_trust_store()
        self.assertGreater(len(trust_store), 50, "Should load Mozilla root CA bundle")

    def test_full_pipeline_forensic_integrity(self):
        """Verify full EmailPCAPAnalyzer pipeline preserves separation of evidence and deterministic rules."""
        if not self.smtp_pcap.exists():
            self.skipTest("smtp.pcap not available")

        analyzer = EmailPCAPAnalyzer(str(self.smtp_pcap))
        res = analyzer.analyze()

        self.assertTrue(res['success'])
        self.assertIn('tcp_streams', res)
        self.assertIn('certificate_chains', res)
        self.assertIn('findings', res)
        self.assertIn('risk', res)

        for f in res['findings']:
            self.assertIn('structured_evidence', f)
            self.assertIn('rule_id', f)


if __name__ == '__main__':
    unittest.main()
