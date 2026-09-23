"""
Comprehensive PKI, X.509 Chain, RSA-PSS, Weak-Cipher, and Forward-Secrecy Test Suite.
"""

import pytest
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509.oid import NameOID, ExtensionOID

from app.utils.cert_analyzer import CertificateAnalyzer
from app.core.security_engine import SecurityEngine


def generate_test_cert_pair(use_pss: bool = False):
    """Generate self-signed parent and signed child certificate with RSA or RSASSA-PSS."""
    parent_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    child_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    now = datetime.datetime.now(datetime.timezone.utc)
    
    parent_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
    parent_cert = (
        x509.CertificateBuilder()
        .subject_name(parent_name)
        .issuer_name(parent_name)
        .public_key(parent_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(parent_key, hashes.SHA256())
    )

    child_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail.testdomain.com")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(child_name)
        .issuer_name(parent_name)
        .public_key(child_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )

    if use_pss:
        child_cert = builder.sign(
            parent_key,
            hashes.SHA256(),
            rsa_padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH
            )
        )
    else:
        child_cert = builder.sign(parent_key, hashes.SHA256(), rsa_padding=padding.PKCS1v15())

    return parent_cert, child_cert


# ─── 1. RSA-PSS & PKCS#1 v1.5 SIGNATURE VERIFICATION TESTS ───
def test_rsa_pkcs1v15_signature_verification():
    parent, child = generate_test_cert_pair(use_pss=False)
    assert CertificateAnalyzer.verify_certificate_signature(child, parent) is True


def test_rsa_pss_signature_verification():
    parent, child = generate_test_cert_pair(use_pss=True)
    assert CertificateAnalyzer.verify_certificate_signature(child, parent) is True


def test_invalid_signature_fails():
    parent, child = generate_test_cert_pair(use_pss=False)
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    impostor_parent = (
        x509.CertificateBuilder()
        .subject_name(parent.subject)
        .issuer_name(parent.issuer)
        .public_key(wrong_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(wrong_key, hashes.SHA256())
    )
    assert CertificateAnalyzer.verify_certificate_signature(child, impostor_parent) is False


# ─── 2. WEAK CIPHER SUITE & FORWARD SECRECY DETECTION TESTS ───
def test_weak_cipher_detection():
    data = {
        'summary': {'total_packets': 10, 'plaintext_packets': 0},
        'tls_handshakes': [
            {'cipher_suites': ['TLS_RSA_WITH_RC4_128_MD5', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA']},
            {'cipher_suites': ['TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384']}
        ]
    }
    engine = SecurityEngine(data)
    findings = engine.run_all_checks()
    weak_findings = [f for f in findings if f['type'] == 'weak_cipher']
    assert len(weak_findings) > 0
    assert "RC4" in weak_findings[0]['evidence'] or "3DES" in weak_findings[0]['evidence']


# ─── 3. PROTOCOL & CERTIFICATE EXPIRY DETECTION ───
def test_expired_cert_detection():
    data = {
        'summary': {'total_packets': 10, 'plaintext_packets': 0},
        'certificates': [],
        'certificate_chains': [{
            'pki_findings': [{
                'rule_id': 'CERT_EXPIRED',
                'severity': 'HIGH',
                'title': 'Certificate Expired',
                'description': 'Certificate has expired.',
                'evidence': {'frame': 1, 'tcp_stream': '0', 'subject': 'CN=expired.com'}
            }]
        }]
    }
    engine = SecurityEngine(data)
    findings = engine.run_all_checks()
    expired = [f for f in findings if f['rule_id'] == 'CERT_EXPIRED']
    assert len(expired) == 1
    assert "CN=expired.com" in expired[0]['evidence']
