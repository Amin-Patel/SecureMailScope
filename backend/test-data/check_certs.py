import sys
sys.path.insert(0, '../app')
from utils.cert_analyzer import CertificateAnalyzer

certs = CertificateAnalyzer.extract_certificates('rsasnakeoil2.cap')
print(f'Certificate count: {len(certs)}')
for i, cert in enumerate(certs, 1):
    print(f'\nCertificate {i}:')
    print(f'  Subject: {cert.get("subject", "N/A")}')
    print(f'  Issuer: {cert.get("issuer", "N/A")}')
    print(f'  Key Algorithm: {cert.get("public_key_algorithm", "N/A")}')
    print(f'  Key Size: {cert.get("key_size", "N/A")} bits')
    print(f'  Signature Algorithm: {cert.get("signature_algorithm", "N/A")}')
    print(f'  Valid From: {cert.get("not_before", "N/A")}')
    print(f'  Valid Until: {cert.get("not_after", "N/A")}')
    print(f'  Self-Signed: {cert.get("is_self_signed", False)}')
    print(f'  Expired: {cert.get("is_expired", False)}')
