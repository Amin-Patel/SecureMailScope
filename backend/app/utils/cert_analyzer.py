"""
Certificate extraction and analysis for SecureMailScope.

tshark's own X.509-dissection fields (x509af.signatureAlgorithm,
x509af.publicKeyAlgorithm, x509af.publicKey.length, x509af.validity.*)
have drifted across Wireshark versions -- querying them against a recent
tshark (verified: 4.6.8) fails outright with "Some fields aren't valid",
which the previous implementation silently swallowed into an always-empty
certificate list (no error surfaced anywhere; every certificate-based
security check was silently dead as a result).

Instead, this extracts only the one X.509 field tshark reliably exposes
across versions -- the raw DER-encoded certificate bytes
(tls.handshake.certificate / ssl.handshake.certificate, a plain FT_BYTES
field with no version-specific sub-dissection) -- and parses them
directly with the `cryptography` library (already a project dependency),
which gives typed, version-independent access to subject, issuer,
validity, signature algorithm, and public key info instead of depending
on tshark's dissector internals.
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec

try:
    from utils.tshark_helper import TSharkHelper
except ImportError:
    try:
        from app.utils.tshark_helper import TSharkHelper
    except ImportError:
        from .tshark_helper import TSharkHelper


def _public_key_algorithm_name(public_key) -> str:
    """Name string for security_engine.py's MIN_KEY_SIZES substring lookup
    (expects 'rsa', 'ec', or 'dh' to appear in the lowercased string)."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "rsaEncryption"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ecPublicKey"
    if isinstance(public_key, dsa.DSAPublicKey):
        return "dsaEncryption"
    return type(public_key).__name__


class CertificateAnalyzer:
    """Extract and analyze X.509 certificates from PCAP TLS handshakes."""

    @staticmethod
    def extract_certificates(pcap_path: str) -> List[Dict]:
        """
        Extract certificate metadata from TLS Certificate handshake messages.

        Pulls the raw DER bytes tshark exposes and parses them with
        `cryptography` rather than relying on tshark's own X.509 field
        dissection, which is not stable across Wireshark versions.
        """
        pcap_file = Path(pcap_path)
        if not pcap_file.exists():
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")

        tshark_path = TSharkHelper.get_tshark_path()
        cmd = [
            tshark_path,
            '-r', str(pcap_file),
            '-Y', 'tls.handshake.type == 11 || ssl.handshake.type == 11',
            '-T', 'json',
            '-e', 'frame.number',
            '-e', 'frame.time',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tls.handshake.certificate',
            '-e', 'ssl.handshake.certificate',
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if not result.stdout.strip():
                return []

            raw_data = json.loads(result.stdout)
            certificates = []
            seen_serials = set()

            for packet in raw_data:
                layers = packet.get('_source', {}).get('layers', {})

                frame_number = layers.get('frame.number', [''])[0]
                frame_time = layers.get('frame.time', [''])[0]
                src = layers.get('ip.src', [''])[0]
                dst = layers.get('ip.dst', [''])[0]

                der_hex_list = (
                    layers.get('tls.handshake.certificate') or
                    layers.get('ssl.handshake.certificate') or
                    []
                )

                # A Certificate message can carry a full chain; tshark
                # reports one hex entry per certificate in the message.
                for der_hex in der_hex_list:
                    try:
                        der_bytes = bytes.fromhex(der_hex)
                        cert = x509.load_der_x509_certificate(der_bytes)
                    except Exception as e:
                        print(f"[!] Skipping unparsable certificate: {e}")
                        continue

                    serial = str(cert.serial_number)
                    if serial in seen_serials:
                        continue
                    seen_serials.add(serial)

                    public_key = cert.public_key()
                    key_size = getattr(public_key, 'key_size', 0)

                    # EdDSA certificates have no separate hash step, so
                    # signature_hash_algorithm is None for them.
                    sig_hash = cert.signature_hash_algorithm
                    signature_algorithm = sig_hash.name if sig_hash else "eddsa"

                    is_expired = cert.not_valid_after_utc < datetime.now(timezone.utc)

                    # Structural comparison of the parsed RDN sequences,
                    # not a fragile raw-string comparison.
                    is_self_signed = cert.subject == cert.issuer

                    cert_info = {
                        'frame': frame_number,
                        'timestamp': frame_time,
                        'src': src,
                        'dst': dst,
                        'subject': cert.subject.rfc4514_string(),
                        'issuer': cert.issuer.rfc4514_string(),
                        'serial': serial,
                        'not_before': cert.not_valid_before_utc.isoformat(),
                        'not_after': cert.not_valid_after_utc.isoformat(),
                        'signature_algorithm': signature_algorithm,
                        'public_key_algorithm': _public_key_algorithm_name(public_key),
                        'key_size': key_size,
                        'is_self_signed': is_self_signed,
                        'is_expired': is_expired,
                    }

                    certificates.append(cert_info)

            return certificates

        except FileNotFoundError:
            raise RuntimeError(
                "TShark executable was not found. Install Wireshark with TShark support or configure the TShark executable path."
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("tshark certificate extraction timed out")
        except json.JSONDecodeError:
            return []
        except Exception as e:
            print(f"[!] Certificate extraction error: {e}")
            return []


# Test
if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python cert_analyzer.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    certs = CertificateAnalyzer.extract_certificates(pcap_file)

    print(f"[+] Extracted {len(certs)} unique certificates\n")

    for i, cert in enumerate(certs, 1):
        print(f"Certificate #{i}:")
        print(f"  Subject:    {cert['subject']}")
        print(f"  Issuer:     {cert['issuer']}")
        print(f"  Valid:      {cert['not_before']} -> {cert['not_after']}")
        print(f"  Sig Algo:   {cert['signature_algorithm']}")
        print(f"  Key Algo:   {cert['public_key_algorithm']}")
        print(f"  Key Size:   {cert['key_size']} bits")
        print(f"  Self-Signed:{cert['is_self_signed']}")
        print(f"  Expired:    {cert['is_expired']}")
        print()
