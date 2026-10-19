"""
Certificate extraction and analysis using tshark + cryptography
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519

try:
    from utils.tshark_helper import TSharkHelper
except ImportError:
    try:
        from app.utils.tshark_helper import TSharkHelper
    except ImportError:
        from .tshark_helper import TSharkHelper


class CertificateAnalyzer:
    """Extract and analyze X.509 certificates from PCAP using tshark + cryptography.x509"""

    @staticmethod
    def parse_der_certificate(
        der_bytes: bytes,
        frame_num: str = "",
        frame_time: str = "",
        src_ip: str = "",
        dst_ip: str = ""
    ) -> Dict[str, Any]:
        """
        Parse raw X.509 DER bytes into a structured certificate dictionary.
        Extracts genuine key bit length, public key algorithm, validity, and subject/issuer DNs.
        Preserves uncertainty: if parsing fails, key_size and algorithm remain None (no default constants).
        """
        try:
            cert = x509.load_der_x509_certificate(der_bytes)
        except Exception as e:
            return {
                'frame': frame_num,
                'timestamp': frame_time,
                'src': src_ip,
                'dst': dst_ip,
                'subject': 'Unknown (Unparseable DER)',
                'issuer': 'Unknown (Unparseable DER)',
                'serial': '',
                'not_before': '',
                'not_after': '',
                'signature_algorithm': 'Unknown',
                'public_key_algorithm': None,
                'key_size': None,
                'is_self_signed': False,
                'is_expired': False,
                'parse_error': str(e)
            }

        # Subject & Issuer formatting
        try:
            subject = cert.subject.rfc4514_string()
        except Exception:
            subject = ', '.join(f"{attr.oid._name}={attr.value}" for attr in cert.subject)

        try:
            issuer = cert.issuer.rfc4514_string()
        except Exception:
            issuer = ', '.join(f"{attr.oid._name}={attr.value}" for attr in cert.issuer)

        # Validity dates
        try:
            not_before = cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S (UTC)")
        except Exception:
            not_before = cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S (UTC)")

        try:
            not_after = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S (UTC)")
            expiry_utc = cert.not_valid_after_utc
        except Exception:
            not_after = cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S (UTC)")
            expiry_utc = cert.not_valid_after.replace(tzinfo=timezone.utc)

        is_expired = expiry_utc < datetime.now(timezone.utc)

        # Public Key & Genuine Bit Length Extraction
        pub_key = cert.public_key()
        key_size = None
        pub_key_algo = None

        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_key_algo = 'RSA'
            key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key_algo = 'EC'
            key_size = pub_key.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            pub_key_algo = 'DSA'
            key_size = pub_key.key_size
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            pub_key_algo = 'Ed25519'
            key_size = 256
        else:
            pub_key_algo = type(pub_key).__name__
            key_size = getattr(pub_key, 'key_size', None)

        # Signature algorithm
        sig_algo = getattr(cert.signature_algorithm_oid, '_name', str(cert.signature_algorithm_oid))

        # Self-signed determination
        is_self_signed = (cert.subject == cert.issuer)

        return {
            'frame': frame_num,
            'timestamp': frame_time,
            'src': src_ip,
            'dst': dst_ip,
            'subject': subject,
            'issuer': issuer,
            'serial': hex(cert.serial_number),
            'not_before': not_before,
            'not_after': not_after,
            'signature_algorithm': sig_algo,
            'public_key_algorithm': pub_key_algo,
            'key_size': key_size,
            'is_self_signed': is_self_signed,
            'is_expired': is_expired,
        }

    @staticmethod
    def extract_certificates(pcap_path: str) -> List[Dict]:
        """
        Extract certificate metadata from TLS handshakes using tshark + cryptography.x509.
        Primary path extracts raw DER certificates and parses public keys and attributes directly.
        """
        pcap_file = Path(pcap_path)
        if not pcap_file.exists():
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")

        tshark_path = TSharkHelper.get_tshark_path()

        # Extract certificate records in JSON mode to access raw DER hex
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
            '-e', 'ssl.handshake.certificate'
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

            raw_packets = json.loads(result.stdout)
            certificates = []
            seen_fingerprints = set()

            for packet in raw_packets:
                layers = packet.get('_source', {}).get('layers', {})
                frame_num = layers.get('frame.number', [''])[0]
                frame_time = layers.get('frame.time', [''])[0]
                src_ip = layers.get('ip.src', [''])[0]
                dst_ip = layers.get('ip.dst', [''])[0]

                cert_hex_list = (
                    layers.get('tls.handshake.certificate', []) or
                    layers.get('ssl.handshake.certificate', [])
                )

                for cert_hex in cert_hex_list:
                    cleaned_hex = cert_hex.replace(':', '').replace(' ', '').strip()
                    if not cleaned_hex:
                        continue

                    # Deduplicate certificates by hex hash
                    if cleaned_hex in seen_fingerprints:
                        continue
                    seen_fingerprints.add(cleaned_hex)

                    try:
                        der_bytes = bytes.fromhex(cleaned_hex)
                        cert_dict = CertificateAnalyzer.parse_der_certificate(
                            der_bytes=der_bytes,
                            frame_num=frame_num,
                            frame_time=frame_time,
                            src_ip=src_ip,
                            dst_ip=dst_ip
                        )
                        certificates.append(cert_dict)
                    except Exception as e:
                        print(f"[!] Error decoding certificate DER: {e}")
                        continue

            return certificates

        except FileNotFoundError:
            raise RuntimeError(
                "TShark executable was not found. Install Wireshark with TShark support or configure the TShark executable path."
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("tshark certificate extraction timed out")
        except Exception as e:
            print(f"[!] Certificate extraction error: {e}")
            import traceback
            traceback.print_exc()
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
        print(f"  Valid:      {cert['not_before']} → {cert['not_after']}")
        print(f"  Sig Algo:   {cert['signature_algorithm']}")
        print(f"  Key Algo:   {cert['public_key_algorithm']}")
        print(f"  Key Size:   {cert['key_size']} bits")
        print(f"  Self-Signed:{cert['is_self_signed']}")
        print(f"  Expired:    {cert['is_expired']}")
        print()