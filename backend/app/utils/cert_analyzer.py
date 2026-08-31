"""
Certificate extraction and analysis using tshark + cryptography
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict
from datetime import datetime, timezone

try:
    from utils.tshark_helper import TSharkHelper
except ImportError:
    try:
        from app.utils.tshark_helper import TSharkHelper
    except ImportError:
        from .tshark_helper import TSharkHelper


class CertificateAnalyzer:
    """Extract and analyze X.509 certificates from PCAP"""

    @staticmethod
    def extract_certificates(pcap_path: str) -> List[Dict]:
        """
        Extract certificate metadata from TLS handshakes using tshark.
        Uses tshark's built-in X.509 dissection fields.
        """
        pcap_file = Path(pcap_path)
        if not pcap_file.exists():
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")

        # tshark extracts X.509 fields automatically from TLS Certificate messages
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
            '-e', 'x509af.subject',
            '-e', 'x509af.issuer',
            '-e', 'x509af.validity.notBefore',
            '-e', 'x509af.validity.notAfter',
            '-e', 'x509af.signatureAlgorithm',
            '-e', 'x509af.publicKeyAlgorithm',
            '-e', 'x509af.publicKey.length',
            '-e', 'x509af.serialNumber',
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

                subject = layers.get('x509af.subject', [''])[0]
                issuer = layers.get('x509af.issuer', [''])[0]
                serial = layers.get('x509af.serialNumber', [''])[0]

                # Skip duplicates (same cert appears in multiple frames)
                if serial and serial in seen_serials:
                    continue
                if serial:
                    seen_serials.add(serial)

                not_before = layers.get('x509af.validity.notBefore', [''])[0]
                not_after = layers.get('x509af.validity.notAfter', [''])[0]
                sig_algo = layers.get('x509af.signatureAlgorithm', [''])[0]
                pub_key_algo = layers.get('x509af.publicKeyAlgorithm', [''])[0]
                key_length = layers.get('x509af.publicKey.length', [''])[0]

                # Determine if self-signed
                is_self_signed = False
                if subject and issuer:
                    is_self_signed = (subject.strip() == issuer.strip())

                # Determine if expired
                is_expired = False
                if not_after:
                    try:
                        # tshark date format: "Jan  1 00:00:00 2025 GMT"
                        expiry = datetime.strptime(
                            not_after.strip(), "%b %d %H:%M:%S %Y %Z"
                        )
                        if expiry < datetime.utcnow():
                            is_expired = True
                    except ValueError:
                        pass  # Can't parse date, skip expiry check

                # Parse key size
                key_size = 0
                if key_length:
                    try:
                        key_size = int(key_length)
                    except ValueError:
                        pass

                cert_info = {
                    'frame': layers.get('frame.number', [''])[0],
                    'timestamp': layers.get('frame.time', [''])[0],
                    'src': layers.get('ip.src', [''])[0],
                    'dst': layers.get('ip.dst', [''])[0],
                    'subject': subject,
                    'issuer': issuer,
                    'serial': serial,
                    'not_before': not_before,
                    'not_after': not_after,
                    'signature_algorithm': sig_algo,
                    'public_key_algorithm': pub_key_algo,
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
        print(f"  Valid:      {cert['not_before']} → {cert['not_after']}")
        print(f"  Sig Algo:   {cert['signature_algorithm']}")
        print(f"  Key Algo:   {cert['public_key_algorithm']}")
        print(f"  Key Size:   {cert['key_size']} bits")
        print(f"  Self-Signed:{cert['is_self_signed']}")
        print(f"  Expired:    {cert['is_expired']}")
        print()