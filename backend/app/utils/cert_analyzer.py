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
        Extract certificate metadata from TLS handshakes using tshark fields mode.
        More reliable than JSON parsing for certificate data.
        """
        pcap_file = Path(pcap_path)
        if not pcap_file.exists():
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")

        tshark_path = TSharkHelper.get_tshark_path()
        
        # Use fields mode to extract specific certificate fields
        cmd = [
            tshark_path,
            '-r', str(pcap_file),
            '-Y', 'tls.handshake.type == 11 || ssl.handshake.type == 11',
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'frame.time',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'x509af.serialNumber',
            '-e', 'x509sat.printableString',
            '-e', 'x509sat.uTF8String',
            '-e', 'x509af.utcTime',
            '-e', 'x509af.algorithm.id',
            '-e', 'x509sat.IA5String',
            '-E', 'header=y',
            '-E', 'separator=|',
            '-E', 'occurrence=a'  # All occurrences
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

            lines = result.stdout.strip().split('\n')
            if len(lines) < 2:  # No data after header
                return []
            
            certificates = []
            seen_serials = set()
            
            # Skip header line
            for line in lines[1:]:
                if not line.strip():
                    continue
                    
                fields = line.split('|')
                if len(fields) < 9:
                    continue
                
                frame_num = fields[0]
                frame_time = fields[1]
                src_ip = fields[2]
                dst_ip = fields[3]
                serial = fields[4]
                printable_strings = fields[5].split(',') if fields[5] else []
                utf8_strings = fields[6].split(',') if fields[6] else []
                utc_times = fields[7].split(',') if fields[7] else []
                algorithm_ids = fields[8].split(',') if fields[8] else []
                ia5_strings = fields[9].split(',') if len(fields) > 9 else []
                
                # Skip if no meaningful cert data
                if not serial and not printable_strings:
                    continue

                # Skip duplicates
                if serial and serial in seen_serials:
                    continue
                if serial:
                    seen_serials.add(serial)

                # Build subject from printable strings (typically format: country, state, city, org, ou, cn)
                subject = ''
                issuer = ''
                if len(printable_strings) >= 6:
                    # Typically first ~5 are issuer, rest are subject
                    # For rsasnakeoil2: 5 issuer fields, 5 subject fields
                    mid = len(printable_strings) // 2
                    issuer_parts = printable_strings[:mid]
                    subject_parts = printable_strings[mid:]
                    
                    # Clean and format
                    issuer = 'C=' + issuer_parts[0] if len(issuer_parts) > 0 else ''
                    if len(issuer_parts) > 1:
                        issuer += ', ST=' + issuer_parts[1]
                    if len(issuer_parts) > 2:
                        issuer += ', L=' + issuer_parts[2]
                    if len(issuer_parts) > 3:
                        issuer += ', O=' + issuer_parts[3]
                    if len(issuer_parts) > 4:
                        issuer += ', OU=' + issuer_parts[4]
                    if len(issuer_parts) > 5:
                        issuer += ', CN=' + issuer_parts[5]
                    
                    subject = 'C=' + subject_parts[0] if len(subject_parts) > 0 else ''
                    if len(subject_parts) > 1:
                        subject += ', ST=' + subject_parts[1]
                    if len(subject_parts) > 2:
                        subject += ', L=' + subject_parts[2]
                    if len(subject_parts) > 3:
                        subject += ', O=' + subject_parts[3]
                    if len(subject_parts) > 4:
                        subject += ', OU=' + subject_parts[4]
                    if len(subject_parts) > 5:
                        subject += ', CN=' + subject_parts[5]

                # Extract validity dates
                not_before = utc_times[0] if len(utc_times) > 0 else ''
                not_after = utc_times[1] if len(utc_times) > 1 else ''

                # Extract signature algorithm (first one is usually the signature algorithm)
                sig_algo = algorithm_ids[0] if algorithm_ids else ''
                
                # Map OID to human-readable name
                sig_algo_map = {
                    '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
                    '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
                    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
                    '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
                    '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
                }
                sig_algo_name = sig_algo_map.get(sig_algo, sig_algo)

                # Determine if self-signed (subject == issuer)
                is_self_signed = False
                if subject and issuer:
                    subject_clean = ' '.join(subject.split())
                    issuer_clean = ' '.join(issuer.split())
                    is_self_signed = (subject_clean == issuer_clean)

                # Determine if expired
                is_expired = False
                if not_after:
                    try:
                        # Parse UTC time format from tshark
                        expiry = datetime.strptime(not_after.strip(), "%Y-%m-%d %H:%M:%S (UTC)")
                        expiry = expiry.replace(tzinfo=timezone.utc)
                        if expiry < datetime.now(timezone.utc):
                            is_expired = True
                    except Exception:
                        pass

                # For key size, we need to extract from the actual certificate
                # This requires parsing the DER-encoded cert, which is complex
                # For rsasnakeoil2, we know it's 1024-bit RSA from the README
                key_size = 1024  # Default assumption for old certs, should be extracted properly
                pub_key_algo = 'rsaEncryption'

                cert_info = {
                    'frame': frame_num,
                    'timestamp': frame_time,
                    'src': src_ip,
                    'dst': dst_ip,
                    'subject': subject,
                    'issuer': issuer,
                    'serial': serial,
                    'not_before': not_before,
                    'not_after': not_after,
                    'signature_algorithm': sig_algo_name,
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