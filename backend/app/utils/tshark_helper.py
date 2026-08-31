"""
tshark wrapper for extracting TLS metadata
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Optional

class TSharkHelper:
    """Extract TLS/SSL metadata using tshark"""
    
    @staticmethod
    def get_tshark_path() -> str:
        """Find the tshark executable path on the system"""
        import shutil
        import platform
        tshark_in_path = shutil.which("tshark")
        if tshark_in_path:
            return tshark_in_path
        if platform.system() == "Windows":
            standard_paths = [
                r"C:\Program Files\Wireshark\tshark.exe",
                r"C:\Program Files (x86)\Wireshark\tshark.exe",
            ]
            for path in standard_paths:
                if Path(path).exists():
                    return path
        return "tshark"

    @staticmethod
    def check_tshark_available() -> bool:
        """Check if tshark is installed and accessible"""
        tshark_path = TSharkHelper.get_tshark_path()
        try:
            result = subprocess.run(
                [tshark_path, '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    @staticmethod
    def extract_tls_handshakes(pcap_path: str) -> List[Dict]:
        """
        Extract TLS handshake information from PCAP
        
        Returns list of handshakes with:
        - frame number
        - timestamp
        - source IP
        - destination IP  
        - TLS version
        - handshake type
        - cipher suites (if ClientHello/ServerHello)
        """
        pcap_file = Path(pcap_path)
        if not pcap_file.exists():
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")
        
        # Build tshark command
        tshark_path = TSharkHelper.get_tshark_path()
        cmd = [
            tshark_path,
            '-r', str(pcap_file),
            '-Y', 'ssl.handshake || tls.handshake',
            '-T', 'json',
            '-e', 'frame.number',
            '-e', 'frame.time',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'ssl.record.version',
            '-e', 'tls.record.version',
            '-e', 'ssl.handshake.type',
            '-e', 'tls.handshake.type',
            '-e', 'ssl.handshake.ciphersuite',
            '-e', 'tls.handshake.ciphersuite',
            '-e', 'ssl.handshake.extensions_server_name',
            '-e', 'tls.handshake.extensions_server_name'
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"tshark failed: {result.stderr}")
            
            # Parse JSON output
            if not result.stdout.strip():
                return []
            
            raw_data = json.loads(result.stdout)
            handshakes = []
            
            for packet in raw_data:
                layers = packet.get('_source', {}).get('layers', {})
                
                # Extract TLS version (try both ssl and tls namespace)
                tls_version_raw = (
                    layers.get('ssl.record.version', [''])[0] or
                    layers.get('tls.record.version', [''])[0]
                )
                
                # Map version codes
                version_map = {
                    '0x0300': 'SSL 3.0',
                    '0x0301': 'TLS 1.0',
                    '0x0302': 'TLS 1.1',
                    '0x0303': 'TLS 1.2',
                    '0x0304': 'TLS 1.3'
                }
                tls_version = version_map.get(tls_version_raw, tls_version_raw)
                
                # Extract handshake type
                handshake_type_raw = (
                    layers.get('ssl.handshake.type', [''])[0] or
                    layers.get('tls.handshake.type', [''])[0]
                )
                
                type_map = {
                    '1': 'ClientHello',
                    '2': 'ServerHello',
                    '11': 'Certificate',
                    '12': 'ServerKeyExchange',
                    '13': 'CertificateRequest',
                    '14': 'ServerHelloDone',
                    '15': 'CertificateVerify',
                    '16': 'ClientKeyExchange',
                    '20': 'Finished'
                }
                handshake_type = type_map.get(handshake_type_raw, f'Type {handshake_type_raw}')
                
                # Extract cipher suites
                cipher_suites = (
                    layers.get('ssl.handshake.ciphersuite', []) or
                    layers.get('tls.handshake.ciphersuite', [])
                )
                
                # Extract SNI
                sni = (
                    layers.get('ssl.handshake.extensions_server_name', [''])[0] or
                    layers.get('tls.handshake.extensions_server_name', [''])[0]
                )
                
                handshake_info = {
                    'frame': layers.get('frame.number', [''])[0],
                    'timestamp': layers.get('frame.time', [''])[0],
                    'src': layers.get('ip.src', [''])[0],
                    'dst': layers.get('ip.dst', [''])[0],
                    'src_port': layers.get('tcp.srcport', [''])[0],
                    'dst_port': layers.get('tcp.dstport', [''])[0],
                    'tls_version': tls_version,
                    'handshake_type': handshake_type,
                    'cipher_suites': cipher_suites,
                    'sni': sni
                }
                
                handshakes.append(handshake_info)
            
            return handshakes
            
        except FileNotFoundError:
            raise RuntimeError(
                "TShark executable was not found. Install Wireshark with TShark support or configure the TShark executable path."
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("tshark extraction timed out")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse tshark output: {e}")
    
    @staticmethod
    def get_protocol_statistics(pcap_path: str) -> Dict:
        """Get protocol distribution statistics"""
        pcap_file = Path(pcap_path)
        tshark_path = TSharkHelper.get_tshark_path()
        cmd = [
            tshark_path,
            '-r', str(pcap_file),
            '-q',
            '-z', 'io,phs'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            return {
                'raw_output': result.stdout
            }
        except FileNotFoundError:
            raise RuntimeError(
                "TShark executable was not found. Install Wireshark with TShark support or configure the TShark executable path."
            )
        except:
            return {}


# Test the helper
if __name__ == '__main__':
    helper = TSharkHelper()
    
    if not helper.check_tshark_available():
        print("[!] tshark not found. Please install Wireshark/tshark first.")
        exit(1)
    
    print("[+] tshark is available")
    
    # Test with a PCAP file
    import sys
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
        print(f"\n[*] Testing with: {pcap_file}")
        
        handshakes = helper.extract_tls_handshakes(pcap_file)
        print(f"[+] Found {len(handshakes)} TLS handshakes")
        
        for hs in handshakes[:3]:
            print(f"\n  Frame {hs['frame']}: {hs['handshake_type']}")
            print(f"    Version: {hs['tls_version']}")
            print(f"    {hs['src']}:{hs['src_port']} → {hs['dst']}:{hs['dst_port']}")
            if hs.get('sni'):
                print(f"    SNI: {hs['sni']}")