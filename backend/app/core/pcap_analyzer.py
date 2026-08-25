"""
Core PCAP analysis module for SecureMailScope
Combines tshark TLS extraction with PyShark email protocol detection
"""

import pyshark
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
import json
import hashlib

# Import our tshark helper
import sys
sys.path.append(str(Path(__file__).parent.parent))
from utils.tshark_helper import TSharkHelper


class EmailPCAPAnalyzer:
    """Advanced PCAP analyzer for email security assessment"""
    
    # Email protocol port mappings
    EMAIL_PORTS = {
        25: 'SMTP',
        587: 'SMTP-Submission',
        465: 'SMTPS',
        2525: 'SMTP-Alt',
        110: 'POP3',
        995: 'POP3S',
        143: 'IMAP',
        993: 'IMAPS'
    }
    
    def __init__(self, pcap_path: str):
        self.pcap_path = Path(pcap_path)
        self.email_packets = []
        self.sessions = []
        self.tls_handshakes = []
        self.tshark = TSharkHelper()
        
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
    
    def analyze(self) -> Dict:
        """Main analysis pipeline"""
        print(f"[*] Analyzing: {self.pcap_path.name}")
        
        try:
            # Step 1: Extract TLS handshakes using tshark
            print("[*] Extracting TLS handshakes...")
            self.tls_handshakes = self.tshark.extract_tls_handshakes(str(self.pcap_path))
            print(f"[+] Found {len(self.tls_handshakes)} TLS handshakes")
            
            # Step 2: Extract email packets using PyShark
            print("[*] Filtering email packets...")
            self._extract_email_packets()
            print(f"[+] Found {len(self.email_packets)} email packets")
            
            # Step 3: Reconstruct sessions
            print("[*] Reconstructing sessions...")
            self._reconstruct_sessions()
            print(f"[+] Reconstructed {len(self.sessions)} sessions")
            
            # Step 4: Link TLS data to sessions
            self._link_tls_to_sessions()
            
            # Step 5: Generate summary
            summary = self._generate_summary()
            
            return {
                'success': True,
                'capture_id': self._generate_capture_id(),
                'filename': self.pcap_path.name,
                'summary': summary,
                'sessions': self.sessions,
                'tls_handshakes': self.tls_handshakes,
                'total_email_packets': len(self.email_packets)
            }
            
        except Exception as e:
            print(f"[!] Analysis failed: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__
            }
    
    def _extract_email_packets(self):
        """Extract email-related packets using PyShark"""
        try:
            # Use PyShark with display filter for performance
            capture = pyshark.FileCapture(
                str(self.pcap_path),
                display_filter='tcp',
                keep_packets=False  # Don't keep packets in memory
            )
            
            for packet in capture:
                try:
                    # Check if packet has TCP layer
                    if not hasattr(packet, 'tcp'):
                        continue
                    
                    src_port = int(packet.tcp.srcport)
                    dst_port = int(packet.tcp.dstport)
                    
                    # Check if email-related
                    protocol = None
                    if src_port in self.EMAIL_PORTS:
                        protocol = self.EMAIL_PORTS[src_port]
                    elif dst_port in self.EMAIL_PORTS:
                        protocol = self.EMAIL_PORTS[dst_port]
                    
                    if protocol:
                        packet_info = {
                            'number': packet.number,
                            'timestamp': str(packet.sniff_time),
                            'src': packet.ip.src if hasattr(packet, 'ip') else 'N/A',
                            'dst': packet.ip.dst if hasattr(packet, 'ip') else 'N/A',
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'protocol': protocol,
                            'length': int(packet.length),
                            'encrypted': protocol in ['SMTPS', 'IMAPS', 'POP3S']
                        }
                        
                        self.email_packets.append(packet_info)
                
                except AttributeError:
                    # Skip packets without required fields
                    continue
            
            capture.close()
            
        except Exception as e:
            print(f"[!] PyShark error: {e}")
            raise
    
    def _reconstruct_sessions(self):
        """Group packets into logical sessions"""
        session_map = {}
        
        for pkt in self.email_packets:
            # Create normalized session key (always lower IP:port first)
            endpoints = sorted([
                (pkt['src'], pkt['src_port']),
                (pkt['dst'], pkt['dst_port'])
            ])
            session_key = f"{endpoints[0][0]}:{endpoints[0][1]}-{endpoints[1][0]}:{endpoints[1][1]}"
            
            if session_key not in session_map:
                session_map[session_key] = {
                    'id': f"session_{len(session_map) + 1}",
                    'protocol': pkt['protocol'],
                    'src': pkt['src'],
                    'dst': pkt['dst'],
                    'src_port': pkt['src_port'],
                    'dst_port': pkt['dst_port'],
                    'start_time': pkt['timestamp'],
                    'end_time': pkt['timestamp'],
                    'packet_count': 0,
                    'encrypted': pkt['encrypted'],
                    'tls_info': None
                }
            
            session_map[session_key]['packet_count'] += 1
            session_map[session_key]['end_time'] = pkt['timestamp']
        
        self.sessions = list(session_map.values())
    
    def _link_tls_to_sessions(self):
        """Link TLS handshake data to sessions"""
        for session in self.sessions:
            # Find matching TLS handshakes
            matching_handshakes = []
            
            for hs in self.tls_handshakes:
                # Check if handshake belongs to this session
                if ((hs['src'] == session['src'] and hs['dst'] == session['dst']) or
                    (hs['src'] == session['dst'] and hs['dst'] == session['src'])):
                    matching_handshakes.append(hs)
            
            if matching_handshakes:
                # Extract TLS version from handshakes
                versions = [hs['tls_version'] for hs in matching_handshakes if hs['tls_version']]
                cipher_suites = []
                for hs in matching_handshakes:
                    if hs.get('cipher_suites'):
                        cipher_suites.extend(hs['cipher_suites'])
                
                session['tls_info'] = {
                    'versions_detected': list(set(versions)),
                    'handshake_count': len(matching_handshakes),
                    'cipher_suites': list(set(cipher_suites)),
                    'handshakes': matching_handshakes
                }
    
    def _generate_summary(self) -> Dict:
        """Generate analysis summary"""
        total_packets = len(self.email_packets)
        encrypted_count = sum(1 for p in self.email_packets if p['encrypted'])
        plaintext_count = total_packets - encrypted_count
        
        protocols = set(p['protocol'] for p in self.email_packets)
        
        # Count TLS versions
        tls_versions = {}
        for hs in self.tls_handshakes:
            ver = hs['tls_version']
            if ver:
                tls_versions[ver] = tls_versions.get(ver, 0) + 1
        
        # Count sessions with/without TLS
        tls_sessions = sum(1 for s in self.sessions if s.get('tls_info'))
        
        return {
            'total_packets': total_packets,
            'encrypted_packets': encrypted_count,
            'plaintext_packets': plaintext_count,
            'encryption_ratio': round(encrypted_count / total_packets, 2) if total_packets > 0 else 0,
            'protocols_detected': list(protocols),
            'tls_versions': tls_versions,
            'session_count': len(self.sessions),
            'tls_sessions': tls_sessions,
            'plaintext_sessions': len(self.sessions) - tls_sessions,
            'handshake_count': len(self.tls_handshakes)
        }
    
    def _generate_capture_id(self) -> str:
        """Generate unique capture ID"""
        timestamp = datetime.now().isoformat()
        unique_str = f"{self.pcap_path.name}_{timestamp}"
        return hashlib.md5(unique_str.encode()).hexdigest()[:12]


def main():
    """Test the analyzer"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python pcap_analyzer.py <path_to_pcap>")
        print("\nExample:")
        print("  python pcap_analyzer.py test-data/rsasnakeoil2.cap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    analyzer = EmailPCAPAnalyzer(pcap_file)
    result = analyzer.analyze()
    
    if result['success']:
        print("\n" + "="*70)
        print("ANALYSIS COMPLETE")
        print("="*70)
        print("\nSUMMARY:")
        print(json.dumps(result['summary'], indent=2))
        
        print("\n" + "-"*70)
        print("SESSIONS:")
        for session in result['sessions']:
            print(f"\n  {session['id']}: {session['protocol']}")
            print(f"    {session['src']}:{session['src_port']} ↔ {session['dst']}:{session['dst_port']}")
            print(f"    Packets: {session['packet_count']}")
            print(f"    Encrypted: {session['encrypted']}")
            if session.get('tls_info'):
                print(f"    TLS Versions: {', '.join(session['tls_info']['versions_detected'])}")
        
        print("\n" + "="*70)
        print(f"Capture ID: {result['capture_id']}")
        print("="*70)
    else:
        print(f"\n[!] Analysis failed: {result['error']}")


if __name__ == '__main__':
    main()