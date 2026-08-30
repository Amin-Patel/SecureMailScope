"""
Core PCAP analysis module for SecureMailScope
Full pipeline: PCAP → Detection → TLS → Certs → Security → AI Intelligence → Risk
Uses tshark directly for maximum speed and FastAPI compatibility
"""

import subprocess
from pathlib import Path
from typing import Dict
from datetime import datetime
import json
import hashlib
import sys

sys.path.append(str(Path(__file__).parent.parent))
from utils.tshark_helper import TSharkHelper
from utils.cert_analyzer import CertificateAnalyzer
from core.security_engine import SecurityEngine
from services.gemini_service import GeminiSecurityAssistant


class EmailPCAPAnalyzer:
    """Full PCAP analysis pipeline for email security assessment"""

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
        self.certificates = []
        self.tshark = TSharkHelper()
        self.ai_assistant = GeminiSecurityAssistant()

        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    def analyze(self) -> Dict:
        """Full analysis pipeline"""
        print(f"\n{'='*70}")
        print(f"  SecureMailScope — Email Security Analysis")
        print(f"  File: {self.pcap_path.name}")
        print(f"{'='*70}\n")

        try:
            # Step 1: TLS handshakes
            print("[1/7] Extracting TLS handshakes...")
            self.tls_handshakes = self.tshark.extract_tls_handshakes(
                str(self.pcap_path)
            )
            print(f"       Found {len(self.tls_handshakes)} TLS handshakes")

            # Step 2: Email packets (using tshark directly)
            print("[2/7] Detecting email protocols...")
            self._extract_email_packets()
            print(f"       Found {len(self.email_packets)} email packets")

            # Step 3: Sessions
            print("[3/7] Reconstructing sessions...")
            self._reconstruct_sessions()
            self._link_tls_to_sessions()
            print(f"       Reconstructed {len(self.sessions)} sessions")

            # Step 4: Certificates
            print("[4/7] Extracting certificates...")
            self.certificates = CertificateAnalyzer.extract_certificates(
                str(self.pcap_path)
            )
            print(f"       Extracted {len(self.certificates)} certificates")

            # Step 5: Security checks
            print("[5/7] Running security checks...")
            analysis_data = {
                'summary': self._generate_summary(),
                'sessions': self.sessions,
                'tls_handshakes': self.tls_handshakes,
                'certificates': self.certificates
            }
            engine = SecurityEngine(analysis_data)
            findings = engine.run_all_checks()
            risk = engine.calculate_risk_score()
            print(f"       Found {len(findings)} security issues")
            print(f"       Risk Score: {risk['risk_score']}/100 ({risk['risk_level']})")

            # Step 6: AI-Powered Intelligence Enrichment
            print("[6/7] Generating AI Explanations & Threat Intelligence...")
            for finding in findings:
                ai_meta = self.ai_assistant.explain_finding(finding)
                finding['ai_explanation'] = ai_meta.get('ai_explanation', '')
                finding['ai_confidence'] = ai_meta.get('ai_confidence', 'HIGH')

            ai_summary = self.ai_assistant.generate_executive_summary(
                analysis_data['summary'], findings, risk
            )
            print("       AI Threat Intelligence generated successfully")

            # Step 7: Compile results
            print("[7/7] Compiling results...\n")
            summary = analysis_data['summary']
            summary['risk_score'] = risk['risk_score']
            summary['risk_level'] = risk['risk_level']

            result = {
                'success': True,
                'capture_id': self._generate_capture_id(),
                'filename': self.pcap_path.name,
                'summary': summary,
                'ai_summary': ai_summary,
                'findings': findings,
                'risk': risk,
                'sessions': self._clean_sessions(),
                'certificates': self.certificates,
                'tls_handshakes': self.tls_handshakes
            }

            self._print_report(result)
            return result

        except Exception as e:
            print(f"\n[!] Analysis failed: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__
            }

    def _extract_email_packets(self):
        """Extract email-related packets using tshark (fast & async-safe)"""
        filter_expr = (
            "tcp.port==25 || tcp.port==587 || tcp.port==465 || "
            "tcp.port==2525 || tcp.port==110 || tcp.port==995 || "
            "tcp.port==143 || tcp.port==993"
        )
        cmd = [
            'tshark',
            '-r', str(self.pcap_path),
            '-Y', filter_expr,
            '-T', 'json',
            '-e', 'frame.number',
            '-e', 'frame.time',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'frame.len'
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if not result.stdout.strip():
                return

            raw_data = json.loads(result.stdout)
            for packet in raw_data:
                layers = packet.get('_source', {}).get('layers', {})
                src_port_raw = layers.get('tcp.srcport', [''])[0]
                dst_port_raw = layers.get('tcp.dstport', [''])[0]
                if not src_port_raw or not dst_port_raw:
                    continue

                src_port = int(src_port_raw)
                dst_port = int(dst_port_raw)

                protocol = None
                if src_port in self.EMAIL_PORTS:
                    protocol = self.EMAIL_PORTS[src_port]
                elif dst_port in self.EMAIL_PORTS:
                    protocol = self.EMAIL_PORTS[dst_port]

                if protocol:
                    self.email_packets.append({
                        'number': layers.get('frame.number', [''])[0],
                        'timestamp': layers.get('frame.time', [''])[0],
                        'src': layers.get('ip.src', [''])[0] or 'N/A',
                        'dst': layers.get('ip.dst', [''])[0] or 'N/A',
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'length': int(layers.get('frame.len', ['0'])[0]),
                        'encrypted': protocol in ['SMTPS', 'IMAPS', 'POP3S']
                    })
        except Exception as e:
            print(f"       [!] Packet extraction error: {e}")

    def _reconstruct_sessions(self):
        """Group packets into sessions"""
        session_map = {}

        for pkt in self.email_packets:
            endpoints = sorted([
                (pkt['src'], pkt['src_port']),
                (pkt['dst'], pkt['dst_port'])
            ])
            key = f"{endpoints[0][0]}:{endpoints[0][1]}-{endpoints[1][0]}:{endpoints[1][1]}"

            if key not in session_map:
                session_map[key] = {
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

            session_map[key]['packet_count'] += 1
            session_map[key]['end_time'] = pkt['timestamp']

        self.sessions = list(session_map.values())

    def _link_tls_to_sessions(self):
        """Link TLS data to sessions"""
        for session in self.sessions:
            matching = [
                hs for hs in self.tls_handshakes
                if (hs['src'] == session['src'] and hs['dst'] == session['dst'])
                or (hs['src'] == session['dst'] and hs['dst'] == session['src'])
            ]
            if matching:
                versions = list(set(
                    hs['tls_version'] for hs in matching if hs['tls_version']
                ))
                ciphers = []
                for hs in matching:
                    ciphers.extend(hs.get('cipher_suites', []))

                session['tls_info'] = {
                    'versions': versions,
                    'handshake_count': len(matching),
                    'cipher_suites': list(set(ciphers))
                }

    def _clean_sessions(self):
        """Return sessions without raw packet data"""
        clean = []
        for s in self.sessions:
            clean.append({
                'id': s['id'],
                'protocol': s['protocol'],
                'src': f"{s['src']}:{s['src_port']}",
                'dst': f"{s['dst']}:{s['dst_port']}",
                'packet_count': s['packet_count'],
                'encrypted': s['encrypted'],
                'tls_versions': (
                    s['tls_info']['versions'] if s.get('tls_info') else []
                )
            })
        return clean

    def _generate_summary(self) -> Dict:
        total = len(self.email_packets)
        encrypted = sum(1 for p in self.email_packets if p['encrypted'])

        tls_versions = {}
        for hs in self.tls_handshakes:
            v = hs['tls_version']
            if v:
                tls_versions[v] = tls_versions.get(v, 0) + 1

        return {
            'total_packets': total,
            'encrypted_packets': encrypted,
            'plaintext_packets': total - encrypted,
            'encryption_ratio': round(encrypted / total, 2) if total > 0 else 0,
            'protocols_detected': list(set(
                p['protocol'] for p in self.email_packets
            )),
            'tls_versions': tls_versions,
            'session_count': len(self.sessions),
            'handshake_count': len(self.tls_handshakes),
            'certificate_count': len(self.certificates)
        }

    def _generate_capture_id(self) -> str:
        ts = datetime.now().isoformat()
        return hashlib.md5(f"{self.pcap_path.name}_{ts}".encode()).hexdigest()[:12]

    def _print_report(self, result):
        """Print formatted report to console"""
        summary = result['summary']
        risk = result['risk']
        findings = result['findings']
        ai_summary = result.get('ai_summary', '')

        print(f"{'='*70}")
        print(f"  SECURITY ASSESSMENT REPORT")
        print(f"{'='*70}")
        print(f"\n  Risk Score: {risk['risk_score']}/100  [{risk['risk_level']}]")
        print(f"  Email Packets: {summary['total_packets']}")
        print(f"  Encrypted: {summary['encrypted_packets']}  |  Plaintext: {summary['plaintext_packets']}")
        print(f"  Protocols: {', '.join(summary['protocols_detected']) or 'None'}")
        print(f"  TLS Versions: {', '.join(summary['tls_versions'].keys()) or 'None'}")
        
        if ai_summary:
            print(f"\n  🤖 AI EXECUTIVE BRIEFING:")
            print(f"  {ai_summary}")

        if findings:
            print(f"\n  {'─'*66}")
            print(f"  FINDINGS & AI INSIGHTS ({len(findings)})")
            print(f"  {'─'*66}")
            for f in findings:
                icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(f['severity'], '⚪')
                print(f"\n  {icon} [{f['severity']}] {f['title']}")
                print(f"     Evidence: {f['evidence']}")
                if f.get('ai_explanation'):
                    print(f"     🤖 AI Analysis: {f['ai_explanation']}")
        else:
            print(f"\n  ✅ No security issues detected!")

        print(f"\n{'='*70}\n")