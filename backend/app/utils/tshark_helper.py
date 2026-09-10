"""
TShark wrapper for structured TCP stream reconstruction and TLS/X.509 metadata extraction.
Adheres strictly to deterministic packet extraction and protocol-aware credential redaction.
"""

import subprocess
import json
import re
import binascii
from pathlib import Path
from typing import List, Dict, Optional, Tuple


class TSharkHelper:
    """Extracts structured TCP stream telemetry and TLS handshake forensics using tshark"""

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
        Extract TLS handshake metadata with frame numbers, stream IDs, and cipher suites.
        """
        pcap_file = Path(pcap_path)
        if not pcap_file.exists():
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")

        tshark_path = TSharkHelper.get_tshark_path()
        cmd = [
            tshark_path,
            '-r', str(pcap_file),
            '-Y', 'ssl.handshake || tls.handshake',
            '-T', 'json',
            '-e', 'frame.number',
            '-e', 'frame.time',
            '-e', 'tcp.stream',
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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                raise RuntimeError(f"tshark failed: {result.stderr}")
            if not result.stdout.strip():
                return []

            raw_data = json.loads(result.stdout)
            handshakes = []

            for packet in raw_data:
                layers = packet.get('_source', {}).get('layers', {})

                tls_version_raw = (
                    layers.get('ssl.record.version', [''])[0] or
                    layers.get('tls.record.version', [''])[0]
                )

                version_map = {
                    '0x0300': 'SSL 3.0',
                    '0x0301': 'TLS 1.0',
                    '0x0302': 'TLS 1.1',
                    '0x0303': 'TLS 1.2',
                    '0x0304': 'TLS 1.3'
                }
                tls_version = version_map.get(tls_version_raw, tls_version_raw)

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

                cipher_suites = (
                    layers.get('ssl.handshake.ciphersuite', []) or
                    layers.get('tls.handshake.ciphersuite', [])
                )

                sni = (
                    layers.get('ssl.handshake.extensions_server_name', [''])[0] or
                    layers.get('tls.handshake.extensions_server_name', [''])[0]
                )

                handshake_info = {
                    'frame': layers.get('frame.number', [''])[0],
                    'timestamp': layers.get('frame.time', [''])[0],
                    'tcp_stream': layers.get('tcp.stream', [''])[0],
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
            raise RuntimeError("TShark executable was not found.")
        except subprocess.TimeoutExpired:
            raise RuntimeError("tshark extraction timed out")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse tshark output: {e}")

    @staticmethod
    def extract_raw_certificates(pcap_path: str) -> List[Dict]:
        """
        Extract raw X.509 DER byte representations from TLS Certificate messages (Handshake Type 11).
        Preserves frame numbers, stream IDs, and SNI context.
        """
        pcap_file = Path(pcap_path)
        if not pcap_file.exists():
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")

        tshark_path = TSharkHelper.get_tshark_path()
        cmd = [
            tshark_path,
            '-r', str(pcap_file),
            '-Y', 'tls.handshake.certificate || ssl.handshake.certificate',
            '-T', 'json',
            '-e', 'frame.number',
            '-e', 'frame.time',
            '-e', 'tcp.stream',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'tls.handshake.certificate',
            '-e', 'ssl.handshake.certificate',
            '-e', 'tls.handshake.extensions_server_name',
            '-e', 'ssl.handshake.extensions_server_name'
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if not result.stdout.strip():
                return []

            raw_data = json.loads(result.stdout)
            extracted_certs = []

            for packet in raw_data:
                layers = packet.get('_source', {}).get('layers', {})
                frame_number = int(layers.get('frame.number', ['0'])[0] or 0)
                frame_time = layers.get('frame.time', [''])[0]
                tcp_stream = layers.get('tcp.stream', [''])[0]
                ip_src = layers.get('ip.src', [''])[0]
                ip_dst = layers.get('ip.dst', [''])[0]
                src_port = layers.get('tcp.srcport', [''])[0]
                dst_port = layers.get('tcp.dstport', [''])[0]

                sni = (
                    layers.get('tls.handshake.extensions_server_name', [''])[0] or
                    layers.get('ssl.handshake.extensions_server_name', [''])[0]
                )

                certs_hex_list = (
                    layers.get('tls.handshake.certificate', []) or
                    layers.get('ssl.handshake.certificate', [])
                )

                # Each cert entry could contain comma-separated multiple certs in the presented chain
                chain_index = 0
                for cert_hex_entry in certs_hex_list:
                    # In tshark JSON, multiple certificates are separated by comma
                    individual_hexes = cert_hex_entry.split(',')
                    for single_hex in individual_hexes:
                        cleaned_hex = single_hex.replace(':', '').strip()
                        if not cleaned_hex:
                            continue
                        try:
                            der_bytes = binascii.unhexlify(cleaned_hex)
                            extracted_certs.append({
                                'frame_number': frame_number,
                                'frame_time': frame_time,
                                'tcp_stream': tcp_stream,
                                'ip_src': ip_src,
                                'ip_dst': ip_dst,
                                'src_port': src_port,
                                'dst_port': dst_port,
                                'sni': sni,
                                'der_bytes': der_bytes,
                                'chain_position': chain_index
                            })
                            chain_index += 1
                        except Exception as e:
                            print(f"[!] DER unhexlify error: {e}")
                            continue

            return extracted_certs

        except Exception as e:
            print(f"[!] Error extracting raw certificates: {e}")
            return []

    @staticmethod
    def extract_structured_tcp_streams(pcap_path: str) -> Dict[str, Dict]:
        """
        Extract complete structured TCP streams, determining client/server orientation
        from SYN/SYN-ACK handshake, reconstructing chunks, and applying protocol-aware redaction.
        """
        pcap_file = Path(pcap_path)
        if not pcap_file.exists():
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")

        tshark_path = TSharkHelper.get_tshark_path()
        cmd = [
            tshark_path,
            '-r', str(pcap_file),
            '-Y', 'tcp',
            '-T', 'json',
            '-e', 'frame.number',
            '-e', 'frame.time_relative',
            '-e', 'frame.time_epoch',
            '-e', 'tcp.stream',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'tcp.flags.syn',
            '-e', 'tcp.flags.ack',
            '-e', 'tcp.payload',
            '-e', 'frame.len',
            '-e', 'tls.record.content_type',
            '-e', 'ssl.record.content_type'
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            if not result.stdout.strip():
                return {}

            raw_data = json.loads(result.stdout)
            streams_raw: Dict[str, Dict] = {}

            # First pass: Group frames and identify TCP initiator (Client)
            for packet in raw_data:
                layers = packet.get('_source', {}).get('layers', {})
                stream_id_str = layers.get('tcp.stream', [''])[0]
                if not stream_id_str:
                    continue

                frame_num = int(layers.get('frame.number', ['0'])[0] or 0)
                rel_time = float(layers.get('frame.time_relative', ['0.0'])[0] or 0.0)
                epoch_time = float(layers.get('frame.time_epoch', ['0.0'])[0] or 0.0)
                src_ip = layers.get('ip.src', [''])[0]
                dst_ip = layers.get('ip.dst', [''])[0]
                src_port_raw = layers.get('tcp.srcport', ['0'])[0]
                dst_port_raw = layers.get('tcp.dstport', ['0'])[0]
                src_port = int(src_port_raw) if src_port_raw else 0
                dst_port = int(dst_port_raw) if dst_port_raw else 0
                syn_flag = layers.get('tcp.flags.syn', ['0'])[0] == '1'
                ack_flag = layers.get('tcp.flags.ack', ['0'])[0] == '1'
                payload_hex = layers.get('tcp.payload', [''])[0].replace(':', '')
                tls_ct = layers.get('tls.record.content_type', []) or layers.get('ssl.record.content_type', [])

                if stream_id_str not in streams_raw:
                    streams_raw[stream_id_str] = {
                        'stream_id': int(stream_id_str),
                        'initiator': None,
                        'responder': None,
                        'packets': [],
                        'has_tls_app_data': False,
                        'first_seen': epoch_time,
                        'last_seen': epoch_time
                    }

                st = streams_raw[stream_id_str]
                st['last_seen'] = max(st['last_seen'], epoch_time)
                if st['first_seen'] == 0:
                    st['first_seen'] = epoch_time

                # Check if TCP SYN packet indicates initiator
                if syn_flag and not ack_flag and not st['initiator']:
                    st['initiator'] = (src_ip, src_port)
                    st['responder'] = (dst_ip, dst_port)
                elif syn_flag and ack_flag and not st['responder']:
                    st['responder'] = (src_ip, src_port)
                    st['initiator'] = (dst_ip, dst_port)

                # Check TLS content type 23 (Application Data)
                if any(ct in ['23', '0x17'] for ct in tls_ct):
                    st['has_tls_app_data'] = True

                st['packets'].append({
                    'frame_number': frame_num,
                    'rel_time': rel_time,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'payload_hex': payload_hex,
                    'has_payload': bool(payload_hex),
                    'tls_ct': tls_ct
                })

            # Second pass: Structure streams, assign client/server, reconstruct and redact chunks
            final_streams: Dict[str, Dict] = {}

            for sid, st in streams_raw.items():
                packets = st['packets']
                if not packets:
                    continue

                # If initiator not resolved from SYN, use well-known mail ports heuristic
                initiator = st['initiator']
                responder = st['responder']
                if not initiator:
                    # Look at ports
                    p0 = packets[0]
                    src_p = p0['src_port']
                    dst_p = p0['dst_port']
                    if dst_p in TSharkHelper.EMAIL_PORTS:
                        initiator = (p0['src_ip'], src_p)
                        responder = (p0['dst_ip'], dst_p)
                    elif src_p in TSharkHelper.EMAIL_PORTS:
                        responder = (p0['src_ip'], src_p)
                        initiator = (p0['dst_ip'], dst_p)
                    else:
                        initiator = (p0['src_ip'], src_p)
                        responder = (p0['dst_ip'], dst_p)

                client_ip, client_port = initiator
                server_ip, server_port = responder

                # Determine protocol
                protocol = TSharkHelper.EMAIL_PORTS.get(server_port) or TSharkHelper.EMAIL_PORTS.get(client_port) or 'TCP'

                # Build chunks
                chunks = []
                total_payload_bytes = 0
                redaction_count = 0
                has_redaction = False
                is_encrypted_stream = st['has_tls_app_data'] or protocol in ['SMTPS', 'IMAPS', 'POP3S']

                # State tracking for multi-step auth (e.g. SMTP AUTH LOGIN)
                smtp_auth_state = None

                for pkt in packets:
                    if not pkt['payload_hex']:
                        continue

                    raw_bytes = binascii.unhexlify(pkt['payload_hex'])
                    total_payload_bytes += len(raw_bytes)

                    # Direction
                    if pkt['src_ip'] == client_ip and pkt['src_port'] == client_port:
                        direction = 'client_to_server'
                    else:
                        direction = 'server_to_client'

                    # Decode ASCII safely
                    ascii_text = ''.join(chr(b) if (32 <= b <= 126 or b in (9, 10, 13)) else '.' for b in raw_bytes)

                    # Protocol-aware sensitive credential redaction
                    redacted_text, count, smtp_auth_state = TSharkHelper._redact_protocol_credentials(
                        ascii_text, direction, protocol, smtp_auth_state
                    )
                    if count > 0:
                        has_redaction = True
                        redaction_count += count

                    chunks.append({
                        'frame_number': pkt['frame_number'],
                        'direction': direction,
                        'timestamp': round(pkt['rel_time'], 4),
                        'payload': redacted_text,
                        'hex_payload': pkt['payload_hex']
                    })

                duration = max(0.0, round(st['last_seen'] - st['first_seen'], 2))

                final_streams[sid] = {
                    'stream_id': st['stream_id'],
                    'protocol': protocol,
                    'client': {
                        'ip': client_ip,
                        'port': client_port
                    },
                    'server': {
                        'ip': server_ip,
                        'port': server_port
                    },
                    'packet_count': len(packets),
                    'payload_bytes': total_payload_bytes,
                    'duration': duration,
                    'encrypted': is_encrypted_stream,
                    'redacted': has_redaction,
                    'redaction_count': redaction_count,
                    'chunks': chunks
                }

            return final_streams

        except Exception as e:
            print(f"[!] Error extracting structured TCP streams: {e}")
            return {}

    @staticmethod
    def _redact_protocol_credentials(text: str, direction: str, protocol: str, state: Optional[str]) -> Tuple[str, int, Optional[str]]:
        """
        Protocol-aware credential redaction for SMTP, POP3, and IMAP.
        Does NOT mask arbitrary Base64 strings.
        """
        redactions = 0
        new_state = state
        lines = text.split('\r\n')
        processed_lines = []

        for line in lines:
            trimmed = line.strip()

            # 1. SMTP AUTH PLAIN
            if direction == 'client_to_server' and trimmed.upper().startswith('AUTH PLAIN'):
                parts = line.split(maxsplit=2)
                if len(parts) >= 3:
                    line = f"{parts[0]} {parts[1]} [REDACTED_PLAIN_CREDENTIALS]"
                    redactions += 1
                else:
                    new_state = 'SMTP_AUTH_PLAIN_WAIT'

            elif direction == 'client_to_server' and state == 'SMTP_AUTH_PLAIN_WAIT':
                line = "[REDACTED_PLAIN_CREDENTIALS]"
                redactions += 1
                new_state = None

            # 2. SMTP AUTH LOGIN
            elif direction == 'client_to_server' and trimmed.upper().startswith('AUTH LOGIN'):
                parts = line.split(maxsplit=2)
                if len(parts) >= 3:
                    line = f"{parts[0]} {parts[1]} [REDACTED_USER_BASE64]"
                    redactions += 1
                    new_state = 'SMTP_AUTH_LOGIN_PASS'
                else:
                    new_state = 'SMTP_AUTH_LOGIN_USER'

            elif direction == 'server_to_client' and '334 VXNlcm5hbWU6' in line: # 'Username:' in B64
                new_state = 'SMTP_AUTH_LOGIN_USER'

            elif direction == 'server_to_client' and '334 UGFzc3dvcmQ6' in line: # 'Password:' in B64
                new_state = 'SMTP_AUTH_LOGIN_PASS'

            elif direction == 'client_to_server' and state == 'SMTP_AUTH_LOGIN_USER':
                line = "[REDACTED_USERNAME_BASE64]"
                redactions += 1
                new_state = 'SMTP_AUTH_LOGIN_PASS'

            elif direction == 'client_to_server' and state == 'SMTP_AUTH_LOGIN_PASS':
                line = "[REDACTED_PASSWORD_BASE64]"
                redactions += 1
                new_state = None

            # 3. POP3 USER and PASS
            elif direction == 'client_to_server' and trimmed.upper().startswith('PASS '):
                line = "PASS [REDACTED_PASSWORD]"
                redactions += 1

            # 4. IMAP LOGIN
            elif direction == 'client_to_server' and re.search(r'^[A-Za-z0-9]+\s+LOGIN\s+', trimmed, re.IGNORECASE):
                # Format: tag LOGIN user pass
                parts = line.split(maxsplit=3)
                if len(parts) >= 4:
                    line = f"{parts[0]} {parts[1]} {parts[2]} [REDACTED_PASSWORD]"
                    redactions += 1

            # 5. Bearer / OAuth Tokens
            elif 'Bearer ' in line:
                line = re.sub(r'Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*', 'Bearer [REDACTED_BEARER_TOKEN]', line)
                redactions += 1

            processed_lines.append(line)

        return '\r\n'.join(processed_lines), redactions, new_state


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        pcap = sys.argv[1]
        streams = TSharkHelper.extract_structured_tcp_streams(pcap)
        print(f"Extracted {len(streams)} structured TCP streams")
        for sid, s in list(streams.items())[:2]:
            print(f"Stream {sid}: {s['protocol']} {s['client']['ip']}:{s['client']['port']} -> {s['server']['ip']}:{s['server']['port']} ({s['packet_count']} pkts, {len(s['chunks'])} chunks, redacted: {s['redacted']})")