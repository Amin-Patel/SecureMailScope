"""
Synthesizes a compliant, modern SMTPS/IMAPS packet capture (TLS 1.2 / TLS 1.3)
Used as the Green Benchmark in SecureMailScope judge demonstrations.
"""

from scapy.all import wrpcap, Ether, IP, TCP, Raw
from pathlib import Path
from datetime import datetime

def generate_secure_pcap(output_path: str = "test-data/secure_mail.pcap"):
    packets = []
    
    client_ip = "192.168.1.50"
    server_ip = "198.51.100.25"  # mail.enterprise.com
    
    # ─── 1. SMTPS Session on Port 465 (TLS 1.3) ───
    client_port_smtp = 49152
    
    # TCP 3-Way Handshake (SYN, SYN-ACK, ACK)
    t = datetime.now().timestamp()
    p1 = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port_smtp, dport=465, flags="S", seq=1000)
    p1.time = t
    p2 = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=465, dport=client_port_smtp, flags="SA", seq=2000, ack=1001)
    p2.time = t + 0.01
    p3 = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port_smtp, dport=465, flags="A", seq=1001, ack=2001)
    p3.time = t + 0.02
    packets.extend([p1, p2, p3])

    # TLS 1.3 ClientHello (Content Type 0x16, Version 0x0303 / TLS 1.2 record layer wrapping TLS 1.3)
    client_hello_payload = bytes([
        0x16, 0x03, 0x03, 0x00, 0x35, # Handshake Record, TLS 1.2 wrapper, length 53
        0x01, 0x00, 0x00, 0x31,       # ClientHello, length 49
        0x03, 0x03,                   # Client Version TLS 1.2
    ]) + b"\x00" * 32 + bytes([        # Random 32 bytes
        0x00,                         # Session ID length 0
        0x00, 0x04,                   # Cipher suites length 4
        0x13, 0x01, 0x13, 0x02,       # TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
        0x01, 0x00                    # Compression methods (null)
    ])
    
    p_ch = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port_smtp, dport=465, flags="PA", seq=1001, ack=2001)/Raw(load=client_hello_payload)
    p_ch.time = t + 0.03
    packets.append(p_ch)

    # TLS 1.3 ServerHello (Selected TLS_AES_256_GCM_SHA384)
    server_hello_payload = bytes([
        0x16, 0x03, 0x03, 0x00, 0x2A, # Handshake Record, length 42
        0x02, 0x00, 0x00, 0x26,       # ServerHello, length 38
        0x03, 0x03,                   # Server Version TLS 1.2
    ]) + b"\x00" * 32 + bytes([        # Random 32 bytes
        0x00,                         # Session ID length 0
        0x13, 0x02,                   # Selected Cipher: TLS_AES_256_GCM_SHA384
        0x00                          # Compression null
    ])
    
    p_sh = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=465, dport=client_port_smtp, flags="PA", seq=2001, ack=1001 + len(client_hello_payload))/Raw(load=server_hello_payload)
    p_sh.time = t + 0.05
    packets.append(p_sh)

    # Encrypted Application Data packets (Content Type 0x17)
    for i in range(15):
        enc_data = bytes([0x17, 0x03, 0x03, 0x00, 0x64]) + (b"\xAA" * 100)
        p_app = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port_smtp, dport=465, flags="PA", seq=1100 + (i*105), ack=2100)/Raw(load=enc_data)
        p_app.time = t + 0.1 + (i * 0.01)
        packets.append(p_app)

    # ─── 2. IMAPS Session on Port 993 (TLS 1.3 Encrypted) ───
    client_port_imap = 49153
    p_im1 = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port_imap, dport=993, flags="S", seq=3000)
    p_im1.time = t + 0.5
    p_im2 = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=993, dport=client_port_imap, flags="SA", seq=4000, ack=3001)
    p_im2.time = t + 0.51
    p_im3 = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port_imap, dport=993, flags="A", seq=3001, ack=4001)
    p_im3.time = t + 0.52
    packets.extend([p_im1, p_im2, p_im3])

    for i in range(10):
        enc_data = bytes([0x17, 0x03, 0x03, 0x00, 0x50]) + (b"\xBB" * 80)
        p_app_imap = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port_imap, dport=993, flags="PA", seq=3001 + (i*85), ack=4001)/Raw(load=enc_data)
        p_app_imap.time = t + 0.55 + (i * 0.01)
        packets.append(p_app_imap)

    # Save to disk
    out = Path(output_path)
    out.parent.mkdir(exist_ok=True)
    wrpcap(str(out), packets)
    print(f"[+] Successfully generated compliant capture: {output_path} ({len(packets)} packets)")

if __name__ == "__main__":
    generate_secure_pcap()