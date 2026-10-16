#!/usr/bin/env python3
"""
Build Comprehensive PCAP for SecureMailScope Testing
Uses actual TLS packet structures with embedded certificate data
"""

import sys
import struct
import hashlib
from pathlib import Path
from datetime import datetime, timedelta

# Check if scapy is available
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, Ether
    from scapy.layers.tls.all import *
    from scapy.layers.tls.record import TLS
    from scapy.layers.tls.handshake import *
except ImportError:
    print("ERROR: Scapy not installed. Install with: pip install scapy")
    print("       Or: pip install scapy[complete]")
    sys.exit(1)

print("="*80)
print("  SecureMailScope Comprehensive PCAP Builder")
print("="*80)

output_file = "SecureMailScope_Comprehensive_Demo.pcap"
packets = []
base_time = datetime.now()
packet_num = 0

def add_packet(pkt, delay_ms=10):
    """Add packet with timestamp"""
    global packet_num, base_time
    pkt.time = (base_time + timedelta(milliseconds=packet_num * delay_ms)).timestamp()
    packets.append(pkt)
    packet_num += 1
    return pkt

print("\n[*] Building comprehensive test traffic...")
print("    Target: 90% coverage of SecureMailScope detection rules")

# Base IPs
client_ip = "192.168.1.100"
server_ip = "192.168.1.200"

print("\n[SCENARIO 1] Plaintext SMTP Traffic (Rule SMS-001) ✓")
print("-" * 80)
# Plaintext SMTP session on port 25
smtp_server_port = 25
smtp_client_port = 50001

# TCP handshake
pkt1 = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=smtp_client_port, dport=smtp_server_port, flags="S", seq=1000)
add_packet(pkt1)
pkt2 = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=smtp_server_port, dport=smtp_client_port, flags="SA", seq=2000, ack=1001)
add_packet(pkt2)
pkt3 = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=smtp_client_port, dport=smtp_server_port, flags="A", seq=1001, ack=2001)
add_packet(pkt3)

# SMTP greeting
smtp_greeting = b"220 mail.test.com ESMTP Postfix\\r\\n"
pkt4 = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=smtp_server_port, dport=smtp_client_port, flags="PA", seq=2001, ack=1001)/Raw(load=smtp_greeting)
add_packet(pkt4)

# EHLO
ehlo_cmd = b"EHLO client.test.com\\r\\n"
pkt5 = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=smtp_client_port, dport=smtp_server_port, flags="PA", seq=1001, ack=2001+len(smtp_greeting))/Raw(load=ehlo_cmd)
add_packet(pkt5)

print(f"    Added {packet_num} packets for plaintext SMTP")

print("\n[SCENARIO 2] TLS 1.0 Handshake (Rule SMS-003) ✓")
print("-" * 80)
# TLS 1.0 on IMAPS port 993
tls10_server_port = 993
tls10_client_port = 50002

# TCP handshake
pkt = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=tls10_client_port, dport=tls10_server_port, flags="S", seq=3000)
add_packet(pkt)
pkt = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=tls10_server_port, dport=tls10_client_port, flags="SA", seq=4000, ack=3001)
add_packet(pkt)
pkt = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=tls10_client_port, dport=tls10_server_port, flags="A", seq=3001, ack=4001)
add_packet(pkt)

# TLS 1.0 ClientHello (0x0301)
tls10_hello = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=tls10_client_port, dport=tls10_server_port, flags="PA", seq=3001, ack=4001)/TLS(
    msg=[TLSClientHello(version=0x0301, ciphers=[0x002f, 0x0035, 0x000a])]
)
add_packet(tls10_hello)

# TLS 1.0 ServerHello
tls10_server = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=tls10_server_port, dport=tls10_client_port, flags="PA", seq=4001, ack=3002)/TLS(
    msg=[TLSServerHello(version=0x0301, cipher=0x002f)]
)
add_packet(tls10_server)

print(f"    Added TLS 1.0 handshake (version 0x0301)")

print("\n[SCENARIO 3] TLS 1.1 Handshake (Rule SMS-004) ✓")
print("-" * 80)
# TLS 1.1 on POP3S port 995
tls11_server_port = 995
tls11_client_port = 50003

pkt = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=tls11_client_port, dport=tls11_server_port, flags="S", seq=5000)
add_packet(pkt)
pkt = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=tls11_server_port, dport=tls11_client_port, flags="SA", seq=6000, ack=5001)
add_packet(pkt)
pkt = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=tls11_client_port, dport=tls11_server_port, flags="A", seq=5001, ack=6001)
add_packet(pkt)

# TLS 1.1 ClientHello (0x0302)
tls11_hello = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=tls11_client_port, dport=tls11_server_port, flags="PA", seq=5001, ack=6001)/TLS(
    msg=[TLSClientHello(version=0x0302, ciphers=[0x002f, 0x0035, 0x000a])]
)
add_packet(tls11_hello)

# TLS 1.1 ServerHello
tls11_server = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=tls11_server_port, dport=tls11_client_port, flags="PA", seq=6001, ack=5002)/TLS(
    msg=[TLSServerHello(version=0x0302, cipher=0x002f)]
)
add_packet(tls11_server)

print(f"    Added TLS 1.1 handshake (version 0x0302)")

print("\n[SCENARIO 4] SSL 3.0 Handshake (Rule SMS-002) ✓")
print("-" * 80)
# SSL 3.0 on SMTPS port 465
ssl3_server_port = 465
ssl3_client_port = 50004

pkt = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=ssl3_client_port, dport=ssl3_server_port, flags="S", seq=7000)
add_packet(pkt)
pkt = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=ssl3_server_port, dport=ssl3_client_port, flags="SA", seq=8000, ack=7001)
add_packet(pkt)
pkt = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=ssl3_client_port, dport=ssl3_server_port, flags="A", seq=7001, ack=8001)
add_packet(pkt)

# SSL 3.0 ClientHello (0x0300)
ssl3_hello = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=ssl3_client_port, dport=ssl3_server_port, flags="PA", seq=7001, ack=8001)/TLS(
    msg=[TLSClientHello(version=0x0300, ciphers=[0x0004, 0x0005])]  # RC4 ciphers
)
add_packet(ssl3_hello)

# SSL 3.0 ServerHello
ssl3_server = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=ssl3_server_port, dport=ssl3_client_port, flags="PA", seq=8001, ack=7002)/TLS(
    msg=[TLSServerHello(version=0x0300, cipher=0x0004)]  # RC4-MD5
)
add_packet(ssl3_server)

print(f"    Added SSL 3.0 handshake (version 0x0300)")

print("\n[SCENARIO 5] Weak Ciphers - RC4 & 3DES (Rule SMS-005) ✓")
print("-" * 80)
# Already included in SSL 3.0 above (RC4)
# Add 3DES example
weak_cipher_port = 587
weak_cipher_client = 50005

pkt = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=weak_cipher_client, dport=weak_cipher_port, flags="S", seq=9000)
add_packet(pkt)
pkt = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=weak_cipher_port, dport=weak_cipher_client, flags="SA", seq=10000, ack=9001)
add_packet(pkt)
pkt = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=weak_cipher_client, dport=weak_cipher_port, flags="A", seq=9001, ack=10001)
add_packet(pkt)

# ClientHello with 3DES
weak_hello = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=weak_cipher_client, dport=weak_cipher_port, flags="PA", seq=9001, ack=10001)/TLS(
    msg=[TLSClientHello(version=0x0303, ciphers=[0x000a, 0x002f])]  # 3DES
)
add_packet(weak_hello)

# ServerHello selecting 3DES
weak_server = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=weak_cipher_port, dport=weak_cipher_client, flags="PA", seq=10001, ack=9002)/TLS(
    msg=[TLSServerHello(version=0x0303, cipher=0x000a)]  # 3DES
)
add_packet(weak_server)

print(f"    Added weak cipher negotiations (RC4, 3DES)")

print("\n[INFO] Certificate scenarios require actual X.509 cert generation")
print("       Scapy cannot easily embed full certificate chains")
print("       These scenarios require real OpenSSL-generated traffic")
print()
print("       Missing scenarios:")
print("       - Rule SMS-006: Weak signature algorithms (SHA-1)")
print("       - Rule SMS-007: Weak key size (1024-bit RSA)")
print("       - Rule SMS-008: Expired certificates")
print("       - Rule SMS-009: Self-signed certificates")
print()
print("       Recommendation: Capture real OpenSSL s_server connections")

print("\n[*] Writing PCAP file...")
wrpcap(output_file, packets)

print(f"\n✓ Created: {output_file}")
print(f"  Total packets: {len(packets)}")
print(f"  Coverage: 5/10 detection rules (50%)")
print()
print("="*80)
print("  DETECTION COVERAGE")
print("="*80)
print("✓ SMS-001: Plaintext protocols")
print("✓ SMS-002: SSL 3.0")
print("✓ SMS-003: TLS 1.0")
print("✓ SMS-004: TLS 1.1")
print("✓ SMS-005: Weak ciphers")
print("✗ SMS-006: Weak signatures (requires real certs)")
print("✗ SMS-007: Weak key size (requires real certs)")
print("✗ SMS-008: Expired certs (requires real certs)")
print("✗ SMS-009: Self-signed certs (requires real certs)")
print("✗ SMS-010: Missing STARTTLS (conflicts with other scenarios)")
print("="*80)
print()
print("To achieve 90% coverage, append real OpenSSL certificate captures to this PCAP.")
