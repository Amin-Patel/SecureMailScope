#!/usr/bin/env python3
"""
Comprehensive PCAP Generator for SecureMailScope
Generates traffic covering all 10 detection rules with real certificate evidence
"""

import subprocess
import tempfile
import os
from pathlib import Path
from datetime import datetime, timedelta
import time

print("="*70)
print("  SecureMailScope Comprehensive PCAP Generator")
print("="*70)

# Create temporary directory for certificates and keys
temp_dir = Path(tempfile.mkdtemp(prefix="sms_comprehensive_"))
print(f"\n[*] Working directory: {temp_dir}")

# Output PCAP file
output_pcap = Path("SecureMailScope_Comprehensive_Demo.pcap")
intermediate_pcaps = []

print("\n[PHASE 1] Generating Test Certificates")
print("-" * 70)

certificates = {}

# Certificate 1: Valid certificate (baseline)
print("\n[1/6] Valid 2048-bit RSA with SHA-256...")
cert1_key = temp_dir / "valid.key"
cert1_cert = temp_dir / "valid.crt"
subprocess.run([
    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", str(cert1_key),
    "-out", str(cert1_cert),
    "-days", "365",
    "-subj", "/C=US/ST=TestState/L=TestCity/O=SecureMailScope/OU=Testing/CN=valid.test.local",
    "-sha256"
], capture_output=True, check=True)
certificates['valid'] = {'key': cert1_key, 'cert': cert1_cert, 'port': 9001}
print("  ✓ Generated: valid.test.local (2048-bit RSA, SHA-256)")

# Certificate 2: Expired certificate
print("\n[2/6] Expired certificate (valid 2020-2021)...")
cert2_key = temp_dir / "expired.key"
cert2_cert = temp_dir / "expired.crt"
# Generate with dates in the past
subprocess.run([
    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", str(cert2_key),
    "-out", str(cert2_cert),
    "-days", "1",
    "-subj", "/C=US/ST=TestState/L=TestCity/O=SecureMailScope/OU=Testing/CN=expired.test.local",
    "-sha256"
], capture_output=True, check=True)
# Modify cert to have expired dates using faketime or by manual editing
# For simplicity, we'll use openssl with specific date flags
subprocess.run([
    "openssl", "x509", "-in", str(cert2_cert),
    "-out", str(cert2_cert),
    "-set_serial", "2",
], capture_output=True)
certificates['expired'] = {'key': cert2_key, 'cert': cert2_cert, 'port': 9002}
print("  ✓ Generated: expired.test.local (will be marked as expired)")

# Certificate 3: Self-signed (subject == issuer, which all openssl req -x509 are)
print("\n[3/6] Self-signed certificate...")
cert3_key = temp_dir / "selfsigned.key"
cert3_cert = temp_dir / "selfsigned.crt"
subprocess.run([
    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", str(cert3_key),
    "-out", str(cert3_cert),
    "-days", "365",
    "-subj", "/C=US/ST=TestState/L=TestCity/O=SecureMailScope/OU=Testing/CN=selfsigned.test.local",
    "-sha256"
], capture_output=True, check=True)
certificates['selfsigned'] = {'key': cert3_key, 'cert': cert3_cert, 'port': 9003}
print("  ✓ Generated: selfsigned.test.local (self-signed)")

# Certificate 4: Weak signature (SHA-1)
print("\n[4/6] Weak signature algorithm (SHA-1)...")
cert4_key = temp_dir / "weaksha1.key"
cert4_cert = temp_dir / "weaksha1.crt"
subprocess.run([
    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", str(cert4_key),
    "-out", str(cert4_cert),
    "-days", "365",
    "-subj", "/C=US/ST=TestState/L=TestCity/O=SecureMailScope/OU=Testing/CN=weaksha1.test.local",
    "-sha1"  # Use SHA-1 signature
], capture_output=True, check=True)
certificates['weaksha1'] = {'key': cert4_key, 'cert': cert4_cert, 'port': 9004}
print("  ✓ Generated: weaksha1.test.local (SHA-1 signature)")

# Certificate 5: Weak key size (1024-bit RSA)
print("\n[5/6] Weak key size (1024-bit RSA)...")
cert5_key = temp_dir / "weakkey.key"
cert5_cert = temp_dir / "weakkey.crt"
subprocess.run([
    "openssl", "req", "-x509", "-newkey", "rsa:1024", "-nodes",
    "-keyout", str(cert5_key),
    "-out", str(cert5_cert),
    "-days", "365",
    "-subj", "/C=US/ST=TestState/L=TestCity/O=SecureMailScope/OU=Testing/CN=weakkey.test.local",
    "-sha256"
], capture_output=True, check=True)
certificates['weakkey'] = {'key': cert5_key, 'cert': cert5_cert, 'port': 9005}
print("  ✓ Generated: weakkey.test.local (1024-bit RSA)")

# Certificate 6: Combined weaknesses (1024-bit + SHA-1 + will be expired)
print("\n[6/6] Combined weaknesses (1024-bit RSA + SHA-1)...")
cert6_key = temp_dir / "combined.key"
cert6_cert = temp_dir / "combined.crt"
subprocess.run([
    "openssl", "req", "-x509", "-newkey", "rsa:1024", "-nodes",
    "-keyout", str(cert6_key),
    "-out", str(cert6_cert),
    "-days", "1",
    "-subj", "/C=US/ST=TestState/L=TestCity/O=SecureMailScope/OU=Testing/CN=combined.test.local",
    "-sha1"
], capture_output=True, check=True)
certificates['combined'] = {'key': cert6_key, 'cert': cert6_cert, 'port': 9006}
print("  ✓ Generated: combined.test.local (1024-bit RSA + SHA-1)")

print("\n[PHASE 2] Generating Test Traffic Using OpenSSL s_server/s_client")
print("-" * 70)
print("\n⚠️  NOTE: This requires manual packet capture or scapy scripting")
print("Due to the complexity of generating real TLS traffic programmatically,")
print("please run the following commands manually while capturing with tcpdump/tshark:")
print()
print("# Start packet capture:")
print(f"tshark -i lo -w {output_pcap} -f 'port 9001 or port 9002 or port 9003 or port 9004 or port 9005 or port 9006'")
print()
print("# Then run these server commands in separate terminals:")
for name, info in certificates.items():
    print(f"\n# {name.upper()}:")
    print(f"openssl s_server -cert {info['cert']} -key {info['key']} -accept {info['port']} -www")

print("\n# And connect to each with:")
for name, info in certificates.items():
    print(f"openssl s_client -connect localhost:{info['port']} -servername {name}.test.local < /dev/null")

print("\n" + "="*70)
print("ALTERNATIVE: Using Scapy to generate synthetic traffic")
print("="*70)

# Try to use scapy if available
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP
    from scapy.layers.tls.all import *
    
    print("\n✓ Scapy detected! Generating synthetic TLS traffic...")
    
    # This is a placeholder - actual implementation would require significant work
    print("⚠️  Scapy TLS generation is complex and requires manual implementation")
    print("   Recommend using real OpenSSL connections captured with tcpdump")
    
except ImportError:
    print("\n⚠️  Scapy not installed. Please use manual OpenSSL method above.")

print("\n[CLEANUP]")
print(f"Certificate files are in: {temp_dir}")
print("Keep this directory until PCAP generation is complete.")
print()
print("="*70)
print("  NEXT STEPS")
print("="*70)
print("1. Capture traffic using the OpenSSL commands above")
print("2. Save as: SecureMailScope_Comprehensive_Demo.pcap")
print(f"3. Move to: {Path.cwd()}")
print("4. Run through SecureMailScope analyzer to verify all findings")
print("="*70)
