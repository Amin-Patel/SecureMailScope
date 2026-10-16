#!/usr/bin/env python3
"""
Generate Real Certificate Traffic for SIH Demo PCAP
Creates OpenSSL certificates with various vulnerabilities and captures TLS handshakes
"""

import subprocess
import os
import time
import sys
from pathlib import Path

def run_command(cmd, cwd=None, capture_output=True):
    """Run shell command and return output"""
    print(f"[*] Running: {cmd}")
    result = subprocess.run(
        cmd, 
        shell=True, 
        cwd=cwd, 
        capture_output=capture_output, 
        text=True,
        timeout=30
    )
    if result.returncode != 0 and capture_output:
        print(f"[!] Error: {result.stderr}")
    return result

def generate_weak_1024bit_sha1_cert():
    """Generate 1024-bit RSA certificate with SHA-1 signature (SMS-006, SMS-007)"""
    print("\n" + "="*80)
    print("SCENARIO 1: Weak 1024-bit RSA + SHA-1 Signature")
    print("="*80)
    
    # Generate 1024-bit RSA key
    run_command(
        'openssl genrsa -out weak_1024_sha1.key 1024',
        cwd='temp_certs'
    )
    
    # Create certificate with SHA-1 signature
    run_command(
        'openssl req -new -x509 -key weak_1024_sha1.key -out weak_1024_sha1.pem '
        '-days 365 -sha1 -subj "/C=US/ST=Test/L=Test/O=WeakCrypto/CN=mail.weak1024.test"',
        cwd='temp_certs'
    )
    
    print("✓ Created: 1024-bit RSA certificate with SHA-1 signature")
    return 'weak_1024_sha1'

def generate_expired_cert():
    """Generate expired certificate (SMS-008)"""
    print("\n" + "="*80)
    print("SCENARIO 2: Expired Certificate")
    print("="*80)
    
    # Generate 2048-bit RSA key (valid strength)
    run_command(
        'openssl genrsa -out expired.key 2048',
        cwd='temp_certs'
    )
    
    # Create certificate that expired 100 days ago
    run_command(
        'openssl req -new -x509 -key expired.key -out expired.pem '
        '-days -100 -sha256 -subj "/C=US/ST=Test/L=Test/O=ExpiredCert/CN=mail.expired.test"',
        cwd='temp_certs'
    )
    
    print("✓ Created: Expired certificate (notAfter in the past)")
    return 'expired'

def generate_self_signed_cert():
    """Generate self-signed certificate (SMS-009)"""
    print("\n" + "="*80)
    print("SCENARIO 3: Self-Signed Certificate")
    print("="*80)
    
    # Generate 2048-bit RSA key
    run_command(
        'openssl genrsa -out selfsigned.key 2048',
        cwd='temp_certs'
    )
    
    # Create self-signed certificate
    run_command(
        'openssl req -new -x509 -key selfsigned.key -out selfsigned.pem '
        '-days 365 -sha256 -subj "/C=US/ST=Test/L=Test/O=SelfSigned/CN=mail.selfsigned.test"',
        cwd='temp_certs'
    )
    
    print("✓ Created: Self-signed certificate (issuer == subject)")
    return 'selfsigned'

def generate_weak_512bit_cert():
    """Generate 512-bit RSA certificate (extremely weak - SMS-007)"""
    print("\n" + "="*80)
    print("SCENARIO 4: Ultra-Weak 512-bit RSA")
    print("="*80)
    
    # Generate 512-bit RSA key
    run_command(
        'openssl genrsa -out weak_512.key 512',
        cwd='temp_certs'
    )
    
    # Create certificate
    run_command(
        'openssl req -new -x509 -key weak_512.key -out weak_512.pem '
        '-days 365 -sha256 -subj "/C=US/ST=Test/L=Test/O=UltraWeak/CN=mail.weak512.test"',
        cwd='temp_certs'
    )
    
    print("✓ Created: 512-bit RSA certificate (ultra-weak)")
    return 'weak_512'

def capture_tls_handshake(cert_name, port_offset):
    """Capture TLS handshake using the generated certificate"""
    port = 8400 + port_offset
    
    print(f"\n[*] Starting TLS server on port {port}...")
    print(f"[*] Certificate: temp_certs/{cert_name}.pem")
    
    # Start tshark capture in background
    capture_file = f'temp_certs/capture_{cert_name}.pcap'
    print(f"[*] Starting packet capture -> {capture_file}")
    
    tshark_proc = subprocess.Popen(
        f'tshark -i Loopback -w {capture_file} -f "port {port}"',
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait for tshark to start
    time.sleep(2)
    
    # Start OpenSSL server in background
    print(f"[*] Starting OpenSSL s_server on port {port}...")
    server_proc = subprocess.Popen(
        f'openssl s_server -accept {port} -cert temp_certs/{cert_name}.pem -key temp_certs/{cert_name}.key -www',
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait for server to start
    time.sleep(2)
    
    # Connect with client to trigger handshake
    print(f"[*] Connecting client to capture certificate exchange...")
    client_result = subprocess.run(
        f'echo "Q" | openssl s_client -connect localhost:{port} -showcerts',
        shell=True,
        capture_output=True,
        text=True,
        timeout=10
    )
    
    # Wait a bit for packets to be captured
    time.sleep(1)
    
    # Stop server
    print(f"[*] Stopping OpenSSL server...")
    server_proc.terminate()
    server_proc.wait(timeout=5)
    
    # Stop tshark
    print(f"[*] Stopping packet capture...")
    tshark_proc.terminate()
    tshark_proc.wait(timeout=5)
    
    # Verify capture has packets
    result = subprocess.run(
        f'tshark -r {capture_file} -Y "tls.handshake.certificate" | findstr /C:"Certificate"',
        shell=True,
        capture_output=True,
        text=True
    )
    
    if result.stdout:
        print(f"✓ Certificate captured successfully in {capture_file}")
        return capture_file
    else:
        print(f"[!] Warning: No certificate found in {capture_file}")
        return capture_file

def merge_pcaps():
    """Merge all captured PCAPs with original SIH demo"""
    print("\n" + "="*80)
    print("MERGING ALL PCAPS")
    print("="*80)
    
    # List all capture files
    captures = list(Path('temp_certs').glob('capture_*.pcap'))
    
    if not captures:
        print("[!] No capture files found to merge!")
        return
    
    # Build mergecap command
    capture_files = ' '.join([str(c) for c in captures])
    
    print(f"[*] Found {len(captures)} certificate captures to merge")
    print(f"[*] Merging with original SecureMailScope_SIHDemo.pcap...")
    
    # Merge with original SIH demo
    run_command(
        f'mergecap -w SecureMailScope_SIHDemo_WithCerts.pcap '
        f'SecureMailScope_SIHDemo.pcap {capture_files}'
    )
    
    # Verify merged file
    result = subprocess.run(
        'tshark -r SecureMailScope_SIHDemo_WithCerts.pcap -qz io,stat,0',
        shell=True,
        capture_output=True,
        text=True
    )
    
    print("\n" + "="*80)
    print("MERGE COMPLETE")
    print("="*80)
    print(result.stdout)
    
    # Count certificates in merged file
    cert_count = subprocess.run(
        'tshark -r SecureMailScope_SIHDemo_WithCerts.pcap -Y "tls.handshake.certificate" | find /C "Certificate"',
        shell=True,
        capture_output=True,
        text=True
    )
    
    print(f"\n✓ Created: SecureMailScope_SIHDemo_WithCerts.pcap")
    print(f"✓ Certificate frames: {cert_count.stdout.strip()}")

def main():
    """Main execution flow"""
    print("""
================================================================================
  Certificate Traffic Generator for SecureMailScope SIH Demo
================================================================================
This script will:
1. Generate 4 different vulnerable certificates
2. Capture real TLS handshakes with certificate exchanges
3. Merge captures with original SIH demo PCAP

Requirements:
- OpenSSL installed
- tshark/Wireshark installed
- Administrator/elevated privileges for loopback capture

Expected Results:
- SMS-006: Weak signature algorithms (SHA-1) - TRIGGERED
- SMS-007: Weak key sizes (512-bit, 1024-bit RSA) - TRIGGERED
- SMS-008: Expired certificates - TRIGGERED
- SMS-009: Self-signed certificates - TRIGGERED

================================================================================
""")
    
    # Create temp directory for certificates
    os.makedirs('temp_certs', exist_ok=True)
    
    try:
        # Generate certificates
        scenarios = []
        scenarios.append((generate_weak_1024bit_sha1_cert(), 1))  # SMS-006, SMS-007
        scenarios.append((generate_expired_cert(), 2))            # SMS-008
        scenarios.append((generate_self_signed_cert(), 3))        # SMS-009
        scenarios.append((generate_weak_512bit_cert(), 4))        # SMS-007
        
        # Capture TLS handshakes
        print("\n" + "="*80)
        print("CAPTURING TLS HANDSHAKES")
        print("="*80)
        print("\n⚠️  NOTE: This requires capturing loopback traffic.")
        print("    On Windows: May require Npcap in WinPcap compatibility mode")
        print("    On Linux: May require running with sudo")
        print("")
        
        input("Press ENTER to start capturing (Ctrl+C to cancel)...")
        
        for cert_name, port_offset in scenarios:
            try:
                capture_tls_handshake(cert_name, port_offset)
            except Exception as e:
                print(f"[!] Failed to capture {cert_name}: {e}")
                continue
        
        # Merge all PCAPs
        merge_pcaps()
        
        print("\n" + "="*80)
        print("✓ SUCCESS - Certificate traffic generation complete!")
        print("="*80)
        print("\nNext steps:")
        print("1. Replace SecureMailScope_SIHDemo.pcap with SecureMailScope_SIHDemo_WithCerts.pcap")
        print("2. Test: curl -X POST http://localhost:8001/api/demo/load/sih_comprehensive")
        print("3. Expected: 5+ findings including certificate vulnerabilities")
        print("")
        
    except KeyboardInterrupt:
        print("\n[!] Cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
