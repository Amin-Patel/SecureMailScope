"""
End-to-End Test Suite for SecureMailScope
Verifies API stability, security detection rules, and edge-case handling.
"""

import requests
import sys

BASE_URL = "http://localhost:8001/api"

def print_test(name, passed, details=""):
    badge = "✅ PASS" if passed else "❌ FAIL"
    print(f"{badge} | {name:<50} {details}")

def run_tests():
    print("\n" + "="*70)
    print("  SecureMailScope End-to-End System & Stress Test Suite")
    print("="*70 + "\n")

    passed_count = 0
    total_tests = 0

    # ─── TEST 1: Health Check ───
    total_tests += 1
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        passed = (r.status_code == 200 and r.json().get("status") == "healthy")
        print_test("Health Check Endpoint", passed, f"HTTP {r.status_code}")
        if passed: passed_count += 1
    except Exception as e:
        print_test("Health Check Endpoint", False, str(e))

    # ─── TEST 2: Demo Presets List ───
    total_tests += 1
    try:
        r = requests.get(f"{BASE_URL}/demo/samples", timeout=5)
        samples = r.json().get("samples", [])
        passed = (r.status_code == 200 and len(samples) >= 3)
        print_test("List 3 Demo Presets", passed, f"{len(samples)} Presets Found")
        if passed: passed_count += 1
    except Exception as e:
        print_test("List 3 Demo Presets", False, str(e))

    # ─── TEST 3: Vulnerable SMTP Scenario (Red Test) ───
    total_tests += 1
    try:
        r = requests.post(f"{BASE_URL}/demo/load/vulnerable_smtp", timeout=10)
        data = r.json()
        findings = data.get("findings", [])
        risk = data.get("risk", {}).get("risk_score", 0)
        has_plaintext = any(f.get("type") == "plaintext_protocol" for f in findings)
        passed = (r.status_code == 200 and has_plaintext and risk >= 50)
        print_test("Red Scenario (Plaintext SMTP Detection)", passed, f"Score: {risk}/100, Findings: {len(findings)}")
        if passed: passed_count += 1
    except Exception as e:
        print_test("Red Scenario (Plaintext SMTP Detection)", False, str(e))

    # ─── TEST 4: Deprecated SSL 3.0 Scenario (Yellow Test) ───
    total_tests += 1
    try:
        r = requests.post(f"{BASE_URL}/demo/load/legacy_ssl3", timeout=10)
        data = r.json()
        findings = data.get("findings", [])
        has_ssl3 = any("SSL 3.0" in f.get("title", "") for f in findings)
        passed = (r.status_code == 200 and has_ssl3)
        print_test("Yellow Scenario (SSL 3.0 POODLE Detection)", passed, f"Found {len(findings)} issues")
        if passed: passed_count += 1
    except Exception as e:
        print_test("Yellow Scenario (SSL 3.0 POODLE Detection)", False, str(e))

    # ─── TEST 5: Compliant Secure Scenario (Green Test) ───
    total_tests += 1
    try:
        r = requests.post(f"{BASE_URL}/demo/load/secure_enterprise", timeout=10)
        data = r.json()
        findings = data.get("findings", [])
        risk = data.get("risk", {}).get("risk_score", 0)
        ratio = data.get("summary", {}).get("encryption_ratio", 0)
        passed = (r.status_code == 200 and len(findings) == 0 and ratio == 1.0)
        print_test("Green Scenario (100% Encrypted Baseline)", passed, f"Score: {risk}/100, Encrypted: {ratio*100}%")
        if passed: passed_count += 1
    except Exception as e:
        print_test("Green Scenario (100% Encrypted Baseline)", False, str(e))

    # ─── TEST 6: HTML Report Endpoint ───
    total_tests += 1
    try:
        r_load = requests.post(f"{BASE_URL}/demo/load/vulnerable_smtp", timeout=10)
        cid = r_load.json().get("capture_id")
        r = requests.get(f"{BASE_URL}/analysis/{cid}/report?format=html", timeout=5)
        passed = (r.status_code == 200 and "<!DOCTYPE html>" in r.text and "SecureMailScope" in r.text)
        print_test("Forensic HTML Report Generation", passed, f"HTML Size: {len(r.text)} bytes")
        if passed: passed_count += 1
    except Exception as e:
        print_test("Forensic HTML Report Generation", False, str(e))

    # ─── TEST 7: Edge Case - Invalid File Extension ───
    total_tests += 1
    try:
        files = {'file': ('test.exe', b'fake binary executable content', 'application/octet-stream')}
        r = requests.post(f"{BASE_URL}/upload", files=files, timeout=5)
        passed = (r.status_code == 400 and "Invalid file type" in r.json().get("detail", ""))
        print_test("Edge Case: Reject Non-PCAP File Extension", passed, f"Status: {r.status_code}")
        if passed: passed_count += 1
    except Exception as e:
        print_test("Edge Case: Reject Non-PCAP File Extension", False, str(e))

    # ─── TEST 8: Edge Case - Missing Analysis ID ───
    total_tests += 1
    try:
        r = requests.get(f"{BASE_URL}/analysis/invalid_id_99999/results", timeout=5)
        passed = (r.status_code == 404)
        print_test("Edge Case: 404 on Missing Analysis ID", passed, f"Status: {r.status_code}")
        if passed: passed_count += 1
    except Exception as e:
        print_test("Edge Case: 404 on Missing Analysis ID", False, str(e))

    print("\n" + "="*70)
    print(f"  TEST RESULTS: {passed_count}/{total_tests} PASSED ({(passed_count/total_tests)*100:.1f}%)")
    print("="*70 + "\n")

    if passed_count == total_tests:
        print("🎯 SYSTEM STATUS: PRODUCTION & DEMO READY (0 Failures)\n")
    else:
        print("⚠️ SOME TESTS FAILED. Review output above.\n")

if __name__ == "__main__":
    run_tests()