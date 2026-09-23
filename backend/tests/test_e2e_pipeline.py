"""
End-to-End Test Suite for SecureMailScope
Verifies API stability, security detection rules, and edge-case handling.
"""

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health_check_endpoint():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json().get("status") == "healthy"

def test_demo_presets_list():
    r = client.get("/api/demo/samples")
    assert r.status_code == 200
    assert len(r.json().get("samples", [])) >= 3

def test_vulnerable_smtp_scenario():
    r = client.post("/api/demo/load/vulnerable_smtp")
    assert r.status_code == 200
    data = r.json()
    assert any(f.get("type") == "plaintext_protocol" for f in data.get("findings", []))
    assert data.get("risk", {}).get("risk_score", 0) >= 50

def test_deprecated_ssl3_scenario():
    r = client.post("/api/demo/load/legacy_ssl3")
    assert r.status_code == 200
    data = r.json()
    assert any("SSL 3.0" in f.get("title", "") for f in data.get("findings", []))

def test_compliant_secure_scenario():
    r = client.post("/api/demo/load/secure_enterprise")
    assert r.status_code == 200
    data = r.json()
    assert len(data.get("findings", [])) == 0
    assert data.get("summary", {}).get("encryption_ratio", 0) == 1.0

def test_forensic_html_report_generation():
    r_load = client.post("/api/demo/load/vulnerable_smtp")
    cid = r_load.json().get("capture_id")
    r = client.get(f"/api/analysis/{cid}/report?format=html")
    assert r.status_code == 200
    assert "<!DOCTYPE html>" in r.text
    assert "SecureMailScope" in r.text

def test_edge_case_reject_invalid_file_extension():
    files = {'file': ('test.exe', b'fake binary executable content', 'application/octet-stream')}
    r = client.post("/api/upload", files=files)
    assert r.status_code in [400, 401]

def test_edge_case_missing_analysis_id():
    r = client.get("/api/analysis/invalid_id_99999/results")
    assert r.status_code in [401, 404]