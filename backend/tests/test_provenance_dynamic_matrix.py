"""
Dynamic Evidence Provenance Graph Matrix & Isolation Test Suite (T23 - T30)
Verifies:
- T23: 55% risk demo (vulnerable_smtp) produces correct scoped graph
- T24: Other demo scenarios produce distinct, unique graphs
- T25: Newly analyzed PCAP produces unique capture_id and valid provenance graph
- T26: Dropdown switching retrieves correct isolated data
- T27: Repeated analyses of identical filenames produce distinct distinguishable records
- T28: Invalid analysis IDs return honest HTTP 404
- T29: Cross-analysis contamination and stale data are strictly prevented
- T30: Core regression test (health, results, reports, analyses)
"""

import sys
import json
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)
_base_backend = Path(__file__).resolve().parent.parent
RESULTS_DIR = _base_backend / "results" if (_base_backend / "results").exists() else Path("results")
TEST_DATA_DIR = _base_backend / "test-data" if (_base_backend / "test-data").exists() else Path("test-data")


def test_t23_55_percent_vulnerable_smtp_demo():
    """T23 — Verify existing 55% risk demo opens its own correct graph and metadata"""
    res = client.post("/api/demo/load/vulnerable_smtp")
    assert res.status_code == 200, "Must successfully load vulnerable_smtp demo"
    data = res.json()
    capture_id = data["capture_id"]
    risk = data.get("summary", {}).get("risk_score") or data.get("risk", {}).get("risk_score")
    assert risk == 55, f"Expected risk 55, got {risk}"

    # Fetch provenance graph
    prov_res = client.get(f"/api/analysis/{capture_id}/provenance")
    assert prov_res.status_code == 200
    graph = prov_res.json()
    assert graph["success"] is True
    assert graph["capture_id"] == capture_id
    assert graph["metrics"]["findings_linked"] >= 1
    # Check that plaintext SMTP rule is present
    op_nodes = [n for n in graph["nodes"] if n["type"] == "analysis_operation"]
    assert any("PLAINTEXT" in n["id"] or "STARTTLS" in n["id"] for n in op_nodes)
    print("✓ T23: 55% Risk Vulnerable SMTP Demo verified successfully.")


def test_t24_different_demo_scenarios():
    """T24 — Verify different demos open their own distinct graphs with unique metadata"""
    # 1. Clean Enterprise (0 risk)
    res_clean = client.post("/api/demo/load/secure_enterprise")
    assert res_clean.status_code == 200
    clean_id = res_clean.json()["capture_id"]
    clean_graph = client.get(f"/api/analysis/{clean_id}/provenance").json()
    assert clean_graph["metrics"]["findings_linked"] == 0
    assert any("PASS" in n["id"] or "COMPLIANCE" in n["id"] for n in clean_graph["nodes"])

    # 2. Legacy SSL 3.0 (POODLE)
    res_ssl3 = client.post("/api/demo/load/legacy_ssl3")
    assert res_ssl3.status_code == 200
    ssl3_id = res_ssl3.json()["capture_id"]
    ssl3_graph = client.get(f"/api/analysis/{ssl3_id}/provenance").json()
    assert ssl3_graph["metrics"]["findings_linked"] >= 1
    assert any("SSL" in n["id"] or "POODLE" in n.get("label", "") for n in ssl3_graph["nodes"])

    # 3. SIH Comprehensive (Multi-protocol)
    res_sih = client.post("/api/demo/load/sih_comprehensive")
    assert res_sih.status_code == 200
    sih_id = res_sih.json()["capture_id"]
    sih_graph = client.get(f"/api/analysis/{sih_id}/provenance").json()
    assert sih_graph["metrics"]["total_nodes"] > clean_graph["metrics"]["total_nodes"]
    assert sih_graph["metrics"]["findings_linked"] == 6

    print("✓ T24: Multi-Scenario Demos verified (Clean, SSL 3.0, SIH Comprehensive).")


def test_t25_new_pcap_upload_workflow():
    """T25 — Verify new PCAP upload generates unique ID and dynamic provenance entry"""
    sample_pcap = TEST_DATA_DIR / "secure_mail.pcap"
    assert sample_pcap.exists(), "Test fixture secure_mail.pcap must exist"

    with open(sample_pcap, "rb") as f:
        res = client.post("/api/upload", files={"file": ("uploaded_test_capture.pcap", f, "application/octet-stream")})
    assert res.status_code == 200, f"Upload failed: {res.text}"
    upload_data = res.json()
    new_capture_id = upload_data["capture_id"]

    # Verify provenance graph exists for new capture
    prov_res = client.get(f"/api/analysis/{new_capture_id}/provenance")
    assert prov_res.status_code == 200
    graph = prov_res.json()
    assert graph["capture_id"] == new_capture_id
    assert graph["filename"] == "uploaded_test_capture.pcap"

    # Verify new capture appears at the top of /api/analyses
    analyses_res = client.get("/api/analyses")
    assert analyses_res.status_code == 200
    analyses = analyses_res.json()["analyses"]
    assert any(a["capture_id"] == new_capture_id for a in analyses[:3]), "New analysis must be near top of recent analyses"
    print("✓ T25: New PCAP Upload & Dynamic Provenance Registration verified.")


def test_t26_dropdown_switching_and_retrieval():
    """T26 — Verify rapid dropdown switching returns correct isolated payloads"""
    analyses_res = client.get("/api/analyses")
    analyses = analyses_res.json()["analyses"]
    assert len(analyses) >= 2, "Need at least 2 analyses to test switching"

    first_id = analyses[0]["capture_id"]
    second_id = analyses[1]["capture_id"]

    graph_1 = client.get(f"/api/analysis/{first_id}/provenance").json()
    graph_2 = client.get(f"/api/analysis/{second_id}/provenance").json()

    assert graph_1["capture_id"] == first_id
    assert graph_2["capture_id"] == second_id
    # Nodes must be scoped to their own capture
    assert any(first_id in n["id"] for n in graph_1["nodes"] if n["type"] == "source_artifact")
    assert any(second_id in n["id"] for n in graph_2["nodes"] if n["type"] == "source_artifact")
    print("✓ T26: Dropdown Switching & Strict ID Scoping verified.")


def test_t27_repeated_filename_distinction():
    """T27 — Verify multiple analyses of same file produce distinct, distinguishable records"""
    sample_pcap = TEST_DATA_DIR / "smtp.pcap"
    with open(sample_pcap, "rb") as f:
        res1 = client.post("/api/upload", files={"file": ("repeated_smtp.pcap", f, "application/octet-stream")})
    with open(sample_pcap, "rb") as f:
        res2 = client.post("/api/upload", files={"file": ("repeated_smtp.pcap", f, "application/octet-stream")})

    id1 = res1.json()["capture_id"]
    id2 = res2.json()["capture_id"]
    assert id1 != id2, "Repeated analyses must generate unique capture_ids"

    g1 = client.get(f"/api/analysis/{id1}/provenance").json()
    g2 = client.get(f"/api/analysis/{id2}/provenance").json()
    assert g1["capture_id"] == id1
    assert g2["capture_id"] == id2
    print("✓ T27: Repeated Filename Distinction verified.")


def test_t28_missing_or_invalid_analysis_handling():
    """T28 — Verify missing IDs and invalid entities return HTTP 404 without crashing"""
    # 1. Invalid capture ID
    res_fake = client.get("/api/analysis/nonexistent_fake_capture_99999/provenance")
    assert res_fake.status_code == 404
    assert "not found" in res_fake.json().get("detail", "").lower()

    # 2. Invalid node in valid capture
    valid_id = next(RESULTS_DIR.glob("*.json")).stem
    res_fake_node = client.get(f"/api/analysis/{valid_id}/provenance/node/fake_node_id_xyz")
    assert res_fake_node.status_code == 404
    print("✓ T28: Missing & Invalid Analysis Error Handling verified.")


def test_t29_stale_data_prevention_and_isolation():
    """T29 — Verify strict data isolation (no leakage of nodes/edges across analyses)"""
    # Freshly load SIH comprehensive and Secure Enterprise
    res_sih = client.post("/api/demo/load/sih_comprehensive")
    assert res_sih.status_code == 200
    sih_file = res_sih.json()["capture_id"]

    res_clean = client.post("/api/demo/load/secure_enterprise")
    assert res_clean.status_code == 200
    clean_file = res_clean.json()["capture_id"]

    g_sih = client.get(f"/api/analysis/{sih_file}/provenance").json()
    g_clean = client.get(f"/api/analysis/{clean_file}/provenance").json()

    sih_node_ids = {n["id"] for n in g_sih["nodes"]}
    clean_node_ids = {n["id"] for n in g_clean["nodes"]}

    # SIH nodes should not contain clean capture artifact
    assert f"artifact:{clean_file}" not in sih_node_ids
    assert f"artifact:{sih_file}" not in clean_node_ids
    # Clean capture should have 0 findings
    assert len([n for n in g_clean["nodes"] if n["type"] == "finding"]) == 0
    # SIH capture should have 6 findings
    assert len([n for n in g_sih["nodes"] if n["type"] == "finding"]) == 6
    print("✓ T29: Cross-Analysis Isolation & Stale-Data Prevention verified.")


def test_t30_regression_endpoints():
    """T30 — Verify existing API endpoints remain unbroken"""
    # Health check
    assert client.get("/api/health").status_code == 200
    # Demo presets
    assert client.get("/api/demo/samples").status_code == 200
    # Analyses list
    assert client.get("/api/analyses").status_code == 200

    sample_id = next(RESULTS_DIR.glob("*.json")).stem
    # Analysis results JSON
    assert client.get(f"/api/analysis/{sample_id}/results").status_code == 200
    # Forensic Report HTML
    assert client.get(f"/api/analysis/{sample_id}/report?format=html").status_code == 200
    # Forensic Report JSON
    assert client.get(f"/api/analysis/{sample_id}/report?format=json").status_code == 200
    print("✓ T30: Core Regression Verification (Health, Results, Reports, History) passed.")


if __name__ == "__main__":
    print("\n" + "="*70)
    print("  Executing Provenance Dynamic Matrix & Isolation Test Suite")
    print("="*70 + "\n")
    test_t23_55_percent_vulnerable_smtp_demo()
    test_t24_different_demo_scenarios()
    test_t25_new_pcap_upload_workflow()
    test_t26_dropdown_switching_and_retrieval()
    test_t27_repeated_filename_distinction()
    test_t28_missing_or_invalid_analysis_handling()
    test_t29_stale_data_prevention_and_isolation()
    test_t30_regression_endpoints()
    print("\n" + "="*70)
    print("  ALL TESTS T23 - T30 PASSED WITH 100% SUCCESS!")
    print("="*70 + "\n")
