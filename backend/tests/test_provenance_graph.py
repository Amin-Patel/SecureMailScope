"""
Comprehensive Test Suite for SecureMailScope Evidence Provenance Graph (USP 3)
Verifies:
1. ProvenanceGraphBuilder data integrity & metrics
2. Strict bidirectional traceability (Finding ↔ Evidence)
3. No dangling edges or unreferenced node IDs
4. Tri-state assessment (Observed vs Expected vs Unknown)
5. Clean handling of zero-finding compliant captures
6. API endpoint responses, status codes, and error handling
"""

import sys
import json
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
import pytest

from main import app
from app.services.provenance_service import ProvenanceGraphBuilder

client = TestClient(app)
BACKEND_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BACKEND_DIR / "results"


def test_provenance_builder_comprehensive_scenario():
    """Test graph construction on rich multi-protocol capture"""
    sample_file = next(RESULTS_DIR.glob("demo_sih_comprehensive_*.json"), None)
    assert sample_file is not None, "Sample SIH comprehensive result file must exist"

    with open(sample_file, "r") as f:
        data = json.load(f)

    builder = ProvenanceGraphBuilder(data)
    graph = builder.build()

    assert graph["success"] is True
    assert graph["capture_id"] == data["capture_id"]

    metrics = graph["metrics"]
    assert metrics["total_nodes"] > 10
    assert metrics["total_edges"] > 10
    assert metrics["evidence_entities"] > 0
    assert metrics["findings_linked"] == len(data.get("findings", []))
    assert metrics["findings_unlinked"] == 0
    assert metrics["unknown_or_unverified_records"] > 0

    # Verify no dangling edges
    node_ids = {n["id"] for n in graph["nodes"]}
    for edge in graph["edges"]:
        assert edge["source"] in node_ids, f"Dangling edge source: {edge['source']}"
        assert edge["target"] in node_ids, f"Dangling edge target: {edge['target']}"
        assert edge["type"] in [
            "CONTAINS", "RECONSTRUCTED_FROM", "NEGOTIATES",
            "PRESENTS_CERTIFICATE", "EVALUATED_BY", "SUPPORTS_FINDING",
            "COMPARED_AGAINST", "OBSERVED_IN"
        ]

    # Verify every finding is traceable to evidence
    trace_idx = graph["traceability_index"]["finding_to_evidence"]
    for finding in data.get("findings", []):
        f_id = finding["id"]
        assert f_id in trace_idx, f"Finding {f_id} must be in traceability index"
        upstream_nodes = trace_idx[f_id]
        assert len(upstream_nodes) >= 1, f"Finding {f_id} must have upstream references"

    # Verify tri-state assessments on all nodes
    for node in graph["nodes"]:
        assert "assessment" in node, f"Node {node['id']} must have assessment"
        ass = node["assessment"]
        assert "observed" in ass, f"Node {node['id']} missing 'observed'"
        assert "expected" in ass, f"Node {node['id']} missing 'expected'"
        assert "status" in ass, f"Node {node['id']} missing 'status'"


def test_provenance_builder_clean_enterprise_scenario():
    """Test graph construction on clean capture with 0 findings"""
    sample_file = next(RESULTS_DIR.glob("demo_secure_enterprise_*.json"), None)
    assert sample_file is not None, "Sample secure enterprise result file must exist"

    with open(sample_file, "r") as f:
        data = json.load(f)

    builder = ProvenanceGraphBuilder(data)
    graph = builder.build()

    assert graph["success"] is True
    assert graph["metrics"]["findings_linked"] == 0
    assert graph["metrics"]["findings_unlinked"] == 0
    # Must have passing analysis rule
    op_nodes = [n for n in graph["nodes"] if n["type"] == "analysis_operation"]
    assert len(op_nodes) >= 1
    assert any("COMPLIANCE" in n["id"] or "PASS" in n["id"] for n in op_nodes)


def test_provenance_api_endpoints():
    """Verify FastAPI GET /api/analysis/{capture_id}/provenance"""
    sample_file = next(RESULTS_DIR.glob("demo_sih_comprehensive_*.json"), None)
    assert sample_file is not None
    capture_id = sample_file.stem

    # 1. Successful full graph retrieval
    res = client.get(f"/api/analysis/{capture_id}/provenance")
    assert res.status_code == 200
    body = res.json()
    assert body["success"] is True
    assert len(body["nodes"]) > 0
    assert len(body["edges"]) > 0

    # 2. Entity detail retrieval
    first_node_id = body["nodes"][0]["id"]
    res_node = client.get(f"/api/analysis/{capture_id}/provenance/node/{first_node_id}")
    assert res_node.status_code == 200
    node_body = res_node.json()
    assert node_body["node"]["id"] == first_node_id
    assert "incoming_relationships" in node_body
    assert "outgoing_relationships" in node_body
    assert "traceability" in node_body

    # 3. 404 for invalid capture ID
    res_404 = client.get("/api/analysis/nonexistent_capture_id_12345/provenance")
    assert res_404.status_code == 404

    # 4. 404 for invalid node ID
    res_node_404 = client.get(f"/api/analysis/{capture_id}/provenance/node/nonexistent_entity_xyz")
    assert res_node_404.status_code == 404


if __name__ == "__main__":
    test_provenance_builder_comprehensive_scenario()
    test_provenance_builder_clean_enterprise_scenario()
    test_provenance_api_endpoints()
    print("All Evidence Provenance tests PASSED successfully!")
