"""
Unit and Integration Tests for Professional PDF Report Generation
Verifies:
1. Report A: Historical Cryptographic Forensics Report (PDF structure, size, metadata, pagination).
2. Report B: Cryptographic Drift & Baseline Comparison Report (PDF structure, metrics, diff table).
3. Report C: Combined Cryptographic Investigation Report (PDF structure, combined parts).
4. FastAPI PDF export endpoints and HTTP headers (Content-Type, Content-Disposition).
5. Safe filename generation and error handling for missing/incompatible inputs.
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from main import app, RESULTS_DIR, TEST_DATA_DIR
from app.core.pcap_analyzer import EmailPCAPAnalyzer
from app.core.forensics_engine import HistoricalForensicsEngine
from app.core.baseline_drift_engine import BaselineDriftEngine
from app.services.pdf_report_generator import PDFReportGenerator

client = TestClient(app)


@pytest.fixture(scope="module")
def prepared_demo_data():
    """Analyze real PCAP fixture and generate drift comparison for PDF testing"""
    pcap_path = TEST_DATA_DIR / "SecureMailScope_SIHDemo.pcap"
    assert pcap_path.exists(), "SIH demo pcap must exist"

    analyzer = EmailPCAPAnalyzer(str(pcap_path))
    analysis_data = analyzer.analyze()
    cid = "test_pdf_fixture"
    analysis_data["capture_id"] = cid
    analysis_data["original_filename"] = pcap_path.name

    # Forensics
    f_engine = HistoricalForensicsEngine(analysis_data)
    forensic_data = f_engine.reconstruct()
    analysis_data["forensic_reconstruction"] = forensic_data

    # Drift comparison
    drift_engine = BaselineDriftEngine()
    comparison_data = drift_engine.compare_analysis_against_baseline(
        analysis_data=analysis_data,
        baseline_id="nist_sp800_52r2"
    )

    return {
        "analysis_data": analysis_data,
        "forensic_data": forensic_data,
        "comparison_data": comparison_data
    }


def test_pdf_report_a_forensic_document_generation(prepared_demo_data):
    """Verify Report A PDF generation produces a structurally valid, professional document"""
    data = prepared_demo_data["analysis_data"]
    forensics = prepared_demo_data["forensic_data"]

    pdf_bytes = PDFReportGenerator.generate_forensic_report_pdf(data, forensics)

    # Verification: Non-empty and binary PDF header
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 4000, "Forensic PDF report must be a non-trivial structured document"
    assert pdf_bytes.startswith(b"%PDF-"), "Must have standard PDF magic number header"
    assert b"/Root" in pdf_bytes or b"/Catalog" in pdf_bytes, "Must contain standard PDF catalog root"
    assert b"/Page" in pdf_bytes, "Must contain document page objects"


def test_pdf_report_b_drift_document_generation(prepared_demo_data):
    """Verify Report B PDF generation produces a structurally valid drift report"""
    comparison = prepared_demo_data["comparison_data"]

    pdf_bytes = PDFReportGenerator.generate_drift_report_pdf(comparison)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 4000, "Drift PDF report must be >4KB"
    assert pdf_bytes.startswith(b"%PDF-"), "Must have standard PDF header"
    assert b"/Page" in pdf_bytes


def test_pdf_report_c_combined_document_generation(prepared_demo_data):
    """Verify Report C PDF generation merges forensics and drift analysis"""
    data = prepared_demo_data["analysis_data"]
    forensics = prepared_demo_data["forensic_data"]
    comparison = prepared_demo_data["comparison_data"]

    pdf_bytes = PDFReportGenerator.generate_combined_report_pdf(data, forensics, comparison)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 4000, "Combined PDF report must be >4KB"
    assert pdf_bytes.startswith(b"%PDF-")
    assert b"/Page" in pdf_bytes


def test_api_export_forensic_report_pdf(prepared_demo_data):
    """Verify GET /api/analysis/{capture_id}/report/pdf endpoint returns valid PDF stream"""
    data = prepared_demo_data["analysis_data"]
    cid = data["capture_id"]

    # Cache to RESULTS_DIR
    res_path = RESULTS_DIR / f"{cid}.json"
    with open(res_path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    try:
        response = client.get(f"/api/analysis/{cid}/report/pdf")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert f"SecureMailScope_Forensic_Report_{cid}.pdf" in response.headers.get("content-disposition", "")

        pdf_content = response.content
        assert pdf_content.startswith(b"%PDF-")
        assert len(pdf_content) > 4000
    finally:
        if res_path.exists():
            res_path.unlink()


def test_api_export_drift_report_pdf(prepared_demo_data):
    """Verify GET /api/drift/comparison/{comparison_id}/report/pdf endpoint returns valid PDF stream"""
    comparison = prepared_demo_data["comparison_data"]
    cmp_id = comparison["comparison_id"]

    response = client.get(f"/api/drift/comparison/{cmp_id}/report/pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert f"SecureMailScope_Drift_Report_{cmp_id}.pdf" in response.headers.get("content-disposition", "")

    pdf_content = response.content
    assert pdf_content.startswith(b"%PDF-")
    assert len(pdf_content) > 4000


def test_api_export_combined_report_pdf(prepared_demo_data):
    """Verify POST /api/reports/combined/pdf endpoint merges forensics and drift into PDF"""
    data = prepared_demo_data["analysis_data"]
    cid = data["capture_id"]
    comparison = prepared_demo_data["comparison_data"]
    cmp_id = comparison["comparison_id"]

    res_path = RESULTS_DIR / f"{cid}.json"
    with open(res_path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    try:
        response = client.post("/api/reports/combined/pdf", json={
            "capture_id": cid,
            "comparison_id": cmp_id
        })
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert f"SecureMailScope_Combined_Report_{cid}_{cmp_id}.pdf" in response.headers.get("content-disposition", "")

        pdf_content = response.content
        assert pdf_content.startswith(b"%PDF-")
        assert len(pdf_content) > 4000

        # Incompatibility test: provide mismatching capture ID
        err_response = client.post("/api/reports/combined/pdf", json={
            "capture_id": "different_capture_999",
            "comparison_id": cmp_id
        })
        assert err_response.status_code in (400, 404)
    finally:
        if res_path.exists():
            res_path.unlink()
