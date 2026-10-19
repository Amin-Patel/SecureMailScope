"""
SecureMailScope ΓÇö FastAPI Backend
Serves the PCAP analysis pipeline, AI enrichment, demo presets, and forensic reporting.
"""

import os
import sys
import json
import uuid
from pathlib import Path
from datetime import datetime

# Ensure UTF-8 console output on Windows to prevent UnicodeEncodeError
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, Response

# Import analysis pipeline & reporting engine
from app.core.pcap_analyzer import EmailPCAPAnalyzer
from app.services.report_generator import ReportGenerator
from app.services.provenance_service import ProvenanceGraphBuilder
from app.core.crypto_state_engine import CryptographicStateEngine
from app.core.evidence_assessment_engine import EvidenceAssessmentEngine
from app.core.forensics_engine import HistoricalForensicsEngine
from app.core.baseline_drift_engine import BaselineDriftEngine
from app.services.pdf_report_generator import PDFReportGenerator

# Initialize Drift & Baseline Engine
drift_engine = BaselineDriftEngine()

# ΓöÇΓöÇΓöÇ APP SETUP ΓöÇΓöÇΓöÇ
app = FastAPI(
    title="SecureMailScope API",
    description="AI-Driven Email Security Assessment & Forensics",
    version="1.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Open for development & demo environments
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ΓöÇΓöÇΓöÇ DIRECTORIES ΓöÇΓöÇΓöÇ
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads" if (BASE_DIR / "uploads").exists() else Path("uploads")
RESULTS_DIR = BASE_DIR / "results" if (BASE_DIR / "results").exists() else Path("results")
TEST_DATA_DIR = BASE_DIR / "test-data" if (BASE_DIR / "test-data").exists() else Path("test-data")

UPLOAD_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)
TEST_DATA_DIR.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB


# ΓöÇΓöÇΓöÇ 1. HEALTH CHECK ΓöÇΓöÇΓöÇ
@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "SecureMailScope",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }


# ΓöÇΓöÇΓöÇ 2. UPLOAD & ANALYZE ΓöÇΓöÇΓöÇ
@app.post("/api/upload")
async def upload_and_analyze(file: UploadFile = File(...)):
    """Upload a PCAP file and execute the full forensic analysis pipeline."""
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type '{file_ext}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    capture_id = uuid.uuid4().hex[:12]
    safe_filename = f"{capture_id}{file_ext}"
    file_path = UPLOAD_DIR / safe_filename

    try:
        with open(file_path, "wb") as buffer:
            content = await file.read()
            if len(content) > MAX_FILE_SIZE:
                raise HTTPException(status_code=413, detail="File size exceeds 100MB limit.")
            buffer.write(content)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")

    return run_analysis_pipeline(file_path, file.filename, capture_id, len(content))


# ΓöÇΓöÇΓöÇ 3. DEMO SCENARIO PRESETS ΓöÇΓöÇΓöÇ
# ΓöÇΓöÇΓöÇ 3. DEMO SCENARIO PRESETS ΓöÇΓöÇΓöÇ
@app.get("/api/demo/samples")
async def list_demo_samples():
    """List available pre-packaged demo scenarios."""
    samples = [
        {
            "id": "vulnerable_smtp",
            "name": "Vulnerable SMTP Infrastructure",
            "description": "Cleartext port 25 transmission with missing STARTTLS and exposed email payloads.",
            "file": "smtp.pcap",
            "expected_risk": "HIGH / CRITICAL (55/100)"
        },
        {
            "id": "legacy_ssl3",
            "name": "Legacy SSL 3.0 Handshake (POODLE Target)",
            "description": "Outdated cryptographic handshake using deprecated SSL 3.0 protocol.",
            "file": "rsasnakeoil2.cap",
            "expected_risk": "CRITICAL / DEPRECATED"
        },
        {
            "id": "secure_enterprise",
            "name": "Compliant Enterprise Posture (SMTPS + IMAPS)",
            "description": "100% encrypted email transport using modern TLS 1.2/1.3 and AEAD cipher suites.",
            "file": "secure_mail.pcap",
            "expected_risk": "CLEAN / LOW (0/100)"
        },
        {
            "id": "sih_comprehensive",
            "name": "Comprehensive SIH Demo (Multi-Protocol)",
            "description": "Multi-protocol email capture across SMTP, IMAP, and POP3 with TLS 1.2 and plaintext traffic.",
            "file": "SecureMailScope_SIHDemo.pcap",
            "expected_risk": "MEDIUM (37/100)"
        }
    ]
    return JSONResponse(
        content={"samples": samples},
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )


@app.post("/api/demo/load/{sample_id}")
async def load_demo_sample(sample_id: str):
    """Instantly analyze a built-in demo PCAP scenario."""
    sample_map = {
        "vulnerable_smtp": "smtp.pcap",
        "legacy_ssl3": "rsasnakeoil2.cap",
        "secure_enterprise": "secure_mail.pcap",
        "sih_comprehensive": "SecureMailScope_SIHDemo.pcap"
    }

    if sample_id not in sample_map:
        raise HTTPException(status_code=404, detail=f"Unknown demo scenario: {sample_id}")

    filename = sample_map[sample_id]
    file_path = TEST_DATA_DIR / filename

    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Demo PCAP file '{filename}' not found in test-data/ directory."
        )

    capture_id = f"demo_{sample_id}_{uuid.uuid4().hex[:6]}"
    file_size = file_path.stat().st_size

    return run_analysis_pipeline(file_path, filename, capture_id, file_size)


# ΓöÇΓöÇΓöÇ 4. RETRIEVE STORED RESULTS ΓöÇΓöÇΓöÇ
@app.get("/api/analysis/{capture_id}/results")
async def get_results(capture_id: str):
    """Retrieve existing analysis results by capture_id with cryptographic state reasoning."""
    results_file = RESULTS_DIR / f"{capture_id}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {capture_id}")

    with open(results_file, "r") as f:
        data = json.load(f)

    # Ensure cryptographic_state_assessment is populated
    if "cryptographic_state_assessment" not in data or not data["cryptographic_state_assessment"]:
        try:
            engine = CryptographicStateEngine(data)
            assessment = engine.evaluate()
            data["cryptographic_state_assessment"] = assessment
            if "summary" in data and isinstance(data["summary"], dict):
                data["summary"]["cryptographic_state"] = assessment["overall_state"]
                data["summary"]["cryptographic_state_label"] = assessment["overall_state_label"]
            with open(results_file, "w") as f_out:
                json.dump(data, f_out, indent=2, default=str)
        except Exception as e:
            print(f"Error deriving cryptographic state assessment: {e}")

    # Ensure evidence_based_assessment is populated (USP 5)
    if "evidence_based_assessment" not in data or not data["evidence_based_assessment"]:
        try:
            ev_engine = EvidenceAssessmentEngine(data)
            data["evidence_based_assessment"] = ev_engine.evaluate()
            with open(results_file, "w") as f_out:
                json.dump(data, f_out, indent=2, default=str)
        except Exception as e:
            print(f"Error deriving evidence-based assessment: {e}")

    # Ensure forensic_reconstruction is populated (USP 1)
    if "forensic_reconstruction" not in data or not data["forensic_reconstruction"]:
        try:
            f_engine = HistoricalForensicsEngine(data)
            data["forensic_reconstruction"] = f_engine.reconstruct()
            with open(results_file, "w") as f_out:
                json.dump(data, f_out, indent=2, default=str)
        except Exception as e:
            print(f"Error deriving forensic reconstruction: {e}")

    return JSONResponse(content=data)


# ─── 4B. EVIDENCE PROVENANCE GRAPH ───
@app.get("/api/analysis/{capture_id}/provenance")
async def get_provenance_graph(capture_id: str):
    """
    Retrieve the complete Evidence Provenance Graph for a specific analysis.
    Provides full bidirectional traceability from capture artifacts and network packets
    through protocol sessions, handshakes, certificates, and analysis rules to security findings.
    """
    results_file = RESULTS_DIR / f"{capture_id}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {capture_id}")

    try:
        with open(results_file, "r") as f:
            data = json.load(f)
        builder = ProvenanceGraphBuilder(data)
        graph = builder.build()
        return JSONResponse(content=graph)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate provenance graph: {str(e)}")


@app.get("/api/analysis/{capture_id}/provenance/node/{node_id}")
async def get_provenance_node_detail(capture_id: str, node_id: str):
    """
    Retrieve forensic details for a specific provenance entity, including incoming and outgoing
    relationships, upstream evidence, downstream findings, and assessment states.
    """
    results_file = RESULTS_DIR / f"{capture_id}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {capture_id}")

    try:
        with open(results_file, "r") as f:
            data = json.load(f)
        builder = ProvenanceGraphBuilder(data)
        graph = builder.build()

        node = next((n for n in graph["nodes"] if n["id"] == node_id), None)
        if not node:
            raise HTTPException(status_code=404, detail=f"Entity '{node_id}' not found in analysis {capture_id}")

        incoming = [e for e in graph["edges"] if e["target"] == node_id]
        outgoing = [e for e in graph["edges"] if e["source"] == node_id]

        return JSONResponse(content={
            "node": node,
            "incoming_relationships": incoming,
            "outgoing_relationships": outgoing,
            "traceability": {
                "upstream_evidence": graph["traceability_index"]["finding_to_evidence"].get(node_id.replace("finding:", ""), []),
                "downstream_findings": graph["traceability_index"]["evidence_to_findings"].get(node_id, [])
            }
        })
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve entity details: {str(e)}")


# ΓöÇΓöÇΓöÇ 5. FORENSIC REPORT GENERATION ΓöÇΓöÇΓöÇ
@app.get("/api/analysis/{capture_id}/report")
async def get_report(capture_id: str, format: str = Query("html", pattern="^(html|json)$")):
    """Generate and return an official Forensic Assessment Report in HTML or JSON format."""
    results_file = RESULTS_DIR / f"{capture_id}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {capture_id}")

    with open(results_file, "r") as f:
        data = json.load(f)

    if format == "json":
        return JSONResponse(
            content=data,
            headers={"Content-Disposition": f"attachment; filename=SecureMailScope_Report_{capture_id}.json"}
        )
    else:
        html_content = ReportGenerator.generate_html_report(data)
        return HTMLResponse(content=html_content)


# ΓöÇΓöÇΓöÇ 6. LIST ALL COMPLETED ANALYSES ΓöÇΓöÇΓöÇ
@app.get("/api/analyses")
async def list_all_analyses():
    """List summary records of all performed analyses."""
    analyses = []
    for f in RESULTS_DIR.glob("*.json"):
        try:
            with open(f, "r") as file:
                data = json.load(file)
                analyses.append({
                    "capture_id": data.get("capture_id"),
                    "filename": data.get("original_filename") or data.get("filename") or f.name,
                    "risk_score": data.get("summary", {}).get("risk_score"),
                    "risk_level": data.get("summary", {}).get("risk_level"),
                    "timestamp": data.get("upload_timestamp"),
                    "findings_count": len(data.get("findings", []))
                })
        except:
            continue
    # Sort newest first
    analyses.sort(key=lambda x: str(x.get("timestamp") or ""), reverse=True)
    return {"analyses": analyses, "total": len(analyses)}


# ─── 7. DELETE ANALYSES ───
class BatchDeleteRequest(BaseModel):
    capture_ids: List[str]

def _delete_single_analysis(capture_id: str) -> bool:
    deleted = False
    results_file = RESULTS_DIR / f"{capture_id}.json"
    if results_file.exists():
        try:
            results_file.unlink()
            deleted = True
        except Exception as e:
            print(f"Failed to delete {results_file}: {e}")
    for upload_file in UPLOAD_DIR.glob(f"{capture_id}.*"):
        try:
            upload_file.unlink()
        except Exception as e:
            print(f"Failed to delete upload file {upload_file}: {e}")
    return deleted

@app.delete("/api/analysis/{capture_id}")
async def delete_analysis(capture_id: str):
    """Delete a specific completed analysis record and its uploaded files."""
    results_file = RESULTS_DIR / f"{capture_id}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {capture_id}")
    
    _delete_single_analysis(capture_id)
    return {"success": True, "deleted_id": capture_id, "message": "Analysis record deleted successfully."}

@app.post("/api/analyses/delete-batch")
async def delete_analyses_batch(req: BatchDeleteRequest):
    """Selectively delete multiple analysis records in bulk."""
    deleted_ids = []
    for cid in req.capture_ids:
        if _delete_single_analysis(cid):
            deleted_ids.append(cid)
    return {
        "success": True,
        "deleted_count": len(deleted_ids),
        "deleted_ids": deleted_ids,
        "message": f"Successfully deleted {len(deleted_ids)} analysis record(s)."
    }


# ─── 5B. PROFESSIONAL PDF REPORT GENERATION (REPORTS A, B, C) ───
@app.get("/api/analysis/{capture_id}/report/pdf")
async def export_forensic_report_pdf(capture_id: str):
    """
    Export Report A: Professional Historical Cryptographic Forensics PDF Report.
    Generates publication-quality PDF document with formal cover page,
    metadata, timeline, PKI certificates, findings, and ISO/IEC 27037 forensic boundaries.
    """
    results_file = RESULTS_DIR / f"{capture_id}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {capture_id}")

    with open(results_file, "r") as f:
        data = json.load(f)

    forensic_data = data.get("forensic_reconstruction")
    if not forensic_data:
        try:
            forensics_engine = HistoricalForensicsEngine(data)
            forensic_data = forensics_engine.reconstruct()
            data["forensic_reconstruction"] = forensic_data
            with open(results_file, "w") as f_out:
                json.dump(data, f_out, indent=2, default=str)
        except Exception:
            forensic_data = None

    try:
        pdf_bytes = PDFReportGenerator.generate_forensic_report_pdf(data, forensic_data)
        safe_filename = f"SecureMailScope_Forensic_Report_{capture_id}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate forensic PDF report: {str(e)}")


@app.get("/api/drift/comparison/{comparison_id}/report/pdf")
async def export_drift_report_pdf(comparison_id: str):
    """
    Export Report B: Professional Cryptographic Drift & Baseline Comparison PDF Report.
    """
    comp = drift_engine.get_comparison(comparison_id)
    if not comp:
        raise HTTPException(status_code=404, detail=f"Comparison not found: {comparison_id}")

    try:
        pdf_bytes = PDFReportGenerator.generate_drift_report_pdf(comp)
        safe_filename = f"SecureMailScope_Drift_Report_{comparison_id}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate drift PDF report: {str(e)}")


class CombinedReportRequest(BaseModel):
    capture_id: str
    comparison_id: str


@app.post("/api/reports/combined/pdf")
async def export_combined_report_pdf(req: CombinedReportRequest):
    """
    Export Report C: Professional Combined Cryptographic Investigation PDF Report.
    Unifies forensic findings, session timelines, and drift matrix.
    """
    results_file = RESULTS_DIR / f"{req.capture_id}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {req.capture_id}")

    with open(results_file, "r") as f:
        data = json.load(f)

    comp = drift_engine.get_comparison(req.comparison_id)
    if not comp:
        raise HTTPException(status_code=404, detail=f"Comparison not found: {req.comparison_id}")

    # Validate compatibility: check if capture_id matches
    if comp.get("capture_id") and comp.get("capture_id") != req.capture_id:
        raise HTTPException(
            status_code=400,
            detail=f"Incompatible report sources: Comparison {req.comparison_id} was generated for capture {comp.get('capture_id')}, not {req.capture_id}."
        )

    forensic_data = data.get("forensic_reconstruction")
    if not forensic_data:
        try:
            forensics_engine = HistoricalForensicsEngine(data)
            forensic_data = forensics_engine.reconstruct()
        except Exception:
            forensic_data = None

    try:
        pdf_bytes = PDFReportGenerator.generate_combined_report_pdf(data, forensic_data, comp)
        safe_filename = f"SecureMailScope_Combined_Report_{req.capture_id}_{req.comparison_id}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate combined PDF report: {str(e)}")


# ─── 8. USP 1: HISTORICAL CRYPTOGRAPHIC FORENSICS ───
@app.get("/api/analysis/{capture_id}/forensics")
async def get_forensic_timeline(capture_id: str):
    """
    USP 1: Historical Cryptographic Forensics.
    Returns reconstructed chronological event timelines across sessions,
    endpoint correlation, and longitudinal host risk history tracking.
    """
    results_file = RESULTS_DIR / f"{capture_id}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {capture_id}")

    with open(results_file, "r") as f:
        data = json.load(f)

    try:
        engine = HistoricalForensicsEngine(data)
        forensic_summary = engine.reconstruct()
        data["forensic_reconstruction"] = forensic_summary
        with open(results_file, "w") as f_out:
            json.dump(data, f_out, indent=2, default=str)
        return JSONResponse(content=forensic_summary)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reconstruct forensics: {str(e)}")


# ─── 9. USP 6: CRYPTOGRAPHIC DRIFT & BASELINE ANALYSIS ───
class CreateBaselineRequest(BaseModel):
    capture_id: str
    name: str
    description: Optional[str] = ""
    target_endpoint: Optional[str] = None


class DriftCompareRequest(BaseModel):
    capture_id: str
    baseline_id: str
    target_endpoint: Optional[str] = None


@app.get("/api/baselines")
async def list_baselines():
    """List all available baselines (pre-seeded standards and custom captured baselines)."""
    try:
        baselines = drift_engine.list_baselines()
        return JSONResponse(content={"baselines": baselines, "total": len(baselines)})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list baselines: {str(e)}")


@app.post("/api/baselines")
async def create_baseline(req: CreateBaselineRequest):
    """Create an empirical baseline from a completed capture analysis."""
    results_file = RESULTS_DIR / f"{req.capture_id}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {req.capture_id}")

    with open(results_file, "r") as f:
        data = json.load(f)

    try:
        baseline = drift_engine.create_baseline_from_analysis(
            analysis_data=data,
            name=req.name,
            description=req.description or "",
            target_endpoint=req.target_endpoint
        )
        return JSONResponse(content=baseline)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create baseline: {str(e)}")


@app.get("/api/baselines/{baseline_id}")
async def get_baseline(baseline_id: str):
    """Retrieve full details of a specific baseline."""
    b = drift_engine.get_baseline(baseline_id)
    if not b:
        raise HTTPException(status_code=404, detail=f"Baseline not found: {baseline_id}")
    return JSONResponse(content=b)


@app.delete("/api/baselines/{baseline_id}")
async def delete_baseline(baseline_id: str):
    """Delete a custom baseline."""
    success = drift_engine.delete_baseline(baseline_id)
    if not success:
        raise HTTPException(status_code=400, detail="Cannot delete baseline (protected default or not found).")
    return {"success": True, "deleted_id": baseline_id}


@app.post("/api/drift/compare")
async def compare_drift(req: DriftCompareRequest):
    """
    USP 6: Compare an analyzed capture against a baseline.
    Computes property-by-property diffs, evaluates security significance,
    and records to comparison history.
    """
    results_file = RESULTS_DIR / f"{req.capture_id}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {req.capture_id}")

    with open(results_file, "r") as f:
        data = json.load(f)

    try:
        comp_record = drift_engine.compare_analysis_against_baseline(
            analysis_data=data,
            baseline_id=req.baseline_id,
            target_endpoint=req.target_endpoint
        )
        return JSONResponse(content=comp_record)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Drift comparison failed: {str(e)}")


@app.get("/api/drift/history")
async def get_drift_history(capture_id: Optional[str] = None):
    """Retrieve historical drift comparison runs."""
    try:
        history = drift_engine.list_comparisons(capture_id=capture_id)
        return JSONResponse(content={"comparisons": history, "total": len(history)})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve drift history: {str(e)}")


@app.get("/api/drift/comparison/{comparison_id}")
async def get_comparison_detail(comparison_id: str):
    """Retrieve a specific completed drift comparison report."""
    comp = drift_engine.get_comparison(comparison_id)
    if not comp:
        raise HTTPException(status_code=404, detail=f"Comparison not found: {comparison_id}")
    return JSONResponse(content=comp)


# ΓöÇΓöÇΓöÇ HELPER PIPELINE FUNCTION ΓöÇΓöÇΓöÇ
def run_analysis_pipeline(file_path: Path, original_filename: str, capture_id: str, file_size: int):
    """Executes the PCAP analyzer, saves the payload, and returns JSON."""
    try:
        analyzer = EmailPCAPAnalyzer(str(file_path))
        result = analyzer.analyze()

        if not result.get("success"):
            raise HTTPException(status_code=500, detail=f"Analysis failed: {result.get('error')}")

        result["capture_id"] = capture_id
        result["upload_timestamp"] = datetime.now().isoformat()
        result["original_filename"] = original_filename
        result["file_size"] = file_size
        result["status"] = "completed"

        # Automatically compute forensic reconstruction (USP 1)
        try:
            f_engine = HistoricalForensicsEngine(result)
            result["forensic_reconstruction"] = f_engine.reconstruct()
        except Exception as fe:
            print(f"Forensics engine warning: {fe}")

        # Save to cache
        results_file = RESULTS_DIR / f"{capture_id}.json"
        with open(results_file, "w") as f:
            json.dump(result, f, indent=2, default=str)

        return JSONResponse(content=result)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*50)
    print("  SecureMailScope API Server")
    print("  http://localhost:8001")
    print("  Docs: http://localhost:8001/docs")
    print("="*50 + "\n")
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
