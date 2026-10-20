"""
SecureMailScope — FastAPI Backend
Serves the PCAP analysis pipeline, AI enrichment, demo presets, forensic reporting,
and full Six-USP cryptographic intelligence suite.
Secured with Supabase JWT Authentication, User Ownership & IDOR Protection,
Path Traversal Prevention, Upload Validation, and Credential Redaction.
"""

import os
import json
import sys
import uuid
import re
import shutil
from contextlib import asynccontextmanager
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from fastapi import FastAPI, UploadFile, File, HTTPException, Query, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, Response

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    HAS_SLOWAPI = True
except ImportError:
    HAS_SLOWAPI = False
    class Limiter:
        def __init__(self, *args, **kwargs):
            pass
        def limit(self, *args, **kwargs):
            def decorator(func):
                return func
            return decorator
        def reset(self):
            pass
    def get_remote_address(request=None):
        return "127.0.0.1"
    class RateLimitExceeded(Exception):
        pass
    def _rate_limit_exceeded_handler(request, exc):
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})

# Ensure UTF-8 console output on Windows to prevent UnicodeEncodeError
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Import analysis pipeline & reporting engine
from app.core.pcap_analyzer import EmailPCAPAnalyzer
from app.core.crypto_state_engine import CryptographicStateEngine
from app.core.evidence_assessment_engine import EvidenceAssessmentEngine
from app.core.forensics_engine import HistoricalForensicsEngine
from app.core.baseline_drift_engine import CryptographicDriftEngine, get_drift_engine
from app.services.provenance_service import ProvenanceGraphBuilder
from app.services.report_generator import ReportGenerator
from app.services.pdf_report_generator import PDFReportGenerator
from app.core.auth import get_current_user, get_optional_user, require_admin_role
from app.services.knowledge_base import get_knowledge_base
from app.services import knowledge_ingestion
from app.services.pcap_watcher import PcapWatcher
from app.services import email_auth_checker

# ─── RATE LIMITER SETUP ───
limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])

# ─── DRIFT ENGINE SETUP (USP 6) ───
drift_engine = get_drift_engine()

# ─── LIFESPAN ───
watcher: "PcapWatcher | None" = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Start the folder watcher only when WATCH_DIR is set (opt-in)."""
    global watcher
    watch_dir = os.getenv("WATCH_DIR", "").strip()
    if watch_dir:
        watcher = PcapWatcher(
            Path(watch_dir),
            analyze_watched_file,
            poll_seconds=float(os.getenv("WATCH_POLL_SECONDS", "5")),
        )
        watcher.start()
    yield
    if watcher:
        watcher.stop()


app = FastAPI(
    lifespan=lifespan,
    title="SecureMailScope API",
    description="AI-Driven Email Security Assessment, Multi-Tier PKI Audit & Cryptographic State Reasoning",
    version="1.0.0"
)
app.state.limiter = limiter
if HAS_SLOWAPI:
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS Configuration — restrict origins in production via ALLOWED_ORIGINS env var
_raw_origins = os.getenv("ALLOWED_ORIGINS", "https://mailscope.dpdns.org,http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000").strip()
CORS_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Requested-With"],
)

# ─── DIRECTORIES ───
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
RESULTS_DIR = BASE_DIR / "results"
TEST_DATA_DIR = BASE_DIR / "test-data"

UPLOAD_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)
TEST_DATA_DIR.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

# PCAP & PCAPNG Magic Numbers
PCAP_MAGIC_NUMBERS = [
    b"\xa1\xb2\xc3\xd4",  # Standard pcap (microsecond)
    b"\xd4\xc3\xb2\xa1",  # Standard pcap (swapped)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond pcap
    b"\x4d\x3c\xb2\xa1",  # Nanosecond pcap (swapped)
    b"\x0a\x0d\x0d\x0a",  # PCAPNG format
]

CAPTURE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]+$")


def sanitize_capture_id(capture_id: str) -> str:
    """Validates capture ID to prevent directory traversal attacks."""
    if not capture_id or not CAPTURE_ID_REGEX.match(capture_id) or ".." in capture_id or "/" in capture_id or "\\" in capture_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid capture ID format."
        )
    return capture_id


def verify_pcap_magic_bytes(header: bytes) -> bool:
    """Check if header contains a recognized PCAP or PCAPNG magic number."""
    if len(header) < 4:
        return False
    return any(header.startswith(magic) for magic in PCAP_MAGIC_NUMBERS)


def check_resource_ownership(data: Dict[str, Any], user: Optional[Dict[str, Any]], allow_public_demo: bool = True):
    """
    Strictly verifies resource ownership.
    - If capture is a demo (`demo_*` or owner_user_id in ['system_demo', 'demo', 'anonymous', None, '']), allow access if allow_public_demo is True.
    - Otherwise, requires valid user whose `user_id` matches `owner_user_id`.
    """
    owner_id = data.get("owner_user_id")
    cid = str(data.get("capture_id", ""))
    is_demo = owner_id in ["system_demo", "demo", "anonymous", None, ""] or cid.startswith("demo_")
    if owner_id and owner_id not in ["system_demo", "demo", "anonymous"] and not cid.startswith("demo_"):
        is_demo = False

    if is_demo and allow_public_demo:
        return

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to access this analysis resource."
        )

    if owner_id != user.get("user_id"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not own this analysis record."
        )


# ─── 1. HEALTH CHECK ───
@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "SecureMailScope",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }


# ─── 2. UPLOAD & ANALYZE ───
@app.post("/api/upload")
@limiter.limit("20/minute")
async def upload_and_analyze(
    request: Request,
    file: UploadFile = File(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Upload a PCAP file and execute the full forensic analysis pipeline for the authenticated user."""
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file type '{file_ext}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    capture_id = uuid.uuid4().hex[:12]
    safe_filename = f"{capture_id}{file_ext}"
    file_path = UPLOAD_DIR / safe_filename

    try:
        content = await file.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File size exceeds 100MB limit.")
        
        # Verify PCAP magic bytes
        if not verify_pcap_magic_bytes(content[:4]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File content header does not match valid PCAP or PCAPNG magic numbers."
            )

        with open(file_path, "wb") as f:
            f.write(content)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")

    user_id = current_user.get("user_id")
    return run_analysis_pipeline(file_path, file.filename, capture_id, len(content), owner_user_id=user_id)


# ─── 3. DEMO SCENARIO PRESETS ───
@app.get("/api/demo/samples")
@limiter.limit("60/minute")
async def list_demo_samples(request: Request):
    """List available pre-packaged demo scenarios covering all test profiles."""
    samples = [
        {
            "id": "vulnerable_smtp",
            "name": "Vulnerable SMTP Infrastructure",
            "description": "Cleartext port 25 transmission with missing STARTTLS and exposed email payloads.",
            "file": "smtp.pcap",
            "expected_risk": "HIGH (57/100, grade E)"
        },
        {
            "id": "legacy_ssl3",
            "name": "Legacy SSL 3.0 Handshake (POODLE Target)",
            "description": "Outdated cryptographic handshake using deprecated SSL 3.0 protocol.",
            "file": "rsasnakeoil2.cap",
            "expected_risk": "CRITICAL (80/100, grade F)"
        },
        {
            "id": "secure_enterprise",
            "name": "Compliant Enterprise Posture (SMTPS + IMAPS)",
            "description": "100% encrypted email transport using modern TLS 1.2/1.3 and AEAD cipher suites.",
            "file": "secure_mail.pcap",
            "expected_risk": "LOW (0/100, grade A)"
        },
        {
            "id": "sih_comprehensive",
            "name": "Comprehensive SIH Demo (Multi-Protocol)",
            "description": "Multi-protocol email capture across SMTP, SMTP-Submission, SMTP-Alt, POP3 and IMAP, mixing SSL 3.0 and TLS 1.2 handshakes with cleartext traffic and four X.509 certificates.",
            "file": "SecureMailScope_SIHDemo.pcap",
            "expected_risk": "CRITICAL (100/100, grade F)"
        }
    ]
    return {"samples": samples}


@app.post("/api/demo/load/{sample_id}")
@limiter.limit("20/minute")
async def load_demo_sample(
    request: Request,
    sample_id: str,
    optional_user: Optional[Dict[str, Any]] = Depends(get_optional_user)
):
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
    owner_id = optional_user.get("user_id") if optional_user else "system_demo"

    return run_analysis_pipeline(file_path, filename, capture_id, file_size, owner_user_id=owner_id)


# ─── 4. RETRIEVE STORED RESULTS ───
@app.get("/api/analysis/{capture_id}/results")
@limiter.limit("100/minute")
async def get_results(
    request: Request,
    capture_id: str,
    optional_user: Optional[Dict[str, Any]] = Depends(get_optional_user)
):
    """Retrieve existing analysis results by capture_id with strict ownership checks."""
    cid = sanitize_capture_id(capture_id)
    results_file = RESULTS_DIR / f"{cid}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {cid}")

    with open(results_file, "r") as f:
        data = json.load(f)

    check_resource_ownership(data, optional_user, allow_public_demo=True)

    # Back-fill assessments for historical results stored before engines were run
    if not data.get("cryptographic_state_assessment") or not data.get("evidence_based_assessment"):
        attach_assessments(data)

    return JSONResponse(content=data)


# ─── 4B. EVIDENCE PROVENANCE GRAPH (USP 3) ───
def _load_owned_result(capture_id: str, user: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Resolve a capture_id to its stored result, enforcing path-traversal
    sanitisation and ownership checks."""
    cid = sanitize_capture_id(capture_id)
    results_file = RESULTS_DIR / f"{cid}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {cid}")
    with open(results_file, "r") as f:
        data = json.load(f)
    check_resource_ownership(data, user, allow_public_demo=True)
    return data


@app.get("/api/analysis/{capture_id}/provenance")
@limiter.limit("60/minute")
async def get_provenance_graph(
    request: Request,
    capture_id: str,
    optional_user: Optional[Dict[str, Any]] = Depends(get_optional_user)
):
    """Evidence Provenance Graph (USP 3): bidirectional traceability from the capture
    artifact and packets, through sessions, handshakes, certificates and analysis
    rules, to the security findings."""
    data = _load_owned_result(capture_id, optional_user)
    try:
        return JSONResponse(content=ProvenanceGraphBuilder(data).build())
    except Exception as e:
        print(f"[!] Provenance graph build failed for {capture_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate provenance graph.")


@app.get("/api/analysis/{capture_id}/provenance/node/{node_id}")
@limiter.limit("120/minute")
async def get_provenance_node_detail(
    request: Request,
    capture_id: str,
    node_id: str,
    optional_user: Optional[Dict[str, Any]] = Depends(get_optional_user)
):
    """Forensic detail for one provenance entity: its incoming and outgoing
    relationships, upstream evidence and downstream findings."""
    data = _load_owned_result(capture_id, optional_user)
    try:
        graph = ProvenanceGraphBuilder(data).build()
    except Exception as e:
        print(f"[!] Provenance graph build failed for {capture_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve entity details.")

    node = next((n for n in graph["nodes"] if n["id"] == node_id), None)
    if not node:
        raise HTTPException(status_code=404, detail="Entity not found in this analysis.")

    index = graph.get("traceability_index", {})
    return JSONResponse(content={
        "node": node,
        "incoming_relationships": [e for e in graph["edges"] if e["target"] == node_id],
        "outgoing_relationships": [e for e in graph["edges"] if e["source"] == node_id],
        "traceability": {
            "upstream_evidence": index.get("finding_to_evidence", {}).get(
                node_id.replace("finding:", ""), []
            ),
            "downstream_findings": index.get("evidence_to_findings", {}).get(node_id, []),
        },
    })


# ─── 5. FORENSIC REPORT GENERATION (HTML & XHTML2PDF) ───
@app.get("/api/analysis/{capture_id}/report")
@limiter.limit("60/minute")
async def get_report(
    request: Request,
    capture_id: str,
    format: str = Query("html", pattern="^(html|json|pdf)$"),
    optional_user: Optional[Dict[str, Any]] = Depends(get_optional_user)
):
    """Generate and return an official Forensic Assessment Report in HTML, JSON, or PDF format."""
    cid = sanitize_capture_id(capture_id)
    results_file = RESULTS_DIR / f"{cid}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {cid}")

    with open(results_file, "r") as f:
        data = json.load(f)

    check_resource_ownership(data, optional_user, allow_public_demo=True)

    if format == "json":
        return JSONResponse(
            content=data,
            headers={"Content-Disposition": f"attachment; filename=SecureMailScope_Report_{cid}.json"}
        )
    elif format == "pdf":
        try:
            pdf_bytes = ReportGenerator.generate_pdf_report(data)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=SecureMailScope_Report_{capture_id}.pdf"}
        )
    else:
        html_content = ReportGenerator.generate_html_report(data)
        return HTMLResponse(content=html_content)


# ─── 5B. PROFESSIONAL REPORTLAB PDF EXPORTS (REPORTS A, B, C) ───
@app.get("/api/analysis/{capture_id}/report/pdf")
async def export_forensic_report_pdf(
    capture_id: str,
    optional_user: Optional[Dict[str, Any]] = Depends(get_optional_user)
):
    """
    Export Report A: Professional Historical Cryptographic Forensics PDF Report.
    Generates publication-quality PDF document with formal cover page,
    metadata, timeline, PKI certificates, findings, and ISO/IEC 27037 forensic boundaries.
    """
    cid = sanitize_capture_id(capture_id)
    results_file = RESULTS_DIR / f"{cid}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {cid}")

    with open(results_file, "r") as f:
        data = json.load(f)

    check_resource_ownership(data, optional_user, allow_public_demo=True)

    forensic_data = data.get("forensic_reconstruction")
    if not forensic_data:
        try:
            forensics_engine = HistoricalForensicsEngine(data)
            forensic_data = forensics_engine.reconstruct()
            data["forensic_reconstruction"] = forensic_data
        except Exception:
            forensic_data = None

    try:
        pdf_bytes = PDFReportGenerator.generate_forensic_report_pdf(data, forensic_data)
        safe_filename = f"SecureMailScope_Forensic_Report_{cid}.pdf"
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
async def export_combined_report_pdf(
    req: CombinedReportRequest,
    optional_user: Optional[Dict[str, Any]] = Depends(get_optional_user)
):
    """
    Export Report C: Professional Combined Cryptographic Investigation PDF Report.
    Unifies forensic findings, session timelines, and drift matrix.
    """
    cid = sanitize_capture_id(req.capture_id)
    results_file = RESULTS_DIR / f"{cid}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {cid}")

    with open(results_file, "r") as f:
        data = json.load(f)

    check_resource_ownership(data, optional_user, allow_public_demo=True)

    comp = drift_engine.get_comparison(req.comparison_id)
    if not comp:
        raise HTTPException(status_code=404, detail=f"Comparison not found: {req.comparison_id}")

    if comp.get("capture_id") and comp.get("capture_id") != cid:
        raise HTTPException(
            status_code=400,
            detail=f"Incompatible report sources: Comparison {req.comparison_id} was generated for capture {comp.get('capture_id')}, not {cid}."
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
        safe_filename = f"SecureMailScope_Combined_Report_{cid}_{req.comparison_id}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{safe_filename}"'}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate combined PDF report: {str(e)}")


# ─── 6. LIST USER ANALYSES ───
@app.get("/api/analyses")
@limiter.limit("60/minute")
async def list_user_analyses(
    request: Request,
    optional_user: Optional[Dict[str, Any]] = Depends(get_optional_user)
):
    """List summary records of analyses. If authenticated, returns user-owned records; if demo, returns demo records."""
    user_id = optional_user.get("user_id") if optional_user else None
    analyses = []
    for f in RESULTS_DIR.glob("*.json"):
        try:
            with open(f, "r") as file:
                data = json.load(file)
                owner = data.get("owner_user_id")
                # Show if user matches or if public demo
                if user_id and owner == user_id:
                    analyses.append({
                        "capture_id": data.get("capture_id"),
                        "filename": data.get("original_filename"),
                        "risk_score": data.get("summary", {}).get("risk_score"),
                        "risk_level": data.get("summary", {}).get("risk_level"),
                        "timestamp": data.get("upload_timestamp"),
                        "findings_count": len(data.get("findings", [])),
                        "session_count": data.get("summary", {}).get("session_count", 0)
                    })
                elif not user_id and (str(data.get("capture_id", "")).startswith("demo_") or owner in ["system_demo", "demo", "anonymous"]):
                    analyses.append({
                        "capture_id": data.get("capture_id"),
                        "filename": data.get("original_filename"),
                        "risk_score": data.get("summary", {}).get("risk_score"),
                        "risk_level": data.get("summary", {}).get("risk_level"),
                        "timestamp": data.get("upload_timestamp"),
                        "findings_count": len(data.get("findings", [])),
                        "session_count": data.get("summary", {}).get("session_count", 0)
                    })
        except:
            continue
            
    analyses.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)
    return {"analyses": analyses, "total": len(analyses)}


# ─── 7. DELETE ANALYSES ───
class BatchDeleteRequest(BaseModel):
    capture_ids: List[str]


def _delete_single_analysis(capture_id: str, requesting_user_id: Optional[str]) -> bool:
    cid = sanitize_capture_id(capture_id)
    results_file = RESULTS_DIR / f"{cid}.json"
    if not results_file.exists():
        return False
        
    with open(results_file, "r") as f:
        data = json.load(f)
        
    # Deletion always requires an authenticated owner. Demo records are public to
    # read, but anyone may not delete them: without this, a missing user id skipped
    # the check entirely and allowed anonymous deletion of any record.
    owner = data.get("owner_user_id")
    if not requesting_user_id or owner != requesting_user_id:
        return False

    deleted = False
    try:
        results_file.unlink()
        deleted = True
    except Exception as e:
        print(f"Failed to delete {results_file}: {e}")

    for upload_file in UPLOAD_DIR.glob(f"{cid}.*"):
        try:
            upload_file.unlink()
        except Exception as e:
            print(f"Failed to delete upload file {upload_file}: {e}")
    return deleted


@app.delete("/api/analysis/{capture_id}")
@limiter.limit("30/minute")
async def delete_analysis(
    request: Request,
    capture_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Delete a specific completed analysis record and its uploaded files.

    Reading analyses stays public for demo captures; deleting never is.
    """
    cid = sanitize_capture_id(capture_id)
    results_file = RESULTS_DIR / f"{cid}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {cid}")

    with open(results_file, "r") as f:
        data = json.load(f)

    user_id = current_user.get("user_id")
    owner = data.get("owner_user_id")
    if owner != user_id:
        raise HTTPException(status_code=403, detail="Access denied: You cannot delete another user's analysis.")

    _delete_single_analysis(cid, user_id)
    return {"success": True, "deleted_id": cid, "message": "Analysis record deleted successfully."}


@app.post("/api/analyses/delete-batch")
@limiter.limit("20/minute")
async def delete_analyses_batch(
    request: Request,
    req: BatchDeleteRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Selectively delete multiple analysis records in bulk.

    Each record is still ownership-checked individually in _delete_single_analysis.
    """
    deleted_ids = []
    user_id = current_user.get("user_id")
    for cid in req.capture_ids:
        try:
            clean_id = sanitize_capture_id(cid)
            if _delete_single_analysis(clean_id, user_id):
                deleted_ids.append(clean_id)
        except HTTPException:
            continue

    return {
        "success": True,
        "deleted_count": len(deleted_ids),
        "deleted_ids": deleted_ids,
        "message": f"Successfully deleted {len(deleted_ids)} analysis record(s)."
    }


# ─── 8. USP 1: HISTORICAL CRYPTOGRAPHIC FORENSICS ───
@app.get("/api/analysis/{capture_id}/forensics")
async def get_forensic_timeline(
    capture_id: str,
    optional_user: Optional[Dict[str, Any]] = Depends(get_optional_user)
):
    """
    USP 1: Historical Cryptographic Forensics.
    Returns reconstructed chronological event timelines across sessions,
    endpoint correlation, and longitudinal host risk history tracking.
    """
    cid = sanitize_capture_id(capture_id)
    results_file = RESULTS_DIR / f"{cid}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {cid}")

    with open(results_file, "r") as f:
        data = json.load(f)

    check_resource_ownership(data, optional_user, allow_public_demo=True)

    try:
        engine = HistoricalForensicsEngine(data)
        forensic_summary = engine.reconstruct()
        data["forensic_reconstruction"] = forensic_summary
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
async def create_baseline(
    req: CreateBaselineRequest,
    optional_user: Optional[Dict[str, Any]] = Depends(get_optional_user)
):
    """Create an empirical baseline from a completed capture analysis."""
    cid = sanitize_capture_id(req.capture_id)
    results_file = RESULTS_DIR / f"{cid}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {cid}")

    with open(results_file, "r") as f:
        data = json.load(f)

    check_resource_ownership(data, optional_user, allow_public_demo=True)

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
async def compare_drift(
    req: DriftCompareRequest,
    optional_user: Optional[Dict[str, Any]] = Depends(get_optional_user)
):
    """
    USP 6: Compare an analyzed capture against a baseline.
    Computes property-by-property diffs, evaluates security significance,
    and records to comparison history.
    """
    cid = sanitize_capture_id(req.capture_id)
    results_file = RESULTS_DIR / f"{cid}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {cid}")

    with open(results_file, "r") as f:
        data = json.load(f)

    check_resource_ownership(data, optional_user, allow_public_demo=True)

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
        clean_cid = sanitize_capture_id(capture_id) if capture_id else None
        history = drift_engine.list_comparisons(capture_id=clean_cid)
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


# ─── 10. KNOWLEDGE BASE (RAG) ───
@app.get("/api/knowledge/sources")
async def list_knowledge_sources():
    """List reference documents currently live in the retrieval index."""
    kb = get_knowledge_base()
    return {"sources": kb.list_sources()}


@app.get("/api/knowledge/gaps")
async def list_knowledge_gaps():
    """List finding types where retrieval has come back empty or below confidence threshold."""
    return {"gaps": knowledge_ingestion.list_gaps()}


@app.post("/api/knowledge/gaps/{finding_type}/propose")
async def propose_knowledge_source(finding_type: str):
    """Draft a candidate reference document for a coverage gap via Gemini."""
    try:
        draft_path = knowledge_ingestion.propose_source_for_gap(finding_type)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return {"success": True, "finding_type": finding_type, "draft_path": str(draft_path)}


@app.get("/api/knowledge/pending")
async def list_pending_knowledge_sources():
    """List AI-drafted reference documents awaiting human approval."""
    return {"pending": knowledge_ingestion.list_pending()}


@app.post("/api/knowledge/pending/{finding_type}/approve")
async def approve_pending_knowledge_source(finding_type: str):
    """Publish an approved draft into the live retrieval index."""
    try:
        chunk_count = knowledge_ingestion.approve_pending(finding_type)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"success": True, "finding_type": finding_type, "chunks_ingested": chunk_count}


@app.delete("/api/knowledge/pending/{finding_type}")
async def reject_pending_knowledge_source(finding_type: str):
    """Discard a pending draft without publishing it."""
    deleted = knowledge_ingestion.reject_pending(finding_type)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"No pending draft for finding_type: {finding_type}")
    return {"success": True, "finding_type": finding_type, "message": "Draft discarded."}


# ─── 11. STREAM RETRIEVAL (TCP STREAM VIEWER) ───
@app.get("/api/analysis/{capture_id}/stream/{stream_id}")
@limiter.limit("100/minute")
async def get_stream_details(
    request: Request,
    capture_id: str,
    stream_id: str,
    optional_user: Optional[Dict[str, Any]] = Depends(get_optional_user)
):
    """Retrieve structured TCP conversation stream by capture_id and stream_id."""
    cid = sanitize_capture_id(capture_id)
    results_file = RESULTS_DIR / f"{cid}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {cid}")

    with open(results_file, "r") as f:
        data = json.load(f)

    check_resource_ownership(data, optional_user, allow_public_demo=True)

    tcp_streams = data.get("tcp_streams", {})
    stream_data = tcp_streams.get(str(stream_id))

    if not stream_data:
        raise HTTPException(status_code=404, detail=f"TCP Stream #{stream_id} not found in capture {cid}")

    return JSONResponse(content=stream_data)


# ─── 12. RAG & KNOWLEDGE BASE ADMINISTRATION (ADMIN ONLY) ───
class KnowledgeBaseArticle(BaseModel):
    title: str
    category: str
    content: str
    tags: List[str] = []

KB_STORE: Dict[str, Dict[str, Any]] = {
    "kb_001": {
        "id": "kb_001",
        "title": "MTA-STS & STARTTLS Hardening Guide",
        "category": "Email Security",
        "content": "Mandate TLS 1.3 and deploy RFC 8461 MTA-STS policies to defeat STARTTLS stripping attacks.",
        "status": "APPROVED",
        "tags": ["MTA-STS", "STARTTLS", "Hardening"]
    }
}

@app.get("/api/kb/articles")
async def list_kb_articles(optional_user: Optional[Dict[str, Any]] = Depends(get_optional_user)):
    """List approved Knowledge Base and RAG reference articles (Public read for approved items)."""
    return {"articles": list(KB_STORE.values()), "total": len(KB_STORE)}

@app.post("/api/admin/kb/articles")
async def create_kb_article(
    article: KnowledgeBaseArticle,
    admin_user: Dict[str, Any] = Depends(require_admin_role)
):
    """Create new knowledge base / RAG document (Admin Only)."""
    art_id = f"kb_{uuid.uuid4().hex[:6]}"
    doc = {
        "id": art_id,
        "title": article.title,
        "category": article.category,
        "content": article.content,
        "tags": article.tags,
        "status": "APPROVED",
        "created_by": admin_user.get("user_id"),
        "created_at": datetime.now().isoformat()
    }
    KB_STORE[art_id] = doc
    return {"success": True, "article": doc}

@app.put("/api/admin/kb/articles/{article_id}/approve")
async def approve_kb_article(
    article_id: str,
    admin_user: Dict[str, Any] = Depends(require_admin_role)
):
    """Approve a pending RAG / Knowledge Base article (Admin Only)."""
    if article_id not in KB_STORE:
        raise HTTPException(status_code=404, detail="Knowledge base article not found.")
    KB_STORE[article_id]["status"] = "APPROVED"
    KB_STORE[article_id]["approved_by"] = admin_user.get("user_id")
    return {"success": True, "article": KB_STORE[article_id]}

@app.delete("/api/admin/kb/articles/{article_id}")
async def delete_kb_article(
    article_id: str,
    admin_user: Dict[str, Any] = Depends(require_admin_role)
):
    """Delete a Knowledge Base / RAG reference document (Admin Only)."""
    if article_id not in KB_STORE:
        raise HTTPException(status_code=404, detail="Knowledge base article not found.")
    deleted = KB_STORE.pop(article_id)
    return {"success": True, "deleted_id": article_id, "deleted_title": deleted.get("title")}


# ─── 13. ACTIVE EMAIL AUTHENTICATION CHECK ───
class EmailAuthRequest(BaseModel):
    domain: str
    dkim_selector: Optional[str] = None


@app.post("/api/email-auth-check")
def email_auth_check(req: EmailAuthRequest):
    """SPF/DKIM/DMARC lookup for a domain. Active DNS queries, user-initiated."""
    try:
        return email_auth_checker.run_email_auth_checks(req.domain, req.dkim_selector)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


# ─── 14. LIVE MONITORING STATUS ───
@app.get("/api/watch/status")
async def watch_status():
    """Whether folder monitoring is active, and what it has processed recently."""
    if watcher is None:
        return {"enabled": False, "running": False, "recent": []}
    return {"enabled": True, **watcher.status()}


# ─── HELPER PIPELINE FUNCTIONS ───

def attach_assessments(result: Dict[str, Any]) -> None:
    """Run the passive cryptographic-state and evidence-assessment engines over a
    completed analysis and attach their output in place."""
    try:
        assessment = CryptographicStateEngine(result).evaluate()
        result["cryptographic_state_assessment"] = assessment
        summary = result.get("summary")
        if isinstance(summary, dict):
            summary["cryptographic_state"] = assessment["overall_state"]
            summary["cryptographic_state_label"] = assessment["overall_state_label"]
    except Exception as e:
        print(f"[!] Cryptographic state assessment failed: {e}")

    try:
        result["evidence_based_assessment"] = EvidenceAssessmentEngine(result).evaluate()
    except Exception as e:
        print(f"[!] Evidence-based assessment failed: {e}")


def analyze_and_store(
    file_path: Path,
    original_filename: str,
    capture_id: str,
    file_size: int,
    owner_user_id: str = "anonymous"
) -> dict:
    """Run the analyzer, persist the result to the results store, attach forensics reconstruction, and return it."""
    analyzer = EmailPCAPAnalyzer(str(file_path))
    result = analyzer.analyze()

    if not result.get("success"):
        raise RuntimeError(f"Analysis failed: {result.get('error')}")

    result["capture_id"] = capture_id
    result["owner_user_id"] = owner_user_id
    result["upload_timestamp"] = datetime.now().isoformat()
    result["original_filename"] = original_filename
    result["file_size"] = file_size
    result["status"] = "completed"

    attach_assessments(result)

    # Attach historical forensics reconstruction (USP 1)
    try:
        forensics_engine = HistoricalForensicsEngine(result)
        result["forensic_reconstruction"] = forensics_engine.reconstruct()
    except Exception as _fe_err:
        print(f"[!] Forensics reconstruction notice: {_fe_err}")

    results_file = RESULTS_DIR / f"{capture_id}.json"
    with open(results_file, "w") as f:
        json.dump(result, f, indent=2, default=str)
    return result


def run_analysis_pipeline(
    file_path: Path,
    original_filename: str,
    capture_id: str,
    file_size: int,
    owner_user_id: str = "anonymous"
):
    """Executes the PCAP analyzer, saves the payload, and returns JSON."""
    try:
        return JSONResponse(content=analyze_and_store(
            file_path, original_filename, capture_id, file_size, owner_user_id
        ))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {str(e)}")


def analyze_watched_file(path: Path):
    """Watcher callback: analyze one dropped-in capture into the normal results store."""
    capture_id = f"watch_{path.stem}_{uuid.uuid4().hex[:6]}"
    staged = UPLOAD_DIR / f"{capture_id}{path.suffix.lower()}"
    try:
        shutil.copyfile(path, staged)
        analyze_and_store(staged, path.name, capture_id, staged.stat().st_size)
        return capture_id
    except Exception as e:
        print(f"[!] Watched file analysis failed for {path.name}: {e}")
        return None


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
