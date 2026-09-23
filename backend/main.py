"""
SecureMailScope — FastAPI Backend
Serves the PCAP analysis pipeline, AI enrichment, demo presets, and forensic reporting.
Secured with Supabase JWT Authentication, User Ownership & IDOR Protection,
Path Traversal Prevention, Upload Validation, and Credential Redaction.
"""

import os
import json
import uuid
import re
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any

from pydantic import BaseModel
from fastapi import FastAPI, UploadFile, File, HTTPException, Query, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, Response

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Import analysis pipeline & reporting engine
from app.core.pcap_analyzer import EmailPCAPAnalyzer
from app.services.report_generator import ReportGenerator
from app.core.auth import get_current_user, get_optional_user, require_admin_role

# ─── RATE LIMITER SETUP ───
limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])

# ─── APP SETUP ───
app = FastAPI(
    title="SecureMailScope API",
    description="AI-Driven Email Security Assessment & Forensics",
    version="1.0.0"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Open for development & demo environments
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── DIRECTORIES ───
BASE_DIR = Path(__file__).parent
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
    - If capture is a demo (`demo_*` or owner_user_id is 'system_demo'), allow access if allow_public_demo is True.
    - Otherwise, requires valid user whose `user_id` matches `owner_user_id`.
    """
    owner_id = data.get("owner_user_id")
    is_demo = str(data.get("capture_id", "")).startswith("demo_") or owner_id in ["system_demo", "demo"]

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

        with open(file_path, "wb") as buffer:
            buffer.write(content)
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
        "secure_enterprise": "secure_mail.pcap"
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
    return JSONResponse(content=data)


# ─── 5. FORENSIC REPORT GENERATION ───
@app.get("/api/analysis/{capture_id}/report")
@limiter.limit("60/minute")
async def get_report(
    request: Request,
    capture_id: str,
    format: str = Query("html", pattern="^(html|json)$"),
    optional_user: Optional[Dict[str, Any]] = Depends(get_optional_user)
):
    """Generate and return an official Forensic Assessment Report in HTML or JSON format."""
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
    else:
        html_content = ReportGenerator.generate_html_report(data)
        return HTMLResponse(content=html_content)


# ─── 6. LIST USER ANALYSES ───
@app.get("/api/analyses")
@limiter.limit("60/minute")
async def list_user_analyses(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List summary records of analyses owned by the requesting authenticated user."""
    user_id = current_user.get("user_id")
    analyses = []
    for f in RESULTS_DIR.glob("*.json"):
        try:
            with open(f, "r") as file:
                data = json.load(file)
                if data.get("owner_user_id") == user_id:
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
            
    # Sort newest first
    analyses.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)
    return {"analyses": analyses, "total": len(analyses)}


# ─── 7. DELETE ANALYSES ───
class BatchDeleteRequest(BaseModel):
    capture_ids: List[str]


def _delete_single_analysis(capture_id: str, requesting_user_id: str) -> bool:
    cid = sanitize_capture_id(capture_id)
    results_file = RESULTS_DIR / f"{cid}.json"
    if not results_file.exists():
        return False
        
    with open(results_file, "r") as f:
        data = json.load(f)
        
    if data.get("owner_user_id") != requesting_user_id:
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
    """Delete a specific completed analysis record and its uploaded files (Owner Only)."""
    cid = sanitize_capture_id(capture_id)
    results_file = RESULTS_DIR / f"{cid}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {cid}")

    with open(results_file, "r") as f:
        data = json.load(f)

    if data.get("owner_user_id") != current_user.get("user_id"):
        raise HTTPException(status_code=403, detail="Access denied: You cannot delete another user's analysis.")

    _delete_single_analysis(cid, current_user.get("user_id"))
    return {"success": True, "deleted_id": cid, "message": "Analysis record deleted successfully."}


@app.post("/api/analyses/delete-batch")
@limiter.limit("20/minute")
async def delete_analyses_batch(
    request: Request,
    req: BatchDeleteRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Selectively delete multiple analysis records in bulk (Owner Only)."""
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


# ─── 8. STREAM RETRIEVAL ───
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


# ─── 9. RAG & KNOWLEDGE BASE ADMINISTRATION (ADMIN ONLY) ───
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


# ─── HELPER PIPELINE FUNCTION ───
def run_analysis_pipeline(
    file_path: Path,
    original_filename: str,
    capture_id: str,
    file_size: int,
    owner_user_id: str = "anonymous"
):
    """Executes the PCAP analyzer, saves the payload, and returns JSON."""
    try:
        analyzer = EmailPCAPAnalyzer(str(file_path))
        result = analyzer.analyze()

        if not result.get("success"):
            raise HTTPException(status_code=500, detail=f"Analysis failed: {result.get('error')}")

        result["capture_id"] = capture_id
        result["owner_user_id"] = owner_user_id
        result["upload_timestamp"] = datetime.now().isoformat()
        result["original_filename"] = original_filename
        result["file_size"] = file_size
        result["status"] = "completed"

        # Save to results
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
    print("  SecureMailScope API Server (Secured)")
    print("  http://localhost:8001")
    print("  Docs: http://localhost:8001/docs")
    print("="*50 + "\n")
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
