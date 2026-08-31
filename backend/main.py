"""
SecureMailScope — FastAPI Backend
Serves the PCAP analysis pipeline, AI enrichment, demo presets, and forensic reporting.
"""

import os
import json
import uuid
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, Response

# Import analysis pipeline & reporting engine
from app.core.pcap_analyzer import EmailPCAPAnalyzer
from app.services.report_generator import ReportGenerator

# ─── APP SETUP ───
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

# ─── DIRECTORIES ───
UPLOAD_DIR = Path("uploads")
RESULTS_DIR = Path("results")
TEST_DATA_DIR = Path("test-data")

UPLOAD_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)
TEST_DATA_DIR.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB


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


# ─── 3. DEMO SCENARIO PRESETS ───
# ─── 3. DEMO SCENARIO PRESETS ───
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
        }
    ]
    return {"samples": samples}


@app.post("/api/demo/load/{sample_id}")
async def load_demo_sample(sample_id: str):
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

    return run_analysis_pipeline(file_path, filename, capture_id, file_size)


# ─── 4. RETRIEVE STORED RESULTS ───
@app.get("/api/analysis/{capture_id}/results")
async def get_results(capture_id: str):
    """Retrieve existing analysis results by capture_id."""
    results_file = RESULTS_DIR / f"{capture_id}.json"
    if not results_file.exists():
        raise HTTPException(status_code=404, detail=f"Analysis not found for ID: {capture_id}")

    with open(results_file, "r") as f:
        return JSONResponse(content=json.load(f))


# ─── 5. FORENSIC REPORT GENERATION ───
@app.get("/api/analysis/{capture_id}/report")
async def get_report(capture_id: str, format: str = Query("html", regex="^(html|json)$")):
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


# ─── 6. LIST ALL COMPLETED ANALYSES ───
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
                    "filename": data.get("original_filename"),
                    "risk_score": data.get("summary", {}).get("risk_score"),
                    "risk_level": data.get("summary", {}).get("risk_level"),
                    "timestamp": data.get("upload_timestamp"),
                    "findings_count": len(data.get("findings", []))
                })
        except:
            continue
    return {"analyses": analyses, "total": len(analyses)}


# ─── HELPER PIPELINE FUNCTION ───
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