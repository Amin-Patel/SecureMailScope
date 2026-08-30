"""
SecureMailScope — FastAPI Backend
Serves the PCAP analysis pipeline over HTTP
"""

import os
import json
import uuid
import shutil
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Import our analysis pipeline
from app.core.pcap_analyzer import EmailPCAPAnalyzer

# ─── APP SETUP ───
app = FastAPI(
    title="SecureMailScope API",
    description="AI-Driven Email Security Assessment & Forensics",
    version="1.0.0"
)

# CORS — Allow React frontend to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── DIRECTORIES ───
UPLOAD_DIR = Path("uploads")
RESULTS_DIR = Path("results")
UPLOAD_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB


# ─── HEALTH CHECK ───
@app.get("/api/health")
async def health_check():
    """Check if the API is running"""
    return {
        "status": "healthy",
        "service": "SecureMailScope",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }


# ─── UPLOAD & ANALYZE ───
@app.post("/api/upload")
async def upload_and_analyze(file: UploadFile = File(...)):
    """
    Upload a PCAP file and run full security analysis.
    Returns complete analysis results.
    """

    # 1. Validate file extension
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type '{file_ext}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # 2. Generate unique capture ID
    capture_id = uuid.uuid4().hex[:12]

    # 3. Save uploaded file
    safe_filename = f"{capture_id}{file_ext}"
    file_path = UPLOAD_DIR / safe_filename

    try:
        with open(file_path, "wb") as buffer:
            content = await file.read()

            # Check file size
            if len(content) > MAX_FILE_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail="File too large. Maximum size is 100MB."
                )

            buffer.write(content)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to save file: {str(e)}"
        )

    # 4. Run analysis
    try:
        analyzer = EmailPCAPAnalyzer(str(file_path))
        result = analyzer.analyze()

        if not result.get('success'):
            raise HTTPException(
                status_code=500,
                detail=f"Analysis failed: {result.get('error', 'Unknown error')}"
            )

        # 5. Add metadata
        result['capture_id'] = capture_id
        result['upload_timestamp'] = datetime.now().isoformat()
        result['original_filename'] = file.filename
        result['file_size'] = len(content)
        result['status'] = 'completed'

        # 6. Save results to JSON
        results_file = RESULTS_DIR / f"{capture_id}.json"
        with open(results_file, "w") as f:
            json.dump(result, f, indent=2, default=str)

        # 7. Return results
        return JSONResponse(content=result)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis error: {str(e)}"
        )


# ─── GET RESULTS ───
@app.get("/api/analysis/{capture_id}/results")
async def get_results(capture_id: str):
    """Retrieve stored analysis results by capture ID"""

    results_file = RESULTS_DIR / f"{capture_id}.json"

    if not results_file.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Analysis not found for capture_id: {capture_id}"
        )

    try:
        with open(results_file, "r") as f:
            result = json.load(f)
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to read results: {str(e)}"
        )


# ─── GET STATUS ───
@app.get("/api/analysis/{capture_id}/status")
async def get_status(capture_id: str):
    """Check analysis status"""

    results_file = RESULTS_DIR / f"{capture_id}.json"

    if results_file.exists():
        return {"capture_id": capture_id, "status": "completed"}
    else:
        return {"capture_id": capture_id, "status": "not_found"}


# ─── LIST ALL ANALYSES ───
@app.get("/api/analyses")
async def list_analyses():
    """List all completed analyses"""

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
                    "findings_count": len(data.get("findings", [])),
                    "session_count": data.get("summary", {}).get("session_count", len(data.get("sessions", []))),
                    "total_packets": data.get("summary", {}).get("total_packets", 0)
                })
        except:
            continue

    # Sort latest first by timestamp
    analyses.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
    return {"analyses": analyses, "total": len(analyses)}


if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*50)
    print("  SecureMailScope API Server")
    print("  http://localhost:8001")
    print("  Docs: http://localhost:8001/docs")
    print("="*50 + "\n")
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)