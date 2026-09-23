"""
Knowledge base gap detection and AI-assisted source drafting for SecureMailScope.

Detects when a security finding has no (or weak) knowledge-base coverage, and
can draft a candidate reference document via Gemini. Drafts land in
sources/pending/ and require an explicit approval call before they enter the
live retrieval index -- unreviewed auto-ingested content is not acceptable
for a security tool (a bad/spoofed source could translate directly into bad
remediation advice shown to a user).
"""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from dotenv import load_dotenv

load_dotenv()

try:
    from google import genai
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

from services.knowledge_base import get_knowledge_base, SOURCES_DIR, STORE_DIR

PENDING_DIR = SOURCES_DIR / "pending"
GAPS_FILE = STORE_DIR / "gaps.json"

FINDING_TYPES = {
    "plaintext_protocol",
    "deprecated_protocol",
    "weak_cipher",
    "weak_signature",
    "insufficient_key_size",
    "expired_certificate",
    "self_signed_certificate",
    "missing_starttls",
}


def _load_gaps() -> Dict:
    if GAPS_FILE.exists():
        try:
            return json.loads(GAPS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _save_gaps(gaps: Dict) -> None:
    STORE_DIR.mkdir(exist_ok=True)
    GAPS_FILE.write_text(json.dumps(gaps, indent=2), encoding="utf-8")


def record_gap(finding_type: str, sample_title: str = "") -> None:
    """Record that retrieval for this finding type came back empty or below threshold."""
    gaps = _load_gaps()
    entry = gaps.get(finding_type, {"count": 0, "sample_titles": []})
    entry["count"] = entry.get("count", 0) + 1
    entry["last_seen"] = datetime.now().isoformat()
    if sample_title and sample_title not in entry.get("sample_titles", []):
        entry["sample_titles"] = (entry.get("sample_titles", []) + [sample_title])[-5:]
    gaps[finding_type] = entry
    _save_gaps(gaps)


def clear_gap(finding_type: str) -> None:
    gaps = _load_gaps()
    if finding_type in gaps:
        del gaps[finding_type]
        _save_gaps(gaps)


def list_gaps() -> List[Dict]:
    gaps = _load_gaps()
    return [{"finding_type": ft, **info} for ft, info in gaps.items()]


def list_pending() -> List[Dict]:
    if not PENDING_DIR.exists():
        return []
    return [
        {
            "finding_type": p.stem,
            "preview": p.read_text(encoding="utf-8")[:280],
        }
        for p in sorted(PENDING_DIR.glob("*.md"))
    ]


def _draft_prompt(finding_type: str, sample_titles: List[str]) -> str:
    titles = "; ".join(sample_titles) if sample_titles else finding_type
    return (
        "You are a Principal Cybersecurity Analyst writing an internal reference document "
        "for a security-findings knowledge base used to ground AI explanations.\n\n"
        f"Finding type: {finding_type}\n"
        f"Observed finding titles needing coverage: {titles}\n\n"
        "Write a factual, technically accurate reference document in Markdown with exactly "
        "these four sections: '## Overview', '## Why It's Dangerous', "
        "'## Standards & Compliance References' (cite real RFCs/CVEs/NIST publications where "
        "genuinely applicable -- do not invent citation numbers), and '## Remediation'. "
        "Keep it to 150-300 words total. Do not include any content outside these four sections."
    )


def propose_source_for_gap(finding_type: str) -> Path:
    """Draft a candidate reference document via Gemini and write it to sources/pending/.

    Requires a configured GEMINI_API_KEY -- there is no offline way to draft new content
    (offline mode can only retrieve what already exists, not author anything new)."""
    if finding_type not in FINDING_TYPES:
        raise ValueError(f"Unknown finding_type: {finding_type}")

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not HAS_GENAI or not api_key:
        raise RuntimeError(
            "Drafting a knowledge-base proposal requires a configured GEMINI_API_KEY -- "
            "there is no offline drafting path. Set GEMINI_API_KEY and retry."
        )

    sample_titles = _load_gaps().get(finding_type, {}).get("sample_titles", [])

    client = genai.Client(api_key=api_key)
    model_name = os.getenv("GEMINI_MODEL", "gemini-3.6-flash").strip()
    response = client.models.generate_content(
        model=model_name,
        contents=_draft_prompt(finding_type, sample_titles),
    )
    draft_text = response.text.strip()

    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    draft_path = PENDING_DIR / f"{finding_type}.md"
    draft_path.write_text(draft_text, encoding="utf-8")
    return draft_path


def approve_pending(finding_type: str) -> int:
    """Publish a pending draft into the live source set and retrieval index.
    Returns the number of chunks ingested."""
    draft_path = PENDING_DIR / f"{finding_type}.md"
    if not draft_path.exists():
        raise FileNotFoundError(f"No pending draft for finding_type: {finding_type}")

    text = draft_path.read_text(encoding="utf-8")
    live_path = SOURCES_DIR / f"{finding_type}.md"
    live_path.write_text(text, encoding="utf-8")
    draft_path.unlink()

    kb = get_knowledge_base()
    chunk_count = kb.ingest_document(doc_id=finding_type, text=text, finding_type=finding_type, source="ai_drafted")
    clear_gap(finding_type)
    return chunk_count


def reject_pending(finding_type: str) -> bool:
    draft_path = PENDING_DIR / f"{finding_type}.md"
    if draft_path.exists():
        draft_path.unlink()
        return True
    return False
