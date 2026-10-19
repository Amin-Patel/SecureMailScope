"""
Knowledge Base service for SecureMailScope
Chromadb-backed retrieval store used to ground AI finding explanations in
curated reference material (RFCs, CVEs, standards guidance).

Mirrors the online/offline pattern in gemini_service.py: uses Gemini
embeddings when a GEMINI_API_KEY is available, falls back to a deterministic
offline embedding otherwise, so retrieval works with no API key at all.
"""

import os
import re
import hashlib
from pathlib import Path
from typing import Dict, List, Optional

import chromadb
from dotenv import load_dotenv

load_dotenv()

try:
    from google import genai
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

SOURCES_DIR = Path(__file__).parent.parent / "knowledge_base" / "sources"
STORE_DIR = Path(__file__).parent.parent.parent / "knowledge_store"
OFFLINE_DIM = 512


class KnowledgeBase:
    """Retrieval store for security-finding reference material."""

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "").strip()
        self.embedding_model = os.getenv("GEMINI_EMBEDDING_MODEL", "text-embedding-004").strip()
        self.client = None
        self.is_online = False

        if HAS_GENAI and self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
                self._embed_text("connectivity check")
                self.is_online = True
            except Exception as e:
                print(f"[*] Knowledge base embedding note: {e}. Using Offline Lexical Retrieval Engine.")
                self.client = None
                self.is_online = False
        else:
            print("[*] No Gemini API key detected. Knowledge base using Offline Lexical Retrieval Engine.")

        STORE_DIR.mkdir(exist_ok=True)
        self._chroma = chromadb.PersistentClient(
            path=str(STORE_DIR),
            settings=chromadb.Settings(anonymized_telemetry=False),
        )

        # Collection is named per embedding mode so switching modes across restarts
        # never mixes incompatible vector spaces/dimensions -- it just re-seeds fresh.
        collection_name = "security_reference_online" if self.is_online else "security_reference_offline"
        self._collection = self._chroma.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )

        mode = f"Gemini embeddings ({self.embedding_model})" if self.is_online else "Offline Lexical Retrieval Engine"
        print(f"[+] Knowledge Base initialized — {mode} — collection='{collection_name}'")

    # ─── EMBEDDING ───

    def _embed_text(self, text: str) -> List[float]:
        if self.is_online and self.client:
            try:
                response = self.client.models.embed_content(model=self.embedding_model, contents=text)
                return list(response.embeddings[0].values)
            except Exception as e:
                print(f"[!] Gemini embedding call failed, using offline fallback for this text: {e}")
                return self._offline_embed(text)
        return self._offline_embed(text)

    @staticmethod
    def _offline_embed(text: str, dim: int = OFFLINE_DIM) -> List[float]:
        """Deterministic feature-hashing bag-of-words vector. No network or ML model required."""
        vector = [0.0] * dim
        tokens = re.findall(r"[a-z0-9]+", text.lower())
        for token in tokens:
            bucket = int(hashlib.md5(token.encode()).hexdigest(), 16) % dim
            vector[bucket] += 1.0
        norm = sum(v * v for v in vector) ** 0.5
        if norm > 0:
            vector = [v / norm for v in vector]
        return vector

    # ─── INGESTION ───

    @staticmethod
    def _chunk(text: str) -> List[str]:
        """Paragraph-based chunking. Lone Markdown heading lines (## Overview, etc.) are
        prefixed onto the next paragraph with real content instead of becoming their own
        near-empty chunk, which would otherwise be an easy top-similarity false match."""
        raw_paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
        chunks: List[str] = []
        pending_headings: List[str] = []

        for part in raw_paragraphs:
            is_heading_only = part.startswith("#") and "\n" not in part
            if is_heading_only:
                pending_headings.append(part)
                continue
            if pending_headings:
                part = "\n".join(pending_headings) + "\n\n" + part
                pending_headings = []
            chunks.append(part)

        if pending_headings:
            chunks.append("\n".join(pending_headings))

        return chunks or [text.strip()]

    def ingest_document(self, doc_id: str, text: str, finding_type: str, source: str = "curated") -> int:
        """Chunk, embed, and upsert a document. Returns the number of chunks ingested."""
        chunks = self._chunk(text)
        doc_hash = hashlib.sha256(text.encode()).hexdigest()[:16]

        ids, embeddings, documents, metadatas = [], [], [], []
        for i, chunk in enumerate(chunks):
            ids.append(f"{doc_id}::{i}")
            embeddings.append(self._embed_text(chunk))
            documents.append(chunk)
            metadatas.append({
                "finding_type": finding_type,
                "source": source,
                "doc_id": doc_id,
                "doc_hash": doc_hash,
            })

        self._collection.upsert(ids=ids, embeddings=embeddings, documents=documents, metadatas=metadatas)
        return len(chunks)

    def _existing_hash(self, doc_id: str) -> Optional[str]:
        try:
            existing = self._collection.get(ids=[f"{doc_id}::0"], include=["metadatas"])
            if existing["ids"]:
                return existing["metadatas"][0].get("doc_hash")
        except Exception:
            pass
        return None

    def seed_from_sources(self) -> Dict[str, int]:
        """Idempotently ingest every *.md directly under sources/ (skips sources/pending/)."""
        ingested = {}
        if not SOURCES_DIR.exists():
            return ingested

        for path in sorted(SOURCES_DIR.glob("*.md")):
            doc_id = path.stem
            text = path.read_text(encoding="utf-8")
            new_hash = hashlib.sha256(text.encode()).hexdigest()[:16]

            if self._existing_hash(doc_id) == new_hash:
                continue

            ingested[doc_id] = self.ingest_document(doc_id=doc_id, text=text, finding_type=doc_id, source="curated")

        return ingested

    # ─── RETRIEVAL ───

    def query(self, text: str, finding_type: Optional[str] = None, top_k: int = 3) -> List[Dict]:
        try:
            count = self._collection.count()
        except Exception:
            count = 0
        if count == 0:
            return []

        query_embedding = self._embed_text(text)
        where = {"finding_type": finding_type} if finding_type else None

        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=min(top_k, count),
            where=where,
        )

        matches = []
        docs = (results.get("documents") or [[]])[0]
        metas = (results.get("metadatas") or [[]])[0]
        distances = (results.get("distances") or [[]])[0]
        for doc, meta, distance in zip(docs, metas, distances):
            matches.append({
                "text": doc,
                "finding_type": meta.get("finding_type"),
                "source": meta.get("source"),
                "score": round(1.0 - distance, 4),  # cosine space: distance = 1 - similarity
            })
        return matches

    def list_sources(self) -> List[Dict]:
        try:
            all_docs = self._collection.get(include=["metadatas"])
        except Exception:
            return []
        seen = {}
        for meta in all_docs.get("metadatas", []):
            doc_id = meta.get("doc_id")
            if doc_id and doc_id not in seen:
                seen[doc_id] = {
                    "doc_id": doc_id,
                    "finding_type": meta.get("finding_type"),
                    "source": meta.get("source"),
                }
        return list(seen.values())


# Module-level singleton -- cheap to keep alive across requests, and chroma's
# PersistentClient should not be re-opened on every call.
_kb_instance: Optional[KnowledgeBase] = None


def get_knowledge_base() -> KnowledgeBase:
    global _kb_instance
    if _kb_instance is None:
        _kb_instance = KnowledgeBase()
        _kb_instance.seed_from_sources()
    return _kb_instance
