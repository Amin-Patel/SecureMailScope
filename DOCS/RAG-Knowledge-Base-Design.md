# RAG Knowledge Base — Design & Implementation Notes

Follow-up to [`RAG-and-Fine-Tuning-Notes.md`](RAG-and-Fine-Tuning-Notes.md),
which left an open question: invest in a RAG layer for the MVP's AI
explanations, or defer it. Decision: **build it** — RAG over fine-tuning,
per the reasoning in that doc. This note covers what we additionally decided
and built on top of that: a knowledge base that can detect its own coverage
gaps and grow itself, with a human approval step. The implementation lives on
the `feature/rag-knowledge-base` branch.

---

## Why go further than a static knowledge base

A hand-curated set of reference docs is a fine start, but it goes stale the
moment a finding type is added or a doc turns out to be too thin to ground a
good explanation. The ask was: can the knowledge base notice when it doesn't
have good coverage for something, and improve itself?

The answer is yes, with one important constraint we agreed on before
building it: **this is a security tool, so nothing gets auto-published into
the retrieval index without a human looking at it first.** Unreviewed
auto-ingested content is a real risk here — a bad or spoofed source could
translate directly into bad remediation advice shown to a user. So the
"self-improving" part stops at *drafting a proposal*; a person has to
approve it before it goes live.

## Why this was tractable to build in one session

Security findings in this codebase come from a **fixed, closed set of 8
`finding_type` values** (`backend/app/core/security_engine.py`):
`plaintext_protocol`, `deprecated_protocol`, `weak_cipher`, `weak_signature`,
`insufficient_key_size`, `expired_certificate`, `self_signed_certificate`,
`missing_starttls`. This isn't an open-ended retrieval problem — the
knowledge base only ever needs one solid reference doc per type. That made
gap detection simple (bootstrap seeds all 8; gaps only arise if a doc is
thin or a new finding type gets added later) and kept the whole feature
tightly scoped.

## Architecture

- **Storage**: `chromadb`, persisted locally (`backend/knowledge_store/`,
  gitignored — same treatment as `uploads/`/`results/`). We always supply
  our own precomputed embedding vectors rather than using chroma's default
  embedding function.
- **Embeddings**: mirrors the online/offline pattern already established in
  `gemini_service.py` — Gemini's embedding endpoint when `GEMINI_API_KEY` is
  set, otherwise a deterministic feature-hashing bag-of-words fallback (no
  network, no extra ML dependency). The collection name is suffixed by mode
  so switching between online/offline across restarts never mixes
  incompatible vector spaces — it just re-seeds fresh in the new mode.
- **Seed content**: 8 curated Markdown docs
  (`backend/app/knowledge_base/sources/*.md`), one per finding type, each
  grounded in real standards — RFC 8996 (TLS 1.0/1.1 deprecation), RFC 3207
  (STARTTLS), POODLE/CVE-2014-3566, Sweet32/CVE-2016-2183, NIST SP 800-52r2,
  etc.
- **Retrieval wiring**: `gemini_service.py`'s `explain_finding` queries the
  knowledge base before building its prompt (online path: reference material
  gets injected as grounding context for Gemini; offline path: also queried,
  surfaced as a supplementary `ai_reference` field alongside the existing
  hardcoded explanation — nothing about the existing offline behavior
  regresses).
- **Gap detection**: when retrieval for a finding comes back empty or below
  a similarity threshold, it's logged to `knowledge_store/gaps.json` (one
  entry per finding type, not an unbounded log).
- **AI-assisted drafting + approval queue**: a gap can be sent to Gemini to
  draft a candidate reference doc, which lands in
  `knowledge_base/sources/pending/` (gitignored). It only enters the live
  index after an explicit approve call, which moves the file into `sources/`
  and re-ingests it. A reject call just discards the draft.

## New endpoints

`GET /api/knowledge/sources`, `GET /api/knowledge/gaps`,
`POST /api/knowledge/gaps/{type}/propose`, `GET /api/knowledge/pending`,
`POST /api/knowledge/pending/{type}/approve`,
`DELETE /api/knowledge/pending/{type}`.

No frontend was built for the review queue — these are plain REST endpoints
for whoever picks up the "Admin" surface already anticipated in
[`Master Website Functionality Map.md`](Master%20Website%20Functionality%20Map.md)
to wire a screen to.

## What was verified, and what wasn't

First pass was verified in isolation (offline mode, no API key, no TShark
installed in the dev environment this was built in):

- All 8 seed docs index correctly on startup.
- Retrieval correctly matches synthetic findings to the right reference doc,
  called directly against `explain_finding` — not through a real analysis
  request, since the PCAP pipeline itself needs TShark and none was
  installed yet.
- Found and fixed a real bug in the process: naive paragraph chunking was
  splitting Markdown section headings (`## Overview`, etc.) into their own
  near-empty chunks, which could become the top "match" instead of actual
  content. Fixed by folding heading-only chunks into the following
  paragraph.
- The full gap → propose (fails cleanly with HTTP 503 when no API key is
  configured) → approve → reject loop, exercised via live HTTP calls.
- The existing `backend/tests/test_e2e_pipeline.py` suite — no regressions
  beyond the (at the time) missing-TShark failures.

**Follow-up pass — genuine end-to-end confirmation.** Wireshark (bundles
TShark) was installed on the dev machine specifically to close the gap above
and actually run a real PCAP through the full pipeline rather than testing
the RAG layer in isolation:

- `POST /api/demo/load/vulnerable_smtp` against the live server on
  `feature/rag-knowledge-base` returned a real analysis: 2 findings, risk
  score 55/100.
- The `missing_starttls` finding came back with `ai_reference` populated
  with real content retrieved live from the knowledge base (RFC 3207/2595/
  8314 material) — confirming the RAG grounding fires inside the actual
  request path, not just in a synthetic test.
- The `plaintext_protocol` finding correctly came back with
  `ai_reference: null` and was logged to `/api/knowledge/gaps` — the
  0.35 confidence threshold did its job rather than forcing a weak match
  through.
- Ran twice; the gap counter for `plaintext_protocol` went 1 → 2
  consistently across runs, confirming the bookkeeping in
  `knowledge_store/gaps.json` is sound.

**Still not verified**: the online path (real Gemini embeddings + AI-drafted
proposals) — no `GEMINI_API_KEY` was available in the environment this was
built in. The offline lexical fallback is intentionally crude (a hashing
bag-of-words, not real semantic search); in testing it correctly identified
the right document but sometimes just missed the confidence threshold
(e.g. 0.328 vs. the 0.35 cutoff), which is by design — an uncertain match
becomes a logged gap rather than false-confidence grounding. Whoever has a
real key should smoke-test the `propose` endpoint and confirm online
embedding quality clears the threshold more consistently.

## Known issue found along the way (not a RAG bug — a Windows/console bug)

Getting the real end-to-end run working surfaced a **separate, pre-existing
bug** unrelated to this feature: `pcap_analyzer.py`'s `_print_report()`
prints a 🤖 emoji to the console. On a Windows console using the default
cp1252 code page, that `print()` raises `UnicodeEncodeError` — and because
it happens *after* the analysis has already fully succeeded but *inside* the
same `try` block, the outer exception handler reports the entire analysis as
failed (HTTP 500) even though `findings`, `risk`, and `ai_summary` were all
correctly computed. This has likely been silently swallowing successful
Windows-console analyses for a while; it just hadn't been hit here before
because TShark wasn't installed, so no analysis had gotten far enough to
reach that line.

Not fixed in `feature/rag-knowledge-base` (out of scope for that branch —
worked around locally for testing by setting `PYTHONIOENCODING=utf-8`), but
worth a dedicated fix: either reconfigure stdout to UTF-8 at process start
(`sys.stdout.reconfigure(encoding="utf-8")` in `main.py`), or drop the emoji
from the print statements.

## Also fixed along the way

Two pre-existing gaps this feature depended on, fixed in the same branch:

- `backend/requirements.txt` was missing `google-genai` and `python-dotenv`
  even though `gemini_service.py` already imported them.
- `pcap_analyzer.py` was discarding `ai_source` (and now `ai_reference`)
  from the AI service's response instead of attaching it to the finding.

## Local dev setup note

Running the full pipeline locally (not just the RAG layer) requires
Wireshark/TShark installed and on `PATH` or at one of the paths
`tshark_helper.py` checks (`C:\Program Files\Wireshark\tshark.exe` on
Windows). Without it, `/api/upload` and `/api/demo/load/*` will 500 at the
TLS-handshake-extraction step, before any of the RAG code even runs.
