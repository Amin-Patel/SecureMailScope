# Next Features Roadmap: PDF Export, A–F Grading, Live Monitoring, SPF/DKIM/DMARC

Scoped after the ML risk classifier's PKI feature audit was completed and
merged (see `Bugs-Found-and-Fixed.md` and the ML classifier commits on
`feature/ml-risk-classifier`). With the RAG knowledge base, ML risk
classifier (all 8 PKI rules covered), and SSLBL threat intel feed all
built, these four are the remaining gaps against the official spec and the
competitive field. Independent features, each implementable and mergeable
on its own — this doc records the scoping so anyone can pick one up.


> **Status (2026-09-19): implemented and merged into `main`** via
> [PR #3](https://github.com/Amin-Patel/SecureMailScope/pull/3)
> (the threat-intel feed, a separate feature, merged as
> [PR #4](https://github.com/Amin-Patel/SecureMailScope/pull/4)). Sections
> below keep the original scoping; each has an **As built** note where the
> shipped version differs. For the full current status and what is left, see
> [`Feature-Status-and-Backlog.md`](Feature-Status-and-Backlog.md).

---

## 1. Real server-side PDF export

**Why:** the official spec requires "Exportable reports in JSON, PDF, and
HTML." JSON already worked (`GET /api/analysis/{capture_id}/report?format=json`
in `backend/main.py`) and HTML has a real generator
(`ReportGenerator.generate_html_report()` in
`backend/app/services/report_generator.py`, print-ready with `@media print`
CSS) which the dashboard's report dropdown links to. But the only "PDF" was
the browser print dialog (`window.print()` on a hidden `PrintableReport.jsx`);
there was no real server-generated PDF file.

**As built:** `xhtml2pdf` (pure Python via `reportlab`; `pyHanko` pulls in
`cryptography>=48`, so that pin was raised to `>=48,<51`).
`ReportGenerator.generate_pdf_report()` reuses the HTML, strips emoji (the
built-in PDF fonts render them as boxes), and `format=pdf` was added to the
existing endpoint, with download actions in the dashboard dropdown and export
modal. xhtml2pdf ignores CSS grid, so the summary cards stack vertically in
the PDF; page layout was not visually reviewed.

**Plan:**
- Add `xhtml2pdf` to `backend/requirements.txt` (pure-Python HTML→PDF via
  `reportlab`, no native system dependency — avoids weasyprint's
  Pango/Cairo/GTK install pain on Windows).
- `ReportGenerator.generate_pdf_report(data) -> bytes`: reuses
  `generate_html_report(data)`, feeds it through `xhtml2pdf.pisa.CreatePDF()`.
- Extend `get_report`'s `format` pattern in `main.py` from
  `^(html|json)$` to `^(html|json|pdf)$`; return
  `Response(content=pdf_bytes, media_type="application/pdf", ...)`.
- Frontend `ReportExportModal.jsx`: add a real "Download PDF" button that
  fetches the new endpoint and triggers a blob download (same pattern the
  existing JSON button already uses).

## 2. A–F security grading

**As built:** boundaries were aligned to the existing risk-level thresholds
(20/40/70) so a grade can never contradict the level: **A 0-9, B 10-19,
C 20-39, D 40-54, E 55-69, F 70+**. When ML fusion raises the level, the
grade is floored to match (MEDIUM→C, HIGH→D, CRITICAL→F). The thresholds
quoted in the plan below are superseded.

**Why:** competitor MalharBhoi grades servers A–F instead of a bare 0-100
score — more presentation-friendly, cheap to add alongside (not instead
of) the existing score.

**Current state:** `SecurityEngine.calculate_risk_score()`
(`backend/app/core/security_engine.py:445-488`) returns a capture-wide
0-100 `risk_score` + `risk_level` (thresholds 20/40/70). No per-server/
per-session breakdown exists — findings are capture-wide, not tagged by
host. Per-host grading is a bigger lift (would need tagging in
`run_all_checks()`) — **out of scope for this pass**, noted as a limitation.

**Plan:**
- `risk_score_to_grade(score: int) -> str` next to `calculate_risk_score`
  in `security_engine.py`: `0-9→A, 10-24→B, 25-44→C, 45-64→D, 65-84→E,
  85-100→F`.
- Add `'risk_grade'` to `calculate_risk_score()`'s return dict.
- `ml_risk_service.fuse_risk_level()` should recompute `risk_grade` from
  the *fused* score too, same as it already overrides `risk_level`.
- Render the grade badge in `report_generator.py` and next to the SVG
  gauge in `Dashboard.jsx` (~line 417-420, reading `backendRisk.risk_grade`).

## 3. Live/continuous monitoring

**As built:** opt-in via `WATCH_DIR` (plus `WATCH_POLL_SECONDS`), a daemon
thread rather than an asyncio task since analysis is blocking subprocess
work. Files are analyzed once their size is stable across two polls;
processed files are recorded in `WATCH_DIR/.processed.json` so restarts
don't re-analyze them (failures are recorded too). The upload pipeline was
refactored into a shared `analyze_and_store()`. Status at
`GET /api/watch/status`; the History page shows an indicator and refreshes
when a capture lands.

**Why:** every team surveyed, us included, is "upload one PCAP, get one
report." The official spec's language about assisting a SOC in real time
implies something more continuous. This is the biggest architectural gap
against the field.

**Current state:** Purely synchronous — `POST /api/upload` calls
`run_analysis_pipeline()` inline and returns in the same request. Results
persist as `results/{capture_id}.json` (flat-file store, no DB, no
in-memory cache). No background task machinery anywhere.
`tshark_helper.py` always invokes tshark with `-r <file>` (offline mode)
via raw `subprocess` — true live capture (`-i <interface>`) would be a
much bigger, riskier lift (capture permissions, indefinite-duration
subprocess management).

**What the competitor actually built** (per
`Competitive-Landscape-SIH26159.md` Tier 2 item 11): dhanush-girish's
`watch_and_forward.py` is a **file watcher**, not true live packet
capture — it forwards newly-appearing PCAP files into the existing
pipeline automatically, plus a `/history` API and a polling dashboard.
Same win, much lower risk — that's the right scope for us too.

**Plan:**
- `backend/app/services/pcap_watcher.py`: `PcapWatcher` polls a configured
  `WATCH_DIR` (default `backend/watch/`, gitignored) every N seconds via
  `os.scandir` + a seen-set (no new dependency — skip `watchdog`, a simple
  poll loop is enough). New file → calls the same `run_analysis_pipeline()`
  the upload endpoint already uses, writes to the same `results/` store —
  `GET /api/analyses` and `GET /api/analysis/{id}/results` work for it
  with zero changes.
- Wire it as an **opt-in** FastAPI lifespan task (`asyncio.create_task` in
  `main.py`'s `lifespan`), started only if `WATCH_DIR` is configured via
  `.env` — never changes behavior for anyone not using it.
- `GET /api/watch/status` for the frontend to poll (running? queue?
  recently processed?).
- `History.jsx` gets a small "Live monitoring: ON, watching `<dir>`"
  indicator, auto-refreshing when a new result lands — reuses the
  existing history UI rather than building a new view.

## 4. SPF/DKIM/DMARC — passive from the capture, plus an on-demand lookup

**Direction changed during implementation.** The original plan made this an
active-only DNS check because the project is a *passive* analyzer. The
decision was to make it passive first: when a PCAP is uploaded, SPF/DKIM/DMARC
evidence is read from the packets themselves. The active lookup was kept as
a separate, user-initiated extra.

**Passive analysis** (`backend/app/services/email_auth_analyzer.py`, no DNS
queries):
- Message headers in *plaintext* SMTP/IMAP/POP3 streams:
  `Authentication-Results`, `Received-SPF`, `DKIM-Signature`.
- SPF/DMARC/DKIM TXT records in plaintext DNS responses in the capture
  (`TSharkHelper.extract_dns_txt_records`).
- Findings of type `email_authentication`, one per rule listing every
  affected message/record: recorded SPF/DKIM/DMARC failures, `rsa-sha1`
  signatures, signatures not covering `From`, `l=` body-length limits,
  signing domain not aligned with From, unsigned mail (LOW), permissive SPF
  (`+all`/`?all`), non-enforcing DMARC, DKIM keys under 1024/2048 bits.
- Included in the risk score, AI explanations (RAG doc
  `email_authentication.md`), dashboard card and the HTML/PDF report.

**Limits, stated in the output:** verdicts are what servers wrote into the
headers, not independently verified (verifying a signature needs the public
key from live DNS); TLS-encrypted streams hide headers and are only counted;
a message with no `Authentication-Results` is "not asserted", not a failure.
Like `missing_starttls`, these are capture-level findings the per-session ML
classifier does not model.

**On-demand lookup** (`email_auth_checker.py`, `POST /api/email-auth-check`):
active DNS TXT lookups, run only when the user clicks Check, tagged
`check_type=active_dns_lookup`, and kept out of the capture's findings and
risk score. Raises alerts for dangerous published records: missing or
permissive SPF, more than 10 SPF lookups, deprecated `ptr`, missing or
`p=none` DMARC, and weak DKIM keys. DKIM selectors cannot be discovered from
DNS, so with no selector common ones are probed and "not found" means only
that. The panel suggests domains seen in the capture.

## Suggested sequencing

1. **PDF export** — closes a literal spec gap, smallest, no new architecture.
2. **A–F grading** — trivial once #1's report-rendering path is touched anyway.
3. **Live monitoring** — the real differentiator, medium lift, isolated via
   opt-in lifespan task so it can't break existing flows.
4. **SPF/DKIM/DMARC** — independent of the other three, can be done in
   parallel; the labeling risk is already resolved above.

## Verification (per feature)

Run on 2026-09-19 unless noted; the dashboard UI itself was not viewed in a
browser (it sits behind a Supabase login), only built and API-tested.

- **PDF**: `POST /api/demo/load/vulnerable_smtp` → `GET
  /api/analysis/{capture_id}/report?format=pdf` → confirm a valid,
  correctly-rendered PDF. Click the new frontend button, confirm the same
  file downloads.
- **Grading**: unit-check `risk_score_to_grade()` at each threshold
  boundary. Run a known-CRITICAL demo capture, confirm `F`/`E`; run a
  clean capture, confirm `A`.
- **Live monitoring**: set `WATCH_DIR`, drop a demo `.pcap` into it,
  confirm it appears in `GET /api/analyses` with no manual upload call.
  Confirm `POST /api/upload` still works unchanged with `WATCH_DIR` unset.
- **SPF/DKIM/DMARC**: run against a domain with known-good records (e.g.
  `google.com`) and confirm healthy results; against a domain with no
  records and confirm missing/weak is correctly reported. Confirm it
  never appears in the main passive-findings list.
