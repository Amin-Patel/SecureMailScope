# Next Features Roadmap: PDF Export, A–F Grading, Live Monitoring, SPF/DKIM/DMARC

Scoped after the ML risk classifier's PKI feature audit was completed and
merged (see `Bugs-Found-and-Fixed.md` and the ML classifier commits on
`feature/ml-risk-classifier`). With the RAG knowledge base, ML risk
classifier (all 8 PKI rules covered), and SSLBL threat intel feed all
built, these four are the remaining gaps against the official spec and the
competitive field. Independent features, each implementable and mergeable
on its own — this doc records the scoping so anyone can pick one up.

---

## 1. Real server-side PDF export

**Why:** the official spec requires "Exportable reports in JSON, PDF, and
HTML." JSON already works (`GET /api/analysis/{capture_id}/report?format=json`
in `backend/main.py:165`) and HTML has a real generator
(`ReportGenerator.generate_html_report()` in
`backend/app/services/report_generator.py`, already print-ready with
`@media print` CSS). But it's **not wired to the frontend at all** — the
"Print / Save as PDF" button in `Dashboard.jsx` just calls `window.print()`
on a hidden `PrintableReport.jsx` component. There is no real,
server-generated PDF file anywhere in the app today.

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

## 4. SPF/DKIM/DMARC checks (explicitly labeled as supplementary/active)

**Why:** a real feature a couple competitors (fredfe08, Dikshant0Git)
built, but **confirmed out of the official NTRO spec scope** — the
`problem_statement.json` deliverables are entirely passive-PCAP/TLS/cert
focused. SPF/DKIM/DMARC requires **active** DNS lookups, a fundamentally
different trust model than the rest of this tool. Must be presented as a
clearly separate, opt-in, active check — never silently mixed into the
passive-PCAP findings list, so the tool never misrepresents what its core
analysis actually does.

**Current state:** no DNS lookup capability exists anywhere in the
codebase today (`dnspython` not in `requirements.txt`, no `socket`/`dns`
usage found).

**Plan:**
- Add `dnspython` to `backend/requirements.txt`.
- `backend/app/services/email_auth_checker.py`:
  - `check_spf(domain)`: TXT lookup, find `v=spf1`, check for terminal
    `-all` (hard fail, good) vs `~all` (soft) vs `+all`/missing (bad).
  - `check_dkim(domain, selector="default")`: TXT lookup at
    `{selector}._domainkey.{domain}` — note DKIM selectors aren't
    DNS-discoverable, so this needs a user-supplied/best-guess selector;
    document the limitation directly in the docstring and UI.
  - `check_dmarc(domain)`: TXT lookup at `_dmarc.{domain}`, parse `p=`
    policy (`reject`/`quarantine` good, `none` weak, missing bad).
  - `run_email_auth_checks(domain, dkim_selector=None)`: runs all three,
    returns a result with an explicit `"check_type": "active_dns_lookup"`
    marker so downstream consumers can visually separate it.
- `POST /api/email-auth-check` in `main.py`, body
  `{domain, dkim_selector?}` — **not** auto-triggered by PCAP upload, a
  separate user-initiated action. Can pre-fill `domain` from a
  certificate's CN/SAN already extracted from the capture as a
  convenience default, never executed automatically.
- Frontend: a separate "Email Authentication (Active Check)" panel, not
  mixed into the main findings list — visually distinguished (different
  accent color, an "Active DNS lookup — not part of passive PCAP analysis"
  caption).

---

## Suggested sequencing

1. **PDF export** — closes a literal spec gap, smallest, no new architecture.
2. **A–F grading** — trivial once #1's report-rendering path is touched anyway.
3. **Live monitoring** — the real differentiator, medium lift, isolated via
   opt-in lifespan task so it can't break existing flows.
4. **SPF/DKIM/DMARC** — independent of the other three, can be done in
   parallel; the labeling risk is already resolved above.

## Verification (per feature, once implemented)

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
