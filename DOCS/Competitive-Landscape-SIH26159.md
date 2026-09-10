# SIH26159 Competitive Landscape — SecureMailScope Implementations

## What this is

SecureMailScope is [SIH26159](https://sih.gov.in), an official Smart India
Hackathon 2026 problem statement sponsored by the National Technical
Research Organisation (NTRO), theme "Blockchain & Cybersecurity." At least
28 independent teams have public GitHub repos building their own
implementation of the same spec. This doc surveys them, verifies which
README-claimed features actually exist in code (several don't), and
prioritizes what's worth building into **our** repo
([Amin-Patel/SecureMailScope](https://github.com/Amin-Patel/SecureMailScope))
next.

**Method:** `gh search repos "SecureMailScope"`, then for each repo with
non-trivial size, fetched the README and full file tree via the GitHub API
and spot-checked source files directly for any feature claimed in a README
— READMEs are marketing copy, source files are the ground truth. ~16 of 28
repos had enough content to be worth reading; the rest are empty scaffolds,
boilerplate templates, or single-commit stubs (listed at the bottom for
completeness).

---

## The official spec (ground truth for "worth it")

Pulled directly from `problem_statement.json` in
[xarjunpatil's repo](https://github.com/xarjunpatil/SIH26159-SecureMailScope-AI-Assisted-Cryptographic-Security-Posture-Assessment-for),
which mirrors the literal NTRO listing. Deliverables explicitly required:

- Passive PCAP analysis of SMTP/IMAP/POP3, protocol ID, STARTTLS detection
- TCP stream + TLS handshake reconstruction
- X.509 extraction, chain validation, expiry, key-length, signature-algorithm checks
- Negotiated TLS version, cipher suite, key-exchange mechanism identification
- **Forward Secrecy assessment**
- **AI-based cryptographic risk scoring** (i.e. an actual model, not just a rules engine)
- **AI-assisted anomaly detection** for suspicious TLS sessions
- Prioritized findings + remediation recommendations
- **Exportable reports in JSON, PDF, and HTML**
- Interactive dashboard

Anything below is graded against this list plus what competitors visibly
built beyond it.

---

## Repos with real, verified substance

| Repo | Stack | What's actually real (verified in source, not just README) |
|---|---|---|
| [fredfe08/SecureMailScope](https://github.com/fredfe08/SecureMailScope) | Python, modular (`M1`/`tls-engine`) | Real `spf_checker.py`/`dkim_checker.py`/`dmarc_checker.py`; live domain scanning *in addition to* passive PCAP; evidence states `OBSERVED`/`NOT_FOUND`/`UNKNOWN`/`INSUFFICIENT_EVIDENCE` instead of binary pass/fail; 14+11 unit tests |
| [MalharBhoi/SecureMailScope](https://github.com/MalharBhoi/SecureMailScope) | Python, `engine/securemailscope/` package | Real `ml/train.py` + `predict.py` + `dataset.py` pipeline (not inline toy code); externalized `kb/rules.yaml` + `cipher_suites.json` (data-driven rules, not hardcoded if/elif); A–F server grading (`scoring/grade.py`); **passively cross-checks MTA-STS/DANE DNS policy against what the capture shows** ("domain says mail must be encrypted — why did this session use cleartext?"); README section "Bugs worth knowing about" documenting real incidents |
| [geetanshu17-tech/securemailscope](https://github.com/geetanshu17-tech/securemailscope) | Python, `backend/app/` | Dedicated `ml/fusion.py` combining rule-based + ML risk with a genuinely sound principle: *"deterministic evidence wins — a model may raise a session's priority but can never lower one below the rule-established severity"*; `fixtures/certificate_factory.py` + `tls_builder.py` for synthetic test data generation; explicit pipeline stage for **Forward Secrecy assessment**; strict evidence-claim discipline documented as a literal "says / does not say" table |
| [Astra-Innovators/SecureMailScope-Prototype](https://github.com/Astra-Innovators/SecureMailScope-Prototype) | Python | Real `sklearn.RandomForestClassifier` in `risk_engine.py` (verified — actual `.fit()` call on a small labeled feature set, `no_pfs` is literally one of its 8 input features); `anomaly_engine.py` (IsolationForest); real `pdf_builder.py`; SHA-256 evidence-integrity ledger; honest handling of TLS 1.3's passive-decryption limits |
| [pitu2k/Securemailscope](https://github.com/pitu2k/Securemailscope) | Python, packaged (`pyproject.toml`) | Docker + docker-compose; real `pdf_report.py`; proper `tests/`+`requirements-dev.txt`; rule-ID-based findings; `models/` dir present but empty (`.gitkeep` only — ML claimed in README, not yet committed) |
| [Dikshant0Git/SecureMailScope](https://github.com/Dikshant0Git/SecureMailScope) | **Node.js** (not Python) | Real, clean `spfParser.js`/`dmarcParser.js` (pure functions, unit-tested, JSDoc'd, cite their own internal build-spec section numbers); proves SPF/DKIM/DMARC isn't a Python-only pattern |
| [anushka2602/SecureMailScope](https://github.com/anushka2602/SecureMailScope) | Python, FastAPI + React | Standard passive pipeline + "combines rule-based security analysis with machine-learning-based risk classification and anomaly detection" per README (not independently source-verified beyond README) |
| [M-Tech-ops/SecureMailScope](https://github.com/M-Tech-ops/SecureMailScope) | React (frontend-only) | Clean `mockApi.js` API-shape abstraction so a real backend can be swapped in later without UI changes — a good pattern, no backend logic to evaluate |
| [mulugujayavenkatadattasai-333/securemailscope](https://github.com/mulugujayavenkatadattasai-333/securemailscope) | — | `Dockerfile` + `docker-compose.yml` + `Procfile` + `render.yaml` (actually deployment-ready to Render.com) + `generate_test_pcaps.py` (synthetic PCAP generator — useful standalone utility) |
| [souravpal11/securemailscope](https://github.com/souravpal11/securemailscope) | Python + React, Gmail OAuth | **Architecturally diverges from the spec**: uses `@react-oauth/google` + `gmail_connection.py` to analyze a live authenticated Gmail account rather than passive PCAP evidence. Interesting direction, but likely non-compliant with the "passive, no live server contact" requirement — flagged as a curiosity, not a feature to copy. |
| [xarjunpatil/SIH26159-...](https://github.com/xarjunpatil/SIH26159-SecureMailScope-AI-Assisted-Cryptographic-Security-Posture-Assessment-for) | — | Carries the literal official `problem_statement.json` — used as this doc's spec source, not a competing implementation |
| [BatthulaRajeswari](https://github.com/BatthulaRajeswari/SecureMailScope), [Arulesh-08](https://github.com/Arulesh-08/securemailscope), [bikramjitsamanta10-creator](https://github.com/bikramjitsamanta10-creator/SecureMailScope), [thanmaikrishnakelam-dot](https://github.com/thanmaikrishnakelam-dot/SecureMailScope), [sharanaks](https://github.com/sharanaks/SecureMailScope)/[Impana-Prakash](https://github.com/Impana-Prakash/SecureMailScope) (near-identical, likely shared template) | Python, small | Single-file or few-file prototypes (`analyzer.py`, `mock_scoring.py`, `ai_engine.py`) — early-stage, nothing beyond what we already have |

## Repos checked and confirmed trivial (empty scaffold, template boilerplate, or `node_modules` accidentally committed with no real backend logic)

`Atharva006`, `kris-5710`, `TeamPort587` (all-`.gitkeep` planned structure),
`akshaymede` (committed `node_modules`, no real source), `tejaswini7-bit`
(README only, ".zip.zip" placeholder), `CodeWithSantoshM07`,
`tatikondasai2006-debug/SecureEmailScope` (a zip file, unopened),
`tatikondasai2006-debug/-SecureMailScope-`, `Daddy-Dagger` (governance
files only — CODEOWNERS, CONTRIBUTING — no implementation yet), `Shrihare7734`.

---

## Prioritized recommendations for our repo

Ranked by (spec-required first) × (verified-real elsewhere) × (effort to
build here).

### Tier 1 — Do next (explicitly spec-required, verified real elsewhere, we're missing it)

1. **Fix the certificate pipeline** (not a competitor feature — our own
   confirmed-dead code, see
   [`Bugs-Found-and-Fixed.md`](Bugs-Found-and-Fixed.md)). This blocks 4 of
   our checks *and* every cert-dependent feature below it. Do this before
   anything else on this list, or the next two items are built on sand.
2. **AI/ML risk classifier** — explicitly required by the spec, not just a
   nice-to-have. Astra-Innovators' `RandomForestClassifier` and
   geetanshu17-tech's fusion approach are both small, honest, achievable
   patterns (a handful of engineered features — `legacy_tls`, `weak_cipher`,
   `no_pfs`, etc. — feeding a shallow classifier). Recommend
   geetanshu17-tech's fusion rule specifically: **the ML output can only
   raise a finding's priority, never suppress a rule-confirmed one** —
   avoids the failure mode where an ML layer silently hides a real
   deterministic finding.
3. **AI-assisted anomaly detection** — also explicitly spec-required, also
   currently absent from our repo. IsolationForest on the same feature
   vectors used for risk scoring is the path every team that built this
   took; low marginal effort once the risk-classifier features exist.
4. **Real PDF export endpoint** — spec explicitly lists PDF as a required
   export format. We currently only have client-side `window.print()`
   ("Print / Save as PDF"), not a server-generated file. Astra-Innovators'
   `pdf_builder.py` and pitu2k's `pdf_report.py` are both small, proven
   patterns (`weasyprint` or `reportlab` over the existing HTML report
   template is the least-effort route, since we already generate the HTML).

### Tier 2 — Worth doing, not spec-required but a real differentiator judges would notice

5. **SPF/DKIM/DMARC checking** — three independent teams (fredfe08 in
   Python, Dikshant0Git in Node.js, both verified as real code) built this.
   It's a whole security dimension (mail spoofing/phishing defense) the
   official spec doesn't ask for but that any judge with real email-security
   background will expect to see mentioned, since it's the other half of
   "is this email trustworthy" that TLS analysis alone doesn't cover.
   Requires DNS TXT record lookups (active, not passive — would need to be
   clearly labeled as a supplementary live check, not part of the passive
   PCAP claim).
6. **MTA-STS/DANE policy-vs-reality check** — MalharBhoi's standout idea.
   Genuinely clever and, unlike SPF/DKIM, stays 100% passive (it reads DNS
   records already present in the same capture, no live lookup needed) —
   arguably higher-value than item 5 for that reason alone, at similar
   effort.
7. **A–F / letter-grade posture summary** — cheap, presentation-only layer
   on top of our existing risk score. Purely a judge-facing legibility
   improvement (MalharBhoi does this well); no new detection logic needed.
8. **Evidence-strictness language** — fredfe08's `OBSERVED`/`NOT_FOUND`/
   `UNKNOWN`/`INSUFFICIENT_EVIDENCE` framing and geetanshu17-tech's explicit
   "says / does not say" table are both about the same thing: being precise
   about what a *passive* tool can and can't actually prove (e.g. can't
   prove a cert chain is complete if the intermediate wasn't in the
   capture). This is free to adopt in our existing finding/description text
   and meaningfully strengthens credibility in front of judges who know
   passive analysis' limits.

### Tier 3 — Nice ideas, low priority for us right now

9. **Synthetic PCAP/test-fixture generators** (`generate_test_pcaps.py`,
   `certificate_factory.py`/`tls_builder.py`) — good engineering hygiene,
   useful once we're iterating on detection logic more than once a week,
   not urgent today.
10. **Deployment manifests** (Docker/Render/Procfile, seen in
    mulugujayavenkatadattasai-333) — worth doing once the feature set
    stabilizes, premature before then.

### Skip

- **Live Gmail OAuth account analysis** (souravpal11) — architecturally
  contradicts the spec's "passive, no server contact" requirement. Not
  worth pursuing unless the team deliberately wants to reposition away from
  the passive-forensics angle, which would be a strategy call, not a
  feature addition.
- **Blockchain** — the SIH theme tag is "Blockchain & Cybersecurity," but
  nothing in the official spec's deliverable list asks for it, and no
  competitor repo surveyed (including the biggest ones) implements anything
  blockchain-related. Treat the theme tag as NTRO's category label, not a
  literal requirement.
