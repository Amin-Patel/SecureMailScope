# SIH26159 Competitive Landscape — SecureMailScope Implementations

## What this is

SecureMailScope is [SIH26159](https://sih.gov.in), an official Smart India
Hackathon 2026 problem statement sponsored by the National Technical
Research Organisation (NTRO), theme "Blockchain & Cybersecurity." At least
35+ independent teams have public GitHub repos building their own
implementation of the same spec, and the field is moving fast — see the
update log below. This doc surveys them, verifies which README-claimed
features actually exist in code (several don't), and prioritizes what's
worth building into **our** repo
([Amin-Patel/SecureMailScope](https://github.com/Amin-Patel/SecureMailScope))
next.

**Method:** `gh search repos "SecureMailScope"`, then for each repo with
non-trivial size, fetched the README and full file tree via the GitHub API
and spot-checked source files directly for any feature claimed in a README
— READMEs are marketing copy, source files are the ground truth.

## Update log

- **2026-09-09**: initial survey, ~16 of 28 repos worth reading.
- **2026-09-16**: re-checked. Several repos that were empty scaffolds a
  week ago are now the most sophisticated implementations in the field —
  see "New/escalated since last survey" below. The pace here is fast:
  don't treat this doc as static, re-run the method above before relying
  on any "we're ahead" claim.
- **2026-09-17**: no new repos or pushes since 09-16 (checked). Dug deeper
  into three repos' actual source (not just READMEs) that had only been
  surface-checked before — see the three new Tier 2 items below
  (server-config remediation snippets, per-server behavioral
  fingerprinting, live/continuous monitoring architecture).

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

## New / escalated since last survey (2026-09-16 update)

The single biggest change: **AI/ML risk scoring and anomaly detection —
Tier 1 item #2/#3 below — went from "nobody has really built this" to
"multiple teams have working, tested, committed models" in one week.**
This is no longer a theoretical spec requirement; it's a demonstrated,
shipped capability elsewhere.

| Repo | Stack | What's real |
|---|---|---|
| [TeamPort587/SecureMailScope](https://github.com/TeamPort587/SecureMailScope) | Python/Django | Was an empty `.gitkeep` scaffold on 09-09; is now, by a wide margin, **the most rigorous ML engineering of any repo surveyed**. A `ml/training/` pipeline with ablation studies (`ablation.py`), cross-validation, a leakage audit (`leakage_audit.py` — actively checks the model isn't cheating on held-out data), robustness evaluation against partial captures, confidence calibration, a "perfect model audit" (flags suspiciously-perfect scores as a leakage smell), model-selection policy, and a **13-file dedicated ML test suite** (`tests/ml/`). A real committed model (`ml/artifacts/risk_model.joblib`) plus a full report bundle (confusion matrix, feature importances, cross-validation report). Also runs a local LLM via Ollama (`ollama/Modelfile`) rather than a cloud API. This is the bar to know about even if not fully matched. |
| [saravana-rr0411/SecureMailScope](https://github.com/saravana-rr0411/SecureMailScope) | Python + React | New (first seen 09-11, still actively growing). Explicit architectural separation of deterministic rules / unsupervised anomaly detection / supervised risk scoring. `crypto_risk_scorer.py`: a `RandomForestClassifier` over a genuinely large engineered feature vector (protocol layer, STARTTLS state, TLS version, cipher AEAD/CBC characterization). `anomaly_detector.py` alongside it. **A 1.4MB trained model file actually committed** (`crypto_risk_model.joblib`) and a full per-module test suite. |
| [S-Vetrivel/SecureMailScope-SIH](https://github.com/S-Vetrivel/SecureMailScope-SIH) | **Go (parser + API) + Python (AI)** | The only repo surveyed using Go (`gopacket`) for packet parsing and Gin+PostgreSQL for the API — a deliberate performance-oriented architecture choice none of the Python-only teams made. AI engine explicitly uses **XGBoost + IsolationForest** (gradient boosting, not just Random Forest) plus a dedicated `remediation.py` for AI-driven fix suggestions. |
| [gouravsehlangia/SecureMailScope](https://github.com/gouravsehlangia/SecureMailScope) | Python | Grew from a 22KB stub to 926KB. Real `sklearn.IsolationForest` anomaly detection over an 8-feature vector (TLS version, cipher, key exchange, protocol, STARTTLS, forward secrecy, cert expiry, chain validity). Also built something genuinely novel: `keylog_manager.py` parses **NSS SSLKEYLOGFILE** data to decrypt TLS 1.3 handshakes and recover the Certificate message — solving the "TLS 1.3 hides certs from passive analysis" limitation that every other team (us included) just documents as unavoidable. Only works if session keys were captured (e.g. a demo/test environment with `SSLKEYLOGFILE` set), so it doesn't help against arbitrary real-world captures, but it's a legitimately clever answer to a limitation we've been treating as a hard wall. |
| [dhanush-girish/securemailscope](https://github.com/dhanush-girish/securemailscope) | Python | New (09-16). Explicit two-phase framing: "Phase 1 capture & parsing" feeding a "Phase 2 AI/ML pipeline" with a live dashboard. Worth a closer look once it matures further. |
| [ashwini-1608/SecureMailScope](https://github.com/ashwini-1608/SecureMailScope) | Python | New (09-15). Frames its goal as detecting *deviations from a server's own usual cryptographic behavior* rather than generic anomaly detection — a per-server baseline framing, more sophisticated than a flat classifier. Heavy investment in synthetic TLS test fixtures (multiple `.pcapng` scenarios covering TLS 1.2/1.3, multi-session captures). |
| [pm534485/SecureMailScope](https://github.com/pm534485/SecureMailScope) | Python | New (09-15), early-stage but has `backend/ml/training.py` + `inference.py` as a dedicated split from day one. |
| [ganeshparmarit-lgtm/securemailscope](https://github.com/ganeshparmarit-lgtm/securemailscope) | **Java (Spring Boot)** | New (09-11), currently just the default Spring Boot bootstrap — no real feature code yet. Notable only as the first entirely different-language entrant (everyone else is Python/Node/Go). |

## Repos checked and confirmed trivial (empty scaffold, template boilerplate, or `node_modules` accidentally committed with no real backend logic)

`Atharva006`, `kris-5710`, `akshaymede` (committed `node_modules`, no real
source), `tejaswini7-bit` (README only, ".zip.zip" placeholder),
`CodeWithSantoshM07`, `tatikondasai2006-debug/SecureEmailScope` (a zip
file, unopened), `tatikondasai2006-debug/-SecureMailScope-`,
`Daddy-Dagger` (governance files only — CODEOWNERS, CONTRIBUTING — no
implementation yet), `Shrihare7734`, `Jxgxn-007` (empty repo),
`thanmaikrishnakelam-dot/SecureMailScope-V2` and
`-_webDashboard` (tiny spinoffs, not substantial),
`ganeshparmarit-lgtm` (see table above — real stack choice, no real
content yet). Note `TeamPort587` **moved out of this list** this update —
see above.

---

## Prioritized recommendations for our repo

Ranked by (spec-required first) × (verified-real elsewhere) × (effort to
build here).

### Tier 1 — Do next (explicitly spec-required, verified real elsewhere, we're missing it)

1. ~~**Fix the certificate pipeline**~~ — **done.** Was our own
   confirmed-dead code (see [`Bugs-Found-and-Fixed.md`](Bugs-Found-and-Fixed.md)),
   fixed on `feature/rag-knowledge-base`, then superseded by a teammate's
   full chain/CA-trust-validation implementation on `main` (see
   [`Teammate-Deliverables-3-and-4.md`](Teammate-Deliverables-3-and-4.md)).
   Forward secrecy assessment was also built and is live. Both merged.

2. ~~**AI/ML risk classifier + anomaly detection**~~ — **done**, on
   `feature/ml-risk-classifier`. A `RandomForestClassifier` + `IsolationForest`
   over the session-level feature vector recommended below, kept
   architecturally separate from `SecurityEngine` (the deterministic/
   unsupervised/supervised split several competing teams converged on
   independently), with the geetanshu17-tech fusion rule adopted as
   designed (ML can only raise the risk level, never suppress a
   rule-confirmed finding).

   Crucially, this could **not** be built on any of the datasets
   competitors published or that our own teammate sourced (ISCXTor2016's
   flow-level CSVs turned out to have no TLS/cipher/certificate columns at
   all — wrong shape for this task, see
   [`Bugs-Found-and-Fixed.md`](Bugs-Found-and-Fixed.md) if we ever revisit
   that corpus). We also explicitly ruled out reusing a competitor's
   trained model or code: this is a judged competition, and shipping
   another team's artifact is a plagiarism/disqualification risk regardless
   of the repo being public, on top of being a model we couldn't defend to
   judges since we didn't build it. Instead, trained on synthetic data
   distilled from our own `SecurityEngine` rules (every TLS version x
   cipher x certificate x STARTTLS combination, labeled by max-severity-wins
   over the same conditions the rule engine already checks), folded
   together with real sessions from our demo captures through the same
   extraction path — so real PCAPs slot in later with zero rework, they
   just become more training rows.

   **Update 09-17**: the registration went through and `Tor.zip` (11GB)
   was downloaded — but it turned out to be a dead end specifically for
   this purpose. The archive is split by category (a relief — no need to
   filter an undifferentiated blob), and the four `MAIL_*.pcap` files
   extract to a manageable ~350MB total, but every one of them is
   **Tor-anonymized traffic**: every connection is generic port 443 (with
   Tor's own relay ports 9001/9010 visible in the mix, confirming it),
   zero TLS SNI, zero visible certificate data. That's Tor working as
   designed, not a parsing failure — the real destination (Gmail's actual
   IMAP/POP servers) is hidden inside the encrypted Tor circuit, invisible
   to a passive capture at the client. The dataset's whole point is Tor-
   vs-non-Tor traffic classification, so of course the "Tor" scenario
   routes everything through Tor. What we'd actually need is the
   **`nonTor`** counterpart on the same CIC page — direct, non-anonymized
   captures with real visible SNI/certificates. Not yet downloaded.

   Applied a real, if miniature, version of **TeamPort587's leakage-audit
   habit** rather than skipping it: deduplicated the combined
   synthetic+real dataset before the train/test split (a duplicate row
   landing in both sets is the actual leakage risk here, not raw accuracy
   magnitude — labels are a deterministic function of the features, so
   near-1.0 held-out accuracy is expected, not a smell by itself). Held-out
   test accuracy 97.6%, with errors concentrated in the low-support
   LOW/MEDIUM classes as expected, not a suspiciously perfect score.
   Verified against all three real demo captures, not just synthetic data.

   Building this against real captures also surfaced two real bugs (see
   `Bugs-Found-and-Fixed.md` #6): the synthetic generator had never
   actually produced an "unrecognized cipher" training example, and —
   more significantly — `tshark_helper.py` has been mislabeling every TLS
   1.3 session as "TLS 1.2" (RFC 8446 freezes the outer record-layer
   version for TLS 1.3; the real version is in an extension nothing here
   parses). Worked around in the ML feature extractor and confirmed via a
   real measured confidence jump (77.9% → 94.2%) once fixed, but still
   open at the source in `tshark_helper.py`.

   Not pursued: gouravsehlangia's SSLKEYLOGFILE-based TLS 1.3 decryption
   (clever, but only useful in controlled demo environments where we
   control key logging — noted here in case we want TLS 1.3 cert findings
   to work in a live demo later).

3. **Real PDF export endpoint** — spec explicitly lists PDF as a required
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
9. **Copy-paste server-config remediation, not prose** —
   [S-Vetrivel](https://github.com/S-Vetrivel/SecureMailScope-SIH)'s
   `ai_engine/remediation.py` maps each finding to actual Postfix/Dovecot/
   Nginx/OpenSSL config blocks (e.g. real
   `smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1`
   snippets ready to paste into `/etc/postfix/main.cf`), verified in
   source. Our `remediation` field is numbered prose ("1. Disable SSL 3.0
   on all mail servers immediately"). This is a genuinely low-effort,
   high-credibility upgrade — we already know which finding maps to which
   fix; it's a matter of writing real config syntax instead of English
   instructions for each of our nine finding types.
10. **Per-server behavioral fingerprinting** (bigger lift, not a quick
    add) — [ashwini-1608](https://github.com/ashwini-1608/SecureMailScope)
    doesn't compare a session against a *global* notion of "risky." It
    builds a fingerprint per mail server (the observed distribution of TLS
    version/cipher/forward-secrecy/cert-issuer/key-size across every
    session seen from that server) and flags deviation from that server's
    own history:
    `deviation = 1 - frequency of the observed value in the server's fingerprint`.
    This would catch a real downgrade attack our (and every other team's)
    flat IsolationForest could miss — a server that's used TLS 1.3 in
    every session suddenly showing TLS 1.2 is a strong signal even though
    TLS 1.2 alone isn't "weak." Requires a persistent per-server profile
    store; we're currently stateless (one PCAP in, one report out), so
    this is a real architectural change, not a feature bolt-on.
11. **Live/continuous monitoring, not just batch upload** (also a bigger
    lift) — [dhanush-girish](https://github.com/dhanush-girish/securemailscope)
    built a file watcher (`watch_and_forward.py`) that forwards newly
    captured sessions into the pipeline automatically, plus a `/history`
    API and a dashboard that polls for live updates. Every team surveyed,
    us included, is "upload one PCAP, get one report." This is
    architecturally closer to the official spec's language about
    assisting a SOC in real time. Worth knowing about even if a
    live-capture rebuild isn't realistic before a deadline.

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

---

## Appendix: every repo found, alphabetical

Full `gh search repos "SecureMailScope"` result set as of 2026-09-16, for
reference — cross-check this list before claiming "we checked everyone."
Repos discussed above aren't re-annotated here; see the sections above for
what's actually in them.

- [Amin-Patel/SecureMailScope](https://github.com/Amin-Patel/SecureMailScope) — us
- [Arulesh-08/securemailscope](https://github.com/Arulesh-08/securemailscope)
- [Astra-Innovators/SecureMailScope-Prototype](https://github.com/Astra-Innovators/SecureMailScope-Prototype)
- [Atharva006/securemailscope](https://github.com/Atharva006/securemailscope)
- [BatthulaRajeswari/SecureMailScope](https://github.com/BatthulaRajeswari/SecureMailScope)
- [CodeWithSantoshM07/SecureMailScope-AI](https://github.com/CodeWithSantoshM07/SecureMailScope-AI)
- [Daddy-Dagger/SecureMailScope](https://github.com/Daddy-Dagger/SecureMailScope)
- [Dikshant0Git/SecureMailScope](https://github.com/Dikshant0Git/SecureMailScope)
- [Impana-Prakash/SecureMailScope](https://github.com/Impana-Prakash/SecureMailScope)
- [Jxgxn-007/SecureMailScope](https://github.com/Jxgxn-007/SecureMailScope) — empty
- [M-Tech-ops/SecureMailScope](https://github.com/M-Tech-ops/SecureMailScope)
- [MalharBhoi/SecureMailScope](https://github.com/MalharBhoi/SecureMailScope)
- [S-Vetrivel/SecureMailScope-SIH](https://github.com/S-Vetrivel/SecureMailScope-SIH)
- [Shrihare7734/SecureMailScope](https://github.com/Shrihare7734/SecureMailScope)
- [TeamPort587/SecureMailScope](https://github.com/TeamPort587/SecureMailScope)
- [akshaymede/SecureMailScope](https://github.com/akshaymede/SecureMailScope)
- [anushka2602/SecureMailScope](https://github.com/anushka2602/SecureMailScope)
- [ashwini-1608/SecureMailScope](https://github.com/ashwini-1608/SecureMailScope)
- [bikramjitsamanta10-creator/SecureMailScope](https://github.com/bikramjitsamanta10-creator/SecureMailScope)
- [dhanush-girish/securemailscope](https://github.com/dhanush-girish/securemailscope)
- [fredfe08/SecureMailScope](https://github.com/fredfe08/SecureMailScope)
- [ganeshparmarit-lgtm/securemailscope](https://github.com/ganeshparmarit-lgtm/securemailscope)
- [geetanshu17-tech/securemailscope](https://github.com/geetanshu17-tech/securemailscope)
- [gouravsehlangia/SecureMailScope](https://github.com/gouravsehlangia/SecureMailScope)
- [kris-5710/securemailscope](https://github.com/kris-5710/securemailscope)
- [mulugujayavenkatadattasai-333/securemailscope](https://github.com/mulugujayavenkatadattasai-333/securemailscope)
- [pitu2k/Securemailscope](https://github.com/pitu2k/Securemailscope)
- [pm534485/SecureMailScope](https://github.com/pm534485/SecureMailScope)
- [saravana-rr0411/SecureMailScope](https://github.com/saravana-rr0411/SecureMailScope)
- [sharanaks/SecureMailScope](https://github.com/sharanaks/SecureMailScope)
- [souravpal11/securemailscope](https://github.com/souravpal11/securemailscope)
- [tatikondasai2006-debug/-SecureMailScope-](https://github.com/tatikondasai2006-debug/-SecureMailScope-)
- [tatikondasai2006-debug/SecureEmailScope](https://github.com/tatikondasai2006-debug/SecureEmailScope)
- [tejaswini7-bit/securemailscope-intelligence](https://github.com/tejaswini7-bit/securemailscope-intelligence)
- [thanmaikrishnakelam-dot/SecureMailScope](https://github.com/thanmaikrishnakelam-dot/SecureMailScope)
- [thanmaikrishnakelam-dot/SecureMailScope-V2](https://github.com/thanmaikrishnakelam-dot/SecureMailScope-V2)
- [thanmaikrishnakelam-dot/SecureMailScope-_webDashboard](https://github.com/thanmaikrishnakelam-dot/SecureMailScope-_webDashboard)
- [xarjunpatil/SIH26159-SecureMailScope-AI-Assisted-Cryptographic-Security-Posture-Assessment-for](https://github.com/xarjunpatil/SIH26159-SecureMailScope-AI-Assisted-Cryptographic-Security-Posture-Assessment-for) — carries the official problem statement JSON, used as this doc's spec source
