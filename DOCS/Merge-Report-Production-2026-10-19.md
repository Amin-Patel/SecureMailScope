# Merge Report — branch `Production` — 2026-10-19

Three diverged branches reconciled onto one branch, `Production`, based on
`Abuzer` (`3974bc9`). Nothing was pushed; `Abuzer`, `Amin`, `Yash` and `main`
are unchanged. All work happened in an isolated git worktree.

Tags used below: **[executed]** = run and measured here. **[code-read]** = read
from source, not run.

## 0. How to read the numbers

- Every number is from a run performed on this branch, in
  `.claude/worktrees/agent-a330a6552cd5e38e3`, with the interpreter
  `backend\venv\Scripts\python.exe` invoked as `python -I -X utf8`, from an
  explicit `cd` into this worktree's `backend\`, with driver scripts kept in a
  separate scratchpad directory and the worktree paths passed as arguments.
- **Dependencies came from that pre-existing venv, not from
  `backend/requirements.txt`.** Nothing was installed into it. The venv is
  missing four packages the branch declares — `PyJWT`, `slowapi`, `pytest` and
  `scapy` — and the consequences of each are stated explicitly below rather than
  papered over.
- `tshark` 4.6.x at `C:\Program Files\Wireshark\tshark.exe`, resolved through
  `TSharkHelper.get_tshark_path()`. **[executed]**
- Each driver printed `__file__` for `main`, `cert_analyzer`, `tshark_helper`,
  `security_engine` and `pcap_analyzer` before doing anything, so the tree under
  test is unambiguous; every path printed resolved inside this worktree.

## 1. Branch and commits

`Production` = `5f83c16`, eleven commits on `3974bc9` (this report's own commit
is the twelfth and final one):

| SHA | Subject |
|---|---|
| `c9dc32d` | docs: take the full DOCS/ set from branch Yash |
| `014a8d2` | feat: port Amin's crypto state engine, evidence assessment engine and provenance DAG |
| `5d6531f` | fix(F42/F37): make weak-cipher evidence deterministic and complete |
| `f1b3cc0` | feat: wire the ported engines and provenance DAG into the trunk backend |
| `2207638` | feat(frontend): port the provenance DAG view and assessment panels |
| `ce52070` | chore: remove duplicates and stale artefacts, untrack uploads and results |
| `a8e84b5` | chore(deps): reconcile declared dependencies with what the merged code imports |
| `4fcfce6` | test: reconcile the ported backend tests with the hardened trunk |
| `74abf95` | chore: take .claude/launch.json from Yash; drop obsolete compose version key |
| `aa42590` | docs: add the Production merge report (this file, first revision) |
| `5f83c16` | fix: stop the DAG citing non-negotiating handshakes, and finish F40 |

`git diff --shortstat 3974bc9 HEAD` → **168 files changed, 11,578 insertions,
10,212 deletions** (measured at `5f83c16`, before this report was committed) (the deletions are overwhelmingly the 111 untracked
upload/result blobs).

**`git merge Amin` was never run.** A branch merge produces eight content
conflicts and — the real hazard — silently auto-merges `tshark_helper.py`,
which would land F38's broken TLS-version change on the trunk with no conflict
prompt. Everything from `Amin` arrived as a deliberate file-level addition.

## 2. What came from where

### From `Yash` (documentation only — its code is an ancestor of the trunk)
The whole of `DOCS/`: the September audit (F7–F34), the force-push forensics
(F35–F41), the `4bb0bdc` verification (F42–F59), the enterprise landscape, the
feature backlog, and newer revisions of three existing docs. Plus
`.claude/launch.json`, the project's dev-server launcher, which the trunk lacked.

### From `Abuzer` (`3974bc9`) — the base
Everything else: RAG knowledge base, ML risk classifier and anomaly detector,
SPF/DKIM/DMARC, PDF/HTML/JSON export, A–F grading, folder watcher, SSLBL threat
intel, the DER-based certificate pipeline, the IANA cipher-suite registry, the
auth/IDOR hardening, `sanitizer.py`, `docker-compose.yml`, `nginx.conf`,
`AuthCallback.jsx`, and the three test files that exist nowhere else.

### From `Amin` (`4bb0bdc`) — accepted
| What | Taken how |
|---|---|
| `backend/app/core/crypto_state_engine.py` | unchanged |
| `backend/app/core/evidence_assessment_engine.py` | unchanged |
| `backend/app/services/provenance_service.py` | plus two integration fixes (§4) |
| `backend/tests/test_{crypto_state_reasoning,evidence_based_assessment,evidence_provenance_navigation,provenance_dynamic_matrix,provenance_graph}.py` | the last one reconciled (§7) |
| `frontend/tests/*.test.mjs` | two files' path roots fixed (§7) |
| `ProvenanceGraph.jsx`, `ProvenanceCustomNodes.jsx`, `ProvenanceDetailsDrawer.jsx` (the drawer scroll fix), `CryptographicStateAssessment.jsx`, `EvidenceBasedAssessment.jsx`, `pages/EvidenceProvenance.{jsx,css}`, `utils/resolveGraphNode.js` | unchanged |
| `@xyflow/react ^12.12.0` + regenerated `frontend/package-lock.json` | declared and resolved |
| `backend/test-data/SecureMailScope_SIHDemo.pcap` + its preset | capture unchanged, preset metadata re-measured (F40) |
| `BASE_DIR` fix in `main.py` | `.resolve()` only (§4) |
| `sys.stdout/stderr` UTF-8 guard from `7cd4866` | ported |
| `LICENSE` (MIT) | unchanged |
| `/provenance` routes, nav entry, API helpers, Analysis panels | hand-merged (§5) |

### From `Amin` — rejected, with reasons
| Rejected | Why |
|---|---|
| every edit to `backend/app/utils/cert_analyzer.py` | hardcodes `key_size = 1024` (F35) and parses DNs positionally so self-signed never fires (F36). The trunk measures both from the DER. |
| every edit to `backend/app/utils/tshark_helper.py` | the `record.version` → `handshake.version` change does not fix the TLS-1.3 mislabel and loses the version on most handshake records (F38). |
| every edit to `backend/app/core/security_engine.py` | superseded by the trunk's IANA registry; only the deliberate F42/F37 hunk was applied. |
| every edit to `backend/app/core/pcap_analyzer.py` | the trunk's version is strictly ahead; the two engines were wired in `main.py` instead so this file stays byte-identical. |
| `GET /results` write-back | a read endpoint that rewrites the stored forensic artefact (F46). Back-fill is now in-memory only. |
| unauthenticated `/provenance` endpoints | reopened IDOR on the hardened trunk; re-implemented behind `sanitize_capture_id` + `check_resource_ownership`. |
| `BASE_DIR` cwd fallback (`… if (BASE_DIR/"uploads").exists() else Path("uploads")`) | the trunk already creates those directories under `BASE_DIR`, so the fallback only ever redirects writes to the cwd. |
| `README.md` | describes two state vocabularies that occur zero times in the code and a Tailwind dependency that does not exist (F45, F53). Not shipped rather than shipped wrong. |
| `cryptography>=42,<47` pin | the trunk's DER pipeline is built against the newer API; `>=48,<51` kept. |
| lowercase `docs/` tree, top-level `test-data/`, `SecureMailScope_SIHDemo_Enhanced.pcap`, `docs/testing/` duplicates, `deployment/deploy-to-server.ps1` | duplicates, a case-collision risk on Windows, or personal infrastructure on a public repo (F51, F54). |

**Leak check [executed]:** `git diff 3974bc9 HEAD` over
`cert_analyzer.py`, `tshark_helper.py` and `pcap_analyzer.py` is **empty** —
all three are byte-identical to the trunk. `security_engine.py` differs by
exactly the F42/F37 hunk (13 insertions, 5 deletions).

## 3. The verification gate

Amin's own `SecureMailScope_SIHDemo.pcap`, through the merged pipeline on this
branch. **[executed]**

```
Found 21 TLS handshakes / 112 email packets
Reconstructed 8 sessions across 10 TCP streams
Extracted 4 unique certificates (6 handshake chains)
Found 16 security issues
Risk Score: 100/100 (CRITICAL)   grade F
```

**16 findings** — trunk quality. Amin's branch produced 6 on the same capture.

Certificates, as the pipeline reports them **and** inside the provenance DAG's
`certificate` nodes:

| DAG node | CN | key_size | is_self_signed | Expected |
|---|---|---|---|---|
| `cert:frame_6_0` | `www.snakeoil.dom` | **1024** | **false** | 1024, not self-signed ✓ |
| `cert:frame_89_1` | `smtp-modern.demo.local` | **2048** | **true** | 2048, self-signed ✓ |
| `cert:frame_99_2` | `smtp-expired.demo.local` | **1024** | **true** | 1024, self-signed ✓ |
| `cert:frame_165_3` | `smtp-future.demo.local` | **2048** | **true** | 2048, self-signed ✓ |

All four match. No `1024/false` quartet, so no rejected file leaked into the
merge. This single check covers **F35, F36 and F43**.

The node ids also now carry the real capture frames (6/89/99/165) rather than
the list indices 1–4 — see §4.

## 4. Changes made to ported code

Two integration fixes in `provenance_service.py`, both forced by the move from
Amin's stale base to the trunk:

1. **Certificate frame key.** The builder read `cert['frame']`; the trunk's DER
   pipeline emits `frame_number`. Every certificate node was silently falling
   back to its list index, so the DAG cited "Frame 1–4" for certificates that
   are at frames 6, 89, 99 and 165. Now accepts either key. **[executed]**
2. **F57 — evidence linkage (`findings_linked` 5/16 → 16/16).** The
   finding-type ladder knew only `weak_signature`, `insufficient_key_size`,
   `expired_certificate` and `self_signed_certificate`. The trunk consolidates
   PKI findings under `certificate_pki` and adds `no_forward_secrecy` and
   `email_authentication`, so 11 of 16 findings linked to an abstract rule node
   and nothing else — the chain of custody terminating in a policy statement
   rather than an artefact, silently. Three branches were added:
   `certificate_pki` (resolved by the frame cited in the evidence, falling back
   to subject CN), `no_forward_secrecy` (handshakes with a static key exchange)
   and `email_authentication` (matched on the TCP stream id the finding cites).
   Measured on the demo capture: **59 nodes, 126 edges, findings_linked 16,
   findings_unlinked 0**. **[executed]**
3. **Two linkage branches asserted things the capture does not show.** Edge
   count is not evidence quality, and citing an artefact that does not support
   a finding is the exact failure mode F43 describes, so every
   `SUPPORTS_FINDING` edge was dumped with its source node's handshake type and
   cipher list and checked by hand. **[executed]**
   - `no_forward_secrecy` tested `'DHE' not in cipher_names`, but tshark
     reports cipher suites as hex codes (`0x0035`, `0xc02f`), so the test was
     true for every handshake carrying any cipher: **14 handshakes linked,
     including six ClientHello offer lists and the three ECDHE ServerHellos at
     frames 89/126/155, which are forward-secret.** It now mirrors
     `check_forward_secrecy` — ServerHello only, TLS 1.3 skipped, verdict taken
     from the registry's `forward_secret` flag. Measured after the fix: frames
     **6, 27, 99, 165**, the four static-RSA ServerHellos, matching the
     finding's own evidence string.
   - `weak_cipher` (Amin's branch, originally kept as-is) matched a hardcoded
     hex set across *all* handshakes and so cited the frame-25 ClientHello's
     20-suite offer list as proof of negotiation — **F37 re-appearing inside
     the DAG after being fixed in the engine.** Now ServerHello only, through
     the same IANA registry. Measured after the fix: **frame 27 alone**, the
     ServerHello that negotiated 3DES.
   - `deprecated_protocol` links all 11 SSL 3.0 handshake records, which is
     consistent with the finding's own text ("11 TLS handshakes using SSL
     3.0"), so it was left alone.

   Edges fall from 146 to 126; nodes, findings and linked/unlinked are
   unchanged.

`BASE_DIR` in `main.py` became `Path(__file__).resolve().parent`; Amin's cwd
fallback was not taken (reason in §2).

## 5. Hand-merged files

Three-way merged against the `070d84d` merge base with `git merge-file`, not by
picking a side:

| File | Result |
|---|---|
| `frontend/src/index.css` | clean three-way merge, additive on both sides |
| `frontend/src/App.jsx` | trunk's routes + the two `/provenance` routes, inside the trunk's `ProtectedRoute` |
| `frontend/src/components/Layout.jsx` | taken from Amin wholesale (the trunk never changed it) |
| `frontend/src/utils/api.js` | Amin's two provenance calls appended to the trunk's authenticated axios client, so they carry the bearer token |
| `frontend/src/pages/Analysis.jsx` | **five conflicts, all resolved as unions.** Tab bar is Amin's richer version with the trunk's "Certificates & PKI" tab restored; the sessions table keeps the trunk's "Follow Stream" button *and* gains Amin's "Graph" jump; imports keep `StreamViewerModal` and `CertChainTree` alongside the three new panels. No feature from either side was dropped. |

## 6. Feature inventory — every row executed on `Production`

| # | Feature | Command / call | Observed | Verdict |
|---|---|---|---|---|
| 1 | PCAP ingest + protocol detection | `EmailPCAPAnalyzer(SIHDemo).analyze()` | 112 email packets; SMTP, SMTP-Submission, SMTP-Alt, IMAP, IMAPS, POP3, POP3S, SMTPS | **executed** |
| 2 | TCP stream reassembly | same run | 8 sessions across 10 TCP streams | **executed** |
| 3 | Credential redaction + stream viewer | `GET /api/analysis/{id}/stream/0` | 200; `redacted`/`redaction_count` present; 37 packets, 14,109 payload bytes | **executed** |
| 4 | Certificate chain + expiry + key size + signature algorithm | same run | 4 certs / 6 chains; `pki_findings` `CERT_EXPIRED`, `CERT_UNTRUSTED_CA`, `CERT_SELF_SIGNED`; sig algos `md5WithRSA`, `sha1WithRSA`, `sha256WithRSA`; key sizes 1024/2048/1024/2048 | **executed** |
| 5 | Weak cipher (IANA registry, negotiated only) | finding `weak_cipher` | `Negotiated weak cipher(s): TLS_RSA_WITH_3DES_EDE_CBC_SHA (3DES (Sweet32))` | **executed** |
| 6 | Deprecated protocol | finding `deprecated_protocol` | `11 TLS handshakes using SSL 3.0` | **executed** |
| 7 | Forward secrecy | finding `no_forward_secrecy` | three static-RSA sessions named with cipher and version | **executed** |
| 8 | Plaintext detection | finding `plaintext_protocol` | `82 plaintext packets … SMTP, IMAP, SMTP-Submission, POP3, SMTP-Alt` | **executed** |
| 9 | STARTTLS detection | demo `vulnerable_smtp` | `No STARTTLS Negotiation Detected — 2 SMTP sessions on port 25/587 without STARTTLS` | **executed** |
| 10 | SPF/DKIM/DMARC — passive | `email_auth` in result | `passive: true`, 3 messages analysed, 3 plaintext / 5 encrypted streams, `dkim_signed: 0`, `spf.not_asserted: 3` | **executed** |
| 11 | SPF/DKIM/DMARC — active DNS | `POST /api/email-auth-check {"domain":"gmail.com"}` | 200 in 23.9 s; SPF `pass` (`v=spf1 redirect=_spf.google.com`), DMARC `warn` (`p=none`), DKIM `not_found` across 9 selectors | **executed (live DNS)** |
| 12 | ML risk classifier + anomaly detector | same run | 7 sessions scored; `ml_risk_level CRITICAL`, per-session `ml_confidence` 0.90–0.99, `anomaly_score` present; `risk_classifier.joblib` + `anomaly_detector.joblib` loaded | **executed** |
| 13 | A–F grading | four demos | F (SIH 100), F (legacy_ssl3 80), E (vulnerable_smtp 57), A (secure_enterprise 0) | **executed** |
| 14 | RAG knowledge base | `get_knowledge_base().list_sources()`; findings | 12 curated sources; 12 of 16 findings carry `ai_reference` quoting KB text; `ai_source = SecureMailScope-Intelligence-Engine` | **executed (offline retrieval engine; no `GEMINI_API_KEY`)** |
| 15 | Crypto state engine | `CryptographicStateEngine(...).evaluate()` | `CRYPTOGRAPHIC_FAILURE`; 10 normalized rules; 2 cross-property insights; 0 unresolved conditions | **executed** |
| 16 | Evidence assessment engine | `EvidenceAssessmentEngine(...).evaluate()` | 11 assessed: 0 satisfied / 8 violated / 2 indeterminate / 1 undefined | **executed** |
| 17 | Provenance DAG | `ProvenanceGraphBuilder(...).build()` + both endpoints | 59 nodes, 126 edges, 7 node types, findings_linked 16, unlinked 0; every `SUPPORTS_FINDING` edge audited by hand (§4) | **executed** |
| 18 | JSON / HTML / PDF export | `GET /report?format=…` | 200 / 186,183 B `application/json`; 200 / 39,792 B `text/html`; 200 / 36,502 B `application/pdf`; invalid format → 422 | **executed** |
| 19 | Folder watcher | `PcapWatcher(backend/watch, …)`, file dropped in | picked up `dropped_by_inventory.pcap`, analysed in 1.0 s, status `completed`, `capture_id watch_dropped_by_inventory_7e9ae4` | **executed** |
| 20 | SSLBL threat intel | `get_threat_intel_feed()` | downloaded `sslbl.abuse.ch/blacklist/sslblacklist.csv`, cached 839,711 B, **10,997** fingerprints; positive lookup → `{'listed_since': '2026-10-18 12:25:30', 'reason': 'PureLogsStealer C&C'}`; negative lookup → `None` | **executed (live fetch)** |
| 21 | Auth hardening | TestClient | anonymous `POST /api/upload` → 401, `GET /api/analyses` → 401, `POST /api/admin/kb/articles` → 401 | **executed** |
| 22 | IDOR hardening | two users via `dependency_overrides` | user B against user A's capture: results 403, provenance 403, provenance node 403, report 403, stream 403, delete 403, batch-delete `deleted_count: 0` | **executed** |
| 23 | Path-traversal protection | 10 probes on `/results` and `/provenance` | `..%2F..%2Fsecret` → 404, `a%5C..%5Cb` → 400, `..` → 404, `with spaces` → 400, `x;y` → 400 | **executed** |
| 24 | Knowledge-base admin / gap endpoints | 5 calls | sources 200, gaps 200, pending 200, kb/articles 200, gap-propose → 503 with an honest "requires GEMINI_API_KEY, there is no offline drafting path" | **executed** |
| 25 | Demo presets | `GET /api/demo/samples` + 4 loads | advertised `HIGH (57/100, grade E)`, `CRITICAL (80/100, grade F)`, `LOW (0/100, grade A)`, `CRITICAL (100/100, grade F)`; measured 57/HIGH/E, 80/CRITICAL/F, 0/LOW/A, 100/CRITICAL/F — **all four match** | **executed** |
| 26 | docker / nginx | `docker compose config` | exit 0; backend service, healthcheck, ports and 4 named volumes resolved. `nginx.conf` present (4,072 B) | **config validated; not built, not run** |
| 27 | Frontend build | `npm ci`; `npm run build` | `npm ci` 5.1 s, 157 packages; build 328 modules in ~210 ms, only a chunk-size advisory. `@xyflow/react@12.12.0` resolved and bundled | **executed** |
| 28 | Frontend pages | `vite dev` + browser | app serves; landing and `/login` render; `/provenance` correctly redirects an unauthenticated visitor | **partially executed — see §9** |
| 29 | Evidence Provenance DAG view | bundle + tests | "Evidence Provenance" appears 3× in the production bundle; `resolveGraphNode` unit-tested; the two endpoints it calls return correct data | **not rendered — see §9** |

**26 of 29 rows fully executed. 1 partial (28), 1 config-only (26), 1 not
rendered (29).**

## 7. Test results

### Backend — function-style suites, run with a minimal `pytest` substitute

`pytest` is not installed in the permitted venv and may not be installed, so a
minimal stand-in supplying `fixture` and `raises` was used (those are the only
two pytest features the repository uses). Anything else it is asked for raises,
so an unsupported feature is reported rather than silently skipped.

```
TOTAL 66   PASSED 53   NOT RUN 13   FAILED 0
```

| File | Collected | Pass | Not run |
|---|---|---|---|
| `test_auth_idor.py` | 15 | 2 | **13** |
| `test_crypto_pki.py` | 5 | 5 | 0 |
| `test_crypto_state_reasoning.py` | 13 | 13 | 0 |
| `test_e2e_pipeline.py` | 8 | 8 | 0 |
| `test_evidence_based_assessment.py` | 7 | 7 | 0 |
| `test_evidence_provenance_navigation.py` | 3 | 3 | 0 |
| `test_gemini_grounding.py` | 4 | 4 | 0 |
| `test_provenance_dynamic_matrix.py` | 8 | 8 | 0 |
| `test_provenance_graph.py` | 3 | 3 | 0 |

The 13 "not run" are **all** `test_auth_idor.py` cases that mint JWTs: 12 fail
on `module 'jwt' has no attribute 'encode'` and 1 on `'Limiter' object has no
attribute 'reset'` — both artefacts of the stub `PyJWT`/`slowapi` modules, not
of the application. **They are reported as not run, not as passing and not as
failing.** The two that do run (`test_jwt_auth_required_for_protected_routes`,
`test_demo_preset_accessible_without_auth`) pass, and §6 rows 21–23 exercise
the same surface independently and pass.

### Backend — `unittest` suite

`python -m unittest discover -s tests -p "test_deliverables*.py"` →
**Ran 6 tests … OK** (stream reassembly, credential redaction, certificate
chain and trust path, certifi trust store, encrypted-stream handling, full
pipeline integrity). My function-collector reports this file as 0 collected
because its tests are `unittest.TestCase` methods.

**Backend total: 72 tests collected, 59 pass, 0 fail, 13 not run.**

### Frontend

| Suite | From `frontend/` | From repo root |
|---|---|---|
| `npm run test:unit` (vitest, `src/__tests__`) | **23 / 23 pass** | 23 / 23 pass |
| `npm run test:source` (`node --test tests/*.test.mjs`) | **27 / 27 pass** | 27 / 27 pass |

Both now pass from either directory. Before this merge, `overview_cleanup`
crashed at module load from `frontend/` (its 6 cases never ran) and
`theme_and_usp_labels` failed 3 — three different root conventions across five
files (F48). They now anchor to their own `__dirname`. A `test` script was
added, and vitest is scoped to `src/` because it cannot bundle `node:test`.

`git status` was checked after every test run: **clean**. The F46 behaviour
where running the suite modified a tracked `backend/results/*.json` cannot
recur — the read endpoint no longer writes, and `results/` is no longer tracked.

## 8. Findings

### Resolved by choosing the trunk's files (no fix written)
| ID | Was | Now |
|---|---|---|
| **F35** | every certificate reported as 1024-bit | measured from the DER: 1024 / 2048 / 1024 / 2048 **[executed]** |
| **F36** | positional DN parsing; self-signed never fired | structural comparison: 3 of 4 correctly self-signed; full RDNs **[executed]** |
| **F37** | weak-cipher evidence listed offered, not negotiated | ServerHello-only; the one negotiated 3DES suite named (and tightened further — below) **[executed]** |
| **F38** | `handshake.version` swap that did not fix the TLS-1.3 mislabel and blanked most versions | trunk's `record.version` retained. **The underlying TLS-1.3 mislabel is NOT fixed — see "still open".** |
| **F43** | the DAG presented a fabricated `1024`/`false` as citable chain-of-custody evidence | DAG certificate nodes carry the true values **[executed]** |

### Fixed deliberately
| ID | Fix | Evidence |
|---|---|---|
| **F42 / F37** | `check_weak_ciphers`: suites keyed by cipher code, emitted in ascending code order, **no `[:5]` slice**, and only entries tshark positively identifies as `ServerHello`. | Four separate processes over four captures → byte-identical evidence every time. The pre-fix rendering (set + slice of 5) varied between processes and dropped one of six negotiated suites in a synthetic 7-server case; it also reported five offered-only ciphers from a ClientHello with an empty handshake type, where the fixed version reports none. **[executed]** |
| **F40** | **all four** presets re-measured, not copied, in both `backend/main.py` and the `NewAnalysis.jsx` fallback. The brief named only the new preset, but `vulnerable_smtp` was wrong too (advertised 55, measures 57) and `legacy_ssl3` carried no number at all. | advertised vs measured, side by side: 57/HIGH/E vs 57/HIGH/E; 80/CRITICAL/F vs 80/CRITICAL/F; 0/LOW/A vs 0/LOW/A; 100/CRITICAL/F vs 100/CRITICAL/F. Also fixed the preset card's `expected_risk === 'CRITICAL'` test — an exact comparison against a sentence, which never matched any preset before or after. **[executed]** |
| **F46 (partly)** | the two new endpoints go through `sanitize_capture_id` + `check_resource_ownership`; the `GET /results` write-back is gone. | §6 rows 22–23. The trunk's own five sinks were already sanitised. |
| **F47** | `backend/requirements-dev.txt` declaring `pytest` and `httpx`. | — |
| **F48** | three competing test-root conventions unified; `test` scripts added. | 27/27 from both cwds **[executed]** |
| **F52** | `backend/uploads/` and `backend/results/` untracked, so the existing ignore rules finally bite. | `git check-ignore -v` resolves both; `git status` shows no untracked leftovers **[executed]** |
| **F57** | evidence-linkage ladder extended to the trunk's finding types. | `findings_linked` 5/16 → 16/16 **[executed]** |

### Correction to F42 as written
F42 attributes the nondeterminism to a Python `set`. **On this trunk the
container was already an insertion-ordered `dict`**, so run-to-run ordering was
already stable here; the set-based implementation F42 measured belongs to the
stale line. The genuine residual defects on the trunk were the five-entry slice
(which can drop a negotiated suite) and the loose ServerHello guard. Both are
fixed, and the ordering is now explicit rather than incidental.

### Still open on `Production`
| ID | Severity | Status |
|---|---|---|
| **F17** | **Critical** | A tracked upload carried a plaintext SMTP credential on a **public** repository. Untracking removes it from this branch tip **only** — it remains in every historical commit and is still publicly readable. **Rotate the credential; a history purge is a separate exercise.** Values not reproduced anywhere in this report. |
| **F38 / F9** | High | TLS 1.3 is still reported as TLS 1.2. Rejecting Amin's change restores version coverage but does not fix the mislabel; a real fix needs a `0x13xx`-cipher inference, because `secure_mail.pcap` omits the `supported_versions` extension. Not attempted. |
| **F39** | Medium | Certificate validity is still judged against `datetime.now()`, so the snakeoil certificate (valid at its 2006 capture time) is reported expired. |
| **F44** | Medium | No rule assesses TLS version adequacy, so the crypto state engine cannot distinguish TLS 1.2 from 1.3, and TLS 1.3's encrypted certificates would be reported "truncated or missing". |
| **F45** | High | Not shipped rather than fixed: Amin's `README.md` was rejected, so the false USP vocabularies are not on this branch — but the branch now has **no README at all**. |
| **F12** | Medium | Self-signed findings are still duplicated (3 for `smtp-modern.demo.local` across frames 89/126/155). All now link to the right certificate node, but the duplication remains. |
| **F14**, **F34** | Medium | CORS is origin-restricted on the trunk via `ALLOWED_ORIGINS` (better than the stale line's `*`), but the backend still binds `0.0.0.0`. |
| **F59** | Medium | With no `GEMINI_API_KEY` the "AI Analysis" text is an offline template ladder, and the UI does not say so. The backend does print `[*] No Gemini API key detected. Using High-Fidelity Offline Engine.`, and `ai_source` reads `SecureMailScope-Intelligence-Engine`, but neither reaches the user-facing label. |
| **F7**, **F13**, **F18**, **F24**, **F27**, **F28** | — | Not re-measured here; carried forward from the September audit. |

## 9. What could not be verified, and why

- **The Evidence Provenance DAG view was never rendered in a browser.** It sits
  behind `ProtectedRoute`, which needs a Supabase session; Supabase is a remote
  service and no credentials exist in this environment. Evidence for it is
  therefore indirect: the production bundle contains the components
  (`@xyflow/react` resolved, "Evidence Provenance" present 3×), the
  `resolveGraphNode` helper is unit-tested, 27 source assertions over the JSX
  and CSS pass, the route is registered and correctly redirects an
  unauthenticated visitor, and both endpoints it calls were executed and return
  the correct data. **Nobody has watched the graph draw.** That is the single
  biggest remaining demo risk.
- **The real FastAPI server was never started.** `PyJWT` and `slowapi` are
  declared in `requirements.txt` but absent from the permitted venv, which may
  not be modified. The whole API surface was exercised through
  `fastapi.testclient.TestClient` with no-op stand-ins for those two modules
  (rate limiting disabled; all bearer tokens rejected, which is why
  `dependency_overrides` was used for the authenticated paths). Route
  registration, ownership, sanitisation and all response bodies are real.
- **13 auth tests did not run** (previous section).
- **Docker images were not built and no container was run** — only
  `docker compose config` was validated. `nginx.conf` was not loaded by nginx;
  nginx is not installed here.
- **F7's benign false-positive rate** was not re-measured; the NonTor corpus is
  no longer on this machine.
- **Gemini-backed AI enrichment and KB proposal drafting** were not exercised;
  no API key is configured. Both took their documented offline paths.

## 10. Files needing human review

| File | Why |
|---|---|
| `frontend/src/pages/Analysis.jsx` | The largest hand-merge: five conflicts resolved as unions. It builds and the source-assertion tests pass, but the combined tab bar (9 tabs) and the two-button sessions column have not been seen rendered. |
| `frontend/src/index.css` | 222 lines of Amin's styles merged with the trunk's 15. Clean three-way merge, no visual check. |
| `backend/tests/test_provenance_dynamic_matrix.py` | Numeric expectations changed from 55→57 and 6→16 because this branch measures those values. If the engine's scoring is retuned, these move again. |
| `backend/app/services/provenance_service.py` | The `certificate_pki` CN fallback matches on substring within the finding title/evidence. Correct for the captures here; a certificate whose CN is a substring of another's would over-link. |
| `backend/tests/test_crypto_pki.py` | **A trunk test fixture was edited.** `test_weak_cipher_detection`'s mock handshakes carried no `handshake_type`, so they only produced a finding under the old loose guard; tightening the guard to ServerHello-only made it fail. The fixture now says `'handshake_type': 'ServerHello'` and the assertion is untouched — but this is a trunk test changed to accommodate a deliberate semantic change, and a reviewer should agree the semantics are right. |
| `backend/requirements.txt` | `python-dateutil` and `pyshark` were removed as unimported. If either is needed transitively at runtime, pip will still resolve it, but the intent should be confirmed. |
| `LICENSE` | MIT, taken from Amin. A licensing decision, not a technical one — confirm it is the intended licence. |
| README | There is none. Amin's was rejected as inaccurate; one should be written. |

## 11. Dependency changes

| Change | Reason |
|---|---|
| `+ scapy>=2.5,<3` | `backend/app/utils/generate_secure_sample.py` imports it; declared nowhere (F29) |
| `− pyshark==0.6` | not imported anywhere; tshark is driven via `subprocess` |
| `− python-dateutil==2.8.2` | the string "dateutil" appears nowhere else in the tree |
| `+ backend/requirements-dev.txt` (`pytest`, `httpx`) | every test file imports pytest; most build a `TestClient`, which needs httpx (F47) |
| `+ @xyflow/react ^12.12.0` | the DAG view; resolved in `frontend/package-lock.json`, `npm ci` succeeds |
| `cryptography>=48,<51` kept | Amin's `>=42,<47` rejected; the DER pipeline needs the newer API |
| `.env.example` | `JWT_SECRET`, `SUPABASE_PUBLIC_KEY`, `SUPABASE_JWT_PUBLIC_KEY` (backend) and `VITE_SUPABASE_ANON_KEY` (frontend) documented. Verified by scanning every `os.getenv`/`os.environ` key under `backend/` and every `import.meta.env` key under `frontend/src` against both templates — nothing is now undocumented. **This merge introduces no new environment variable**; the three ported modules read none. |

## 12. What was removed

| Removed | Why |
|---|---|
| `backend/uploads/` (59 files), `backend/results/` (52 files) — untracked, left on disk | the ignore rules had no effect on already-tracked files (F52); see F17 above |
| `local_main.py`, `remote_main.py` | stale UTF-16 copies of the backend entry point, referenced nowhere |
| root `package-lock.json` | a 6-line empty stub |
| `backend/requirements-backup.txt` | superseded |
| `backend/test-data/snakeoil2_070531.tgz` | md5-verified to contain exactly the three `rsasnakeoil2` files already committed beside it |
| `backend/analysis_8d409e81b9cb.json`, `backend/analysis_99af15a660c1.json` | stray artefacts from an older engine |
| `api.js` `getAnalysisStatus()`, `uploadDemo()` | called nowhere under `frontend/src`, and they target `/analysis/{id}/status` and `/upload-demo`, which no route serves |
| `version: "3.9"` in `docker-compose.yml` | obsolete in Compose V2; warned on every invocation |
| never taken from Amin | top-level `test-data/`, `SecureMailScope_SIHDemo_Enhanced.pcap` (byte-identical to the unenhanced capture), `docs/testing/` duplicates |

## 13. How to run the merged app

```sh
# Backend
cd backend
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt            # add -r requirements-dev.txt to run the tests
copy .env.example .env                     # fill in Supabase + (optional) Gemini
venv\Scripts\python.exe -m uvicorn main:app --port 8001
#   optional live monitoring: set WATCH_DIR=watch before starting

# Frontend
cd frontend
npm ci
copy .env.example .env                     # VITE_API_BASE_URL + Supabase anon key
npm run dev                                # http://localhost:5173

# Or both at once, from the repo root, via .claude/launch.json
```

Requires `tshark` on the machine (Wireshark). The backend resolves it through
`TSharkHelper.get_tshark_path()`, so it need not be on `PATH`.

```sh
# Tests
cd backend  && pytest tests/              # needs requirements-dev.txt
cd frontend && npm test                   # vitest (23) + node --test (27)

# Containers
docker compose config                     # validate
docker compose up --build                 # not exercised in this report
```

**Demo path:** start both, sign in, open **Workspace**, click **Comprehensive
SIH Demo (Multi-Protocol)**. Expect 100/100 CRITICAL, grade F, 16 findings, and
— on the Evidence Graph tab or the Evidence Provenance page — 59 nodes and 146
edges with four certificate nodes reading 1024/2048/1024/2048.

**Node version:** `npm test` runs `node --test "tests/*.test.mjs"`, and glob
patterns for `node --test` require **Node 21 or newer** (measured on Node
v22.20.0). On Node 20 LTS, name the five files explicitly or upgrade Node.
