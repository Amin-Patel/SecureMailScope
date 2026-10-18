# Verification of `4bb0bdc` — 2026-10-18

Scope: independent verification of Mohammed Amin Kaifi's commit `4bb0bdc`
("feat: complete project reorganization, crypto state engine, provenance DAG,
and drawer scroll fix", 2026-10-18 21:44 +0530) on `origin/main`.
**Verify-only.** Nothing was pushed, committed, merged or changed on the remote
or in this working copy; every `gh`/`git` call against the remote and against
this repo was read-only. The only file written to this repo is this report.

Findings continue [`Repo-Divergence-2026-10-18.md`](Repo-Divergence-2026-10-18.md)
(F35–F41) and [`Audit-2026-09-21.md`](Audit-2026-09-21.md) (F7–F34).
**New findings start at F42.**

Tags: **[executed]** = I ran it and measured the output. **[code-read]** = read
from source, not run.

## 0. Method

- Fresh clone at `…\scratchpad\clone2\repo`; driver scripts in a **separate**
  directory `…\scratchpad\scripts\`, run with `python -I -B -X utf8` and passed
  clone paths as arguments. Outputs in `…\scratchpad\out\`.
- `.claude/agents/auditor.md` no longer exists; the September audit's severity
  scale and `[executed]`/`[code-read]` convention were used in its place.
- **Clone code was executed with this machine's venv interpreter**
  (`backend\venv\Scripts\python.exe`), from an explicit `cd` into the clone's
  `backend\`. **Dependencies therefore came from the local venv, not the
  clone's `requirements.txt`.** Nothing was installed.
- Requirements diff (clone `4bb0bdc` vs local): clone pins
  `cryptography>=42,<47` where local pins `>=48,<51`, and the clone omits
  `google-genai`, `python-dotenv`, `chromadb`, `certifi`, `scikit-learn`,
  `joblib`, `xhtml2pdf`, `dnspython`. `requirements.txt` is **unchanged** by
  `4bb0bdc`. **[executed]**
- `pytest` is installed nowhere on this machine and is declared in neither
  requirements file, so the five new backend test files were run with a
  minimal substitute runner I wrote (only `@pytest.fixture` is used by them).
  See F47.
- `tshark` 4.6.x at `C:\Program Files\Wireshark\tshark.exe` was used for ground
  truth.
- **No network calls were made by the analysis pipeline.** `GEMINI_API_KEY` is
  unset in this environment and the clone's `backend/` contains no `.env`, so
  `GeminiSecurityAssistant` took its offline branch throughout; the
  "AI Analysis" text in every run below is a hardcoded template (F59).
- The trunk backend was extracted with `git archive FETCH_HEAD backend` into
  `…\scratchpad\trunk\` and run there for the port test in §9. Its SSLBL
  threat-intel feed (F26) is a genuine outbound fetch, but it produced no
  threat-intel finding on the demo and I did not observe a download.

---

## 1. What the commit actually contains

78 files, +12,690 / −543, a fast-forward on `5fc711b` (no force-push this
time). Git detects only **four** renames at 100% similarity:

| From | To |
|---|---|
| `supabase_schema.sql` | `database/supabase_schema.sql` |
| `DOCS/Master Website Functionality Map.md` | `docs/architecture/MASTER_WEBSITE_FUNCTIONALITY_MAP.md` |
| `QUICK_START_COMPREHENSIVE_DEMO.md` | `docs/guides/QUICK_START_COMPREHENSIVE_DEMO.md` |
| `COMPREHENSIVE_PCAP_FINAL_SUMMARY.md` | `docs/reports/COMPREHENSIVE_PCAP_FINAL_SUMMARY.md` |

`DOCS/` held exactly **one** file at `5fc711b`, so "renames `DOCS/` → `docs/`"
is one file moved, not a directory migration of the eight-file local `DOCS/`.

New Python (all stdlib-only imports): `backend/app/core/crypto_state_engine.py`
(+956), `backend/app/core/evidence_assessment_engine.py` (+868),
`backend/app/services/provenance_service.py` (+660). New React:
`ProvenanceGraph.jsx`, `ProvenanceCustomNodes.jsx`, `ProvenanceDetailsDrawer.jsx`,
`EvidenceProvenance.jsx/.css`, `CryptographicStateAssessment.jsx`,
`EvidenceBasedAssessment.jsx`, `resolveGraphNode.js`; `@xyflow/react@^12.12.0`
added to `frontend/package.json` and resolved in `frontend/package-lock.json`.
Also new: `README.md` (+221), `LICENSE` (MIT), `.env.example` (placeholders
only, no live secrets), `deployment/deploy-to-server.ps1`, 7
`docs/implementation/` + 7 `docs/reports/` + 2 `docs/testing/` Markdown files,
5 `backend/tests/` files, 5 `frontend/tests/` files, `scripts/testing/test-presets.html`,
a top-level `test-data/`, three PCAPs and two JSON debug artefacts.

Deleted: `local_main.py`, `remote_main.py`, root `package-lock.json`,
`backend/requirements-backup.txt`, two stray `backend/analysis_*.json`, two
`backend/results/*.json`.

**The brief's "deleted `package-lock.json` (reproducible installs)" premise
does not hold.** The deleted root lockfile was a 6-line empty stub
(`"packages": {}`); the real one, `frontend/package-lock.json`, was *updated*
(+252) and does resolve the new dependency. **[executed]**

The commit message is a single line with no body, so the claims verified below
come from the message subject, `README.md`, and the new `docs/` files.

---

## 2. Claim-by-claim verification

| # | Claim | Source | Verdict | Evidence |
|---|---|---|---|---|
| 1 | "complete project reorganization" | commit subject; `PROJECT_FOLDER_REORGANIZATION_REPORT.md`: "COMPLETE & 100% VERIFIED" | **Partially implemented** | Directory layout created and launchers still work, but four of the moved docs were *copied, not moved* — `docs/testing/COVERAGE_MATRIX_VERIFICATION.md` and `COMPREHENSIVE_PCAP_COVERAGE_REPORT.md` are byte-identical duplicates of the still-tracked `backend/test-data/` originals, and the new top-level `test-data/` duplicates three `backend/test-data/` files by md5. F51. **[executed]** |
| 2 | Reorg "without modifying any core detection logic" | reorg report line 17 | **Holds** | `cert_analyzer.py` and `tshark_helper.py` are untouched by the commit. **[executed]** (`git show --name-status`) |
| 3 | "All path references, import paths, launcher scripts, build pipelines, and automated test suites verified with 100% test pass rates" | reorg report line 17 | **Does not hold** | from `frontend/`, 3 cases fail and 6 more never execute because their file crashes at module load; all 27 pass only with cwd = repo root. No `test` script in `package.json`, no CI. F48. **[executed]** |
| 4 | "Crypto state engine" — "Deterministic State Transition Tracking … `PLAINTEXT` → `UPGRADE_REQUESTED` → `HANDSHAKE_IN_PROGRESS` → `ENCRYPTED`/`DOWNGRADE_DETECTED`" | `README.md` USP 1 | **Asserted only** | Those five identifiers occur **zero** times in the repository. The engine is a 10-rule evaluator over already-computed `analysis_data` with a worst-of precedence ladder over a different 7-state vocabulary (`SECURE_WITHIN_OBSERVED_SCOPE` … `ANALYSIS_ERROR`), `crypto_state_engine.py:17-23, 841-871`. No per-session state machine exists. F45. **[code-read]** |
| 5 | Crypto state engine produces a defensible verdict | `CRYPTOGRAPHIC_STATE_REASONING_IMPLEMENTATION_REPORT.md`: "Fully Implemented (100% Verified Completion)" | **Implemented, and its aggregation is sound** | It runs on all six captures and the precedence ladder behaves as documented. I ran a counterfactual on `secure_mail.pcap` (forcing `tls_version` to `TLS 1.3`): the state, rule statuses and unresolved conditions are **identical**, so the verdict is *not* contaminated by F38 — it is driven by four honest `UNKNOWN` certificate rules. But that also means the engine never assesses TLS 1.2-vs-1.3 at all. F44. **[executed]** |
| 6 | "Tri-State Evidence Assessment Engine … `VERIFIED` / `SUSPICIOUS` / `INCONCLUSIVE`" | `README.md` USP 2 | **Implemented under different names; README wrong** | The engine emits five outcomes — `Satisfied`, `Violated`, `Indeterminate`, `Not Applicable`, `Undefined Expectation` (`evidence_assessment_engine.py:29-48`). None of the three README words appear in the engine or in `EvidenceBasedAssessment.jsx`. F45. **[executed]** |
| 7 | "Evidence Binding: every assessment binds to packet frame numbers … and SHA-256 capture hashes" | `README.md` USP 2 | **Holds** | The artifact node's `sha256_hash` for the demo is `9af8032e…ae66da`, which equals `sha256sum` of `SecureMailScope_SIHDemo.pcap` exactly. It falls back to `'Unavailable (Archived)'` when the file is gone (`provenance_service.py:139-152, 191`). Minor: `file_size` came back `0`. Frame citations are real (see 8). **[executed]** |
| 8 | "Provenance DAG" — bi-directional acyclic graph PCAP → sessions → frames → states → findings | commit subject; `README.md` USP 3 | **Implemented, and structurally sound** | On `SecureMailScope_SIHDemo.pcap`: 47 nodes, 81 edges, node types `handshake`/`session`/`analysis_operation`/`finding`/`certificate`/`source_artifact`/`baseline`; **0 dangling edges**; **acyclic** by a hand-written Kahn's algorithm (47/47 settled); `findings_unlinked: 0`. **[executed]** |
| 9 | Provenance nodes cite real packets | `README.md` USP 3 "Direct Frame Inspection" | **Citations are real; their contents are not** | `handshake:frame_6` claims SSL 3.0 at frame 6 — tshark confirms frame 6 is a ServerHello with `tls.record.version=0x0300`, cipher `0x0035`. But every `certificate:` node carries the fabricated `key_size: 1024` and `is_self_signed: false`. F43. **[executed]** |
| 10 | "drawer scroll fix" | commit subject | **Cannot be confirmed as behaviour** | `drawer_scrollability.test.mjs` only regex-matches `minHeight: 0` / `overflow: 'hidden'` strings in `ProvenanceGraph.jsx`. Nothing is rendered. The fix may well be correct; it is **[code-read]** only. F49. |
| 11 | "24/24 backend automated tests … pass"; "23/23 frontend passed"; "34/34 passed in 6.93s" | crypto report lines 23/136; reorg report lines 225/233 | **Counts do not match the tree** | I collected **34** backend test functions across 5 files (excluding the server-dependent `test_e2e_pipeline.py`) and **27** frontend cases across 5 files. The "24" and "23" figures match no file set in this commit. F55. **[executed]** |
| 12 | Committed `comprehensive_demo_validation_output.json` is the demo's validated result | `backend/test-data/` | **Reproduces, but is stale** | A fresh run gives the same risk 82/CRITICAL and the same five findings with identical evidence strings — good. But the committed file has **no** `cryptographic_state_assessment` and **no** `evidence_based_assessment` keys, i.e. it predates the very engines this commit adds. F56. **[executed]** |
| 13 | `SecureMailScope_SIHDemo_Enhanced.pcap` is an enhanced capture | filename | **False** | md5 `13199e4105340092bc9e93dbe6a0e8bb` — byte-identical to `SecureMailScope_SIHDemo.pcap`. F51. **[executed]** |
| 14 | USP audit report's "1 of 6 USPs partially implemented; 5 of 6 not implemented" | `docs/reports/SecureMailScope_USP_Audit_Report.md` | **Honest, but about the stale base** | It audits `5fc711b`-era code from `c:\Users\Mohammed Amin Kaifi\Desktop\SecureMailScope`, static-only. Its "no ML model exists" and "no RAG" conclusions are true of the stale base *because* the 2026-10-16 force-push removed them, which the report does not say. **[code-read]** |
| 15 | README repository structure | `README.md` | **Partly fictional** | `scripts/development/`, `scripts/maintenance/` and `archive/` are documented and do not exist; a Tailwind CSS badge is displayed with no Tailwind dependency in `frontend/package.json`. F53. **[executed]** |

---

## 3. Does it run? — measured pipeline output

All runs: clone source, local venv interpreter, `cd` into the clone's `backend\`.

| Capture | Risk | Crypto state | Evidence metrics (S/V/I/NA/U) | Findings |
|---|---|---|---|---|
| `SecureMailScope_SIHDemo.pcap` (= `_Enhanced`) | 97 CRITICAL | `CRYPTOGRAPHIC_FAILURE` | 1/7/2/0/1 | 6 |
| `SecureMailScope_Comprehensive_Demo.pcap` | 82 CRITICAL | `CRYPTOGRAPHIC_FAILURE` | 0/4/5/1/1 | 5 |
| `SecureMailScope_SIHDemo_Original.pcap` | 67 HIGH | `CRYPTOGRAPHIC_FAILURE` | not captured | 4 |
| `secure_mail.pcap` | 0 LOW | `ACCEPTABLE_WITH_LIMITATIONS` | 4/0/5/1/1 | 0 |
| `smtp.pcap` | 55 HIGH | `CRYPTOGRAPHIC_FAILURE` | 0/2/0/9/0 | 2 |
| `rsasnakeoil2.cap` | 60 HIGH | `CRYPTOGRAPHIC_FAILURE` | 1/5/3/1/1 | 5 |

The pipeline completes on all six without exception. I ran with `-X utf8`, which
*masks* rather than tests the Windows console crash (F31) — `_print_report` is
still unwrapped in the clone, so F31 is **not re-verified** here. The two new engines execute on every
run and their output is persisted into the result JSON.

`SecureMailScope_Comprehensive_Demo.pcap` is **25 frames / 2,233 bytes** — a
synthetic construction (there is a `build_comprehensive_pcap.py` beside it),
not a capture. The docs present it as a "comprehensive demo". **[executed]**

---

## 4. Test results, as measured

### Backend — `backend/tests/` **[executed]**

Run with my substitute runner (see F47), `test_e2e_pipeline.py` skipped because
it requires a live server on `localhost:8001`.

```
TOTAL 34   PASSED 34   FAILED 0
```

| File | Tests | Result | What it actually asserts |
|---|---|---|---|
| `test_crypto_state_reasoning.py` | 13 | pass | Feeds **hand-written mock** `analysis_data` dicts (with *correct* `key_size: 4096/1024/2048` and `is_self_signed` values, lines 66, 94, 300) into `CryptographicStateEngine` and checks the resulting state label, rule count and explanation shape. `test_t31_deterministic_repeatability` compares two `evaluate()` calls **in one process** and asserts only `overall_state`, `metrics` and `summary_rationale` — never an evidence string — which is why it stays green despite F42. |
| `test_evidence_based_assessment.py` | 7 | pass | Same pattern against `EvidenceAssessmentEngine`; checks outcome counts and colour/description maps. |
| `test_evidence_provenance_navigation.py` | 3 | pass | One fixture graph; checks node resolution and relationship lookup. |
| `test_provenance_dynamic_matrix.py` | 8 | pass | The only ones that touch real data: run the real pipeline (and FastAPI `TestClient`) over real PCAPs, assert isolation between analyses and that endpoints return 200. |
| `test_provenance_graph.py` | 3 | pass | Builds the graph from two scenarios; asserts node/edge presence. |
| `test_e2e_pipeline.py` | 0 (`requests` script) | skipped | Pre-existing; hits `http://localhost:8001/api`. |

Two observations that are themselves findings: the mock dicts give the engines
*correct* certificate data, so **no backend test can ever catch F35 or F36**
(F50); and running the suite **modified a tracked file** —
`git status` afterwards showed ` M backend/results/1dde2bcba1fa.json` (F46).

### Frontend — `frontend/tests/` **[executed]**

`node --test` (Node v22.20.0). Results depend on the working directory:

| File | Cases | From repo root | From `frontend/` |
|---|---|---|---|
| `analysis_ui_refinement.test.mjs` | 5 | pass | pass |
| `drawer_scrollability.test.mjs` | 4 | pass | pass |
| `evidence_navigation.test.mjs` | 9 | pass | pass |
| `overview_cleanup.test.mjs` | 6 | pass | **crashes at module load** (`ENOENT … frontend\frontend\src\pages\Analysis.jsx`) — its 6 cases never run |
| `theme_and_usp_labels.test.mjs` | 3 | pass | **3 fail** (same, `…\frontend\frontend\src`) |
| **Total** | **27** | **27 pass** | **18 run and pass, 3 fail, 6 never execute** |

Cause: `analysis_ui_refinement` uses `path.resolve(__dirname,'../..')` and
`drawer_scrollability` uses `path.resolve(__dirname,'..')`, while
`overview_cleanup` and `theme_and_usp_labels` use bare
`path.resolve('frontend/src/...')`, which is cwd-relative. Three different
root conventions in five files means they were never all run together.

Content: 4 of the 5 files are regular-expression matches over JSX and CSS
*source text*. Only `evidence_navigation.test.mjs` is a real unit test (it
imports `resolveGraphNode` and exercises it against two mock graphs).

### `scripts/testing/` **[code-read]**

Contains one file, `test-presets.html` — a static page with hardcoded `fetch`
calls to `http://localhost:8001`. It is not a runnable test and not wired to
anything. I did not open it.

---

## 5. Status of F35–F41

| ID | Title | Status after `4bb0bdc` | Evidence |
|---|---|---|---|
| **F35** | Certificate key size hardcoded to 1024 | **Still present, and now worse** | `cert_analyzer.py` untouched. Measured on `SecureMailScope_SIHDemo.pcap`: all four certificates reported `key_size: 1024`; two are truly 2048-bit. The SMS-005 evidence string is unchanged. **New harm:** every `certificate:` node in the provenance DAG carries `"key_size": 1024`, and the DAG presents it as chain-of-custody evidence against "NIST SP 800-57 Part 1 Rev. 5". See F43. **[executed]** |
| **F36** | Positional DN parsing; self-signed never fires | **Still present, and now worse** | 3 of 4 certificates come back with empty `subject` and `issuer`; `is_self_signed` is `false` for all four, where three are genuinely self-signed. The one parsed DN is still mangled (`O= Ltd`). Same laundering into the DAG. **[executed]** |
| **F37** | Weak-cipher evidence lists offered, not negotiated | **Still present; code unchanged** | `check_weak_ciphers` still iterates every handshake. tshark ground truth on the demo: the only negotiated weak suite in the capture is `0x000a` (frame 27). One pipeline run reported `0x0015, 0x0013, 0x0004, 0x0006, 0x0003` — **none** negotiated. This commit changes nothing here (`security_engine.py`'s only edit is `_add_finding`), but I newly discovered the list is **nondeterministic**: see F42. **[executed]** |
| **F38** | TLS-version fix does not fix the bug | **Still present; code unchanged** | `tshark_helper.py` is untouched by this commit. `secure_mail.pcap` frame 5: `tls.handshake.version=0x0303`, cipher `0x1302` (TLS-1.3-only); the pipeline still prints `TLS Versions: TLS 1.2`. The empty-`tls_version` regression persists (on the demo, **8 of 21** handshake entries have `tls_version: ''`). The mislabel now also propagates into the provenance graph — `secure_mail.pcap`'s single handshake node reads `tls_version: 'TLS 1.2'` — but, contrary to my first hypothesis, it does **not** change the crypto state verdict (F44). **[executed]** |
| **F39** | "Expired 2008" demo cert was valid at capture time | **Still present** | `cert_analyzer` compares against `datetime.now()`. The provenance operation node even documents it: `RULE-RFC5280-VALIDITY` — "Compares certificate notBefore and notAfter timestamps **against evaluation time**". The snakeoil cert (`notAfter 2008-03-03`, capture dated 2006-04-24) is still reported expired. **[executed]** |
| **F40** | Preset metadata contradicts behaviour | **Still present, both copies** | `backend/main.py:137` and `frontend/src/pages/NewAnalysis.jsx:34` both still read `"expected_risk": "MEDIUM (37/100)"`; the measured result is **97/100 CRITICAL**. **[executed]** |
| **F41** | "Verified with end-to-end testing", no tests | **Improved, but not resolved** | This commit does add 10 test files — genuine progress. But they cannot catch any of F35–F38 (F50), 9 of 27 frontend cases don't pass from the obvious cwd (F48), the backend suite needs an undeclared dependency (F47), and the stale `COVERAGE_MATRIX_VERIFICATION.md` claiming "no certificates" is not corrected — it is **duplicated** into `docs/testing/`. **[executed]** |

**Net: zero of F35–F40 is fixed.** None of the four defective files was edited,
so the defects are unchanged *as code*. What changed is their reach: F35 and
F36 are now re-presented as citable chain-of-custody evidence in the
provenance graph (F43), and F38's mislabel propagates into the graph's
handshake nodes. F37's reach is unchanged, but F42 shows it was worse all
along than anyone had measured.

---

## 6. New findings

### F42 — Weak-cipher evidence is nondeterministic between runs — **Critical** [executed]

`security_engine.py:check_weak_ciphers` accumulates matches into a Python
`set` and then renders `', '.join(list(weak_found)[:5])` into both the
description and the `evidence` field. Set iteration order over strings varies
with Python's per-process hash seed, so the five codes shown are an arbitrary
five of the nine weak codes present. Four separate processes, same capture
(`SecureMailScope_SIHDemo.pcap`), same code:

```
0x0005, 0x000a, 0x0009, 0x0015, 0x0003
0x0003, 0x000a, 0x0012, 0x0009, 0x0005
0x0015, 0x000a, 0x0003, 0x0006, 0x0004
0x0006, 0x0012, 0x0003, 0x0009, 0x000a
```

and the full-pipeline run recorded `0x0015, 0x0013, 0x0004, 0x0006, 0x0003`.
`check_weak_ciphers` is **unchanged by `4bb0bdc`** — this is a pre-existing
defect that nobody had measured, not a regression introduced here. It also
explains why my list differs from the divergence audit's
`0x000a, 0x0012, 0x0009, 0x0016, 0x0003`: that was simply a different process.
A forensic tool must produce the same evidence string for the same input.
It also means the one genuinely negotiated weak suite, `0x000a`, is sometimes
present and sometimes absent from the evidence for the same capture. This
directly contradicts `test_t31_deterministic_repeatability` ("Identical data
produces identical deterministic state") in the crypto report — that test
passes because it checks the *aggregated state label*, not the evidence text.

**Repro:** run `SecurityEngine(...).check_weak_ciphers()` in four separate
processes over the demo's handshakes.

### F43 — The provenance DAG launders fabricated certificate facts into chain-of-custody evidence — **Critical** [executed]

Every `certificate:` node emitted by `ProvenanceGraphBuilder` carries the
`cert_analyzer` output verbatim:

Ground truth was re-measured for this report, not carried forward: I pulled the
DER bytes with `tshark -Y "tls.handshake.type==11" -T fields -e tls.handshake.certificate`
and parsed each with `cryptography`. **[executed]**

| Node | Reported key / self-signed | True CN | True key | True self-signed |
|---|---|---|---|---|
| `cert:frame_6_0` | 1024 / false | `www.snakeoil.dom` | 1024 | **false** (issuer `Snake Oil CA`) |
| `cert:frame_89_1` | 1024 / false | `smtp-modern.demo.local` | **2048** | **true** |
| `cert:frame_99_2` | 1024 / false | `smtp-expired.demo.local` | 1024 | **true** |
| `cert:frame_165_3` | 1024 / false | `smtp-future.demo.local` | **2048** | **true** |

So two of four key sizes are wrong, three of four self-signed flags are wrong,
and three of the four nodes have empty `subject`/`issuer`. Those nodes are then wired
by `EVALUATED_BY` edges to `operation:RULE-NIST-SP800-57-KEYLEN` with
`evaluation_status: VIOLATION_CONFIRMED`, and by `SUPPORTS_FINDING` to
`finding:SMS-005`, whose description reads **"4 certificate(s) have key sizes
below recommended minimums"** against a true population of two. A fabricated
constant has been given a frame number, a standards citation and a clickable
lineage. This is strictly worse than F35 alone: the UI now invites a judge to
drill into the "evidence" for a number that was never measured.

### F44 — The crypto state engine has no rule for TLS version adequacy — **Medium** [executed]

My first hypothesis — that the engine's verdict on `secure_mail.pcap` was
contaminated by the F38 mislabel — **is wrong, and I am recording that
explicitly.** I deep-copied `out/secure_mail.json`, forced every handshake's
`tls_version` to `TLS 1.3`, and re-ran `CryptographicStateEngine.evaluate()`:
`overall_state`, all ten rule statuses and all five `unresolved_conditions`
came back **byte-identical** to the as-is run. The F38 label does not change
the verdict.

What the counterfactual does reveal is two genuine defects:

1. **No rule assesses TLS version adequacy.** The ten rules are
   `RFC8314-PLAINTEXT`, `RFC7568-SSL3`, `RFC8996-TLS10`, `RFC8996-TLS11`,
   `NIST-SP800-52R2-CIPHER`, `RFC5280-SIG-ALGO`, `NIST-SP800-57-KEYLEN`,
   `RFC5280-VALIDITY`, `WEB-PKI-TRUST`, `RFC3207-STARTTLS`. Anything at TLS 1.2
   or above passes identically, so the engine cannot distinguish a TLS 1.2
   deployment from a TLS 1.3 one — and consequently cannot ever *surface* F38
   either. For a tool whose stated USP is "cryptographic state reasoning"
   against RFC 7525, the absence of a modern-version rule is a gap, and it is
   the reason README's `SECURE_MODERN`/`LEGACY_ACCEPTABLE` distinction (F45)
   has no implementation.
2. **Missing certificates will be misattributed on real TLS 1.3 traffic.**
   On `secure_mail.pcap` the engine reports the unresolved condition "TLS
   handshake observed but X.509 Certificate packets were **truncated or
   missing**". For *this* capture that wording is literally accurate — it
   holds a single ServerHello record and no ClientHello. But the same branch
   fires for any genuine TLS 1.3 session, where the Certificate message is
   encrypted by design and a passive observer cannot see it. *This second
   point is an inference: I have no real TLS 1.3 capture to run it against.*
   **[code-read]**

To the engine's credit, the four `UNKNOWN` certificate rules that drive
`ACCEPTABLE_WITH_LIMITATIONS` here are the *right* answer for a capture with no
observable certificates — this is the uncertainty handling working as designed,
and it is the best thing in the commit.

A note on remediation: `tls.handshake.extensions.supported_version` is the
field that would distinguish TLS 1.3, and it occurs **0 times** in the repo's
Python — but tshark also reports it **empty** on `secure_mail.pcap` frame 5.
A real TLS 1.3 ServerHello must carry that extension (RFC 8446 §4.2.1), so
`secure_mail.pcap` is itself synthetic and internally inconsistent: it
negotiates a TLS-1.3-only cipher without the extension that makes it TLS 1.3.
Any fix for F38 needs a capture that is actually valid, or a `0x13xx`-cipher
inference as a fallback.

### F45 — README's USP vocabularies do not exist in the code — **High** [code-read]

`README.md` is the first thing a judge reads and it describes two engines that
are not the ones shipped:

- USP 1 claims a session state machine `PLAINTEXT` → `UPGRADE_REQUESTED` →
  `HANDSHAKE_IN_PROGRESS` → `ENCRYPTED`/`DOWNGRADE_DETECTED`, and a posture
  scale `SECURE_MODERN`/`LEGACY_ACCEPTABLE`/`VULNERABLE_PLAINTEXT`/
  `DOWNGRADE_ATTACK_DETECTED`. A grep over the repository's `.py`,
  `.jsx` and `.js` files for all eight identifiers returns **zero hits** (they
  appear only in `README.md` itself). The shipped engine is a 10-rule worst-of ladder over
  seven different states.
- USP 2 claims tri-state `VERIFIED`/`SUSPICIOUS`/`INCONCLUSIVE`. The shipped
  engine emits `Satisfied`/`Violated`/`Indeterminate`/`Not Applicable`/
  `Undefined Expectation` (`evidence_assessment_engine.py:29-48`). Five states,
  none of them named in the README.
- USP 4 lists "STARTTLS stripping (MITM)" under "Attack Detection". There is
  no stripping detection. `_eval_rule_missing_starttls`
  (`crypto_state_engine.py:622-669`) flags the *absence* of STARTTLS, and
  cross-property rule CPR-02 (`:735-746`) is a heuristic that notes encrypted
  and cleartext SMTP sessions coexisting in one capture and labels it
  "Downgrade Risk". Neither observes a stripped `250-STARTTLS` advertisement.
  F10 is unchanged.

The engines are real work; the README describes a different, more impressive
product than the one in the tree.

### F46 — Two new endpoints extend the path-traversal surface, and a `GET` now mutates stored evidence — **High** [executed]

`GET /api/analysis/{capture_id}/provenance` and
`GET /api/analysis/{capture_id}/provenance/node/{node_id}` both build
`RESULTS_DIR / f"{capture_id}.json"` straight from the path parameter with no
sanitisation (`backend/main.py`), taking F15/F16's unsanitised sinks from five
to seven. `grep -c 'RESULTS_DIR / f"{capture_id}'` returns **7**. **[executed]**

Separately, `GET /api/analysis/{capture_id}/results` was changed to **write
back** to that resolved path whenever the two new assessment keys are absent
(`json.dump(data, f_out, …)`, twice). A read endpoint that rewrites the
forensic artefact is wrong on its own terms — chain of custody. Measured:
running the backend test suite left ` M backend/results/1dde2bcba1fa.json` in
`git status`, and that file now contains `cryptographic_state_assessment` and
`evidence_based_assessment` keys it did not have. **[executed]**

*Inference, not measured:* I did **not** exercise traversal against the write
path. Starlette's default `{capture_id}` converter does not match `/`, so an
attack would need a backslash on Windows, and the handler writes its own
derived content rather than attacker-controlled bytes — so treat this as an
unsanitised-path defect to fix, not a demonstrated write primitive.
**[code-read]** CORS is unchanged
(`allow_origins=["*"]` with `allow_credentials=True`, `main.py:44-45`), and
the backend still binds `0.0.0.0` (`main.py:402`), so F14 and F34 stand.

### F47 — The new backend tests cannot be run from the declared dependencies — **High** [executed]

All five new backend test files `import pytest`. `pytest` appears in neither
the clone's nor this machine's `requirements.txt`, there is no
`requirements-dev.txt`, no `pytest.ini`/`pyproject.toml`/`setup.cfg`, no CI
workflow, and no `pytest` module is importable from either Python on this
machine. A teammate or judge following the README's setup instructions cannot
execute the 1,082 lines of test code that the reports cite as verification.
(I ran them with a hand-written substitute; only `@pytest.fixture` is used.)

### F48 — Frontend tests use three different root conventions; 9 of 27 cases do not pass from `frontend/` — **Medium** [executed]

`analysis_ui_refinement.test.mjs:9` → `path.resolve(__dirname,'../..')`;
`drawer_scrollability.test.mjs:9` → `path.resolve(__dirname,'..')`;
`overview_cleanup.test.mjs:6` and `theme_and_usp_labels.test.mjs` →
bare `path.resolve('frontend/src/...')`, i.e. cwd-relative. `theme_and_usp_labels`
fails 3 cases and `overview_cleanup` crashes at module load, so its 6 cases
never execute at all. Both throw
`ENOENT … frontend\frontend\src\…` when run from `frontend/`, the directory
their `package.json` lives in. No `"test"` script exists in `package.json`, so
nothing pins the cwd. The reorg report's "100% test pass rates" holds only for
one undocumented invocation directory.

### F49 — Four of five frontend test files assert on source text, not behaviour — **Medium** [code-read]

They `readFileSync` a `.jsx`/`.css` file and `assert.match` against regexes such
as `/\.tabs-bar\s*\{[^}]*border-radius:\s*999px;/` and `/minHeight:\s*0/`.
Nothing is rendered, mounted or scrolled. The commit's "drawer scroll fix" is
therefore verified only to the extent that two string literals are present in
`ProvenanceGraph.jsx`. A refactor that changed the units, or a parent container
that re-breaks the flex chain, would leave these green. Only
`evidence_navigation.test.mjs` exercises real code (`resolveGraphNode`).

### F50 — The backend tests structurally cannot catch F35/F36 — **Medium** [executed]

`test_crypto_state_reasoning.py:66,94,300`,
`test_evidence_based_assessment.py:66`, and
`test_evidence_provenance_navigation.py:69` all construct mock analysis
dictionaries by hand with `key_size: 4096/2048/1024` and correct
`is_self_signed` flags. The new engines are therefore only ever tested against
*correct* certificate data, while the production path feeds them the hardcoded
1024 and the always-false self-signed flag. The test suite will stay green for
as long as F35 and F36 remain unfixed.

### F51 — The reorganisation copied rather than moved, leaving duplicate artefacts — **Medium** [executed]

- `docs/testing/COVERAGE_MATRIX_VERIFICATION.md` and
  `docs/testing/COMPREHENSIVE_PCAP_COVERAGE_REPORT.md` are byte-identical to
  the still-tracked `backend/test-data/` originals (git reports them as adds
  with no matching deletes; `git diff` between the two blobs is empty).
- top-level `test-data/` holds `rsasnakeoil2.README`, `rsasnakeoil2.key` and
  `snakeoil2_070531.tgz` — identical md5s to the copies that remain in
  `backend/test-data/`.
- `SecureMailScope_SIHDemo_Enhanced.pcap` is byte-identical
  (md5 `13199e4105340092bc9e93dbe6a0e8bb`) to `SecureMailScope_SIHDemo.pcap`
  despite the name promising an enhancement.

So four of the documents and PCAPs now exist twice, and the duplicated
coverage docs are precisely the stale F41 ones that claim the key-size and
self-signed checks do not fire because there are "no certificates" — a claim
the commit's own demo PCAP (four certificates) contradicts. A judge reading
`docs/testing/` gets the stale story in the new, authoritative-looking location.

### F52 — `.gitignore` now ignores `uploads/` and `results/` but nothing was untracked — **Medium** [executed]

The diff adds `backend/uploads/`, `backend/results/`, `/results/` and `/archive/`
to `.gitignore`. A `.gitignore` entry has no effect on already-tracked files:
at `4bb0bdc`, `git ls-files backend/uploads` still returns **59 files**,
including `backend/uploads/28a7ec2024b8.pcap` — the capture carrying a live
plaintext SMTP credential (F17) — and `git ls-files backend/results` still
returns **23** stale JSONs (F30). The repository is still public. The new
ignore rules make the tree *look* remediated while the exposure is unchanged;
anyone reading the diff could reasonably conclude the problem was handled.
**F17 remains the single most urgent item in this repository.**

### F53 — README documents directories and technologies that do not exist — **Low** [executed]

`README.md`'s repository-structure block lists `scripts/development/`,
`scripts/maintenance/` and `archive/`; none exist (`scripts/` contains only
`testing/`). The header displays a **Tailwind CSS** badge; `frontend/package.json`
has no Tailwind dependency of any kind. `scripts/testing/` is described as
"Test presets and validation utilities" and holds one static HTML page.

### F54 — Deployment script commits personal infrastructure to a public repo — **Low** [code-read]

`deployment/deploy-to-server.ps1:12-13` hardcodes a Tailscale SSH target and
remote home directory belonging to a named individual, and the script
`scp`s the tree there. On a public repository this discloses an account name
and an internal host name for no functional benefit; it belongs in
`.env.example` or a gitignored local config.

### F55 — Test counts in the reports do not match the tree — **Low** [executed]

The crypto report states "24 passed in 6.02 seconds (100% pass rate)" and
"24/24 backend automated tests"; the reorg report states "PASS (23 / 23 passed,
0 failed)" for frontend and "PASS (34 / 34 passed, 0 failed in 6.93s)" for
backend. I collected **34** backend tests (which matches the reorg report) and
**27** frontend cases (which matches nothing). The 24 and 23 figures are
numbers carried forward from an earlier state of the branch and not
re-measured, the same pattern as F40.

### F56 — The committed "validation output" predates the engines it ships with — **Medium** [executed]

`backend/test-data/comprehensive_demo_validation_output.json` reproduces
exactly on a fresh run (risk 82/CRITICAL, the same five findings with
identical evidence strings) — credit where due. But its top-level keys are
`success, capture_id, filename, summary, ai_summary, findings, risk, sessions,
certificates, tls_handshakes, upload_timestamp, original_filename, file_size,
status`: no `cryptographic_state_assessment`, no `evidence_based_assessment`.
It is a snapshot of the pre-`4bb0bdc` schema committed by `4bb0bdc` as
evidence for `4bb0bdc`. The same schema drift means every one of the 23 stale
`backend/results/*.json` will be silently rewritten by the new `GET /results`
handler the first time it is opened (F46).

### F57 — On the real trunk, 11 of 16 findings get a rule node but no artefact evidence — **High** [executed]

Running the trunk's own pipeline output through `ProvenanceGraphBuilder` gives
59 nodes, 101 edges and `findings_linked: 5`, `findings_unlinked: 11`. A
finding counts as "linked" only when the builder can attach a *packet,
session or certificate* node to it (`provenance_service.py:602-611`); the
other eleven get an edge to an abstract rule node and nothing else, so the
chain of custody terminates in a policy statement rather than in an artefact.
The eleven, measured:

```
no_forward_secrecy    TLS Session Without Forward Secrecy
certificate_pki       Certificate Expired: www.snakeoil.dom
certificate_pki       Untrusted Certificate Authority / Incomplete Chain
certificate_pki       Certificate Expired: smtp-expired.demo.local
certificate_pki       Certificate Not Yet Valid: smtp-future.demo.local
certificate_pki       Self-Signed Certificate Detected   (x5, see F12)
email_authentication  Message Carries No DKIM Signature
```

The cause is a hardcoded `f_type` ladder (`provenance_service.py:582`) that
knows only `weak_signature`, `insufficient_key_size`, `expired_certificate`
and `self_signed_certificate`. The trunk consolidated its certificate findings
under the type `certificate_pki` and added `no_forward_secrecy` and
`email_authentication`, none of which the ladder matches. On the stale base
the metric reads `0` unlinked — which is what the reports quote — only because
the stale base emits exactly the six types the ladder knows. So "complete
bidirectional traceability" is 5-of-16 the moment the real trunk is restored,
and it degrades **silently**: the graph still renders, the nodes still appear,
only the evidence edges are missing. Five of the eleven are also F12's
duplicate self-signed findings, which the builder would have had to
deduplicate anyway.

### F58 — Upload validation and the `.tgz` artefact — **Low** [executed]

Unchanged by this commit but re-confirmed, since the brief asked:
`upload_and_analyze` validates by **file extension only**
(`Path(file.filename).suffix.lower() in ALLOWED_EXTENSIONS`), no magic-byte
check, and still does `content = await file.read()` — buffering the entire
body into memory — *before* comparing against `MAX_FILE_SIZE` and returning
413. F24 stands. The new top-level `test-data/snakeoil2_070531.tgz` holds
`rsasnakeoil2.README`, `rsasnakeoil2.cap` and `rsasnakeoil2.key` — the
published Wireshark sample archive. Streaming each member to stdout
(`tar -xzOf … | md5sum`, nothing extracted to disk) gives `156a34c3…`,
`b16be156…` and `9251e730…`: an exact match for the three files already
committed uncompressed in `backend/test-data/` *and* re-copied into the new
top-level `test-data/`. Those three artefacts now exist in the repository
three times over. **[executed]**

### F59 — "AI Analysis" under a robot icon is a hardcoded if/elif ladder — **Medium** [executed]

Every finding in every run printed a "🤖 AI Analysis" line. With
`GEMINI_API_KEY` unset and no `.env` present, `GeminiSecurityAssistant` fell
through to `_offline_enrich_finding` → `_fallback_explanation`
(`gemini_service.py:138-180`), a seven-branch `if/elif` on `finding['type']`
returning fixed prose, with a catch-all "The observed cryptographic parameters
deviate from NIST SP 800-52r2 guidelines…" that is emitted verbatim for both
the signature and the key-size findings. The label and the icon are not
qualified anywhere in the output or the UI, so a judge watching a demo on a
machine without a key sees static template text presented as model output.
Pre-existing, not introduced by `4bb0bdc`, but it is the same
rule-distillation-sold-as-AI pattern the September audit flagged, and the new
`README.md` leans on "AI-assisted" framing. The fix is one line: say when the
offline fallback is in use.

---

## 7. "Passive" check

**The new code is passive.** `crypto_state_engine.py`,
`evidence_assessment_engine.py` and `provenance_service.py` import only
`typing`, `datetime`, `os`, `hashlib` and `pathlib`. No `socket`, `requests`,
`urllib`, `httpx`, `dns`, `ssl`, no OCSP or CRL fetch, no `subprocess` beyond
the pre-existing tshark wrapper. They read the analysis JSON and the capture
file on disk and derive from it. **[executed]** (import grep + successful runs)

Two caveats:

1. **It does not fabricate network activity, but it does present unmeasured
   values as observations.** The 1024-bit key size and the false self-signed
   flag are not observations; attaching them to a frame number and a NIST
   citation in the provenance graph (F43) is, in forensic terms, asserting
   something that was never seen on the wire. That is the "passive framework"
   requirement failing in spirit even though no packet was emitted.
2. **Pre-existing, not introduced here:** `gemini_service.py` *will* call the
   Google Gemini API at step 6 when `GEMINI_API_KEY` is set, sending
   capture-derived summaries to a third party during what is sold as passive
   offline forensics. In my runs the key was unset, so this did not happen —
   the capability is the concern, not anything I observed.
   `deployment/deploy-to-server.ps1` performs live SSH/SCP, but only when
   explicitly run.

---

## 8. What the reorganisation broke

| Area | Result |
|---|---|
| `start.bat` / `start.ps1` | **Fine.** Both resolve `%~dp0`/`$rootDir` and `cd` into `backend`/`frontend`, which still exist. **[executed]** (read) |
| Python imports | **Fine.** The moved files are documents and SQL; no module moved. The pipeline runs. **[executed]** |
| Hardcoded paths in `main.py` | **Improved.** `UPLOAD_DIR`/`RESULTS_DIR`/`TEST_DATA_DIR` now derive from `Path(__file__).resolve().parent` with a cwd fallback, fixing a real cwd bug. Credit. **[code-read]** |
| `.claude/launch.json` | Untracked, local-only, references `backend`/`frontend` — unaffected. **[code-read]** |
| References to old `DOCS/` paths | None left in code; the only `docs/` mentions are in `README.md` and `.gitignore`, and they resolve. **[executed]** (`git grep`) |
| Deleted `local_main.py` / `remote_main.py` | **No references anywhere.** `deployment/deploy-to-server.ps1` supersedes the "remote" lineage. Safe deletion. **[executed]** |
| Deleted root `package-lock.json` | **Harmless** — it was an empty 6-line stub. `frontend/package-lock.json` is intact and resolves `@xyflow/react`. **[executed]** |
| Frontend tests | **Broken for 2 of 5 files** from the natural cwd (F48). |
| Duplicated docs and test data | **New breakage** (F51) — four artefacts now exist in two places, and the stale coverage docs were duplicated rather than corrected. |
| `.gitignore` | **Misleading** (F52) — nothing was untracked. |

---

## 9. Updated merge / untangle impact

Measured in the fresh clone, read-only:
`git fetch <local repo> refs/tags/rescue/origin-main-2026-09-30-3974bc9`, then
`git merge-tree --write-tree --messages 4bb0bdc FETCH_HEAD`. **[executed]**

**It is materially worse than at `5fc711b`. Content conflicts went from 3 to 8,
plus 6 new file-location conflicts.**

Content conflicts:

```
backend/app/core/pcap_analyzer.py        (NEW — was clean at 5fc711b)
backend/app/core/security_engine.py
backend/app/utils/cert_analyzer.py
backend/main.py
frontend/package-lock.json               (NEW)
frontend/src/context/AuthContext.jsx     (NEW)
frontend/src/pages/Analysis.jsx          (NEW)
frontend/src/utils/api.js                (NEW)
```

File-location conflicts — all six of the trunk's `DOCS/*.md` files
(`Bugs-Found-and-Fixed`, `Competitive-Landscape-SIH26159`,
`Next-Features-Roadmap`, `RAG-Knowledge-Base-Design`,
`RAG-and-Fine-Tuning-Notes`, `Teammate-Deliverables-3-and-4`) are flagged as
"added in FETCH_HEAD inside a directory that was renamed in 4bb0bdc". Git
resolves them into `docs/architecture/` and the written tree contains **no
`DOCS/` directory** (26 paths, all under `docs/`), so the Windows case-collision
I was watching for does **not** occur in `merge-tree`'s output — but a human
resolving these by hand on a case-insensitive filesystem can easily recreate it.

**Silent auto-merges.** I diffed every one of them against the trunk
(`git diff FETCH_HEAD bc41c6d -- <file>`). **[executed]**

| File | Δ vs trunk | Verdict |
|---|---|---|
| `backend/app/utils/tshark_helper.py` | 8 lines | **Dangerous.** The merge substitutes `ssl/tls.record.version` → `ssl/tls.handshake.version`, i.e. **F38 lands silently on the trunk**, exactly as last time. Nobody will be prompted. **Take the trunk side explicitly and re-check `git diff` on this file before committing the merge.** |
| `.gitignore` | 18 lines | **Mildly dangerous.** Pulls in F52's ignore rules, which make the still-tracked uploads look remediated. Review by hand. |
| `frontend/src/App.jsx` | 17 lines | **Benign** — adds the two `/provenance` routes and keeps the trunk's `AuthCallback` route and `ProtectedRoute` wrapper. |
| `frontend/src/index.css` | 222 lines | **Benign** — additive styles. |
| `frontend/package.json` | 1 line | **Benign** — adds `@xyflow/react`. |
| `frontend/src/components/Dashboard.jsx` | 2 lines | **Benign.** |

The four conflicting backend files should still be resolved as the divergence
audit prescribes (take `3974bc9` for `cert_analyzer.py`, `security_engine.py`
and `tshark_helper.py`; take `3974bc9` as the base for `main.py` and
`pcap_analyzer.py`, then port forward only the genuinely good parts of this
commit). **The genuinely good parts worth porting are:** the `BASE_DIR`
path resolution in `main.py`, `LICENSE`, `.env.example`, the `source_refs`/
`rule_id` hook on `_add_finding`, the three new engine/service modules, the
React provenance components, and the `sys.stdout.reconfigure` guard from
`7cd4866`. **I tested the port rather than assuming it.** I extracted the trunk's backend
(`git archive FETCH_HEAD backend`) into a clean scratch directory, ran the
trunk pipeline on `SecureMailScope_SIHDemo.pcap`, and fed the resulting JSON
into the clone's three new modules. **[executed]**

- The trunk's DER pipeline reports the certificates **correctly**:
  `(1024, self-signed false)`, `(2048, true)`, `(1024, true)`, `(2048, true)` —
  an exact match for my independent `cryptography` parse, and independent
  confirmation that F35/F36 are fabrications.
- `CryptographicStateEngine` → `CRYPTOGRAPHIC_FAILURE`;
  `EvidenceAssessmentEngine` → 0 satisfied / 8 violated / 2 indeterminate;
  `ProvenanceGraphBuilder` → 59 nodes, 101 edges. **No exceptions, no schema
  drift.** The certificate nodes now carry the *true* 2048-bit sizes and
  self-signed flags.
- **One real caveat, and it is a new finding (F57):** the trunk produces 16
  findings, and the builder attaches artefact evidence to only **5** of them
  (`findings_unlinked: 11`). Its finding-type ladder does not recognise the
  trunk's `certificate_pki`, `no_forward_secrecy` or `email_authentication`
  types, so those findings link to a rule node and nothing else — silently.
  "Complete bidirectional traceability" becomes 5-of-16 on the real trunk.
  It is a contained fix (extend one `elif` chain), not a blocker.

---

## 10. Verdict

**Not safe to build on as it stands, and not safe to demo without fixes — but
for the first time the teammate has produced work that is genuinely worth
keeping.**

What is real: the provenance DAG is a correct, acyclic, fully-linked graph with
real frame citations; the two new engines are substantial, stdlib-only, passive
code with an honest uncertainty side (`Indeterminate`, `Not Applicable`,
`Insufficient Evidence`) that the project did not have before; ten test files
exist where there was one; `BASE_DIR` fixes a real bug; a LICENSE and a README
finally exist. These three modules are the best argument the project has for
SIH26159's "assess the cryptographic security posture" requirement.

What is wrong is that all of it sits on `cert_analyzer.py` and
`tshark_helper.py` as they were at `5fc711b`. The commit builds two new
presentation layers over four unfixed data-integrity defects. Two of those
defects gain reach: a hardcoded `1024` and an always-false self-signed flag now
have frame numbers and a NIST citation attached (F43), and F38's wrong version
label propagates into the graph's handshake nodes. Three further problems are
new to this commit's own code: the state engine has no rule that can assess
TLS 1.2 versus 1.3 (F44); 11 of the real trunk's 16 findings would silently
get no artefact lineage (F57); and the weak-cipher evidence that feeds the DAG
turns out never to have been reproducible between runs (F42, pre-existing but
first measured here). Meanwhile the documentation claims
state machines and tri-state vocabularies that do not exist in the code (F45),
and the `.gitignore` change makes the public credential exposure look addressed
when it is not (F52).

One correction worth stating plainly, because this report is the record: my
initial hypothesis that the crypto state engine's verdict was contaminated by
F38 was **wrong**, and the counterfactual in F44 disproves it. The engine's
aggregation is honest. The damage is concentrated in the certificate path and
in the documentation, not in the new reasoning code.

**Before any demo, in order:**

1. **F17** — rotate the credentials in `backend/uploads/28a7ec2024b8.pcap`. The
   repository is public and `4bb0bdc` did not untrack it. Unrelated to this
   commit; still the most urgent thing in the repo.
2. **F43 / F35 / F36** — do not demo the provenance graph's certificate nodes
   until the DER pipeline from `3974bc9` (`c1e7252`) replaces the hardcoded
   key size and the positional DN parser. A judge who clicks a certificate node
   is one `openssl x509` away from seeing the number is invented.
3. **F42** — sort the weak-cipher set before joining, and restrict it to
   ServerHello (F37). Two lines, and it turns a nondeterministic string into
   evidence.
4. **F44** — add a TLS-version-adequacy rule (nothing currently distinguishes
   1.2 from 1.3), and stop reporting TLS 1.3's encrypted certificates as
   "truncated or missing". Fixing F38 underneath it needs a `0x13xx`-cipher
   inference, because `secure_mail.pcap` is synthetic and omits the
   `supported_versions` extension that would otherwise settle it.
5. **F40** — fix `"MEDIUM (37/100)"` in both `backend/main.py:137` and
   `frontend/src/pages/NewAnalysis.jsx:34`. The headline preset currently
   promises 37 and delivers 97.
6. **F45** — make `README.md` describe the engines that exist. It is the first
   thing read and the easiest thing to be caught on.
7. **F46** — sanitise `capture_id` in all seven endpoints, and stop the `GET`
   results handler from writing to disk.
8. **F47 / F48** — add `pytest` to a `requirements-dev.txt`, add a `"test"`
   script to `frontend/package.json`, and fix the three competing root
   conventions so a reviewer can run `npm test` and see green.

On the merge: do **not** merge `4bb0bdc` into the trunk as a whole. Cherry-pick
the three new engine modules, the React provenance components, `LICENSE`,
`.env.example` and the `BASE_DIR` fix onto `3974bc9`, where they will consume
correct certificate and cipher data, and explicitly take the trunk side of
`tshark_helper.py`, `cert_analyzer.py` and `security_engine.py` — `tshark_helper.py`
will not ask.
