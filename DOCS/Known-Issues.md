# SecureMailScope — Known Issues

**As of:** 2026-10-19 · **Branch:** `Production` (`c298e4a`, 12 commits on the `3974bc9` trunk)

Every bug and problem found across four reviews, in one place, with what is still
wrong on `Production` and what is already dealt with.

**Status vocabulary**

| Status | Meaning |
|---|---|
| **OPEN** | Confirmed still wrong on `Production`, by execution |
| **OPEN (unverified)** | Found earlier, not re-measured on `Production` — assume still wrong |
| **RESOLVED** | Fixed or superseded on `Production`, with executed evidence |
| **PARTIAL** | Materially improved, not finished |

**Sources** — all on this branch, each finding's evidence lives in its source document:

- `DOCS/Audit-2026-09-21.md` — the original audit against the SIH26159 problem statement (F7–F34, plus items 1–6)
- `DOCS/Repo-Divergence-2026-10-18.md` — the force-push forensics and the first review of Amin's demo commits (F35–F41)
- `DOCS/Verification-4bb0bdc-2026-10-18.md` — verification of the reorganisation commit (F42–F59)
- `DOCS/Merge-Report-Production-2026-10-19.md` — what the three-branch merge resolved, fixed and left
- `DOCS/Bugs-Found-and-Fixed.md` — the original session log (items 1–6)

---

## Fix these first

1. **F17 — rotate the leaked SMTP credential.** Nothing else on this list is reachable by a stranger.
2. **F45 — write a truthful README.** The branch has none; judges see the repo's front page first.
3. **F9/F38 — TLS 1.3 is reported as TLS 1.2.** The headline protocol claim, wrong on modern traffic.
4. **F8/F39 — certificate validity is judged against today, not capture time.** Makes every historical capture look expired.
5. **Render the provenance DAG once.** Everything behind it is verified; the view itself never has been.

---

## Open — confirmed on `Production`

| ID | Sev | Problem | Where |
|---|---|---|---|
| **F17** | **Critical** | A tracked upload carried a plaintext SMTP credential, on a **public** repo. Untracking removed it from the branch tip only — it is in every historical commit and still publicly readable. Rotating the password is the fix; a history purge is a separate exercise. | git history |
| **F9 / F38** | High | TLS 1.3 is still reported as TLS 1.2. Rejecting Amin's broken change restored version coverage but did not fix the mislabel. A real fix needs `0x13xx`-cipher inference, because the sample capture omits the `supported_versions` extension. | `tshark_helper.py` |
| **F45** | High | No README on the branch at all. Amin's was rejected because it documented a state machine, a posture scale and three directories that do not exist in the code. | repo root |
| **F8 / F39** | Medium | Certificate expiry and trust are evaluated against `datetime.now()` instead of capture time, so the 2006 snakeoil certificate reads as expired and the demo's "expired 2008" headline is an artefact of this bug. | `cert_analyzer.py` |
| **F12** | Medium | Duplicate self-signed findings — three for `smtp-modern.demo.local` across frames 89/126/155. They now link to the correct certificate node, but the duplication remains and dilutes the A–F grade. | `security_engine.py` |
| **F44** | Medium | The crypto state engine has no TLS-version-adequacy rule, so it cannot tell 1.2 from 1.3, and a real TLS 1.3 session's encrypted certificates would be reported "truncated or missing". | crypto state engine |
| **F26** | Medium | A tool the problem statement calls *passive* performs a live internet download (the SSLBL feed) during analysis. Verified live: 839,711 bytes, 10,997 fingerprints. Legitimate feature, but it must be opt-in and labelled. | `threat_intel_feed.py` |
| **F59** | Medium | With no `GEMINI_API_KEY`, text under an "🤖 AI Analysis" heading is an offline template ladder. The backend says so on the console and `ai_source` records it, but the user-facing label does not. | frontend |
| **F34** | Medium | The backend binds `0.0.0.0`, exposing it to the whole network. | `main.py` |
| **F11 / F20** | High | The ML layer's structural problem is unchanged: labels are distilled from the rule engine, fusion is raise-only so the model cannot alter an outcome, the anomaly detector fired on none of 2,238 sessions, and the "108 real sessions" were also the validation captures. Both models load and score on `Production`, which is presence, not usefulness. Never quote 99.21% as detection accuracy. | `ml/`, `training_report.txt` |
| **F32** | Low | The SIH26159 problem statement is still not committed anywhere in the repo. | — |

---

## Open — not re-measured on `Production`

Carried forward from the September audit. The code paths largely still exist, so treat these as open until someone runs them.

| ID | Sev | Problem |
|---|---|---|
| **F7** | Critical | Non-email captures (browsing, Skype, Hangouts — zero email packets) produced maximum-severity "email security" verdicts. Checks are not scoped to email traffic. **Cannot be re-measured: the `Datasets\NonTor` corpus is gone from the machine.** |
| **F10** | Critical | STARTTLS "validation" is unimplemented, and a correct upgrade on port 587 was reported as cleartext CRITICAL because encryption is decided by port number. |
| **F13** | High | Implicit TLS on non-standard ports is invisible to protocol detection, though the problem statement names IMAPS/POP3S/SMTPS. |
| **F18** | High | Credential redaction is defeated by the stream viewer's hex toggle — the raw bytes survive in `hex_payload`. |
| **F19** | High | RAG grounding was poor for the two finding types that actually occur. **PARTIAL:** on `Production`, 12 of 16 findings carry an `ai_reference` quoting knowledge-base text, but F19's specific case was not re-tested. |
| **F21** | Medium | The exported report showed the unfused (lower) risk level, disagreeing with the dashboard. |
| **F22** | Medium | Unmapped TLS-version codes leak into output as raw hex. |
| **F23** | Medium | A parser failure returns HTTP 500 with raw tshark stderr; extractor error handling is inconsistent. Four third-party captures are corrupt and tshark itself rejects them. |
| **F24** | Medium | Uploads are buffered entirely in memory before the size check, and the frontend's 500 MB limit disagrees with the backend's 100 MB. |
| **F25** | Medium | The folder watcher records `error: null` on failure and leaves an orphaned staged upload. The success path is verified (1.0s pickup); the failure path is not. |
| **F27** | Medium | `check_missing_starttls` is gated capture-wide, so mixed captures are missed. |
| **F28** | Medium | The upload progress bar is a 400 ms animation, not real progress, and the frontend calls a `/status` endpoint that does not exist. |
| **F31** | Low | `_print_report` still throws `UnicodeEncodeError` on a cp1252 console. Running under `-X utf8` masks it rather than fixing it. |
| **F33** | Low | The Supabase project URL is hardcoded and ships in `frontend/dist`. No key is leaked. The auth rewrite may have changed this — unverified. |
| **F49** | Medium | Four of five frontend test files assert on source text rather than behaviour, so they pass whether or not the UI works. |
| **F50** | Medium | The ported backend tests feed hand-written mocks with correct values, so they structurally cannot catch the F35/F36 class of bug. |
| **F56** | Medium | A committed "validation output" predates the engines shipped alongside it. |
| **F58** | Low | Upload validation gaps around the `.tgz` artefact. |

---

## Resolved on `Production`

Don't re-fix these. Each was verified by execution; evidence is in the merge report.

| ID | What changed |
|---|---|
| **F35** | Certificate key sizes are measured from the DER, not hardcoded to 1024: 1024 / 2048 / 1024 / 2048 on the demo capture |
| **F36** | Structural self-signed comparison and full RDN parsing — 3 of 4 certificates correctly flagged |
| **F37 / F42** | Weak-cipher evidence is ServerHello-only, keyed by cipher code, deterministically ordered, and no longer sliced to five entries. Four processes over four captures now give byte-identical evidence |
| **F43** | The provenance DAG's certificate nodes carry true values instead of laundering a fabricated `1024`/`false` into chain-of-custody evidence |
| **F40** | All four demo presets re-measured in both `main.py` and `NewAnalysis.jsx`; the preset card's broken `expected_risk` comparison fixed |
| **F15 / F16** | Path traversal: 10 probes return 400/404, with `sanitize_capture_id` plus ownership checks on every sink |
| **F46** | The two new endpoints are sanitised and ownership-checked, and the `GET` that rewrote stored evidence is gone |
| **F14** | CORS is origin-restricted via `ALLOWED_ORIGINS` instead of `*` (**PARTIAL** — see F34 for the bind address) |
| **F47** | `requirements-dev.txt` declares `pytest` and `httpx` |
| **F48** | One test-root convention; 27/27 frontend cases pass from either directory |
| **F51 / F30** | Duplicate captures, duplicate docs, the byte-identical "Enhanced" PCAP and stale analysis artefacts removed |
| **F52** | `backend/uploads/` and `backend/results/` untracked, so the ignore rules finally bite |
| **F53 / F54** | The false-claim README and the deployment script carrying personal infrastructure are not on this branch |
| **F55 / F41** | Test counts in the docs now match the tree |
| **F57** | DAG evidence linkage 5/16 → 16/16, and the false edges it exposed (ECDHE handshakes cited as *lacking* forward secrecy; a ClientHello offer list cited as negotiation) corrected |
| **F29** | Dependencies reconciled with actual imports |
| Items 1–6 | From the original log: weak ciphers, requirements, dropped AI fields, dead certificate checks, the Windows HTTP 500, and the TLS version label — all superseded by the trunk's implementations, except the TLS 1.3 mislabel which remains open as F9 |

---

## Unverified claims and loose ends

Problems of confidence rather than code.

- **The provenance DAG view has never been rendered in a browser.** It sits behind `ProtectedRoute`, which needs a remote Supabase session no reviewer had credentials for. Everything feeding it is verified; the view is not.
- **The real server has never been started.** The whole API was exercised through `TestClient` with no-op stand-ins for `PyJWT` and `slowapi`, which are declared but absent from the venv. Routes, ownership, sanitisation and response bodies are real; **rate limiting and JWT verification are not**. That the branch behaves identically under real uvicorn is an inference.
- **13 backend tests did not run** — the JWT-minting cases in `test_auth_idor.py`, blocked by those same stubs. Recorded as not run, not as passing. 59 pass, 0 fail.
- **Docker and nginx are unproven.** `docker compose config` exits 0; no image was built and nginx never loaded its config.
- **Gemini-backed paths are untested** — no API key, so only the offline fallbacks ran.
- **A trunk test fixture was edited** (`test_crypto_pki.py`) because tightening the ServerHello guard made it fail. Worth a second pair of eyes.
- **Hand-merged, never seen rendered:** `Analysis.jsx` (five conflicts resolved as unions — a 9-tab bar and a two-button sessions column) and 222 merged lines of `index.css`.
- **Licensing:** a MIT `LICENSE` arrived with the port. That is a decision someone should make deliberately.

---

## Problems in the requirements themselves

From the September audit, still true:

- **"Blockchain" is only the theme tag.** The word appears nowhere in the problem statement's description, objectives or deliverables. Say so in the pitch rather than bolting on a token ledger.
- **SPF/DKIM/DMARC, RAG/Gemini and the threat-intel feed are extras, not requirements.** Good differentiators, but label them as supplementary, and keep the active ones out of any "passive" claim.
- **Synthetic data is explicitly allowed** by the dataset line, so using it is not a flaw. The flaws are narrower: labels distilled from the rules, and no measured false-alarm rate on benign traffic.
- **"Risk score" and "posture" are undefined** by the statement. The 0–100 scale and A–F thresholds are a local definition, and they pin at 100/F on most real captures, so they convey little gradation. Define and defend the scale.
