# Repo Divergence & Differential Audit — 2026-10-18

Scope: forensics on the GitHub repo `Amin-Patel/SecureMailScope`, a fresh clone
of it, and a differential comparison against this local working copy
(`C:\Users\Yash\Documents\Claude\SecureMailScope`). **Report only** — nothing was
pushed, deleted, or changed on the remote; every `gh` call was read-only.

Findings continue the numbering of [`Audit-2026-09-21.md`](Audit-2026-09-21.md)
(F7–F34) and [`Bugs-Found-and-Fixed.md`](Bugs-Found-and-Fixed.md) (items 1–6).
New findings start at **F35**.

Tags: **[executed]** = I ran it and measured the output. **[code-read]** = read
from source, not run.

## 0. Method and caveats

- The brief directed me to `.claude/agents/auditor.md`. **That file does not
  exist** — `.claude/` contains only `launch.json`, and no `auditor.md` exists
  under the repo or `~/.claude/`. I used the September audit's severity scale
  and its `[executed]`/`[code-read]` evidence convention in its place.
- The clone lives at
  `…\scratchpad\clone\SecureMailScope`; a `git clone --mirror` is at
  `…\scratchpad\mirror\SecureMailScope.git`. Driver scripts were written to
  `…\scratchpad\scripts\` (a *different* directory from the clone) and run with
  `python -I`, passing clone paths as arguments.
- **Clone code was executed with the local venv's interpreter**
  (`backend\venv\Scripts\python.exe`), from an explicit `cd` into the clone's
  `backend\`. **Dependencies therefore came from the local venv, not the clone's
  `requirements.txt`** — the venv has `cryptography>=48` while the clone pins
  `<47`, and the venv has `google-genai`/`python-dotenv`, which the clone's
  requirements omit. Nothing was installed into the venv.
- The `C:\Users\Yash\Documents\Datasets\NonTor` corpus used for F7 in September
  **no longer exists on this machine**, so F7's benign false-positive rate was
  **not re-measured** against the clone.
- Findings I did not touch this session are marked **not re-verified** rather
  than guessed at.

---

## 1. What happened to the repo — timeline with evidence

All commit dates below are the GitHub API's author dates (UTC) unless noted.

| When (UTC) | Event | Evidence |
|---|---|---|
| 2026-08-25 09:22 | Repo created, and a `PublicEvent` by `Amin-Patel` appears in the events feed. | `gh api repos/.../events`; `gh api repos/.../ -q .private` → **`private=false`, `visibility=public`** |
| 2026-09-01 04:59 | `070d84d` "We Cooked Babyyyyy" (LightDevil). **This is the merge base** of everything that followed. | `git merge-base origin/main main` → `070d84d` |
| 2026-09-14 08:17 | PR #1 (RAG KB, forward secrecy, cipher + certificate fixes) merged as `5707b2d`. | `gh pr list --state all` |
| 2026-09-17 12:09 | PR #2 (ML risk classifier) merged as `e6f3fe5`. | ditto |
| 2026-09-19 11:42–11:47 | PR #4 (`5d4fd9d`), PR #3 (`9fde317`), PR #5 (`72d2643`) merged. `origin/main` = `72d2643`. | ditto; local reflog `origin/main@{3}` |
| 2026-09-19 13:35 | All four feature branches deleted on GitHub (`DeleteEvent` × 4, Yashbandiwadekar). | events feed |
| 2026-09-23 → 09-29 | LightDevil continues **on top of `72d2643`**: `1751cc1` "Basic Security measures tested and passed", `4902a69` (merge, conflicts resolved in `main.py`/`gemini_service.py`), `207bb28` "safety commit", `3974bc9` "Auth problem solved". Pushed to `main` in two `PushEvent`s (09-24 19:19 → `207bb28`, 09-29 18:47 → `3974bc9`), by actor **`LightDevill`**. | events feed; local reflog `origin/main@{1}`,`@{2}` |
| 2026-10-16 18:26 | `7cd4866` "Add fourth Quick Demo preset…" by **Mohammed Amin Kaifi** — parented on **`070d84d`**, i.e. authored from a checkout last synced around 2026-09-01. | `git log --graph` in clone |
| 2026-10-16 19:46 | `5fc711b` "Enhanced SIH demo PCAP with certificate analysis + bug fixes", same author. | clone log |
| **2026-10-16 19:55:46** | **Force-push.** `PushEvent` by actor **`Amin-Patel`**, `before=3974bc9…`, `head=5fc711b…`. `5fc711b` is not a descendant of `3974bc9`, so this was necessarily a non-fast-forward (forced) update. | `gh api repos/.../events`; local reflog `origin/main@{0}: … forced-update` |

### Who wrote what, and where it lives

Three lines of history exist:

1. **`origin/main` = `5fc711b`** — `070d84d` + two commits by Mohammed Amin
   Kaifi. This is what a clone gets today. It is **~6 weeks and 38 commits
   behind** the merged work.
2. **Local `main` = `72d2643`** — contains all five merged PRs. 38 ahead / 2
   behind `origin/main`.
3. **The LightDevil line, `3974bc9`** — and this is the important structural
   fact: `git merge-base --is-ancestor 72d2643 3974bc9` → **true**. The
   orphaned line is a **strict superset of local `main`**, adding
   `backend/app/core/auth.py` (+242), `backend/app/utils/sanitizer.py` (+130),
   `docker-compose.yml`, `nginx.conf`, `frontend/src/pages/AuthCallback.jsx`,
   rewritten `AuthContext.jsx`/`supabase.js`/`api.js`, and the test files
   `test_auth_idor.py`, `test_crypto_pki.py`, `test_gemini_grounding.py`. It
   also *extends* (does not revert) the local-only fixes — `cipher_suites.py`
   and the DER-based `cert_analyzer.py` survive `4902a69`'s conflict
   resolution and gain RSASSA-PSS/DSA signature verification. **One caveat:**
   `3974bc9` does loosen item 1's ServerHello narrowing — the guard became
   `if hs.get('handshake_type') and hs.get('handshake_type') != 'ServerHello'`,
   so entries with an *empty* handshake type now pass, and the loop widened
   from `ciphers[0]` to every cipher in the entry. On the demo PCAP this
   produced no false positive (only the negotiated 3DES suite was reported —
   §5), but combined with F38's empty-`tls_version` regression it is the one
   place the two lines could interact badly.

Also local-only and on no remote: the audit branch **`docs/audit-2026-09-21`
(`75e424c`)** — `gh api …/commits/75e424c` returns **HTTP 422, "No commit
found"** — plus the untracked `.claude/` directory.

### What I could not establish

- **Whether the force-push was deliberate or an accident.** The `PushEvent`
  actor is `Amin-Patel` and the commit author is Mohammed Amin Kaifi, but the
  API does not record intent, and there is no PR, issue or comment about it
  (`gh issue list` → empty; no issues of any state). *Inference, not fact:*
  the parent chain (`7cd4866` sits directly on `070d84d`) is consistent with
  someone working from a stale local clone and running `push --force` to make
  it go through, rather than a deliberate history rewrite.
- **Whether branch protection ever existed.** `gh api repos/.../branches`
  reports `protected=false` for `main` today; GitHub exposes no history for
  that setting, so I cannot say whether it was ever on.
- **Whether anyone else cloned the repo while the merged work was on `main`.**
  Traffic/clone statistics were not queried (they would require push access
  scope and would not be reliable this far back).
- **F7's benign false-positive rate in the clone** — the dataset is gone.

---

## 2. Recovery position

### The premise in my brief was wrong in the team's favour

The brief states the four LightDevil commits "survive only as dangling objects
in the local object store." **They do not. GitHub still serves them today.**

- `gh api repos/Amin-Patel/SecureMailScope/commits/3974bc9…` → **200 OK**
  (same for `1751cc1`, `4902a69`, `207bb28`, and every PR merge commit).
- In the **fresh clone**, `git fetch origin 3974bc9bb11996d5949aea4c3c91ba8f3159c73c`
  **succeeded** (exit 0), and `git log FETCH_HEAD` walks the full history;
  `git ls-tree -r FETCH_HEAD` lists 253 files. **[executed]**

But no ref points at those objects. They are unreachable, so:

- A plain `git clone` does **not** get them (confirmed: the clone's log stops
  at `5fc711b`/`7cd4866`/`070d84d`).
- `git clone --mirror` does **not** get them either — the mirror's `show-ref`
  lists only `main`, `docs/rag-and-fine-tuning-notes`, and
  `refs/pull/{1..5}/head`; `git cat-file -t 3974bc9` in the mirror → **"Not a
  valid object name"**. **[executed]**
- Unreachable objects are subject to GitHub's garbage collection at any time
  and without notice. **This window will close.**

### What survives where

I measured this rather than assuming it: for each of the 38 commits in
`git rev-list 070d84d..72d2643`, I tested `git cat-file -e <sha>^{commit}`
**in the mirror clone** — which holds only what GitHub advertises on refs,
including `refs/pull/{1..5}/head`. **36 of 38 are present. [executed]**

| Work | Reachable from a live GitHub ref? | Recoverable from GitHub by SHA? | On this machine? |
|---|---|---|---|
| 36 of the 38 merged commits — incl. `c1e7252` (DER certificate rewrite) and `fffce2e` (weak-cipher fix) | **Yes** — via `refs/pull/{1..5}/head`, which the mirror clone carries. Not GC-exposed. | n/a | Yes — local `main` |
| The 2 merge commits `72d2643` (PR #5) and `9fde317` (PR #3) | **No** — the only two missing from the mirror | Yes | Yes |
| LightDevil auth/security/docker work (`1751cc1`, `4902a69`, `207bb28`, `3974bc9`) | **No** — unreachable, GC-exposed | Yes — fetch `3974bc9` | Yes — tags `rescue/origin-main-2026-09-25-207bb28`, `rescue/origin-main-2026-09-30-3974bc9` (left untouched) |
| `docs/audit-2026-09-21` (`75e424c`, this audit series) | No | **No** — HTTP 422, GitHub has never seen it | **Yes, and only here** |
| Untracked `.claude/launch.json` | No | No | Only here |

The repo has **0 forks** (`gh api repos/... -q .forks_count`), so there is no
third copy anywhere.

**If this machine dies today:** the *content* of the merged work survives on
GitHub's PR refs — a teammate could rebuild `main` from `refs/pull/{1..5}/head`
without touching an unreachable SHA. What is genuinely GC-exposed is the
**four LightDevil commits** (auth hardening, sanitizer, docker/nginx, three test
files — work that exists in no PR) and two merge commits. The September audit
branch and `.claude/` are gone outright, with no remote copy of any kind.

**What breaks for a teammate cloning today:** they get a 2026-09-01-era codebase
plus two demo commits. No RAG knowledge base, no ML classifier, no SPF/DKIM/
DMARC, no PDF export, no A–F grading, no folder monitoring, no threat intel, no
`cipher_suites.py`, no DER certificate pipeline, no auth hardening, 9 API
endpoints instead of 18, 1 test file instead of 2, and 1 DOCS file instead of 8.

### Recovery commands — **do not run these; they are the record of what to do**

```sh
# 1. Pin the orphaned line to a real ref on GitHub BEFORE it is garbage-collected.
#    From a clone, or from this working copy:
git fetch origin 3974bc9bb11996d5949aea4c3c91ba8f3159c73c
git branch rescue/lightdevil-3974bc9 FETCH_HEAD
git push origin rescue/lightdevil-3974bc9        # new branch; touches nothing existing

# 2. Push the two local rescue tags (they already point at 207bb28 / 3974bc9):
git push origin rescue/origin-main-2026-09-25-207bb28 \
                rescue/origin-main-2026-09-30-3974bc9

# 3. Push local main and the audit branch to NEW refs — never over origin/main:
git push origin main:refs/heads/rescue/local-main-72d2643
git push origin docs/audit-2026-09-21

# 4. Only then discuss with the team what origin/main should become (see §6).
```

Step 1 is the time-critical one — it is the only thing standing between the four
LightDevil commits and GitHub's garbage collector. Steps 2–4 protect work that
currently exists in exactly one place.

**Before pushing any of this to a ref on a public repo**, note what the
`3974bc9` tree contains: `backend/.env.example`, `frontend/.env.example`,
`backend/test-data/rsasnakeoil2.key` (the published Wireshark sample key) and
`.kilo/agents/data.md`. A scan for literal credential patterns
(`eyJ…`, `service_role`) matched only `frontend/src/lib/supabase.js`, which
holds the already-known hardcoded project **URL**, not a key (F33) — no literal
token was found. The real exposure is F17, which is already public (see §6
step 7). Also note the root-level `local_main.py`, `remote_main.py` and `.kilo/`,
which look like tooling/deployment leftovers rather than deliberate structure.

---

## 3. Differential findings table

Buckets: **NA** (feature absent from the clone), **Worse in clone** (fix exists
only locally), **Both**, **Better in clone**, **Not re-verified**.

| ID | Title (abbrev.) | Verdict | Evidence |
|---|---|---|---|
| 1 | `check_weak_ciphers` never fired | **Worse in clone** | Clone has no `cipher_suites.py`; it uses a 28-entry hardcoded hex set and scans *all* handshakes. Fires on `SecureMailScope_SIHDemo.pcap`, but with four offered-only ClientHello codes in the evidence — see F37. **[executed]** |
| 2 | `requirements.txt` missing deps | **Worse in clone** | Clone's `requirements.txt` lacks `google-genai`, `python-dotenv`, `chromadb`, `scikit-learn`, `joblib`, `xhtml2pdf`, `dnspython`, `certifi`; pins `cryptography>=42,<47` vs local `>=48,<51`. **[executed]** (diff) |
| 3 | AI fields dropped | **Worse in clone** | Clone's `pcap_analyzer.py:99` copies only `ai_explanation` onto each finding — it drops `ai_confidence`, `ai_source` *and* `ai_reference`, i.e. worse than the original bug. **[executed]** |
| 4 | Dead certificate checks | **Both broken, differently** | Clone replaced the dead tshark X.509 fields with *working* ones (`x509af.*`, `x509sat.*`) so checks now fire — but with hardcoded and misparsed values (F35, F36). The local DER rewrite (`c1e7252`) is absent. **[executed]** |
| 5 | HTTP 500 on Windows console | **Worse in clone** | Clone's `_print_report` is **not** wrapped in try/except (local's is, `pcap_analyzer.py:338`). Running the clone's analyzer directly: analysis completes, prints the report, then `Analysis failed: 'charmap' codec can't encode character '\U0001f916'` and returns `{'success': False}`. `7cd4866` adds `sys.stdout.reconfigure(encoding='utf-8')` in `main.py` only, so the **server** path is mitigated **[code-read]**, but any other caller (tests, CLI) still fails **[executed]**. |
| 6 / F9 | TLS 1.3 mislabeled | **Both — and the clone's "fix" does not work** | See **F38**. Clone swapped `record.version` → `handshake.version`; on `secure_mail.pcap` (ServerHello cipher `0x1302`, TLS-1.3-only) tshark reports `handshake.version = 0x0303` and the clone still prints `tls_version: 'TLS 1.2'`. **[executed]** |
| F7 | ~100% benign false positives | **Not re-measured** | NonTor dataset no longer on this machine. |
| F8 | Cert expiry judged against `now()` | **Both** | Clone: `if expiry < datetime.now(timezone.utc)` (`cert_analyzer.py:168`). Demonstrated live — see **F39**. **[executed]** |
| F10 | STARTTLS unimplemented | **Both** | `starttls` appears in the clone's `security_engine.py` and `gemini_service.py` (same `check_missing_starttls` lineage), so the gap is the same gap, not an absence. **[executed]** (grep) |
| F11 | ML layer cannot change outcomes | **NA** | No `backend/app/ml/` in the clone. **[executed]** |
| F12 | Duplicate `CERT_EXPIRED`; A–F grade | **NA (grading)** | Clone's result has no `grade` key. Duplicate-findings behaviour **not re-verified**. |
| F13 | Non-standard implicit-TLS ports | **Not re-verified** | |
| F14 | CORS + credentials | **Both, identical** | Both `main.py` files: `allow_origins=["*"], allow_credentials=True, allow_methods=["*"]`. **[executed]** (grep) |
| F15 | Path traversal in delete endpoints | **Both** | Clone `main.py:251`: `RESULTS_DIR / f"{capture_id}.json"` with no sanitisation, reached from `DELETE /api/analysis/{capture_id}` and the batch endpoint. **[code-read]** |
| F16 | Path traversal in results endpoint | **Both** | `GET /api/analysis/{capture_id}/results` (`main.py:175`) builds `RESULTS_DIR / f"{capture_id}.json"` straight from the path parameter, with no sanitisation — same pattern at lines 190, 235, 252, 291. **[executed]** (grep) |
| F17 | 59 pcaps committed; one with live credentials | **Both — and worse, because the repo is public** | Clone contains all 59 `backend/uploads/*`, including `28a7ec2024b8.pcap` (committed in `a5f918b`, below the merge base). tshark reports 2 plaintext auth-bearing packets (values not reproduced here). The repo is **public** (`gh api` → `private=false`), so this is publicly readable, not merely committed. **Escalate to Critical.** **[executed]** |
| F18 | Hex toggle defeats redaction | **Not re-verified** | |
| F19 | RAG grounding broken | **NA** | No `knowledge_base/` in the clone. |
| F20 | ML training data circular | **NA** | No ML layer. |
| F21 | Report shows unfused risk | **NA** | No PDF/report export in the clone. |
| F22 | Unmapped TLS codes leak as hex | **Both** | Same `version_map` fall-through in the clone's `tshark_helper.py`. **[code-read]** |
| F23 | Parser failure → 500 with raw stderr | **Both** | Clone `run_analysis_pipeline` re-raises as `HTTPException(500, f"...{str(e)}")`. **[code-read]** |
| F24 | Upload buffered before size check | **Not re-verified** | |
| F25 | Folder watcher loses error reason | **NA** | No folder monitoring in the clone. |
| F26 | SSLBL active download | **NA** | No `threat_intel_feed` in the clone. |
| F27 | `check_missing_starttls` gated capture-wide | **Not re-verified** | |
| F28 | Fabricated upload progress bar | **Not re-verified** | |
| F29 | `scapy` missing / `pyshark` unused | **Both (differently)** | Clone ships `generate_secure_sample.py` (scapy) and lists neither `scapy` nor the other missing deps; see item 2. **[executed]** |
| F30 | Stale committed `results/*.json` | **Both** | Clone's `backend/results/` contains 25 tracked JSON files, all below the merge base and all predating the current engine. **[executed]** |
| F31 | `_print_report` raises on cp1252 | **Worse in clone** | See item 5 — in the clone it does not merely truncate output, it fails the whole analysis. **[executed]** |
| F32 | Problem statement not committed | **Both** | Clone's `DOCS/` holds only `Master Website Functionality Map.md`. **[executed]** |
| F33 | Supabase URL hardcoded | **Both, identical** | `frontend/src/lib/supabase.js:3`, same fallback URL. **[executed]** |
| F34 | Backend binds `0.0.0.0` | **Both** | Clone `main.py:310`. **[code-read]** |

Counts over the 33 rows above (items 1–6 plus F7–F34; item 6 and F9 share one
row):

| Bucket | Count | Rows |
|---|---|---|
| Worse in clone | **5** | 1, 2, 3, 5, F31 |
| Present in both | **15** | 4, 6/F9, F8, F10, F14, F15, F16, F17, F22, F23, F29, F30, F32, F33, F34 |
| Not applicable | **7** | F11, F12, F19, F20, F21, F25, F26 |
| Better in clone | **0** | — |
| Not re-verified | **5** | F13, F18, F24, F27, F28 |
| Not re-measured | **1** | F7 |

**A note on finding IDs:** `SMS-NNN` is not stable. `security_engine.py:71`
assigns `f"SMS-{self.finding_counter:03d}"` sequentially per run, so the same
check gets a different ID depending on which checks fired before it. The
teammate's commit message and coverage docs use `SMS-005`/`SMS-007`/`SMS-009`
for checks that my runs numbered differently. Below I refer to findings by
**title**, and give IDs only as they appeared in the run I quote.

---

## 4. New findings on the teammate's two commits (F35–F41)

Both commits are by **Mohammed Amin Kaifi**. All testing below ran the clone's
own source under the local venv (see §0).

### F35 — Certificate key size is hardcoded to 1024, so every certificate is reported as undersized — **Critical** [executed]

`backend/app/utils/cert_analyzer.py:180` in `5fc711b`:

```python
# For key size, we need to extract from the actual certificate
# This requires parsing the DER-encoded cert, which is complex
# For rsasnakeoil2, we know it's 1024-bit RSA from the README
key_size = 1024  # Default assumption for old certs, should be extracted properly
pub_key_algo = 'rsaEncryption'
```

No certificate is ever measured. Ground truth, obtained by pulling the DER bytes
(`tls.handshake.certificate`) out of the commit's own
`backend/test-data/SecureMailScope_SIHDemo.pcap` and parsing them with
`cryptography`:

| Cert CN | True key size | Clone reports |
|---|---|---|
| `www.snakeoil.dom` | 1024 | 1024 |
| `smtp-modern.demo.local` | **2048** | 1024 |
| `smtp-expired.demo.local` | 1024 | 1024 |
| `smtp-future.demo.local` | **2048** | 1024 |

All four certificates are reported as 1024-bit; two of them are 2048-bit. The
shipped demo's "Insufficient Certificate Key Size" evidence reads
`"… (1024 bits, min 2048);  (1024 bits, min 2048);  (1024 bits, min 2048)"` —
three entries, two of them with empty subjects, against a true population of two
undersized certs. (The same check on the local/`3974bc9` trunk names exactly the
two genuinely 1024-bit certs — see §5.) On any real capture with modern
certificates this produces a HIGH finding on 100% of certificates. The commit
message presents SMS-005 as a detection that now works; it is a constant.

### F36 — Subject/issuer DN parsing is positional guesswork; self-signed detection never fires — **High** [executed]

`extract_certificates` reconstructs DNs by taking the flat `x509sat.printableString`
list, splitting it **in half**, and labelling the halves issuer and subject —
and only when there are ≥6 strings at all. Consequences measured on the demo
PCAP:

- 3 of 4 certificates come back with **empty** `subject` and `issuer`.
- `is_self_signed` is `False` for **all four**, but `cryptography` shows
  `subject == issuer` for **three** of them. The self-signed check therefore
  cannot fire — the same class of silently-dead check as item 4.
- Even the one parsed DN is mangled: the snakeoil cert's RDNs are
  `['XY','Snake Desert','Snake Town','Snake Oil, Ltd','Webserver Team','www.snakeoil.dom','www@snakeoil.dom']`
  but render as `C=Snake Desert, ST=Snake Town, L=Snake Oil, O= Ltd, …` — the
  country is dropped and `Snake Oil, Ltd` is split across two fields by the
  comma `split(',')`.

The commit's own `COVERAGE_MATRIX_VERIFICATION.md` claims SMS-009 (self-signed)
does not fire because there are "no certificates" — but the commit ships a PCAP
with four. The docs describe the pre-`5fc711b` state.

### F37 — Weak-cipher evidence lists ciphers the server never negotiated — **High** [executed]

The rewritten `check_weak_ciphers` iterates `cipher_suites` across **all**
handshakes, ClientHello included. On the demo PCAP:

- frame 25 (ClientHello) offers 20 suites; frame 27 (ServerHello) negotiates
  **`0x000a`** only.
- The reported evidence is `Weak ciphers: 0x000a, 0x0012, 0x0009, 0x0016, 0x0003`
  — four of five are offers the server declined.

This re-introduces exactly what item 1's fix removed ("a client merely offering
a weak cipher that the server never selects isn't a real finding"). The hardcoded
`WEAK_CIPHER_CODES` set also stops at `0x001B`, so it misses the export suites
`0x0062`/`0x0064` present in that same ClientHello — over-reporting and
under-reporting at once.

### F38 — The TLS-version "fix" does not fix the bug it claims to — **High** [executed]

`5fc711b` changes `ssl/tls.record.version` → `ssl/tls.handshake.version` and the
commit message asserts this fixes "all handshakes report as TLS 1.2". Measured
with tshark 4.6.8 on `backend/test-data/secure_mail.pcap`:

```
frame 5  type=2(ServerHello)  tls.record.version=0x0303  tls.handshake.version=0x0303  ciphersuite=0x1302
```

`0x1302` is `TLS_AES_256_GCM_SHA384`, TLS-1.3-exclusive, and RFC 8446 §4.1.3
freezes ServerHello `legacy_version` at `0x0303` exactly as it freezes the record
layer. The clone's pipeline still reports `tls_version: 'TLS 1.2'`. Item 6 and F9
are untouched. Two side effects the change does introduce:

- `handshake.version` is absent on non-Hello handshake records, so most
  handshake entries now carry an empty `tls_version`: **8 of 11** on
  `rsasnakeoil2.cap` **[executed]**. Under the old `record.version` those
  records did carry a version, so this is a coverage regression.
- ClientHello entries now report the client's *offered maximum* rather than
  anything negotiated. (The "3 TLS handshakes using SSL 3.0" count in the demo
  is **not** attributable to this change — `record.version` is `0x0300` on
  those frames too, so the old code counted them as well.)

### F39 — The demo's headline "expired 2008" finding is F8 in action — **Medium** [executed]

`SecureMailScope_SIHDemo.pcap` is built by merging `rsasnakeoil2.cap`, whose
frames are dated **2006-04-24**. Parsing that certificate's DER gives
`notBefore 2003-03-05 → notAfter 2008-03-03` **[executed]**, so it was valid at
capture time by almost two years. The clone flags it expired because it compares
against `datetime.now()`. The flagship demo therefore *depends on* F8 being
unfixed: fix F8 and the demo loses a finding.

### F40 — Demo preset metadata contradicts the shipped behaviour — **Medium** [executed]

`7cd4866` registered the preset with `"expected_risk": "MEDIUM (37/100)"` and the
description "SMTP, IMAP, and POP3 with TLS 1.2 and plaintext traffic".
`5fc711b` then changed the same PCAP's result to **97/100 CRITICAL** with SSL 3.0
and 3DES, but left the metadata alone — in **both** `backend/main.py:133` and
`frontend/src/pages/NewAnalysis.jsx:34` (the hardcoded `DEFAULT_SAMPLES`
fallback). A judge clicking the preset sees "MEDIUM (37/100)" and gets a
CRITICAL 97. The duplicated constant means the discrepancy must be fixed twice.

### F41 — "All bugs verified fixed with end-to-end testing" — no test was added — **Low** [executed]

Note first that the four new Markdown files describe the **pre-`5fc711b`**
state: `COVERAGE_MATRIX_VERIFICATION.md` says the key-size and self-signed
checks do not fire because there are "no certificates", while the same commit
ships a PCAP with four and the key-size check *does* fire. `5fc711b` adds
2,152 lines across 11 files and **zero** test files; the clone's
`backend/tests/` still contains only `test_e2e_pipeline.py`, unchanged. The four
new Markdown files assert `✅ FIXED AND VERIFIED` for the three bug fixes, two of
which (F35, F38) do not work. The rewritten extractor also keeps the
`except Exception: print(…); return []` shape that hid item 4 in the first place
(`cert_analyzer.py:206-211`).

---

## 5. Local vs clone comparison

| Dimension | Local (`main` @ `72d2643`, + `docs/audit-2026-09-21`) | Clone (`origin/main` @ `5fc711b`) |
|---|---|---|
| Base | `070d84d` + 38 commits | `070d84d` + 2 commits |
| RAG knowledge base | `backend/app/knowledge_base/` | absent |
| ML risk classifier / anomaly detector | `backend/app/ml/` | absent |
| SPF/DKIM/DMARC | present (`email_auth` in results) | absent |
| PDF export / A–F grading / folder monitoring | present | absent |
| Threat intel (SSLBL) | present | absent |
| Cipher-suite registry | `core/cipher_suites.py` (IANA, ServerHello-only) | 28 hardcoded hex codes, all handshakes |
| Certificate pipeline | DER + `cryptography` (`c1e7252`) | tshark `x509af`/`x509sat` fields, key size hardcoded |
| API routes | 18 | 9 |
| Backend tests | 2 files | 1 file |
| DOCS | 8 files | 1 file |
| `requirements.txt` | 8 extra packages; `cryptography>=48,<51` | `cryptography>=42,<47` |
| Windows console crash | `_print_report` wrapped | unwrapped; mitigated in `main.py` only |
| Demo presets | 3 | 4 (the 4th mislabelled — F40) |

**Who's ahead:** local on every feature axis and on items 1–6; the clone only on
(a) the extra demo PCAP as an *artifact* and (b) the `sys.stdout.reconfigure`
server-level guard, which is a reasonable addition worth keeping.

**What a judge cloning today can demo:** upload a PCAP, see protocol detection,
plaintext/encrypted counts, SSL 3.0 and weak-cipher findings, and four
certificate findings — three of which are partly or wholly fabricated (F35,
F36, F39). No AI/RAG grounding, no ML, no email authentication, no exportable
report, no grade. Roughly the Day-6 product plus a demo capture.

### Head-to-head on the teammate's own demo PCAP [executed]

I extracted the `3974bc9` tree into a clean directory
(`git archive 3974bc9 backend | tar -x`) and ran it, under the same local venv,
against `SecureMailScope_SIHDemo.pcap` — the clone's own demo file. This is the
decisive comparison, because it is the teammate's artefact judged by both
engines:

| (both run under the local venv) | Clone (`5fc711b`) | Trunk (`3974bc9`) |
|---|---|---|
| Findings | 6 | 16 |
| Weak-cipher evidence | `0x000a, 0x0012, 0x0009, 0x0016, 0x0003` — 4 of 5 never negotiated | `TLS_RSA_WITH_3DES_EDE_CBC_SHA (3DES (Sweet32))` — the one suite actually negotiated |
| Key sizes | all 4 certs "1024" (2 are 2048) | names exactly the two genuinely 1024-bit certs, with correct full RDNs |
| Self-signed | fires on **0** of 3 self-signed certs | fires on all 3 |
| Also produced | — | forward secrecy, untrusted-CA/chain, not-yet-valid cert, DKIM-absence, `email_auth`, `ml_assessment`, `certificate_chains`, `tcp_streams` |

One caveat on the trunk side, which is the existing F12: self-signed findings
are **duplicated** (`smtp-modern.demo.local` is reported three times). That is a
pre-existing local defect, not something the clone fixes.

**Independent reimplementation:** yes, and it is the crux of the merge problem.
The teammate re-fixed items **1, 4 and 6** from scratch, in the same three
files, worse, without the registry/DER work — while `3974bc9` had already built
*further* on the local versions. `git merge-tree --write-tree 5fc711b 3974bc9`
in the clone gives the exact landing zone **[executed]**:

```
CONFLICT (content): backend/app/core/security_engine.py
CONFLICT (content): backend/app/utils/cert_analyzer.py
CONFLICT (content): backend/main.py
Auto-merging .gitignore
Auto-merging backend/app/utils/tshark_helper.py      <-- silent, and wrong
```

`tshark_helper.py` **auto-merges**, which is the dangerous one: nobody will be
prompted, and the `record.version` → `handshake.version` change (F38) lands
silently on top of the local tree.

---

## 6. Recommended untangling order

Written for someone reconciling two diverged histories without losing either
side. Steps 1–3 are safe and additive; nothing overwrites an existing ref.

0. **Rotate the credentials in `backend/uploads/28a7ec2024b8.pcap` now, before
   anything else.** This touches no git history and blocks on nothing, so it
   runs in parallel with every step below. The repository is public and the
   capture has been readable since `a5f918b`. (*Inference:* the `PublicEvent`
   timestamp equals the repo's `created_at`, which suggests it has been public
   from creation — about seven weeks of exposure — but GitHub does not expose a
   visibility history, so I cannot prove it was never briefly private.)
1. **Preserve first, decide later — today.** Run §2's recovery commands. 36 of
   the 38 merged commits are safe on GitHub's PR refs, but the **four
   LightDevil commits** (auth hardening, sanitizer, docker/nginx, three unrun
   test files) and the **`docs/audit-2026-09-21` branch** exist on no ref
   anywhere — the former only as GC-exposed objects, the latter only on this
   machine.
2. **Agree the base.** `3974bc9` is a strict superset of local `main`, so it —
   not `72d2643` — is the correct trunk. The only work outside it is the
   teammate's `7cd4866` + `5fc711b`.
3. **Turn on branch protection for `main`** (block force-push, require a PR).
   This is the control whose absence allowed six weeks of work to be replaced by
   one `push --force`.
4. **Restore `main` by merge, not by force-push back.** Open a PR from
   `rescue/lightdevil-3974bc9` into `main`. That merge has exactly three
   conflicts (above) plus one silent auto-merge. Resolution rules:
   - `tshark_helper.py` — **take the local/3974bc9 side explicitly** even though
     git will not ask. The teammate's change does not fix item 6 (F38). Re-check
     `git diff` on this file before committing the merge.
   - `cert_analyzer.py` — **take `3974bc9` wholesale.** The DER pipeline measures
     key sizes and compares RDNs structurally; the clone's version hardcodes
     1024 (F35) and cannot detect self-signed certs (F36).
   - `security_engine.py` — **take `3974bc9`**, then **tighten the ServerHello
     guard back** to `!= 'ServerHello'` without the `and hs.get(...)` escape
     hatch (see the caveat in §1) — otherwise F38's empty-`tls_version`
     entries start slipping into the cipher check. Cherry-pick *nothing* from
     the clone's `WEAK_CIPHER_CODES`; instead verify `cipher_suites.py` covers
     the codes that set names, plus the export suites `0x0062`/`0x0064`, which
     the clone's set misses too.
   - `main.py` — take `3974bc9` as the base, then **port forward two things from
     `7cd4866`**: the `sys.stdout.reconfigure(encoding='utf-8')` guard (genuinely
     useful; keep the local `_print_report` try/except as well) and the
     `sih_comprehensive` preset registration.
5. **Re-run the real tests after the merge** — `backend/tests/test_e2e_pipeline.py`
   and `test_deliverables_3_and_4.py`, plus the three test files that arrive with
   `3974bc9` (`test_auth_idor.py`, `test_crypto_pki.py`, `test_gemini_grounding.py`),
   which have never been run in this environment.
6. **Keep the demo PCAP, fix its labels.** `SecureMailScope_SIHDemo.pcap` is a
   genuinely useful multi-protocol artefact. Once the local certificate pipeline
   is back in place, re-measure it and correct the preset metadata in both
   `main.py` and `NewAnalysis.jsx` (F40). Expect the findings to change: the
   fabricated key-size evidence (F35) and the 2008 expiry (F39, once F8 is
   fixed) will drop out, and self-signed should start firing (F36).
7. **Purge the F17 blob from history — last.** With the credentials already
   rotated (step 0), removing `backend/uploads/28a7ec2024b8.pcap` and the other
   58 captures from history is itself a force-push exercise, and must not be
   attempted until steps 1–4 are done and every ref is safely on the remote.
8. **Finally, preserve `docs/audit-2026-09-21`.** It exists nowhere but here.
   **But note what pushing it to a public repo does:** that branch — and this
   document — contain write-ups of an unauthenticated path traversal, the open
   CORS policy and the exact location of the credential-bearing capture.
   Either back the branch up somewhere private, or push it only after F14–F17
   are fixed.
