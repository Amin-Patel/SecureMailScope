# Bugs Found This Session — Summary

A running log of pre-existing bugs discovered (and, where in scope, fixed)
while building the RAG knowledge base and the forward-secrecy check on
`feature/rag-knowledge-base`. None of these were introduced by that work —
they predate it — but building real, end-to-end-tested features surfaced
them because it's the first time this pipeline was actually run to
completion against real PCAPs in this environment.

---

## Fixed

### 1. `check_weak_ciphers` has likely never fired correctly

**Where:** `backend/app/core/security_engine.py`

**What was wrong:** it string-matched cipher suite *names* (`'RC4' in
cipher.upper()`, etc.), but tshark reports the negotiated cipher suite as a
raw hex code (e.g. `"0x000a"`), never as a name. A hex string can't contain
the substring `"RC4"`, so the check could never match anything, on any
capture, ever.

**Fix:** added `backend/app/core/cipher_suites.py`, an IANA cipher-suite
registry mapping hex codes to name/key-exchange-mechanism/weak status, and
rewrote the check to look up the actual negotiated cipher (from the
ServerHello) against it. Also narrowed the check from "any cipher_suites
entry across all handshake messages" to "the cipher actually negotiated in
ServerHello" — a ClientHello lists many offered ciphers, and a client
merely offering a weak one that the server never selects isn't a real
finding.

**Verified:** the `legacy_ssl3` demo capture (negotiates
`TLS_RSA_WITH_3DES_EDE_CBC_SHA`) now correctly fires this finding; it did
not before.

### 2. `requirements.txt` missing dependencies `gemini_service.py` already used

**Where:** `backend/requirements.txt`

**What was wrong:** `google-genai` and `python-dotenv` were imported by
`gemini_service.py` but never listed, so a clean `pip install -r
requirements.txt` would fail to import that module.

**Fix:** added both, plus `chromadb` for the new knowledge base.

### 3. AI response fields silently dropped before reaching the API

**Where:** `backend/app/core/pcap_analyzer.py`

**What was wrong:** `GeminiSecurityAssistant.explain_finding()` returns
`ai_source` (and now `ai_reference`), but the caller only copied
`ai_explanation` and `ai_confidence` onto the finding — the rest was
computed and thrown away.

**Fix:** now also attaches `ai_source` and `ai_reference` to each finding.

---

## Found, not fixed (out of scope for the work in progress — flagged for follow-up)

### 4. All four certificate-based checks are currently dead

**Where:** `backend/app/utils/cert_analyzer.py`

**Severity: high — this is the most impactful bug found this session.**

**What's wrong:** the tshark field names it queries —
`x509af.validity.notBefore`, `x509af.validity.notAfter`,
`x509af.signatureAlgorithm`, `x509af.publicKeyAlgorithm`,
`x509af.publicKey.length` — do not exist in the installed tshark version
(4.6.8; confirmed via `tshark -G fields`, and by running the exact command
`cert_analyzer.py` builds, which errors with `Some fields aren't valid`).
tshark exits non-zero, `result.stdout` is empty, and the surrounding
`except` swallows this into a silent `return []` — so `extract_certificates`
always returns zero certificates, on every capture, no error surfaced
anywhere.

**Consequence:** `check_weak_signatures`, `check_key_sizes`,
`check_expired_certificates`, and `check_self_signed_certificates` in
`security_engine.py` all operate on an always-empty `certificates` list —
none of them can ever produce a finding, regardless of what's actually in
the capture. That's 4 of the (now) 9 documented security checks.

**Why not fixed now:** the field-name drift goes deeper than a rename —
this tshark version also has no direct equivalent of
`x509af.publicKey.length` (key length would need to be derived from the raw
`x509af.subjectPublicKey` bytes), and signature/public-key algorithm are
now OID-based (`x509af.algorithm.id`), requiring an OID→name lookup similar
in shape to the cipher-suite registry added for forward secrecy. That's a
real, self-contained follow-up task, not a one-line fix.

**Recommended next step:** rebuild `cert_analyzer.py`'s tshark field list
against `tshark -G fields | grep x509af`, add an OID→algorithm-name table
(mirroring `cipher_suites.py`'s approach), and derive key length from the
raw public key bytes. Verify against `test-data/rsasnakeoil2.cap`, which is
known to carry a real certificate.

### 5. Successful analyses crash into HTTP 500 on Windows consoles

**Where:** `backend/app/core/pcap_analyzer.py`, `_print_report()`

**What's wrong:** it prints a 🤖 emoji to the console. On a Windows console
using the default cp1252 code page, that `print()` raises
`UnicodeEncodeError` — and because it happens *after* the analysis has
already fully succeeded but *inside* the same `try` block, the outer
exception handler reports the entire analysis as failed (HTTP 500) even
though `findings`, `risk`, and `ai_summary` were all correctly computed.

**Why not fixed now:** out of scope for the RAG/forward-secrecy branches;
worked around locally for testing via `PYTHONIOENCODING=utf-8`.

**Recommended fix:** `sys.stdout.reconfigure(encoding="utf-8")` once at
process start in `main.py`, or drop the emoji from the print statements.

---

## Net effect once bugs #1 and #4 are both fixed

Before this session, in this environment, the existing
`backend/tests/test_e2e_pipeline.py` suite passed 4/8 (blocked entirely by
TShark not being installed). After installing TShark and fixing #1-#3
above, it passes **8/8** — but that's measuring API-level behavior
(status codes, report generation), not finding correctness. Bug #4 means
the suite's "passing" state doesn't currently exercise certificate-based
findings at all. Fixing #4 is the single highest-leverage remaining item:
it silently restores an entire quarter of the documented security checks.
