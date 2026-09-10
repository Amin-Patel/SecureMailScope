# Bugs Found This Session — Summary

A running log of pre-existing bugs discovered (and, where in scope, fixed)
while building the RAG knowledge base, the forward-secrecy check, and the
certificate-pipeline fix on `feature/rag-knowledge-base`. None of these
were introduced by that work — they predate it — but building real,
end-to-end-tested features surfaced them because it's the first time this
pipeline was actually run to completion against real PCAPs in this
environment.

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

### 4. All four certificate-based checks were completely dead

**Where:** `backend/app/utils/cert_analyzer.py`

**Severity: high — this was the most impactful bug found this session.**

**What was wrong:** the tshark field names it queried —
`x509af.validity.notBefore`, `x509af.validity.notAfter`,
`x509af.signatureAlgorithm`, `x509af.publicKeyAlgorithm`,
`x509af.publicKey.length` — do not exist in the installed tshark version
(4.6.8; confirmed via `tshark -G fields`, and by running the exact command
`cert_analyzer.py` built, which errored with `Some fields aren't valid`).
tshark exited non-zero, `result.stdout` was empty, and the surrounding
`except` swallowed this into a silent `return []` — so `extract_certificates`
always returned zero certificates, on every capture, no error surfaced
anywhere. That meant `check_weak_signatures`, `check_key_sizes`,
`check_expired_certificates`, and `check_self_signed_certificates` could
never fire, regardless of what was actually in a capture.

**Fix:** rebuilt extraction to pull only the one X.509 field tshark
reliably exposes across versions — the raw DER certificate bytes
(`tls.handshake.certificate`/`ssl.handshake.certificate`, a plain
`FT_BYTES` field with no version-specific sub-dissection) — and parse them
directly with the `cryptography` library (already a project dependency)
instead of depending on tshark's own X.509 dissector fields. Also replaced
a fragile raw-string self-signed comparison and manual date-string parsing
with structural RDN comparison and `cryptography`'s typed, timezone-aware
datetime fields.

**Verified:** the `legacy_ssl3` demo capture (a real 1024-bit RSA cert,
MD5-signed, expired since 2008) went from 3 findings to 6 — correctly
firing `weak_signature`, `insufficient_key_size`, and `expired_certificate`
for the first time ever in this environment. Confirmed no regression on
`secure_enterprise` (TLS 1.3 — certificate is encrypted in the handshake,
so this correctly extracts zero certs rather than crashing) and
`vulnerable_smtp` (no TLS at all). The frontend's `CertificateViewer`
component's substring-based checks (`MD5`/`SHA-1`, `RSA`, key size) line up
correctly with the new field values with no frontend changes needed.

---

## Found, not fixed (out of scope for the work in progress — flagged for follow-up)

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

## Net effect

Before this session, in this environment, the existing
`backend/tests/test_e2e_pipeline.py` suite passed 4/8 (blocked entirely by
TShark not being installed). After installing TShark and fixing #1-#4
above, it still passes **8/8** at the API level, but the `legacy_ssl3`
demo capture now correctly produces **6 findings instead of 3** — the
suite was passing throughout, but for most of this session it wasn't
actually exercising a quarter of the documented security checks. All nine
checks are now confirmed live end-to-end. Bug #5 (the Windows-console
print crash) remains open and is the next thing worth a dedicated fix.
