# Bugs Found This Session — Summary

> **Open findings from the 2026-09-21 audit: see [`Audit-2026-09-21.md`](Audit-2026-09-21.md).**
> That audit re-verifies items 1–6 below (item 6 is reopened and escalated; items
> 2 and 5 partially regressed) and adds new findings F7–F34.

A running log of pre-existing bugs discovered (and, where in scope, fixed)
while building the RAG knowledge base, the forward-secrecy check, the
certificate-pipeline fix (`feature/rag-knowledge-base`), and the ML risk
classifier (`feature/ml-risk-classifier`). None of these were introduced
by that work — they predate it — but building real, end-to-end-tested
features keeps surfacing them, since each new feature is often the first
thing to actually exercise a given code path against real PCAPs in this
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

### 5. Successful analyses crash into HTTP 500 on Windows consoles

**Where:** `backend/app/core/pcap_analyzer.py`, `_print_report()`

**What was wrong:** it printed a 🤖 emoji to the console. On a Windows
console using the default cp1252 code page, that `print()` raised
`UnicodeEncodeError` — and because it happened *after* the analysis had
already fully succeeded but *inside* the same `try` block, the outer
exception handler reported the entire analysis as failed (HTTP 500) even
though `findings`, `risk`, and `ai_summary` were all correctly computed.

**Fix:** resolved independently by a teammate in `main` (commit `d03f255`,
alongside deliverables #3/#4) — `_print_report()` is now wrapped in its own
try/except and the emoji characters were replaced with plain-text markers
(`[AI]`, `[+]`). Merged into `feature/rag-knowledge-base` and
`docs/rag-and-fine-tuning-notes`; no longer open. See
[`Teammate-Deliverables-3-and-4.md`](Teammate-Deliverables-3-and-4.md) for
what else came in on that merge.

### 6. Every TLS 1.3 session is mislabeled "TLS 1.2"

**Where:** `backend/app/utils/tshark_helper.py`, the `version_map` in
`extract_tls_handshakes()`

**Severity: worth fixing at the source, not just worked around.**

**What's wrong:** it maps `ssl.record.version`/`tls.record.version` (the
*outer TLS record-layer* version field) straight to a human string —
`'0x0303': 'TLS 1.2'`, `'0x0304': 'TLS 1.3'`. That's correct for TLS
1.0-1.2, but RFC 8446 §5.1 freezes the record-layer version at `0x0303`
for TLS 1.3 specifically for backward-compatibility with middleboxes —
the real negotiated version only appears in the ServerHello's
`supported_versions` extension, which nothing here parses. The practical
effect: every TLS 1.3 session in this codebase is currently reported and
reasoned about as "TLS 1.2."

**How this was found:** building the ML risk classifier
(`feature/ml-risk-classifier`) and feeding it `secure_mail.pcap` (which
negotiates cipher `0x1302` = `TLS_AES_256_GCM_SHA384`, a TLS-1.3-exclusive
suite) — the session came back labeled `'TLS 1.2'` despite the cipher only
existing in TLS 1.3.

**Why it hasn't caused visible false positives (so far):** `cipher_suites.py`
marks all five TLS 1.3 cipher suites `forward_secret: True`, and
`check_forward_secrecy()`'s explicit `tls_version == 'TLS 1.3'` skip turns
out to be a redundant safety net rather than the only thing preventing a
false positive — the cipher lookup alone already produces the right
answer regardless of the mislabeled version. It's been silently harmless
by luck, not by design; anything added later that branches on TLS version
more broadly (a report showing "TLS 1.2 sessions: N", a dashboard filter,
a future check keyed more directly off version) would silently misclassify
every TLS 1.3 session.

**Fix status:** worked around defensively in
`backend/app/ml/feature_extractor.py` (`effective_tls_version()` — trusts
a TLS-1.3-exclusive cipher over the version string) since that's the code
this was discovered in, but **not fixed at the source** in
`tshark_helper.py`, which is shared code other features also depend on.

**Recommended fix:** add `-e tls.handshake.extensions.supported_version`
(or the ClientHello/ServerHello `supported_versions` extension field — the
exact tshark field name should be checked with `tshark -G fields`, the
same way the certificate field names were re-derived for bug #4) to the
`extract_tls_handshakes()` command, and prefer that over the record-layer
version when present.

---

## Net effect

Before this session, in this environment, the existing
`backend/tests/test_e2e_pipeline.py` suite passed 4/8 (blocked entirely by
TShark not being installed). After installing TShark and fixing #1-#4
above, it passed **8/8** at the API level, and the `legacy_ssl3` demo
capture went from 3 findings to 6 — the suite was passing throughout, but
for most of this session it wasn't actually exercising a quarter of the
documented security checks. All nine checks were confirmed live
end-to-end. Bug #5 was independently fixed by a teammate and merged in
afterward. Bug #6 was found while building the ML classifier and worked
around locally there, but is still open at the source in
`tshark_helper.py` -- worth a dedicated fix since other features read the
same (currently wrong) version label.
