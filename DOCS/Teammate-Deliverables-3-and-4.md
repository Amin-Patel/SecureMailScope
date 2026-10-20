# Teammate Work: Deliverables #3 and #4

Written up after merging `main` into `feature/rag-knowledge-base` and
`docs/rag-and-fine-tuning-notes` (commit `d03f255`, "Completed the 3rd and
4th Deliverables and included the Dataset", by LightDevil). This is a
record of what was actually built, verified by reading the source
directly, not just the commit message — so the team has one place that
describes it accurately.

---

## Deliverable #3: Bidirectional TCP Stream Reassembly & Protocol-Aware Credential Redaction

**Where:** `backend/app/utils/tshark_helper.py` —
`extract_structured_tcp_streams()`, plus a new
`GET /api/analysis/{capture_id}/stream/{stream_id}` endpoint in `main.py`
and a new `frontend/src/components/StreamViewerModal.jsx`.

Reconstructs each TCP conversation (SMTP/IMAP/POP3) from its SYN/SYN-ACK
handshake into an ordered, bidirectional, client/server-labeled transcript
— not just a flat packet list. Two things worth knowing about it
specifically:

- **It redacts credentials before they ever reach the UI.** A state
  machine (`_redact_protocol_credentials`) tracks each protocol's
  multi-step auth exchange and replaces the actual secret with a labeled
  placeholder rather than a generic "hide everything" pass:
  - SMTP `AUTH PLAIN` and `AUTH LOGIN` (including the multi-line
    base64 username/password challenge-response — it recognizes the
    literal `334 VXNlcm5hbWU6` / `334 UGFzc3dvcmQ6` server prompts, which
    are just base64 for "Username:"/"Password:", to track which line is
    which secret)
  - POP3 `PASS`
  - IMAP `LOGIN user pass`
  - Explicitly does **not** mask arbitrary base64 strings — only
    protocol-recognized credential fields, so the rest of a session
    transcript stays genuinely readable for forensic purposes.
- **The redaction is visible, not silent.** Each stream reports
  `redacted`/`redaction_count`, and `StreamViewerModal.jsx` surfaces that
  to the viewer explicitly rather than just quietly altering the text —
  important for a forensic tool, where a viewer needs to know evidence was
  modified.

`StreamViewerModal.jsx` itself supports ASCII/hex toggling, in-transcript
search, and copy-to-clipboard.

## Deliverable #4: Multi-Tier Certificate Chain Parsing & CA Trust Hierarchy Validation

**Where:** `backend/app/utils/cert_analyzer.py` (a full rewrite, 748 lines
changed), surfaced via `security_engine.py`'s new `check_certificate_chains()`
and visualized in `frontend/src/components/CertChainTree.jsx`.

This supersedes the single-leaf-certificate fix from earlier in this
branch's history with something considerably more complete:

- **Loads and caches Mozilla's root CA trust store** via `certifi`
  (`get_trust_store()`), so certificate chains can actually be evaluated
  against real-world trust, not just parsed in isolation.
- **Performs real cryptographic signature verification** between each
  certificate and its claimed issuer (`verify_certificate_signature`) —
  supports RSA (PKCS#1 v1.5 and PSS), ECDSA, Ed25519, Ed448, and DSA. A
  chain isn't just "these certificates exist in this order," it's
  "certificate N was actually signed by certificate N+1's private key,"
  cryptographically confirmed.
- **Groups presented certificates by TLS stream/frame** and builds the
  full trust path from leaf to root, flagging where it breaks.
- **Emits nine distinct PKI finding types** via `rule_id`, all funneled
  through a generic `finding_type='certificate_pki'`:
  `CERT_EXPIRED`, `CERT_NOT_YET_VALID`, `CERT_HOSTNAME_MISMATCH`,
  `CERT_SIGNATURE_INVALID`, `CERT_INVALID_CHAIN_ORDER`, `CERT_SELF_SIGNED`,
  `CERT_UNTRUSTED_CA`, `CERT_INVALID_EKU`, `CERT_INVALID_BASIC_CONSTRAINTS`.
- **Extracts a much richer per-certificate profile than before**: Subject
  Alternative Names, Key Usage and Extended Key Usage flags, Subject/
  Authority Key Identifiers, CA/path-length constraints — not just
  subject/issuer/validity/signature/key-size.

`CertChainTree.jsx` renders this as an interactive root -> intermediate ->
leaf tree with trust-anchor and hostname-validation indicators, rather
than a flat certificate list.

This is a genuine architectural improvement over the fix that was on this
branch before the merge (which only parsed a single leaf certificate's own
properties — no chain construction, no trust-path validation, no signature
verification). See
[`Bugs-Found-and-Fixed.md`](Bugs-Found-and-Fixed.md) for that earlier fix's
history; it's now superseded by this work for anything chain/trust-related,
though the four original flat-list checks (`check_weak_signatures`,
`check_key_sizes`) still read from the `extract_certificates()`
backward-compatibility wrapper this code also provides.

## Datasets

`DATASETS/SECUREMAILSCOPE_REAL_DATASET_BENCHMARK 2.0` is a deliberately
honest inventory, not a claim of complete coverage — it uses an explicit
**Have / Partial / Need / Missing** status key per capability, distinguishes
small controlled Wireshark sample captures (plaintext SMTP, MIME/IMF
messages, attachments) from larger realistic corpora (CIC-IDS2017/2018,
ISCXTor2016 from UNB's Canadian Institute for Cybersecurity), and
explicitly flags recovered PCAP payloads/attachments as untrusted evidence
that should never be executed. `Scenario-A-merged_5s.csv` (84k rows) and
`Scenario-B-merged_5s.csv` (14.5k rows) are flow-level data derived from
that benchmark work.

## Integration notes for whoever works on this next

- **RAG knowledge base compatibility**: the new `certificate_pki` finding
  type didn't match any of this branch's existing per-type knowledge-base
  seed docs (which were `expired_certificate.md`/`self_signed_certificate.md`
  — types that no longer get produced, since `check_expired_certificates`/
  `check_self_signed_certificates` were removed in favor of the generic
  chain-based check). Added a consolidated
  `backend/app/knowledge_base/sources/certificate_pki.md` covering all nine
  `rule_id`s during the merge so AI explanations for chain/trust findings
  stay grounded instead of silently becoming coverage gaps. Verified: 6 of
  7 findings on the `legacy_ssl3` demo capture now ground correctly
  (`CERT_EXPIRED` specifically falls just under the offline retrieval
  confidence threshold — the same known characteristic documented in
  [`RAG-Knowledge-Base-Design.md`](RAG-Knowledge-Base-Design.md), not a new
  issue).
- **Missing dependency**: `cert_analyzer.py` imports `certifi` but it
  wasn't in `requirements.txt` — same class of gap as the
  `google-genai`/`python-dotenv` omission documented in
  [`Bugs-Found-and-Fixed.md`](Bugs-Found-and-Fixed.md). Added it during the
  merge.
- **Independently fixed the same Windows-console crash** flagged as bug #5
  in that doc: `_print_report()` is now wrapped in a try/except and the
  emoji characters were replaced with plain-text markers (`[AI]`, `[+]`),
  so that bug is now resolved as a side effect of this merge, not
  something that still needs a dedicated fix.
