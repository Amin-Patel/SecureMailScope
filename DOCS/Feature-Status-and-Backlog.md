# Feature Status and Backlog

Snapshot as of **2026-09-19**, after every feature branch was merged into
`main` (PRs #1 to #5). Every "implemented" entry below was checked against
the code on `main`, not taken from earlier notes. Where a feature has a known
limitation it is stated next to the feature, not buried.

For *why* things were chosen, see the other docs:
[`Competitive-Landscape-SIH26159.md`](Competitive-Landscape-SIH26159.md),
[`Bugs-Found-and-Fixed.md`](Bugs-Found-and-Fixed.md),
[`Next-Features-Roadmap.md`](Next-Features-Roadmap.md),
[`Enterprise-Landscape.md`](Enterprise-Landscape.md).

---

## 1. Coverage of the official SIH26159 spec

| Spec deliverable | Status | Where |
|---|---|---|
| Passive PCAP analysis of SMTP/IMAP/POP3, protocol ID | Done | `pcap_analyzer.py`, `tshark_helper.py` |
| STARTTLS detection | Done (capture-level) | `check_missing_starttls` in `security_engine.py` |
| TCP stream and TLS handshake reconstruction | Done | `extract_structured_tcp_streams`, `extract_tls_handshakes` (teammate deliverable #3) |
| X.509 extraction, chain validation, expiry, key length, signature checks | Done | `cert_analyzer.py` (teammate deliverable #4), 8 PKI rules |
| Negotiated TLS version, cipher suite, key exchange | Done, one known bug | `cipher_suites.py` registry. TLS 1.3 is still mislabeled at source, see backlog |
| Forward secrecy assessment | Done | `check_forward_secrecy` |
| AI-based cryptographic risk scoring | Done | RandomForest, `ml_risk_service.py` |
| AI-assisted anomaly detection | Done | IsolationForest, `anomaly_detector.py` |
| Prioritized findings and remediation | Done | `SecurityEngine` plus RAG-grounded explanations |
| Exportable reports: JSON, PDF, HTML | Done | `/report?format=json\|html\|pdf` |
| Interactive dashboard | Done, not visually re-verified | React frontend. Login currently blocked by the Supabase config, see backlog |

---

## 2. Implemented features

### Analysis pipeline
- **Passive PCAP analysis** with tshark run offline (`-r <file>`). Nothing is
  captured live and no traffic is sent.
- **Stream reassembly with credential redaction** for SMTP/IMAP/POP3, and a
  stream viewer in the UI (`/api/analysis/{id}/stream/{stream_id}`).
- **Certificate chain and CA trust validation** against the Mozilla root store
  (via `certifi`): chain order, signature validity, hostname/SNI match,
  Basic Constraints, EKU, expiry, self-signed, untrusted CA.
- **Cipher suite registry** decoding raw tshark hex codes, with weak and
  forward-secret classification.

### Findings (10 finding types, all with RAG reference docs)
`plaintext_protocol`, `deprecated_protocol` (SSL 3.0, TLS 1.0, TLS 1.1),
`weak_cipher`, `no_forward_secrecy`, `weak_signature`,
`insufficient_key_size`, `missing_starttls`, `certificate_pki`,
`known_malicious_certificate`, `email_authentication`.

### AI and ML
- **Risk classifier and anomaly detector.** Trained on 3,532 unique sessions:
  3,528 synthetic (distilled from our own rule engine) and 108 real sessions
  (demo captures plus the ISCXTor2016 non-Tor IMAP/POP captures). Held-out
  accuracy is 99.2%. **That number is not a quality claim**: labels are a
  deterministic function of the features, so near-1.0 accuracy is expected.
  The real safeguards are the deduplication before the train/test split and
  the label audit against `security_engine.py`.
- **Fusion rule.** ML can only raise the risk level, never suppress a
  rule-confirmed finding. The A-F grade is floored to match if ML raises it.
- **RAG knowledge base.** 12 curated reference docs, ChromaDB store, works
  fully offline (hashing embeddings) and upgrades to Gemini embeddings when a
  key is set. Coverage gaps are recorded and can be drafted for review
  (`/api/knowledge/*`).
- **Gemini explanations** with a deterministic offline fallback.

### Scoring and reporting
- **Risk score 0-100 with an A-F grade.** Boundaries follow the risk levels:
  A 0-9, B 10-19, C 20-39, D 40-54, E 55-69, F 70+.
- **Server-side PDF export** (`xhtml2pdf`), plus HTML and JSON.
- **Report section for SPF/DKIM/DMARC evidence**, HTML-escaped.

### Threat intelligence
- **abuse.ch SSLBL** blacklist of certificate SHA1 fingerprints seen on botnet
  C2 servers. Free, no API key, cached and refreshed on an interval, degrades
  to "no matches" if the feed is unreachable.

### Email authentication (SPF / DKIM / DMARC)
- **Passive, from the capture.** Reads `Authentication-Results`,
  `Received-SPF` and `DKIM-Signature` headers in plaintext streams, and SPF /
  DMARC / DKIM TXT records in plaintext DNS responses. Findings include
  recorded failures, `rsa-sha1`, signatures that omit `From`, `l=` body-length
  limits, misaligned signing domains, permissive SPF, `p=none` DMARC and weak
  DKIM keys.
  Limits, also shown in the UI: verdicts are as asserted by mail servers, not
  independently verified; encrypted streams are counted but cannot be read.
- **On-demand DNS lookup** (`/api/email-auth-check`). The only active feature.
  User-initiated, kept out of the capture's findings and risk score, with
  alerts for dangerous published records.

### Operations
- **Opt-in folder monitoring.** Set `WATCH_DIR` and new captures are analyzed
  automatically. It is a file watcher, not live packet capture.
- **Analysis history**, batch delete, demo captures, health endpoint.

---

## 3. Known issues and honest limitations

| Item | Detail |
|---|---|
| **Login is broken** | The default Supabase project host no longer exists, and there is no `frontend/.env`. Needs a working project URL and anon key, or a dev-only bypass. Blocks any demo of the dashboard. |
| **TLS 1.3 mislabeled as TLS 1.2** | `tshark_helper.py` reads the record-layer version, which RFC 8446 freezes. Worked around in the ML feature extractor only. Bug #6 in the bug log, still open at the source. |
| **Certificate fields not HTML-escaped in the HTML report** | Subject and issuer come from packets. The new email-auth section escapes correctly; the older certificate table does not. |
| **Coarse cert-to-session matching** | The ML service pairs every session with the capture's first certificate, because certificates are not linked to a handshake by frame. |
| **Not modeled by the per-session ML** | `missing_starttls`, `email_authentication` and `known_malicious_certificate` are capture-level or external, so only the rule engine sees them. |
| **Grading is capture-wide only** | No per-server or per-host grade, because findings are not tagged by host. |
| **PDF layout not reviewed** | xhtml2pdf ignores CSS grid, so summary cards stack vertically. Text content was verified, appearance was not. |
| **No automated tests for newer features** | Grading, PDF, watcher, threat intel and email-auth were verified with ad-hoc scripts. Only `test_e2e_pipeline.py` and `test_deliverables_3_and_4.py` exist. |
| **Encrypted mail hides headers** | Email-auth analysis only sees plaintext streams. Most modern mail is encrypted, so expect many captures to report "could not be inspected". |
| **One dataset file unreadable** | `Workstation_Thunderbird_Imap.pcap` (NonTor) is corrupt (oversized packet) and is skipped in training. |

---

## 4. What can be implemented next

Effort is a rough guess (S under a day, M a few days, L a week or more). "Passive"
means it works from the capture alone, which fits the project's positioning.

### Quick wins
| Feature | Why | Effort | Passive |
|---|---|---|---|
| Fix the login (Supabase config, or dev-only bypass) | Nothing in the UI can be demoed until this works | S | n/a |
| Fix TLS 1.3 detection at source (`supported_versions` extension) | Removes a real, documented bug and the ML workaround | S | Yes |
| HTML-escape the certificate table in the report | Untrusted packet data in an HTML report | S | Yes |
| Plaintext-credential finding | Streams already record `redacted` and `redaction_count`. Turn that into an explicit CRITICAL "credentials exposed in plaintext" finding | S | Yes |
| Copy-paste server-config remediation | Real Postfix/Dovecot/OpenSSL snippets instead of prose (from S-Vetrivel's repo) | S-M | Yes |
| Evidence-strictness wording (`OBSERVED` / `NOT_FOUND` / `INSUFFICIENT_EVIDENCE`) | Free credibility with judges who know the limits of passive analysis | S | Yes |
| MITRE ATT&CK tags on findings | Common language for SOC users, see enterprise doc | S | Yes |
| Promote the synthetic-PCAP generator into test fixtures | Repeatable tests for email-auth, DNS and header parsing | S | Yes |
| Regression tests for grading, PDF, watcher, threat intel, email-auth | Protects the merged work | M | n/a |

### Medium
| Feature | Why | Effort | Passive |
|---|---|---|---|
| **MTA-STS / DANE policy versus reality** | Reads `_mta-sts` TXT and TLSA records already in the capture and compares them to what was actually negotiated. Reuses the DNS extraction added for SPF/DMARC. | M | Yes |
| **JA3 / JA4 TLS fingerprinting** | Client fingerprint of each handshake, matched against SSLBL's free JA3 blacklist (same feed family already integrated) | M | Yes |
| **Per-host findings and grading** | Tag findings by server so each mail server gets its own grade | M | Yes |
| Link certificates to handshakes by frame or stream | Removes the coarse `certificates[0]` matching in the ML layer | M | Yes |
| Retrain on more real captures | Only the 4 email files from NonTor were used; the ML gets grounded in more real traffic | M | Yes |
| Structured export for SIEM (JSON events, STIX) | Lets the tool feed other systems, see enterprise doc | M | Yes |
| Deployment manifests (Docker) | Repeatable setup for judges and teammates | M | n/a |

### Larger
| Feature | Why | Effort | Passive |
|---|---|---|---|
| **Per-server behavioral fingerprinting** | Flag a server that suddenly drops from TLS 1.3 to 1.2. Needs a persistent per-server profile store, because the tool is stateless today | L | Yes |
| **Post-quantum readiness flag** | "This session negotiated no PQC key exchange", plus a cryptographic inventory view. Matches where the enterprise market is heading | M-L | Yes |
| Encrypted-traffic metadata ML (packet sizes and timing) | Classify sessions without decrypting, as Cisco ETA does | L | Yes |
| Certificate inventory across many captures | Fleet-level view of what certificates were seen, when they expire | L | Yes |
| Real live capture (`tshark -i`) | The watcher already covers "not one-shot upload". True live capture needs privileges and long-running process management | L | Yes |
| SSLKEYLOGFILE-based TLS 1.3 decryption | Only useful in controlled demos where we control key logging | M | Partly |

### Deliberately not doing
- **Live Gmail/OAuth account analysis.** Contradicts the passive positioning.
- **Blockchain.** Nothing in the official spec asks for it; it is the SIH
  theme label, not a deliverable.
- **Reusing another team's model or code.** Plagiarism and disqualification risk.
