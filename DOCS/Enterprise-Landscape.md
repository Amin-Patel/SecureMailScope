# Enterprise and Commercial Landscape

Who else does parts of what SecureMailScope does, and what we can borrow.
This complements [`Competitive-Landscape-SIH26159.md`](Competitive-Landscape-SIH26159.md),
which covers the other hackathon teams; this one covers real products.

**How reliable this is.** Written 2026-09-19. The product categories and
capabilities come from general knowledge and were **not** re-verified
against current vendor pages or pricing. The two products marked
"looked up" (PcapAI, ScanSuite) were checked online on the same date, from
their own marketing pages only, and neither was tried hands-on. Treat vendor
claims as claims.

---

## 1. Main finding

No single enterprise product does what this project does: passive PCAP
analysis focused on **email** cryptographic posture, with explanations, in one
offline tool. Enterprises cover it with a stack of separate tools. That is
both a positioning opportunity and a checklist of features we can borrow.

---

## 2. Product categories

### Passive traffic analysis (our PCAP, TLS and certificate extraction)
| Product | What it does | Relevance |
|---|---|---|
| **Zeek** (open source) and **Corelight** (commercial) | Logs every TLS handshake, X.509 certificate and SMTP/IMAP session | Closest match to our pipeline. Their `ssl.log`, `x509.log` and `smtp.log` are the de facto formats |
| **Suricata** | TLS, JA3 and certificate detection rules | Uses blacklists like the SSLBL feed we integrated; SSLBL also publishes ready-made Suricata rules |
| **Arkime**, **Wireshark / tshark** | Capture, indexing, dissection | Our tshark layer is the same foundation |
| **ExtraHop Reveal(x)**, **Cisco Secure Network Analytics** | Encrypted-traffic and TLS posture scoring at network scale | Show what "fleet-level" looks like |

### AI risk scoring and anomaly detection
| Product | What it does | Relevance |
|---|---|---|
| **Darktrace**, **Vectra AI** | Unsupervised anomaly detection on traffic | Comparable to our IsolationForest layer |
| **Cisco Encrypted Traffic Analytics** | Classifies malicious encrypted flows from metadata (sizes, timing) without decrypting | Idea for a richer ML feature set |

### TLS and certificate posture with grades
| Product | Relevance |
|---|---|
| **Qualys SSL Labs** | The well-known A-F TLS grader. Our A-F grade follows the same idea |
| **Hardenize (Red Sift)**, **Mozilla Observatory**, **testssl.sh / SSLyze** | Same ground, active scanning |
| **Tenable Nessus**, **Qualys VMDR** | TLS checks inside broader vulnerability scans |

### Certificate inventory and lifecycle
| Product | Relevance |
|---|---|
| **Venafi / CyberArk**, **Keyfactor**, **DigiCert Trust Lifecycle**, **AppViewX** | Discover and monitor certificates across an enterprise |
| **crt.sh**, **Censys** (Certificate Transparency monitoring) | External view of every certificate issued for a domain |

### Email authentication
| Product | Relevance |
|---|---|
| **Red Sift OnDMARC**, **Valimail**, **dmarcian**, **EasyDMARC** | Specialists in SPF/DKIM/DMARC. They mostly consume DMARC aggregate reports |
| **Proofpoint**, **Mimecast**, **Microsoft Defender for Office 365** | Enforce it inside email gateways |

### Cryptographic posture and quantum readiness
| Product | Relevance |
|---|---|
| **IBM Guardium Quantum Safe**, **SandboxAQ AQtive Guard**, **Keyfactor** | Build a cryptographic inventory ("CBOM") and flag weak or non-quantum-safe crypto. This is the wording closest to the SIH problem statement, and the fastest-growing enterprise category |

---

## 3. Two products looked up directly

### PcapAI (pcapai.com), a close functional competitor
- Upload a capture, get an AI-assisted security report in about two minutes.
- Decodes TCP, UDP, DNS, HTTP(S), FTP, SMB, SMTP and Kerberos; extracts TLS
  certificate details; maps findings to **40+ MITRE ATT&CK techniques**
  (command-and-control, lateral movement, credential theft).
- Produces a PDF with risk score and remediation; discovers plaintext
  credentials and masks them.
- Rust engine plus ML models; hosted service with 24-hour retention,
  25-50 MB file limits, entry plan from $9. An **open-source local MCP
  server** lets Claude Desktop analyze captures without uploading them.

### ScanSuite, a different category
- Two products share the name. The open-source project
  (`myappsec/scansuite`) orchestrates code scanners (SAST, dependency, IaC,
  DAST) and sends results to DefectDojo. The commercial platform
  (scansuite.io) advertises network discovery, vulnerability assessment and
  cloud auditing; its features page could not be loaded, so that description
  is from search summaries only.
- Neither reads packet captures. It is not a competitor to this project.

### Comparison
| | SecureMailScope | PcapAI | ScanSuite |
|---|---|---|---|
| Input | Email PCAPs | Any PCAP | Live targets and code |
| Approach | Passive | Passive | Active scanning |
| Email crypto depth | STARTTLS, chain validation, forward secrecy, cipher and key checks, SPF/DKIM/DMARC | Certificates and SMTP among many protocols | None |
| Explanations | RAG-grounded, offline-capable | Generic remediation | n/a |
| Scoring | A-F grade plus rule-engine and ML risk | Risk score | n/a |
| Threat intel | SSLBL certificate blacklist | MITRE ATT&CK mapping | n/a |
| Data handling | Runs locally, nothing uploaded | Cloud upload, 24-hour retention | n/a |

**Where we are stronger:** email-specific cryptographic depth, fully offline,
and grounded explanations. That fits users such as NTRO-type agencies who often
cannot upload captures to a cloud service.

**Where PcapAI is ahead:** far broader protocol coverage, MITRE ATT&CK mapping,
command-and-control and lateral-movement detection, product polish.

---

## 4. What we can pull from them

Ordered by value for effort. Everything in the first group is passive and fits
the current architecture. Items link to the backlog in
[`Feature-Status-and-Backlog.md`](Feature-Status-and-Backlog.md).

| Borrow | From | How it fits us | Effort |
|---|---|---|---|
| **MITRE ATT&CK tags on findings** | PcapAI, Suricata, most SOC tools | Add a technique ID to each finding type (for example plaintext credentials, weak crypto, C2 certificate). Cheap and speaks the SOC's language | S |
| **Plaintext-credential finding** | PcapAI | We already count redactions per stream; make it an explicit finding | S |
| **JA3 / JA4 fingerprints** | Suricata, Zeek, SSLBL | Fingerprint each handshake; match SSLBL's free JA3 blacklist | M |
| **Zeek-style log export** (`ssl.log`, `x509.log`, `smtp.log`) | Zeek / Corelight | Lets analysts pull our extraction into tools they already use | M |
| **Suricata rule export** | Suricata, SSLBL | SSLBL already ships Suricata rules; export rules for certificates we flag | S-M |
| **SIEM / STIX event export** | Darktrace, Vectra, Corelight | Structured JSON events for Splunk or Elastic | M |
| **Post-quantum readiness and crypto inventory (CBOM)** | IBM Guardium Quantum Safe, SandboxAQ | Flag sessions with no PQC key exchange; list every algorithm and key size seen | M-L |
| **Certificate Transparency lookups** | crt.sh, Censys | Compare a capture's certificate to what CT logs say was issued. Active, so label it like the DNS lookup | M |
| **Certificate inventory across captures** | Venafi, Keyfactor | Fleet view of certificates and expiry dates. Needs a persistent store | L |
| **Encrypted-traffic metadata ML** | Cisco ETA | Add packet-size and timing features to the classifier | L |
| **Local MCP server** | PcapAI | Expose analyses to AI assistants without uploading captures. Optional, demo-friendly | M |
| **MTA-STS / DANE checks** | Hardenize and email-security suites | Reuses our new DNS TXT extraction; passive | M |

---

## 5. Positioning line

> Open, explainable, email-specific cryptographic analysis that runs fully
> offline, in the spirit of Zeek/Corelight extraction with a built-in
> scorecard, aimed at agencies that cannot upload captures.

Cheapest ways to strengthen that story before a demo: MITRE tags, the
plaintext-credential finding and JA3/JA4. Post-quantum readiness is the best
longer-term differentiator because it matches where the enterprise market is
moving.

## Sources (looked up 2026-09-19)
- PcapAI: https://pcapai.com/ and https://pcapai.com/about
- ScanSuite: https://github.com/myappsec/scansuite/ and https://scansuite.io/
