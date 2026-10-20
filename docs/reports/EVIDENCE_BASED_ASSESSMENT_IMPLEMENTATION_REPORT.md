# SecureMailScope — Evidence-Based Assessment Implementation Report (USP 5)

**Project Name:** SecureMailScope  
**Feature:** Evidence-Based Assessment (Observed / Expected / Unknown) (USP 5)  
**Date:** 2026-10-18  
**Final Status:** **Fully Implemented** (100% Verified Completion)  
**Authoritative Task Sheet:** [`EVIDENCE_BASED_ASSESSMENT_IMPLEMENTATION_TASKS.md`](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/EVIDENCE_BASED_ASSESSMENT_IMPLEMENTATION_TASKS.md)

---

## 1. Executive Summary

SecureMailScope has been upgraded to include an **Evidence-Based Assessment Engine (USP 5)** that systematically decouples and visualizes:
1. **Observed Evidence** — Concrete wire facts extracted from PCAP packet streams.
2. **Expected Requirements** — Formal security baselines, RFCs, and NIST standards.
3. **Assessment Outcomes** — Deterministic evaluation results distinguishing verified compliance, verified violations, indeterminate states, undefined expectations, and non-applicable policies.
4. **Explicit Uncertainty & Limitation Taxonomy** — Clear demarcation between what was captured on the wire versus what is unobservable from passive network captures (e.g. client-side trust store state).
5. **Bidirectional Provenance Integration** — Clickable links connecting every assessed property and its supporting evidence references directly to the **Evidence Provenance Graph (USP 3)**.

All 40 implementation and verification tasks have been completed and verified against active code, with **31/31 backend automated tests passing** and the frontend building cleanly in **317ms**.

---

## 2. Initial Audit & Problem Statement

Prior to this implementation:
- **Conflation of Observation and Expectation:** The engine had no representation of expected security baselines versus what was actually observed. Output was limited to an ad-hoc list of triggered security issues.
- **Binary Pass/Fail Bias:** The absence of a finding was interpreted as clean compliance, even when essential network packets (such as TLS ServerHello records or certificate chains) were missing or truncated in the capture.
- **Wire Boundary Confusion:** The system could not distinguish between a server presenting a certificate on the wire and a client actually verifying and trusting that certificate.
- **Undefined Expectations:** Emerging standards (such as Post-Quantum Cryptography / hybrid PQ-KEMs) were either ignored or arbitrarily forced into a binary pass/fail decision rather than truthfully reporting that no mandatory policy is yet configured.

---

## 3. Architecture & Data Model

The Evidence-Based Assessment Engine operates as a distinct analysis stage (Step 6c in `EmailPCAPAnalyzer`), evaluating 11 standardized security properties across transport, protocol negotiation, cipher primitives, and PKI integrity.

### 3.1 Orthogonal Status & Outcome Taxonomy

The engine enforces strict orthogonality between the status of evidence and the comparison outcome:

#### Evidence Status (`EvidenceStatus`)
- `Observed`: Physical/logical evidence was successfully extracted from packet headers or payloads.
- `Not Observed`: The relevant handshake, command, or extension was absent from the stream.
- `Unknown`: Handshake truncation or packet loss prevented definitive extraction.
- `Unavailable`: Telemetry is outside the scope of passive wire observation.
- `Not Applicable`: The property does not apply to the captured protocol traffic.

#### Assessment Outcome (`AssessmentOutcome`)
| Outcome | Badge Color | Semantic Meaning |
| :--- | :---: | :--- |
| **Satisfied** | `#10b981` (Emerald) | Observed evidence conclusively satisfies the applicable policy requirement. |
| **Violated** | `#ef4444` (Red) | Observed evidence demonstrably violates the applicable policy requirement. |
| **Indeterminate** | `#f59e0b` (Amber) | Comparison cannot be resolved because evidence or prerequisites are incomplete or unverified. |
| **Not Applicable** | `#9ca3af` (Slate) | Requirement does not apply to the evaluated protocol or traffic scenario. |
| **Undefined Expectation** | `#a855f7` (Purple) | Observation was extracted, but no formal policy baseline has been mandated. |
| **Evaluation Error** | `#64748b` (Dark Slate) | Assessment could not be completed reliably due to a processing error. |

---

## 4. Assessed Security Properties & Policy Baselines

The engine evaluates 11 formal requirements:

| ID | Property Name | Category | Formal Standard / Policy Source | Deterministic Rule |
| :--- | :--- | :--- | :--- | :--- |
| **REQ-RFC8314-ENCRYPT** | Transport Layer Encryption Enforcement | Transport Security | RFC 8314 Section 3 | `plaintext_ratio == 0` |
| **REQ-RFC8996-TLSVER** | Negotiated TLS Protocol Version | Protocol Negotiation | RFC 8996 / NIST SP 800-52r2 | `negotiated_version in {'TLS 1.2', 'TLS 1.3'}` |
| **REQ-NIST52-CIPHER** | Cryptographic Cipher Suite Strength | Transport Primitives | NIST SP 800-52 Rev 2 Section 3.3.1 | `not_contains(WEAK_CIPHERS)` |
| **REQ-NIST57-KEYLEN** | Public Key Asymmetric Bit Strength | X.509 PKI | NIST SP 800-57 Part 1 Rev 5 | `key_size >= MIN_KEY_SIZES[algo]` |
| **REQ-RFC5280-SIGALG** | Digital Signature Hash Algorithm Resistance | X.509 PKI | RFC 5280 Section 4.1.2.3 / CAB Forum BR | `sig_algo_hash not in {'md5', 'sha1'}` |
| **REQ-RFC5280-EXPIRY** | Certificate Temporal Validity Period | X.509 PKI | RFC 5280 Section 4.1.2.5 | `is_expired == False` |
| **REQ-CAB-CATRUST** | Certificate Authority Authenticity & Trust Chain | X.509 PKI | CAB Forum Baseline Requirements Section 6 | `is_self_signed == False` |
| **REQ-RFC3207-STARTTLS** | Opportunistic / Enforced STARTTLS Negotiation | Protocol Transition | RFC 3207 Section 4 / MTA-STS (RFC 8461) | `starttls_upgraded_or_smtps()` |
| **REQ-RFC8446-HANDSHAKE** | Handshake State & Exchange Completeness | Protocol Negotiation | RFC 8446 Section 4 / RFC 5246 | `client_hello and server_hello and finished` |
| **REQ-PKI-CLIENTTRUST** | Client Endpoint Trust Store Acceptance | Client Boundary | Local OS / MUA Trust Store Policy | `client_trust_telemetry_available()` |
| **REQ-EXP-POSTQUANTUM** | Post-Quantum Cryptographic Readiness (PQ-KEM) | Cryptographic Primitives | IETF Draft / Enterprise PQC Roadmap | `[Undefined Expectation] none()` |

---

## 5. Uncertainty & Boundary Handling

### 5.1 Passive Wire Observation Boundary (REQ-PKI-CLIENTTRUST)
When a server presents a valid certificate on the wire, traditional tools report "Certificate Valid" and imply the connection was secure. In contrast, SecureMailScope explicitly acknowledges the network boundary:
- **Observed:** Certificate presented on wire; Client verification unobservable.
- **Outcome:** `Indeterminate`
- **Unknown Reason:** *"Passive network capture boundary: endpoint OS/MUA trust store state is unobservable over the wire."*
- **Missing Prerequisites:** `["Client-side endpoint agent telemetry / MUA log data"]`

### 5.2 Handshake Incompleteness vs Attack Attribution (REQ-RFC8446-HANDSHAKE)
When packet captures are truncated (e.g., only 1 packet captured), the engine marks the exchange `Indeterminate` rather than registering false security violations or assuming malicious tampering.

### 5.3 Truthful Undefined Expectations (REQ-EXP-POSTQUANTUM)
For cutting-edge cryptographic extensions (such as hybrid Kyber / ML-KEM key exchanges), the engine detects whether classical or post-quantum algorithms were used, but returns `Undefined Expectation` because no mandatory standard has been codified for email transport. This prevents arbitrary pass/fail fabrication.

---

## 6. Implementation Files

### 6.1 Files Created
- [`backend/app/core/evidence_assessment_engine.py`](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/core/evidence_assessment_engine.py): Core 869-line assessment engine implementing 11 property evaluations, orthogonal status/outcome tracking, error isolation, and metrics calculation.
- [`frontend/src/components/EvidenceBasedAssessment.jsx`](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/frontend/src/components/EvidenceBasedAssessment.jsx): React component featuring counter chips, outcome filter buttons, real-time search, 3-column tri-state comparison cards, evidence reference tags linking to the Provenance Graph, and expandable reasoning details.
- [`backend/tests/test_evidence_based_assessment.py`](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/tests/test_evidence_based_assessment.py): Comprehensive unit and integration test suite (7 tests) verifying evidence normalization, defined vs undefined expectations, uncertainty handling, and demo scenario integrations.
- [`EVIDENCE_BASED_ASSESSMENT_IMPLEMENTATION_TASKS.md`](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/EVIDENCE_BASED_ASSESSMENT_IMPLEMENTATION_TASKS.md): Authoritative 40-task tracker.
- [`EVIDENCE_BASED_ASSESSMENT_IMPLEMENTATION_REPORT.md`](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/EVIDENCE_BASED_ASSESSMENT_IMPLEMENTATION_REPORT.md): This report.

### 6.2 Files Modified
- [`backend/app/core/pcap_analyzer.py`](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/core/pcap_analyzer.py): Added Step 6c executing `EvidenceAssessmentEngine` and attaching results to output payload.
- [`backend/main.py`](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/main.py): Enhanced `GET /api/analysis/{capture_id}/results` to dynamically compute and return `evidence_based_assessment` for all stored captures.
- [`frontend/src/pages/Analysis.jsx`](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/frontend/src/pages/Analysis.jsx): Embedded `EvidenceBasedAssessment` immediately below Executive Summary in the Overview tab, added Title Bar assessment counter badge, and created dedicated 'Evidence Assessment (USP 5)' tab.

---

## 7. Verification Results & Regression Status

### 7.1 Backend Automated Tests
All 31 backend automated tests pass without failure:
```
============================= test session starts =============================
platform win32 -- Python 3.13.14, pytest-9.1.1, pluggy-1.6.0
collected 31 items

backend/tests/test_crypto_state_reasoning.py .............             [ 41%]
backend/tests/test_evidence_based_assessment.py .......                [ 64%]
backend/tests/test_provenance_dynamic_matrix.py ........               [ 90%]
backend/tests/test_provenance_graph.py ...                             [100%]

============================= 31 passed in 6.71s ==============================
```

### 7.2 Frontend Production Build
```
> vite build
✓ 323 modules transformed.
dist/index.html                     1.29 kB │ gzip:   0.68 kB
dist/assets/index-Bf-EqXT3.css     52.74 kB │ gzip:   9.94 kB
dist/assets/index-D60pqByM.js   1,149.55 kB │ gzip: 328.93 kB
✓ built in 317ms
```

---

## 8. Conclusion

**USP 5 (Evidence-Based Assessment: Observed / Expected / Unknown)** is now **Fully Implemented (100%)**, robustly tested, and seamlessly integrated into both the backend analysis pipeline and the frontend web application. SecureMailScope now features three fully implemented flagship USPs:
- **USP 2:** Cryptographic State Reasoning (7-state precedence model)
- **USP 3:** Evidence Provenance Graph (dynamic DAG with full traceability)
- **USP 5:** Evidence-Based Assessment (tri-state observed/expected/unknown model)
