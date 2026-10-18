# SecureMailScope — Six USP Implementation Audit Report

---

## Section A: Executive Summary

| Field | Detail |
|---|---|
| **Project Name** | SecureMailScope |
| **Audit Date** | 2026-10-18 |
| **Project Root Inspected** | `c:\Users\Mohammed Amin Kaifi\Desktop\SecureMailScope` |
| **Technologies** | **Backend:** Python 3, FastAPI, tshark/Wireshark, Gemini AI (google-genai SDK) · **Frontend:** React (Vite), Axios · **Database:** Supabase (PostgreSQL 17) for auth/metadata; JSON flat-file for analysis results · **External:** tshark CLI, Google Gemini API (optional) |
| **Principal Components** | `backend/app/core/pcap_analyzer.py` (analysis pipeline), `backend/app/core/security_engine.py` (deterministic rules), `backend/app/services/gemini_service.py` (AI enrichment), `backend/app/utils/cert_analyzer.py` (X.509 extraction), `backend/app/utils/tshark_helper.py` (TLS extraction), `backend/app/services/report_generator.py` (HTML report), `frontend/src/components/Dashboard.jsx` (main dashboard) |
| **Scope** | Audit of all six defined USPs through static code inspection |
| **Verification Methods** | Static source-code analysis, file-structure inspection, data-model review, grep-based keyword search, stored-result JSON inspection. No runtime execution was performed (read-only audit). |
| **Overall Implementation Status** | **1 of 6 USPs partially implemented; 5 of 6 USPs not implemented.** The project is a well-built PCAP email security analysis tool with strong deterministic rule-based scanning. However, the six advanced USPs (historical forensics, state reasoning, provenance graph, dual ML+deterministic intelligence, observed-vs-expected-vs-unknown assessment, and cryptographic drift/baseline) are overwhelmingly **not implemented** in the actual codebase. |
| **Most Significant Strengths** | Robust deterministic security rule engine (10 checks); working PCAP→TLS→Certificate→Findings→Risk pipeline; functional Gemini AI integration with offline fallback; professional frontend dashboard; end-to-end test suite. |
| **Most Significant Gaps** | No historical data storage or comparison logic; no provenance graph or evidence-lineage mechanism; no ML model, training pipeline, or inference logic; no baseline creation/comparison/drift detection; no systematic observed-vs-expected-vs-unknown tri-state assessment; no cryptographic state model or cross-property reasoning. |
| **Key Limitations Affecting Confidence** | Audit is static-only; runtime behavior was not verified. The `remote_main.py` and `local_main.py` files could not be fully read due to encoding issues, though their structure mirrors the active `backend/main.py`. |

### Summary Table

| USP | Status | Confidence | Runtime Verified? | Main Finding |
|---|---|---|---|---|
| USP 1: Historical Cryptographic Forensics | **NOT IMPLEMENTED** | High | No | No historical data storage, retrieval, comparison, or temporal analysis logic exists. The word "forensic" in the UI refers to report generation, not historical analysis. |
| USP 2: Cryptographic State Reasoning | **PARTIALLY IMPLEMENTED** | High | No | Individual cryptographic properties are checked (10 rules), but there is no unified state model, no cross-property reasoning, no uncertainty handling, and no state explanation mechanism. |
| USP 3: Evidence Provenance Graph | **NOT IMPLEMENTED** | High | No | No graph structure, no evidence-lineage mechanism, no relationship tracking between artifacts, findings, and conclusions. Findings carry flat `evidence` strings but no structured provenance. |
| USP 4: Deterministic + ML Dual Intelligence | **PARTIALLY IMPLEMENTED** | High | No | Deterministic analysis is fully functional (10 rules). The "ML" component is the Gemini LLM API used for natural-language explanation enrichment — not a trained ML classifier or inference pipeline. No genuine ML model exists. |
| USP 5: Evidence-Based Assessment (Observed/Expected/Unknown) | **NOT IMPLEMENTED** | High | No | No tri-state assessment model. No explicit representation of "expected" baselines, "observed" extractions, or "unknown" states. Findings are binary pass/fail with no uncertainty propagation. |
| USP 6: Cryptographic Drift & Baseline Analysis | **NOT IMPLEMENTED** | High | No | No baseline creation, storage, versioning, retrieval, or comparison logic. No drift detection. Each analysis is a standalone, non-comparative operation. |

---

## Section B: Overall USP Scorecard

| Metric | Count |
|---|---|
| Fully Implemented USPs | **0** |
| Partially Implemented USPs | **2** (USP 2 and USP 4) |
| Not Implemented USPs | **4** (USP 1, 3, 5, 6) |
| Unverified USPs | **0** |
| **Total Audited** | **6** |

**Verified Full-Implementation Percentage:** (0 ÷ 6) × 100 = **0%**

**Meaningful-Implementation Percentage:** ((0 + 2) ÷ 6) × 100 = **33.3%**

> [!IMPORTANT]
> These percentages are implementation coverage indicators for the six defined USPs only. They do not reflect the quality or completeness of the existing PCAP analysis functionality, which is substantive and functional.

---

## Section C: Detailed Audit of Each USP

---

### USP 1: Historical Cryptographic Forensics

#### 1. Final Status
**NOT IMPLEMENTED**

#### 2. Intended Capability
The system should maintain historical cryptographic records, compare current observations against previous ones, detect changes/anomalies/regressions over time, and produce forensic explanations of detected changes.

#### 3. Implementation Evidence

**Files searched:**
- [pcap_analyzer.py](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/core/pcap_analyzer.py) — Main analysis pipeline
- [security_engine.py](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/core/security_engine.py) — Deterministic checks
- [main.py](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/main.py) — API routes
- [supabase_schema.sql](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/supabase_schema.sql) — Database schema
- All `results/*.json` files — Stored analysis output

**Findings:**
- The database schema ([supabase_schema.sql](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/supabase_schema.sql)) defines only two tables: `profiles` (user authentication) and `analyses` (lightweight metadata: capture_id, filename, risk_score, risk_level, findings_count, created_at). There are no tables for historical cryptographic observations, baselines, or temporal comparisons.
- Analysis results are stored as flat JSON files in `results/` directory. Each file is an independent snapshot. No mechanism links one analysis to a prior analysis of the same domain, certificate, or endpoint.
- The `GET /api/analyses` endpoint ([main.py L208-226](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/main.py#L208-L226)) lists all past analyses but only returns summary metadata (capture_id, filename, risk_score, risk_level, timestamp, findings_count). There is no comparison, correlation, or historical query capability.
- The History page ([History.jsx](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/frontend/src/pages/History.jsx)) displays past analyses as a list/grid but performs no cross-analysis comparison.
- Grep search for `historical`, `drift`, `baseline`, `previous`, `compare`, `delta`, `change.*detect` across the entire backend yielded no functional historical comparison logic.

#### 4. Verified Functionality
- **Implemented in code:** Past analysis results are stored as JSON files and can be listed via API.
- **Connected to workflow:** The History page displays past analyses.
- **What this actually provides:** A simple analysis history log — not historical forensic analysis.

#### 5. Missing or Incomplete Functionality
- No storage of historical cryptographic observations (certificate properties, TLS versions, cipher suites) indexed by domain/endpoint/time.
- No retrieval of prior observations for a given subject.
- No comparison logic between current and historical observations.
- No anomaly/change detection over time.
- No temporal ordering or timeline of cryptographic state changes.
- No forensic explanation of detected changes.

#### 6. Test and Verification Results
- Static analysis only. No tests related to historical comparison exist in [test_e2e_pipeline.py](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/tests/test_e2e_pipeline.py).

#### 7. Practical Example
**Scenario:** A user analyzes the same mail server's PCAP twice (Day 1 and Day 30). Day 1 shows TLS 1.2 with SHA-256 certificates. Day 30 shows TLS 1.0 with SHA-1 certificates.

**Current behavior:** Both analyses produce independent results. The system does not recognize that these relate to the same server, does not detect the protocol downgrade or certificate regression, and does not alert the user to the change.

#### 8. Final Justification
No code implements historical comparison, temporal analysis, or cross-analysis correlation. The word "forensic" appears extensively in the UI and documentation but refers to the analysis of a single PCAP capture, not historical forensic investigation across time.

#### 9. Confidence
**High.** Comprehensive search of all backend modules, database schema, API routes, and frontend components confirms the absence of historical comparison functionality.

---

### USP 2: Cryptographic State Reasoning

#### 1. Final Status
**PARTIALLY IMPLEMENTED**

#### 2. Intended Capability
The system should build a cryptographic state from real evidence, evaluate relationships between multiple cryptographic properties, apply meaningful reasoning rules, handle uncertainty, and produce traceable assessments with explanations.

#### 3. Implementation Evidence

**Key files:**
- [security_engine.py](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/core/security_engine.py) — `SecurityEngine` class with 10 deterministic checks (L50-378) and risk scoring (L381-428)
- [cert_analyzer.py](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/utils/cert_analyzer.py) — Certificate property extraction (L24-200)
- [tshark_helper.py](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/utils/tshark_helper.py) — TLS handshake extraction (L47-170)

**What exists:**
- **Attribute extraction:** TLS versions, cipher suites, certificate properties (subject, issuer, serial, validity dates, signature algorithm, key size, self-signed status, expiry) are extracted from PCAP data via tshark.
- **10 deterministic rules:** Plaintext protocol detection, SSL 3.0/TLS 1.0/TLS 1.1 deprecation checks, weak cipher detection (against IANA registry), weak signature algorithm detection (MD5/SHA-1), key size validation (RSA ≥ 2048, EC ≥ 224), expired certificate detection, self-signed certificate detection, missing STARTTLS detection.
- **Risk scoring:** Composite score (0-100) based on severity weights (CRITICAL=15, HIGH=10, MEDIUM=5, LOW=2) plus encryption-ratio penalty.
- **Evidence strings:** Each finding includes a plain-text `evidence` field describing what was detected.

#### 4. Verified Functionality
- **Implemented in code:** ✓ Cryptographic attributes are extracted from real PCAP data.
- **Connected to workflow:** ✓ `SecurityEngine.run_all_checks()` is called in the analysis pipeline ([pcap_analyzer.py L89-91](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/core/pcap_analyzer.py#L89-L91)).
- **Tested:** The E2E test suite verifies detection of plaintext SMTP, SSL 3.0, and clean scenarios.
- **Limitations of what exists:** Each check operates independently on a single property. There is no unified "state" model that evaluates the interaction between properties.

#### 5. Missing or Incomplete Functionality
- **No unified state model:** There is no data structure representing the overall cryptographic state of an analyzed artifact. Checks are independent pass/fail rules, not a state machine.
- **No cross-property reasoning:** For example, the system does not reason about "TLS 1.2 with a weak cipher suite AND an expired certificate AND a small key" as a compound state. Each produces a separate finding.
- **No uncertainty handling:** There is no explicit representation of "unknown" or "unverifiable" conditions. If a certificate cannot be parsed, the system silently defaults `key_size` to 1024 ([cert_analyzer.py L178](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/utils/cert_analyzer.py#L178)) rather than marking it as unknown.
- **No state explanation mechanism:** Findings explain individual issues but do not explain the overall cryptographic state or why a combination of properties is problematic.
- **No relationship modeling:** No evaluation of how one cryptographic property affects the security implications of another.

#### 6. Test and Verification Results
- E2E tests verify individual detection rules (plaintext SMTP, SSL 3.0) but do not test cross-property state reasoning.
- Static analysis confirms independent rule execution with no state aggregation beyond risk scoring.

#### 7. Practical Example
**Scenario:** A PCAP contains TLS 1.2 (good) with a 1024-bit RSA key (bad) and a self-signed certificate (moderate) that expires tomorrow (bad).

**Current behavior:** The system correctly produces three separate findings (insufficient key size, self-signed, expired). However, it does not reason about the compound state — e.g., "This endpoint has fundamentally compromised cryptographic integrity because the combination of a weak key, untrusted issuer, and imminent expiry means any attacker with moderate resources could both forge and intercept communications."

#### 8. Final Justification
The system extracts real cryptographic attributes and applies legitimate rules, qualifying as meaningful individual property checking. However, the absence of a unified state model, cross-property reasoning, uncertainty handling, and state explanation prevents classification as "fully implemented" cryptographic state reasoning.

#### 9. Confidence
**High.** Direct inspection of `SecurityEngine` confirms 10 independent checks with no state aggregation beyond additive risk scoring.

---

### USP 3: Evidence Provenance Graph

#### 1. Final Status
**NOT IMPLEMENTED**

#### 2. Intended Capability
The system should maintain structured relationships between input artifacts, observations, analysis steps, and final conclusions — enabling end-to-end traceability from any finding back to its source evidence.

#### 3. Implementation Evidence

**Files searched:**
- All backend Python modules
- All frontend JSX components
- Database schema
- Stored result JSON files

**What exists:**
- Each finding contains a flat `evidence` string (e.g., `"82 plaintext packets detected on protocols: POP3, SMTP-Submission"`) — see [security_engine.py L65-78](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/core/security_engine.py#L65-L78).
- The `EvidenceViewer` component ([EvidenceViewer.jsx](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/frontend/src/components/EvidenceViewer.jsx)) displays this text string with a "RFC VERIFIED" or "DETERMINISTIC FORENSIC PROOF" badge.
- Analysis results contain `findings`, `sessions`, `certificates`, and `tls_handshakes` as parallel arrays in the JSON output.

**What does NOT exist:**
- No graph data structure (adjacency list, edge table, or linked nodes).
- No unique identifiers linking a finding to specific packets, sessions, handshakes, or certificates.
- No relationship table or edge definition.
- No traversal or lineage query capability.
- No provenance metadata (which analysis step produced which conclusion).
- Grep search for `provenance`, `graph`, `lineage`, `edge`, `node`, `relationship`, `parent`, `child`, `derived_from`, `source_id` returned zero functional results.

#### 4. Verified Functionality
- **Implemented in code:** Findings carry human-readable evidence text strings.
- **Connected to workflow:** Evidence text is displayed in the frontend `EvidenceViewer` and `FindingModal` components.
- **What this actually provides:** A textual description of evidence — not structured provenance.

#### 5. Missing or Incomplete Functionality
- No structured evidence graph, tree, or relationship data structure.
- No unique identifiers linking findings → specific sessions, packets, or certificates.
- No analysis-step provenance (which module produced which intermediate result).
- No graph traversal or lineage query.
- No persistence of provenance relationships.
- The `FindingModal` attempts to show "Affected Sessions" ([FindingModal.jsx L41-49](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/frontend/src/components/FindingModal.jsx#L41-L49)) but the backend never populates `affected_sessions`, `session_ids`, or `sessions` fields on findings. This UI element is always empty.

#### 6. Test and Verification Results
- No tests exist for provenance, lineage, or evidence traceability.
- Static analysis confirms findings contain only flat text evidence.

#### 7. Practical Example
**Scenario:** A user sees "Weak Cipher Suites Detected" and wants to know exactly which session, which handshake, and which packet contained the weak cipher.

**Current behavior:** The finding shows "Weak ciphers: 0x0004, 0x0005, 0x000a" as a text string. There is no link to the specific session, TLS handshake record, or packet number. The user cannot trace the finding to its source evidence.

#### 8. Final Justification
The "evidence" in findings is a human-readable string generated during rule execution. No structured evidence-provenance mechanism, relationship model, or lineage tracking exists anywhere in the codebase.

#### 9. Confidence
**High.** Exhaustive search of all backend models, database schema, API routes, and frontend components confirms no provenance graph implementation.

---

### USP 4: Deterministic + ML Dual Intelligence

#### 1. Final Status
**PARTIALLY IMPLEMENTED**

#### 2. Intended Capability
The system should combine deterministic security analysis with genuine machine learning inference in a meaningful, integrated workflow where both approaches independently contribute to the assessment.

#### 3. Implementation Evidence

**Deterministic Component — FULLY FUNCTIONAL:**
- [security_engine.py](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/core/security_engine.py): `SecurityEngine` class with 10 deterministic rules, severity classification, and composite risk scoring.
- Invoked in the analysis pipeline at [pcap_analyzer.py L89-91](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/core/pcap_analyzer.py#L89-L91).
- Rules check known weak cipher codes against IANA registry, validate key sizes against NIST minimums, detect deprecated protocols per RFC 8996.

**"AI" Component — LLM ENRICHMENT, NOT ML:**
- [gemini_service.py](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/services/gemini_service.py): `GeminiSecurityAssistant` class that calls the Google Gemini LLM API (`gemini-3.6-flash`) to generate natural-language explanations for each deterministic finding.
- Two LLM functions: `explain_finding()` (L68-110) and `generate_executive_summary()` (L112-134).
- **Offline fallback:** When the API is unavailable, the system uses hardcoded template strings ([gemini_service.py L136-204](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/services/gemini_service.py#L136-L204)).
- The LLM output is stored as `ai_explanation` and `ai_confidence` fields on each finding.

**What is NOT present:**
- No trained ML model file (`.pkl`, `.h5`, `.pt`, `.onnx`, `.joblib`, etc.) anywhere in the repository.
- No ML framework in dependencies: `requirements.txt` lists `pyshark`, `fastapi`, `uvicorn`, `python-multipart`, `pydantic`, `cryptography`, `python-dateutil`. No `scikit-learn`, `tensorflow`, `torch`, `xgboost`, or other ML library.
- No feature extraction pipeline for ML input.
- No model training, loading, or inference code.
- No ML-specific predictions (classification, regression, anomaly scores).
- Grep search for `sklearn`, `tensorflow`, `torch`, `model.*load`, `predict`, `classifier`, `inference`, `train` returned zero results.

#### 4. Verified Functionality
- **Deterministic analysis:** ✓ Fully implemented and connected to the workflow.
- **LLM enrichment:** ✓ Gemini API integration exists with offline fallback. Produces natural-language explanations.
- **Genuine ML inference:** ✗ Does not exist.

#### 5. Missing or Incomplete Functionality
- **No ML model:** The "AI" component is an LLM prompt-response system (Gemini), not a trained machine-learning classifier. An LLM generating explanations is valuable but is categorically different from "ML inference that independently analyzes the data."
- **No independent ML predictions:** The Gemini service only re-explains existing deterministic findings. It does not independently analyze the PCAP data, generate its own predictions, or detect anything the deterministic engine didn't find.
- **No separation of ML vs. deterministic results:** Since the LLM only enriches existing findings, there are no independently identifiable "ML-derived" results.
- **Offline mode uses hardcoded text:** When Gemini is unavailable, the system returns template strings (not ML inference) — correctly labeled `DETERMINISTIC_BASELINE` in the `ai_confidence` field.

#### 6. Test and Verification Results
- E2E tests verify the deterministic pipeline produces correct findings and risk scores. No tests verify ML model loading or inference.
- `requirements.txt` confirms no ML dependencies are installed.

#### 7. Practical Example
**Scenario:** User uploads a PCAP file.

**Current behavior:** 
1. The deterministic `SecurityEngine` identifies "SSL 3.0 Detected (POODLE Vulnerable)" as a CRITICAL finding.
2. The `GeminiSecurityAssistant.explain_finding()` sends this finding to the Gemini LLM, which returns a natural-language explanation about POODLE attacks and compliance impact.
3. Both the finding and the LLM explanation are displayed on the dashboard.

**What does NOT happen:** No trained ML model independently analyzes the handshake data, extracts features, runs inference, and produces its own risk classification.

#### 8. Final Justification
The deterministic analysis is robust and fully functional. The Gemini LLM integration provides valuable AI enrichment. However, LLM-based text explanation is fundamentally different from "ML inference." There is no trained model, no feature extraction, no inference pipeline, and no independent ML-derived predictions. The "dual intelligence" claim requires a genuine ML component that independently analyzes data, which does not exist.

Classification as "partially implemented" recognizes the strong deterministic engine and the legitimate (but non-ML) AI enrichment layer.

#### 9. Confidence
**High.** Direct inspection of `requirements.txt`, all Python modules, and the complete absence of model files, ML libraries, or inference code confirms no genuine ML pipeline exists.

---

### USP 5: Evidence-Based Assessment — Observed vs Expected vs Unknown

#### 1. Final Status
**NOT IMPLEMENTED**

#### 2. Intended Capability
The system should systematically distinguish between observed facts (extracted from actual inputs), expected conditions (defined by rules/baselines), and unknown/unverified information, with correct handling of missing evidence and uncertainty propagation.

#### 3. Implementation Evidence

**Files examined:**
- [security_engine.py](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/core/security_engine.py) — All 10 checks
- [cert_analyzer.py](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/utils/cert_analyzer.py) — Certificate extraction
- [pcap_analyzer.py](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/core/pcap_analyzer.py) — Pipeline
- Sample result JSON files

**What exists:**
- Deterministic checks implicitly encode "expected" conditions: RSA keys should be ≥ 2048 bits, protocols should not be SSL 3.0, etc.
- Rules produce binary pass/fail outcomes: "this cipher is weak" or "this certificate is expired."
- Findings include `severity`, `type`, `title`, `description`, `evidence`, `remediation`.

**What does NOT exist:**
- No explicit "observed" data model separate from "expected" baselines.
- No tri-state representation (observed / expected / unknown).
- No explicit handling of "unknown" — when data is missing, the system either silently skips the check or assumes a default value:
  - Certificate key size defaults to 1024 bits when extraction fails ([cert_analyzer.py L178](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/utils/cert_analyzer.py#L178): `key_size = 1024  # Default assumption for old certs`).
  - If certificate parsing fails, no finding is generated — silently treated as "nothing to report."
- No "expected" baselines stored or referenced (beyond the hardcoded constants like `MIN_KEY_SIZES` and `WEAK_CIPHERS`).
- No evidence-assessment separation — the same code both extracts observations and evaluates them.
- No confidence/uncertainty propagation into the final risk score.
- No "unverified" or "insufficient evidence" status on any finding.

#### 4. Verified Functionality
- **Implemented in code:** Rules implicitly encode expected conditions (e.g., `MIN_KEY_SIZES = {'rsa': 2048}`).
- **Connected to workflow:** Rules produce findings when observations violate expectations.
- **What this actually provides:** Traditional pass/fail security checks — not a tri-state assessment system.

#### 5. Missing or Incomplete Functionality
- No explicit observed-vs-expected comparison model.
- No representation of "unknown" or "unverified."
- No uncertainty propagation to risk scores.
- No distinction between "confirmed safe" (verified to meet expectations) and "not checked" (no evidence available).
- Missing evidence is silently ignored or defaulted rather than explicitly flagged.
- No assessment explanations linking observations to specific expectations.

#### 6. Test and Verification Results
- No tests verify tri-state assessment, uncertainty handling, or observed-vs-expected comparison.
- The "Green Scenario" E2E test ([test_e2e_pipeline.py L71-83](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/tests/test_e2e_pipeline.py#L71-L83)) checks that a clean PCAP produces 0 findings and 100% encryption ratio, but this is a pass/fail check, not an evidence-based assessment with uncertainty.

#### 7. Practical Example
**Scenario:** A PCAP contains a certificate whose key size cannot be extracted from the tshark output.

**Current behavior:** The system defaults `key_size = 1024` ([cert_analyzer.py L178](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/utils/cert_analyzer.py#L178)) and then flags it as "Insufficient Certificate Key Size" — a false positive created by silently fabricating evidence for an unknown value.

**Expected behavior (if USP 5 were implemented):** The system would mark key_size as "UNKNOWN," note that the expected value is ≥ 2048 bits, report the assessment as "UNVERIFIED" rather than "CRITICAL," and explain that the key size could not be determined from the available evidence.

#### 8. Final Justification
The system performs traditional binary pass/fail security checks against hardcoded thresholds. There is no systematic distinction between observed, expected, and unknown states. Missing data is silently defaulted or ignored, which is the opposite of the required behavior. The USP requires an explicit assessment framework that the codebase does not implement.

#### 9. Confidence
**High.** Direct inspection of all 10 security checks, certificate extraction logic, and result JSON structure confirms no tri-state assessment mechanism exists.

---

### USP 6: Cryptographic Drift & Baseline Analysis

#### 1. Final Status
**NOT IMPLEMENTED**

#### 2. Intended Capability
The system should establish cryptographic baselines, store them, and compare subsequent observations against those baselines to identify drift, changes, deviations, or regressions.

#### 3. Implementation Evidence

**Files searched:**
- All backend Python modules
- Database schema ([supabase_schema.sql](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/supabase_schema.sql))
- API routes ([main.py](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/main.py))
- Frontend pages and components
- Stored result JSON files

**What exists:**
- Each analysis produces a standalone result JSON with `summary`, `findings`, `risk`, `sessions`, `certificates`, and `tls_handshakes`.
- Results are saved to `results/{capture_id}.json`.
- The History page lists past analyses.

**What does NOT exist:**
- No baseline creation endpoint, function, or data model.
- No baseline storage table in the database schema (only `profiles` and `analyses` with minimal metadata).
- No baseline versioning or timestamping mechanism.
- No comparison logic between a baseline and a subsequent observation.
- No drift detection algorithm.
- No concept of "expected baseline" vs. "current observation" for any cryptographic property.
- No drift classification (expected change vs. suspicious deviation).
- No API endpoint for baseline management.
- Grep search for `baseline`, `drift`, `deviation`, `regression`, `compare`, `previous.*observation`, `delta` across all Python and JavaScript files returned only:
  - Comment in test data generator: `"# Certificate 1: Valid certificate (baseline)"` — a code comment, not implementation.
  - E2E test label: `"Green Scenario (100% Encrypted Baseline)"` — a test name, not baseline analysis.
  - Gemini fallback text: `"compliance baselines"` — natural-language string, not code.

#### 4. Verified Functionality
- **Implemented in code:** Analysis results are persisted as JSON files.
- **Connected to workflow:** The History page lists previous analyses.
- **What this actually provides:** Independent, non-comparative analysis snapshots.

#### 5. Missing or Incomplete Functionality
- No baseline creation from an analysis result.
- No baseline storage or retrieval mechanism.
- No association between baselines and subjects (domains, certificates, endpoints).
- No comparison logic.
- No drift detection.
- No drift classification or explanation.
- No handling of missing baselines or first-time observations.
- No baseline lifecycle management (versioning, updates, expiration).

#### 6. Test and Verification Results
- No tests exist for baseline creation, comparison, or drift detection.

#### 7. Practical Example
**Scenario:** A user analyzes `smtp.pcap` today and gets "TLS 1.2, SHA-256, RSA 2048." Next month, they analyze the same server and see "TLS 1.0, SHA-1, RSA 1024."

**Current behavior:** Two independent analyses with separate risk scores. The system does not recognize they relate to the same server, does not compare results, and does not alert the user to the cryptographic regression.

#### 8. Final Justification
No baseline creation, storage, comparison, or drift detection code exists anywhere in the repository. Each PCAP analysis is a completely independent operation with no cross-analysis comparison capability.

#### 9. Confidence
**High.** Exhaustive search of all source files, database schema, and API routes confirms complete absence of baseline/drift functionality.

---

## Section D: Cross-USP Integration Findings

### Integration Matrix

| | USP 1 (Historical) | USP 2 (State) | USP 3 (Provenance) | USP 4 (Dual Intel) | USP 5 (Obs/Exp/Unk) | USP 6 (Drift) |
|---|---|---|---|---|---|---|
| **USP 1** | — | No integration | No integration | No integration | No integration | No integration |
| **USP 2** | No integration | — | No integration | Partial | No integration | No integration |
| **USP 3** | No integration | No integration | — | No integration | No integration | No integration |
| **USP 4** | No integration | Partial | No integration | — | No integration | No integration |
| **USP 5** | No integration | No integration | No integration | No integration | — | No integration |
| **USP 6** | No integration | No integration | No integration | No integration | No integration | — |

**USP 2 ↔ USP 4 (Partial integration):** The deterministic security engine (USP 2's partial implementation) produces findings that are then enriched by the Gemini LLM (USP 4's AI component). This is the only genuine cross-USP data flow: `SecurityEngine.run_all_checks()` → findings → `GeminiSecurityAssistant.explain_finding()`. See [pcap_analyzer.py L89-104](file:///c:/Users/Mohammed%20Amin%20Kaifi/Desktop/SecureMailScope/backend/app/core/pcap_analyzer.py#L89-L104).

All other USP pairs have no integration because the unimplemented USPs (1, 3, 5, 6) have no code to integrate with.

---

## Section E: Critical Findings and Risks

| Finding ID | Severity | Affected USP | Relevant File/Component | Observed Issue | Evidence | Impact | Recommended Remediation |
|---|---|---|---|---|---|---|---|
| CF-001 | **Critical** | USP 4 | `requirements.txt`, entire backend | No ML model, training pipeline, or ML inference library exists. | No ML framework in dependencies; no model files in repo; no inference code. | The "Deterministic + ML Dual Intelligence" USP cannot be fulfilled. The Gemini LLM provides NL enrichment but is not ML inference. | Implement a genuine trained classifier (e.g., anomaly detection on TLS features) with a real ML framework. |
| CF-002 | **Critical** | USP 1, 6 | `supabase_schema.sql`, `main.py` | No persistent historical/baseline data model. | Database schema has only `profiles` and `analyses` (metadata only). No tables for cryptographic observations, baselines, or drift records. | Historical forensics and baseline drift analysis are structurally impossible without a data model for temporal comparison. | Design and implement database tables for cryptographic observations, baselines, and drift records. |
| CF-003 | **Critical** | USP 3 | `security_engine.py` | No evidence-provenance data structure or relationship model. | Findings contain flat text `evidence` strings. No IDs linking findings to specific sessions, packets, handshakes, or certificates. | End-to-end traceability from finding to source evidence is impossible. | Implement structured evidence references with unique IDs for artifacts, observations, and findings. |
| CF-004 | **High** | USP 5 | `cert_analyzer.py` L178 | Missing data silently defaulted to 1024-bit key size. | `key_size = 1024  # Default assumption for old certs, should be extracted properly` | Creates false positives. Unknown values are treated as known-bad rather than explicitly unknown. | Represent unknown key sizes as `None`/`unknown` and propagate uncertainty. |
| CF-005 | **High** | USP 2 | `security_engine.py` | No cross-property state reasoning. | 10 independent checks with no state aggregation beyond additive risk scoring. | Compound cryptographic weaknesses are not identified or explained as interrelated issues. | Implement a state model that evaluates cryptographic property interactions. |
| CF-006 | **Medium** | USP 3 | `FindingModal.jsx` L41-49 | Frontend references `affected_sessions` but backend never populates it. | `FindingModal` attempts to display affected sessions but the field is always empty. | UI suggests session-finding linkage that doesn't exist; misleading to users. | Either implement session-finding linkage in backend or remove the UI section. |
| CF-007 | **Medium** | USP 4 | `gemini_service.py` L82 | AI confidence is always hardcoded to "HIGH". | `"2. 'ai_confidence': 'HIGH'\\n"` in the LLM prompt. | The confidence label is decorative, not data-driven. | If confidence is displayed, derive it from actual analysis metrics. |

> [!NOTE]
> These findings are product-completeness gaps related to the six USPs. They are not active security vulnerabilities in the application itself.

---

## Section F: Implementation Gap Matrix

| USP | Required Capability | Current State | Evidence | Missing Work | Priority |
|---|---|---|---|---|---|
| USP 1 | Historical observation storage | ❌ Not present | No tables or data model for temporal data | Design schema for historical cryptographic observations indexed by domain/endpoint/time | P0 |
| USP 1 | Historical retrieval by subject | ❌ Not present | No query mechanism for prior observations | Implement API to retrieve historical records for a given subject | P1 |
| USP 1 | Temporal comparison logic | ❌ Not present | No comparison code | Implement diff algorithm comparing current vs. historical properties | P1 |
| USP 1 | Change/anomaly detection | ❌ Not present | No detection logic | Implement change classification (expected vs. suspicious) | P1 |
| USP 1 | Historical timeline UI | ❌ Not present | History page shows list, not timeline | Implement temporal visualization | P2 |
| USP 2 | Unified cryptographic state model | ❌ Not present | No state data structure | Define a CryptoState model aggregating all properties | P1 |
| USP 2 | Cross-property reasoning | ❌ Not present | Independent checks only | Implement rules that evaluate property interactions | P1 |
| USP 2 | Uncertainty representation | ❌ Not present | Missing data defaulted silently | Add "unknown" state for each property | P1 |
| USP 2 | State explanation | ❌ Not present | No compound explanations | Generate explanations for compound states | P2 |
| USP 2 | Individual property checks | ✅ Implemented | 10 rules in `SecurityEngine` | None — already functional | — |
| USP 3 | Evidence node data structure | ❌ Not present | No graph/relationship model | Define evidence nodes with unique IDs | P0 |
| USP 3 | Finding-to-source linkage | ❌ Not present | Flat text evidence strings | Add structured references (finding → session → handshake → packet) | P1 |
| USP 3 | Analysis-step provenance | ❌ Not present | No step tracking | Record which module produced each conclusion | P2 |
| USP 3 | Lineage query/traversal | ❌ Not present | No query capability | Implement traversal from finding to source | P1 |
| USP 3 | Frontend provenance visualization | ❌ Not present | No graph UI | Implement provenance explorer in frontend | P2 |
| USP 4 | Deterministic analysis | ✅ Implemented | 10 rules in `SecurityEngine` | None — fully functional | — |
| USP 4 | Trained ML model | ❌ Not present | No model file, no ML library | Train and integrate a classifier (e.g., anomaly detection on TLS features) | P0 |
| USP 4 | ML feature extraction | ❌ Not present | No feature pipeline | Implement feature extraction from PCAP/TLS/cert data | P0 |
| USP 4 | ML inference execution | ❌ Not present | No inference code | Implement model loading and prediction | P0 |
| USP 4 | Result integration/comparison | ❌ Not present | No dual-result presentation | Display deterministic and ML results side-by-side | P1 |
| USP 4 | LLM enrichment | ✅ Implemented | Gemini API + offline fallback | None — already functional (but is not "ML") | — |
| USP 5 | Observed state representation | ⚠️ Implicit | Extracted attributes exist but no formal "observed" model | Formalize observed data model | P1 |
| USP 5 | Expected baseline definition | ⚠️ Implicit | Hardcoded constants (`MIN_KEY_SIZES`, `WEAK_CIPHERS`) | Externalize and formalize expected rules | P1 |
| USP 5 | Explicit comparison model | ❌ Not present | Binary pass/fail checks | Implement structured observed-vs-expected comparison | P1 |
| USP 5 | Unknown/unverified state | ❌ Not present | Missing data silently defaulted | Represent and propagate unknown states | P0 |
| USP 5 | Uncertainty in risk scoring | ❌ Not present | Risk score treats all findings as certain | Reduce confidence of assessments based on unverifiable data | P2 |
| USP 5 | Assessment explanations | ❌ Not present | No obs-vs-exp explanations | Generate assessment rationale linking observation to expectation | P2 |
| USP 6 | Baseline creation | ❌ Not present | No baseline data model or API | Implement baseline creation from analysis results | P0 |
| USP 6 | Baseline storage/versioning | ❌ Not present | No baseline persistence | Store baselines with timestamps, versions, subject identifiers | P0 |
| USP 6 | Baseline retrieval by subject | ❌ Not present | No retrieval mechanism | Implement baseline lookup for a given domain/endpoint | P1 |
| USP 6 | Comparison logic | ❌ Not present | No diff algorithm | Implement property-by-property comparison | P1 |
| USP 6 | Drift detection/classification | ❌ Not present | No drift logic | Classify changes as expected, suspicious, or critical | P1 |
| USP 6 | Drift explanation | ❌ Not present | No drift reporting | Generate explanations of detected drift | P2 |
| USP 6 | First-observation handling | ❌ Not present | No baseline lifecycle | Handle case when no baseline exists (create initial baseline) | P1 |

---

## Section G: Recommended Implementation Roadmap

### Phase 1 — Foundation (P0): Data Models & Core Infrastructure

| # | Priority | USP(s) | Objective | Relevant Files | Required Change | Dependencies | Acceptance Criteria | Verification Test |
|---|---|---|---|---|---|---|---|---|
| R1 | P0 | 1, 6 | Design persistent historical/baseline data model | `supabase_schema.sql`, new migration files | Add database tables for: `cryptographic_observations` (indexed by domain, endpoint, timestamp, TLS version, cipher suites, cert properties) and `baselines` (snapshot of expected properties for a subject) | PostgreSQL (Supabase) | Tables exist, can insert/query temporal observations and baselines | Insert two observations for the same domain with different timestamps; verify both retrievable |
| R2 | P0 | 3 | Define evidence node data structure | New module (e.g., `evidence_model.py`) | Create evidence node model with unique IDs, types (packet, session, handshake, certificate, finding), and edge definitions (derived_from, observed_in, produced_by) | None | Evidence nodes can be created, linked, and queried | Create a finding node linked to a session node and a certificate node; verify traversal |
| R3 | P0 | 4 | Build ML training/inference pipeline | New module (e.g., `ml_engine.py`), `requirements.txt` update | Add scikit-learn or equivalent; implement feature extraction from TLS/cert data; train a classifier on labeled examples; implement model loading and inference | Training data (can derive from existing demo scenarios) | A trained model file exists; inference produces predictions on new input | Run inference on a test PCAP; verify output is a real prediction (not hardcoded) |
| R4 | P0 | 5 | Implement unknown/unverified state handling | `cert_analyzer.py`, `security_engine.py` | Replace silent defaults with explicit `None`/`unknown` values; add uncertainty propagation logic | None | Unknown values are represented as unknown, not silently defaulted | Extract a certificate with unparseable key size; verify output shows `key_size: null` and finding says "UNVERIFIED" |

### Phase 2 — Core Logic (P1): Analysis & Comparison Engines

| # | Priority | USP(s) | Objective | Relevant Files | Required Change | Dependencies | Acceptance Criteria | Verification Test |
|---|---|---|---|---|---|---|---|---|
| R5 | P1 | 1 | Implement historical comparison logic | New module, `main.py` API routes | Build comparison function that diffs current observations against historical records for the same subject | R1 (data model) | System detects protocol downgrade, cipher changes, certificate rotation | Analyze same server twice with different configs; verify change detection |
| R6 | P1 | 6 | Implement baseline creation and drift detection | New module, `main.py` API routes | Build baseline creation from analysis results; implement property-by-property comparison; classify drift | R1 (data model) | Baseline can be created, subsequent analysis compared, drift itemized | Create baseline; run second analysis with weaker crypto; verify drift items listed |
| R7 | P1 | 2 | Build cryptographic state model | `security_engine.py` or new module | Define `CryptoState` class aggregating all extracted properties; implement cross-property rules | None | State model evaluates compound conditions (e.g., weak key + expired cert = critical compound risk) | Provide input with multiple weaknesses; verify compound state assessment |
| R8 | P1 | 3 | Implement finding-to-evidence linkage | `security_engine.py`, `pcap_analyzer.py` | Add structured references on each finding: session IDs, handshake frame numbers, certificate serials | R2 (evidence model) | Each finding carries traceable references to source artifacts | Verify that a weak-cipher finding links to the specific TLS handshake frame |
| R9 | P1 | 5 | Implement observed-vs-expected comparison | `security_engine.py` or new module | Formalize observed data model; externalize expected rules; implement structured comparison | R4 (unknown handling) | Each assessment shows observed value, expected value, and comparison result | Run analysis; verify each finding shows "observed: TLS 1.0, expected: ≥ TLS 1.2, status: VIOLATION" |
| R10 | P1 | 4 | Integrate ML predictions with deterministic results | `pcap_analyzer.py`, Dashboard frontend | Run both engines; present results side-by-side; handle conflicts | R3 (ML pipeline) | Both deterministic and ML results visible and independently identifiable | Run analysis; verify dashboard shows separate "Deterministic" and "ML" result sections |

### Phase 3 — Integration & Presentation (P2/P3)

| # | Priority | USP(s) | Objective | Relevant Files | Required Change | Dependencies | Acceptance Criteria | Verification Test |
|---|---|---|---|---|---|---|---|---|
| R11 | P2 | 1 | Build historical timeline UI | Frontend new component | Create temporal visualization showing cryptographic property changes over time | R5 | User can view a timeline of changes for a given domain/endpoint | Load history for a domain; verify timeline renders with change annotations |
| R12 | P2 | 3 | Build provenance explorer UI | Frontend new component | Create interactive graph/tree visualization of evidence lineage | R8 | User can click a finding and trace to source packets/sessions | Click a finding; verify graph shows path from finding → session → handshake → packet |
| R13 | P2 | 5 | Add uncertainty to risk scoring | `security_engine.py` | Reduce risk score confidence when assessments are based on incomplete evidence | R4, R9 | Risk score distinguishes "verified high risk" from "unverified, possibly high risk" | Analyze PCAP with missing cert data; verify risk report shows uncertainty |
| R14 | P2 | 6 | Build drift report UI | Frontend new component | Display baseline vs. current comparison with per-property drift indicators | R6 | User can see baseline, current values, and drift status for each property | Run drift analysis; verify UI shows property-level comparison table |
| R15 | P3 | 2 | Add state explanation generation | `security_engine.py` or new module | Generate compound explanations for cryptographic state assessments | R7 | System explains why a combination of properties is problematic | Verify compound explanation: "TLS 1.0 + weak cipher + expired cert = critical compound risk because..." |

---

## Section H: Acceptance Criteria for All Six USPs

| ID | USP | Preconditions | Test Procedure | Expected Result | Status |
|---|---|---|---|---|---|
| AC-01 | USP 1 | Two analysis results exist for the same mail server at different timestamps with different TLS versions | Query historical observations for that server; trigger comparison | System identifies TLS version change, lists old and new values, timestamps each observation | **Not Verified** |
| AC-02 | USP 1 | Historical certificate observation exists for a domain | Analyze same domain with a different certificate | System detects certificate rotation, shows old/new certificate properties | **Not Verified** |
| AC-03 | USP 2 | A PCAP contains TLS 1.0 + weak cipher + expired certificate | Run analysis | System produces a compound state assessment explaining the interaction of all three weaknesses | **Not Verified** |
| AC-04 | USP 2 | A certificate's key size cannot be determined | Run analysis | System reports key size as "unknown" rather than assuming a value | **Not Verified** |
| AC-05 | USP 3 | An analysis produces a "Weak Cipher Suites Detected" finding | Inspect the finding's provenance | Finding links to the specific TLS handshake frame number, session ID, source/destination IP:port | **Not Verified** |
| AC-06 | USP 3 | A user views a finding in the dashboard | Click "trace to evidence" | System displays the chain: Finding → Session → Handshake → Packet with all intermediate references | **Not Verified** |
| AC-07 | USP 4 | A PCAP file is analyzed with both engines available | Run full analysis | Dashboard shows separate "Deterministic Findings" and "ML Predictions" sections with independently identifiable results | **Not Verified** |
| AC-08 | USP 4 | ML model is unavailable | Run analysis | System reports "ML inference unavailable" rather than fabricating a prediction; deterministic results still display normally | **Not Verified** |
| AC-09 | USP 5 | A PCAP is analyzed | Inspect each finding's assessment | Each finding shows: observed value, expected value (with reference), comparison result, and confidence level | **Not Verified** |
| AC-10 | USP 5 | A certificate field cannot be extracted | Inspect the assessment | System shows status as "UNKNOWN" rather than "SAFE" or "CRITICAL"; uncertainty is reflected in risk score | **Not Verified** |
| AC-11 | USP 6 | A baseline has been created for a mail server | Analyze the same server with weaker cryptographic configuration | System identifies specific drift items (e.g., "TLS version changed from 1.2 to 1.0"), classifies each as expected or suspicious | **Not Verified** |
| AC-12 | USP 6 | No baseline exists for a server | Analyze the server for the first time | System offers to create a baseline from the current observation; no drift analysis attempted | **Not Verified** |

All 12 acceptance criteria are marked **Not Verified** because the corresponding functionality does not exist in the current codebase.

---

## Section I: Final Verdict

### Direct Answers

| # | Question | Answer |
|---|---|---|
| 1 | How many USPs are fully implemented? | **0** |
| 2 | How many are partially implemented? | **2** (USP 2: Cryptographic State Reasoning; USP 4: Deterministic + ML Dual Intelligence) |
| 3 | How many are not implemented? | **4** (USP 1, 3, 5, 6) |
| 4 | How many remain unverified? | **0** — all classifications are based on sufficient static-analysis evidence |
| 5 | Which USP is currently the strongest? | **USP 4 (Deterministic + ML)** — the deterministic engine is fully functional with 10 rules, risk scoring, and AI enrichment via Gemini. Only the genuine ML component is missing. |
| 6 | Which USP has the largest gap? | **USP 1 (Historical Cryptographic Forensics)** and **USP 6 (Drift & Baseline)** are tied — both require entirely new data models, persistence layers, comparison logic, detection algorithms, and UI components. Zero code exists for either. |
| 7 | Which dependencies are preventing completion? | (a) No persistent temporal data model for historical/baseline storage. (b) No ML model or training pipeline. (c) No evidence relationship/graph data structure. These three foundational gaps block USPs 1, 3, 4, and 6. |
| 8 | Top three next steps? | **1.** Design and implement the historical/baseline database schema (unlocks USPs 1 and 6). **2.** Build a genuine ML pipeline with a trained classifier (completes USP 4). **3.** Implement structured evidence references with unique IDs on findings (enables USP 3 and strengthens USP 5). |
| 9 | Is the project implementing all six USPs? | **No.** The project currently implements a strong PCAP email security analysis tool with deterministic rules and LLM enrichment. However, the six advanced USPs require substantial additional development. The claim that all six USPs are implemented is **not yet justified** by the codebase. |

### Summary

SecureMailScope is a well-engineered email security analysis platform with a functional analysis pipeline, professional frontend, and useful AI enrichment. However, the six defined USPs represent advanced capabilities — historical forensics, state reasoning, evidence provenance, dual ML+deterministic intelligence, tri-state assessment, and baseline drift detection — that are overwhelmingly **not yet implemented**. The existing codebase provides a solid foundation on which these USPs can be built, but significant architecture, data modeling, and implementation work remains.

---

*Report generated by static code audit on 2026-10-18. No application code was modified during this audit.*
