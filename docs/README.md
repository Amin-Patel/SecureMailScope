# SecureMailScope Documentation Index

Welcome to the comprehensive documentation directory for **SecureMailScope** — a professional forensic analyzer and cryptographic compliance auditor for email protocol network traffic (PCAP / PCAPNG captures).

This directory organizes all project documentation by function, domain, and lifecycle phase.

---

## Directory Structure

```text
docs/
├── README.md                      # This documentation index
├── architecture/                  # Architectural diagrams, system topology, functionality maps
├── setup/                         # Installation, environment prerequisites, server deployment
├── guides/                        # Operational guides, user walkthroughs, demo scripts
├── features/                      # Feature specifications, RFC compliance logic, cryptographic engine
├── testing/                       # Test coverage reports, verification matrix, PCAP test fixture docs
├── reports/                       # Formal audit, enhancement, and implementation reports
├── implementation/                # Task tracking sheets, milestone checklists, and progress logs
└── archive/                       # Deprecated, legacy, or historical documentation retained for audit
```

---

## 1. Architecture & System Design

High-level system architecture, component relationships, data flow diagrams, and functional maps.

- [Master Website Functionality Map](architecture/MASTER_WEBSITE_FUNCTIONALITY_MAP.md) — Comprehensive inventory of application features, navigation topology, frontend/backend component mapping, and API endpoints.

---

## 2. Setup & Installation

Environment setup, dependency management, and configuration.

- **Developer Setup & Quickstart**: Refer to the root [README.md](../README.md#getting-started) for development prerequisites and launch instructions (`start.bat` / `start.ps1`).
- **Environment Template**: See [.env.example](../.env.example) for frontend (Vite/Supabase) and backend (FastAPI/Gemini) environment variable definitions.
- **Remote Deployment**: See [deploy-to-server.ps1](../deployment/deploy-to-server.ps1) for automated deployment instructions via Tailscale SSH.

---

## 3. Usage & Operational Guides

Step-by-step guides for running analyses, working with sample captures, and interpreting findings.

- [Quick Start Comprehensive Demo Guide](guides/QUICK_START_COMPREHENSIVE_DEMO.md) — Instructions for launching and verifying the multi-session forensic analysis using the comprehensive demo capture.

---

## 4. Testing & Verification

Validation matrices, PCAP capture descriptions, and automated test coverage.

- [Comprehensive PCAP Coverage Report](testing/COMPREHENSIVE_PCAP_COVERAGE_REPORT.md) — Multi-session protocol analysis coverage, vulnerability injection details, and cryptographic parameter verification.
- [Coverage Matrix Verification](testing/COVERAGE_MATRIX_VERIFICATION.md) — Formal testing matrix verifying STARTTLS stripping, cipher negotiation, downgrade states, and certificate chain validations.

---

## 5. Reports & Audits

Post-implementation reports, forensic audit findings, and system verification results.

- [Comprehensive PCAP Final Summary](reports/COMPREHENSIVE_PCAP_FINAL_SUMMARY.md) — Summary of PCAP capture forensics, multi-session attack detection, and validation benchmarks.
- [Cryptographic State Reasoning Implementation Report](reports/CRYPTOGRAPHIC_STATE_REASONING_IMPLEMENTATION_REPORT.md) — Technical report on deterministic cryptographic state classification, transition timelines, and RFC policy evaluation.
- [Evidence-Based Assessment Implementation Report](reports/EVIDENCE_BASED_ASSESSMENT_IMPLEMENTATION_REPORT.md) — Technical report on tri-state verifiable assessment engine (Verified / Suspicious / Inconclusive) with cryptographic provenance bindings.
- [UI Theme & Evidence Graph Navigation Report](reports/UI_THEME_AND_EVIDENCE_GRAPH_NAVIGATION_REPORT.md) — Design system overhaul, high-contrast dark theme, and bi-directional Evidence Provenance Graph navigation.
- [Analysis Overview Cleanup Report](reports/ANALYSIS_OVERVIEW_CLEANUP_REPORT.md) — Elimination of duplicate assessment cards in the Overview tab to maintain concise forensic summaries.
- [Analysis UI Refinement Report](reports/ANALYSIS_UI_REFINEMENT_REPORT.md) — Visual hierarchy refinement, glassmorphism navigation styling, and context-aware forensic color coding.
- [SecureMailScope USP Audit Report](reports/SecureMailScope_USP_Audit_Report.md) — Formal audit of core Unique Selling Propositions (USPs) and competitive architectural differentiators.
- [Project Folder Reorganization Report](reports/PROJECT_FOLDER_REORGANIZATION_REPORT.md) — Structural reorganization audit and file inventory report.

---

## 6. Implementation Task Sheets

Persistent task sheets tracking milestones, completion percentages, and verification commands.

- [Project Folder Reorganization Tasks](implementation/PROJECT_FOLDER_REORGANIZATION_TASKS.md) — Active tracking sheet for the repository structural cleanup and organization.
- [Cryptographic State Reasoning Tasks](implementation/CRYPTOGRAPHIC_STATE_REASONING_IMPLEMENTATION_TASKS.md) — Milestone tracking for RFC-backed cryptographic state reasoning and session transition analysis.
- [Evidence-Based Assessment Tasks](implementation/EVIDENCE_BASED_ASSESSMENT_IMPLEMENTATION_TASKS.md) — Milestone tracking for tri-state assessment logic, evidence binding, and UI rendering.
- [Evidence Provenance Implementation Tasks](implementation/EVIDENCE_PROVENANCE_IMPLEMENTATION_TASKS.md) — Milestone tracking for packet-to-insight provenance tracking and interactive graph visualization.
- [UI Theme & Evidence Graph Navigation Tasks](implementation/UI_THEME_AND_EVIDENCE_GRAPH_NAVIGATION_TASKS.md) — Milestone tracking for forensic dark theme consistency and graph cross-linking.
- [Analysis Overview Cleanup Tasks](implementation/ANALYSIS_OVERVIEW_CLEANUP_TASKS.md) — Milestone tracking for Overview section simplification.
- [Analysis UI Refinement Tasks](implementation/ANALYSIS_UI_REFINEMENT_TASKS.md) — Milestone tracking for visual refinement of inner analysis views.

---

## 7. Documentation Maintenance Guidelines

1. **Adding New Documentation**: Place new architectural docs into `architecture/`, how-to guides into `guides/`, test logs into `testing/`, milestone tasks into `implementation/`, and post-mortem/completion reports into `reports/`.
2. **Path References**: Use relative markdown links within `docs/` and `../` for root references.
3. **Preserving History**: Rather than deleting superseded documentation, move it to `docs/archive/` with an explanatory note.
