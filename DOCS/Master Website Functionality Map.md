# SecureMailScope — Master Website Functionality Map

## Frontend Ingredient Specification

### Purpose

This document defines **what the SecureMailScope website must contain and what each element must do**.

It does NOT define:

* Colors
* Layout
* Spacing
* Animations
* Component styling
* Sidebar/navbar design
* Exact visual arrangement

Amin has complete freedom to design and arrange the interface.

> **This document defines the ingredients. Amin cooks and presents them.**

---

# 1. PRODUCT CORE

SecureMailScope is an AI-driven email security assessment and forensics platform.

The primary user journey is:

**PCAP → Analyze → Understand → Investigate → Remediate → Report**

The user should be able to:

1. Upload a `.pcap` or `.pcapng` file.
2. Start an analysis.
3. See the analysis pipeline/progress.
4. Receive an overall security assessment.
5. See security findings.
6. Investigate individual findings.
7. Inspect email sessions.
8. Inspect TLS and certificate information.
9. Understand why a finding matters.
10. Receive remediation recommendations.
11. Generate/export a security/forensic report.

---

# 2. GLOBAL NAVIGATION

The website should provide access to the following major areas:

* Dashboard
* New Analysis
* Analyses / History
* Findings
* Sessions
* Reports
* Security Insights
* Help / Knowledge
* Settings
* User Profile
* Logout

Optional if actually implemented:

* Notifications
* Admin
* System Status

Amin does NOT need to make every item a separate page. He can combine related functionality however he thinks gives the best UX.

---

# 3. LANDING / HOME PAGE

## Purpose

Immediately explain what SecureMailScope does and allow the user to begin an analysis.

### Required content

* SecureMailScope branding
* Short product explanation
* Explanation of email-security assessment
* Key capabilities
* Simple explanation of the workflow

### Primary CTA

**Start Analysis / Upload PCAP**

Action:

→ Open authentication if authentication exists
→ Otherwise → Open New Analysis

### Capability highlights

Possible capabilities to show:

* PCAP analysis
* Email traffic analysis
* TLS analysis
* Certificate analysis
* Cryptographic weakness detection
* Risk scoring
* AI-assisted explanations
* Security reporting

### How it works

Visually communicate:

**PCAP → Analysis → Findings → Risk → Recommendations → Report**

---

# 4. AUTHENTICATION

Only include this if authentication is part of the implemented architecture.

## Login

Fields:

* Email/Username
* Password

Actions:

* Login
* Forgot Password
* Register

States:

* Loading
* Invalid credentials
* Validation error
* Server error
* Successful login

## Registration

Actions:

* Create account
* Return to Login

States:

* Validation
* Duplicate account
* Password requirements
* Success
* Failure

## Password Recovery

* Enter email
* Request reset
* Reset password
* Success/error states

## Session Handling

Frontend must handle:

* Authenticated state
* Unauthenticated state
* Expired session
* Logout
* Unauthorized API response

---

# 5. MAIN DASHBOARD

The dashboard is the user's main command center.

It should answer:

> **"What did SecureMailScope find?"**

## A. Security Posture

Display data returned by the backend:

* Overall security/risk score
* Overall risk level
* Critical findings
* High findings
* Medium findings
* Low findings
* Informational findings

## B. Capture Summary

Possible information:

* PCAP filename
* Capture size
* Capture date/time if available
* Sessions analyzed
* Email-related sessions
* TLS sessions
* Hosts/endpoints identified

## C. TLS Overview

Possible metrics:

* TLS versions observed
* Cipher suites observed
* Certificates observed
* Secure vs weak sessions
* Plaintext email sessions where determinable

## D. Recent / Current Analysis

Show:

* Analysis ID/name
* Status
* Date/time
* Risk score
* Finding count

Action:

**View Analysis**

## E. Quick Actions

* New Analysis
* View Findings
* Explore Sessions
* Generate Report

---

# 6. PCAP UPLOAD

This is the first major functional interaction.

## Supported input

* `.pcap`
* `.pcapng`

## User actions

* Select file
* Drag and drop file
* Remove file
* Replace file
* Start analysis

## Frontend validation

Check:

* File exists
* Supported extension
* File size if a limit exists
* Empty/invalid selection

Backend remains responsible for authoritative validation.

## Upload states

### Before upload

Show an upload area.

### File selected

Show:

* Filename
* File size
* Remove/change option

### Uploading

Show loading/progress.

### Uploaded

Show that the file is ready for analysis.

### Failed

Show:

* Error
* Retry

---

# 7. ANALYSIS CONFIGURATION

Keep this minimal for the MVP.

If the backend supports it, the user may provide:

* Analysis name
* Analysis scope/options

Do NOT add configuration options that the backend does not actually support.

### Primary CTA

**Analyze PCAP**

---

# 8. ANALYSIS PIPELINE / PROGRESS

The backend performs multiple stages.

The frontend should expose meaningful progress.

## Pipeline

1. PCAP ingestion
2. Protocol detection
3. Session reconstruction
4. TLS handshake analysis
5. Certificate extraction
6. Cryptographic assessment
7. Risk scoring
8. AI intelligence/explanation
9. Report preparation

Each stage can have:

* Pending
* Running
* Completed
* Failed

Do NOT fake a percentage if the backend cannot provide real progress.

A staged progress indicator is sufficient.

---

# 9. SECURITY OVERVIEW

After analysis completes, show the main security assessment.

## Overall Security Posture

Display:

* Security/risk score
* Risk level
* Executive summary

## Finding Distribution

Display counts for:

* Critical
* High
* Medium
* Low
* Informational

## Security Statistics

Possible statistics:

* Sessions analyzed
* TLS sessions
* Certificates analyzed
* Weak configurations
* Plaintext/unencrypted email where determinable

## Executive Summary

Explain:

* Overall security condition
* Major weaknesses
* Most important actions

---

# 10. FINDINGS

Findings are one of the core features.

## Finding list

Each finding should contain:

* Finding ID
* Finding title
* Severity
* Category
* Affected host/session
* Short explanation
* Status if implemented

## Severity filters

* Critical
* High
* Medium
* Low
* Informational

## Category filters

Depending on backend implementation:

* TLS
* Certificate
* Cipher
* Authentication
* Encryption
* Protocol
* Configuration
* Other

## Search

Search by:

* Finding title
* Host
* Category
* Finding ID

## Sorting

Possible sorting:

* Severity
* Host
* Finding type
* Session
* Alphabetical

---

# 11. FINDING DETAILS

Clicking a finding should open its complete investigation view.

## Finding information

* Finding ID
* Finding title
* Severity
* Category

## What happened?

Human-readable explanation.

## Why does it matter?

Security impact.

## Evidence

Show what the PCAP actually demonstrated.

## Affected entity

Where available:

* Host
* IP
* Port
* Protocol
* Session ID

## Technical details

Depending on finding:

* TLS version
* Cipher suite
* Certificate information
* Relevant handshake evidence
* Other protocol evidence

## Recommendation

Show what should be fixed.

## Risk

Explain how the finding contributes to the security posture.

---

# 12. SESSION EXPLORER

The Session Explorer is a major investigation feature.

## Session list

Each session can show:

* Session ID
* Source
* Destination
* Source port
* Destination port
* Protocol
* TLS version
* Cipher
* Security status/risk

## Filters

Possible filters:

* Secure
* Weak
* Critical
* TLS version
* Protocol
* Host

## Search

Search by:

* IP
* Host
* Port
* Session ID

---

# 13. SESSION DETAILS

When a session is selected, display:

## Connection information

* Source
* Destination
* Ports
* Protocol

## TLS information

* TLS version
* Cipher suite
* Extensions where available
* Handshake information

## Certificate information

Where available:

* Subject
* Issuer
* Valid from
* Valid until
* Signature algorithm
* Public-key information
* Trust-related information where evidence permits

## Security assessment

* Risk
* Findings associated with the session
* Recommendations

## Evidence

Show the relevant handshake/evidence sequence in an understandable way.

---

# 14. CERTIFICATE EXPLORER

This does not necessarily need to be a separate navigation page.

It can be integrated into:

* Session Details
* Findings
* Security Insights

Where certificates are extracted, show:

* Subject
* Issuer
* Validity period
* Signature algorithm
* Public-key information
* Trust status where evidence permits
* Related findings
* Related sessions

Possible certificate findings:

* Expired certificate
* Weak/deprecated signature
* Small public key
* Self-signed/untrusted certificate where evidence permits

---

# 15. TLS / CRYPTOGRAPHIC ANALYSIS

Show the cryptographic/security characteristics detected by the analysis.

## TLS versions

Potentially:

* TLS 1.0
* TLS 1.1
* TLS 1.2
* TLS 1.3

## Cipher suites

Show:

* Observed cipher
* Security classification
* Weak/deprecated status where applicable

## Possible findings

The MVP risk engine may identify:

* TLS 1.0
* TLS 1.1
* RC4/deprecated cipher
* 3DES
* SHA-1 certificate/signature
* Small public key
* Expired certificate
* Self-signed/untrusted certificate where evidence permits
* Missing STARTTLS / plaintext email
* No forward secrecy where determinable

The frontend must NOT hard-code severity decisions. The backend/risk engine should provide the authoritative finding and severity.

---

# 16. AI INTELLIGENCE

AI should enhance the deterministic security analysis.

AI should NOT invent security findings.

## AI functionality

### Explain Finding

Explain the technical finding in understandable language.

### Why It Matters

Explain practical security impact.

### Prioritization

Help the user understand which findings deserve attention first.

### Remediation Explanation

Explain the recommended fix.

## Possible UI actions

* Explain Finding
* Why Does This Matter?
* Security Insight
* Recommended Action

AI output should remain grounded in the actual evidence and findings produced by SecureMailScope.

---

# 17. REMEDIATION

For actionable findings, show:

* Recommended action
* Why the action is needed
* Priority
* Technical guidance

Potential prioritization:

1. Critical
2. High
3. Medium
4. Low

The platform should communicate:

> **Here is the evidence → here is why it matters → here is what you should do.**

---

# 18. SECURITY / INFRASTRUCTURE MAP

This is an optional advanced/demo feature.

It can visualize:

**Mail Client → Mail Server → TLS Connection**

Possible information:

* Hosts
* Connections
* Security posture
* Risk level
* Sessions

This is NOT a blocker for the MVP.

Do not sacrifice the core analysis pipeline to build this.

---

# 19. REPORTS

Reports should contain:

## Executive Summary

* Overall security posture
* Risk score
* Overall assessment

## Statistics

* Sessions analyzed
* TLS sessions
* Certificates
* Findings by severity

## Findings

For each finding:

* Finding title
* Severity
* Description
* Evidence
* Affected entity
* Recommendation

## Technical Evidence

Relevant:

* Protocol information
* TLS information
* Certificate information
* Session evidence

## Recommendations

Prioritized remediation actions.

## Export formats

MVP:

* JSON
* HTML

Future:

* PDF

## Actions

* Generate Report
* View Report
* Download Report
* Export JSON
* Export HTML

---

# 20. ANALYSIS HISTORY

Allow users to revisit previous analyses.

## Analysis list

Each entry can contain:

* Analysis name
* Analysis ID
* Date/time
* PCAP name
* Status
* Risk score
* Finding count

## Actions

* Open Analysis
* View Findings
* View Sessions
* View Report
* Generate Report
* Delete if backend supports deletion

---

# 21. SETTINGS

Keep settings lightweight for the MVP.

## General

* Profile
* Preferences

## Analysis

Only include actual supported analysis preferences.

## Application

* About SecureMailScope
* Version

## Security

Only include actual implemented security/account controls.

---

# 22. HELP / KNOWLEDGE

Possible sections:

## What is SecureMailScope?

Short product explanation.

## How does analysis work?

PCAP → Extraction → Assessment → Risk Scoring → AI Explanation → Report

## Severity Explanation

* Critical
* High
* Medium
* Low
* Informational

## Supported Input

* PCAP
* PCAPNG

## Technology

Potentially:

* Zeek
* tshark
* Python
* FastAPI
* cryptography

---

# 23. ERROR STATES

The frontend must account for errors.

## Upload errors

* Invalid file
* Unsupported format
* File too large
* Upload failure

## Analysis errors

* Processing failure
* Parser failure
* No relevant email traffic
* No TLS evidence
* Backend unavailable
* Timeout

## Data errors

* No findings
* No sessions
* No certificates
* Incomplete evidence

## API errors

* Validation error
* Unauthorized
* Forbidden
* Analysis not found
* Server error

Each error should provide a useful user action where possible:

* Retry
* Go back
* Upload another file
* Start a new analysis

---

# 24. EMPTY STATES

Do not leave blank screens.

## No analysis

> Upload a PCAP to begin your first security assessment.

## No findings

> No security findings were detected in this analysis.

## No sessions

> No analyzable email sessions were identified.

## No certificates

> No certificates were available for analysis.

## No reports

> Generate a report from a completed analysis.

---

# 25. CORE BUTTON INVENTORY

## Primary actions

* Start Analysis
* Upload PCAP
* Analyze PCAP
* View Analysis
* View Results
* Investigate Finding
* Explore Session
* Generate Report
* Download Report

## Navigation

* Dashboard
* New Analysis
* Analyses
* Findings
* Sessions
* Reports
* Security Insights
* Help
* Settings

## Investigation

* View Details
* View Evidence
* Explain Finding
* View Recommendation
* View Related Sessions
* View Certificate

## Utility

* Search
* Filter
* Sort
* Refresh
* Retry
* Cancel
* Back
* Close
* Clear
* Remove
* Replace

---

# 26. IDEAL USER JOURNEY

The primary user journey should be:

**LANDING**

↓

**START ANALYSIS**

↓

**UPLOAD PCAP**

↓

**VALIDATE**

↓

**ANALYZE**

↓

**ANALYSIS PROGRESS**

↓

**SECURITY OVERVIEW**

↓

**FINDINGS**

↓

**INVESTIGATE FINDING**

↓

**VIEW EVIDENCE**

↓

**UNDERSTAND RISK**

↓

**GET REMEDIATION**

↓

**EXPLORE SESSIONS**

↓

**INSPECT TLS / CERTIFICATES**

↓

**GENERATE REPORT**

↓

**DOWNLOAD / EXPORT**

---

# 27. FRONTEND ↔ BACKEND CONTRACT

Every important frontend action must have a corresponding backend capability.

| Frontend Action      | Backend Responsibility                                        |
| -------------------- | ------------------------------------------------------------- |
| Upload PCAP          | Receive and validate file                                     |
| Start Analysis       | Create analysis job                                           |
| Show Progress        | Return analysis/job status                                    |
| View Overview        | Return analysis summary                                       |
| View Findings        | Return findings                                               |
| Filter Findings      | Backend query or frontend filtering depending on architecture |
| View Finding         | Return finding details/evidence                               |
| View Sessions        | Return extracted sessions                                     |
| View Session         | Return session/TLS evidence                                   |
| View Certificate     | Return certificate information                                |
| AI Explanation       | AI explanation endpoint/service                               |
| View Recommendations | Return remediation mapping                                    |
| Generate Report      | Generate report                                               |
| Download Report      | Return report/file                                            |
| Analysis History     | Retrieve stored analyses                                      |

This table will later be used as the **frontend-backend integration checklist**.

---

# 28. WHAT SHOULD NOT BECOME AN MVP DEPENDENCY

For the 5-day prototype, do NOT make these required for the core product:

* Full ML training
* Live packet monitoring
* Large SIEM integrations
* Complex enterprise RBAC
* Massive threat-intelligence system
* Full infrastructure graph
* Certificate-history system
* Advanced anomaly detection
* Complex historical analytics

These are future expansion features.

---

# 29. MVP PRIORITY

## MUST HAVE

1. Landing
2. PCAP Upload
3. Analysis Trigger
4. Analysis Progress
5. Security Overview
6. Risk Score
7. Finding List
8. Finding Details
9. Evidence
10. Remediation
11. Session Explorer
12. TLS/Certificate Information
13. Report Generation/Download

## SHOULD HAVE

14. Analysis History
15. Search
16. Filtering
17. Sorting
18. AI Explanations
19. Security Charts
20. Certificate Explorer
21. Help/About

## NICE TO HAVE

22. Infrastructure/Security Map
23. Advanced Visualization
24. Advanced AI Prioritization
25. Additional Export Formats
26. Historical Trend Analysis

---

# 30. PRODUCT ARCHITECTURE

The complete SecureMailScope pipeline is:

**RAW PCAP**

↓

**Zeek / tshark**

↓

**Protocol + Session Evidence**

↓

**TLS / X.509 Analysis**

↓

**Deterministic Security Rules**

↓

**Risk Engine**

↓

**AI Explanation**

↓

**Recommendations**

↓

**Security Dashboard**

↓

**JSON / HTML Report**

The website is therefore NOT simply a dashboard.

Its purpose is to convert:

> **Raw PCAP Evidence → Cryptographic Security Posture → Risk → Explanation → Remediation → Report**

---

# 31. DEVELOPMENT RULE FOR AMIN

Amin should use this document as the **functional ingredient list**.

He decides:

* Layout
* Visual hierarchy
* Sidebar/navbar
* Cards
* Tables
* Charts
* Tabs
* Modal/drawer usage
* Animations
* Colors
* Typography
* Responsive design
* Component architecture

But he should NOT remove a required functional capability without discussing it first.

Likewise, the backend team should not create APIs that have no clear frontend purpose.

The frontend and backend should be developed against the same functional contract.

---

# 32. FINAL GOLDEN RULE

SecureMailScope must never become a **fake cybersecurity dashboard**.

Every displayed security result should ultimately trace back to:

**PCAP Evidence**

→ **Protocol/Session Analysis**

→ **TLS/Certificate Analysis**

→ **Deterministic Security Assessment**

→ **Risk Score/Finding**

→ **AI Explanation**

→ **Recommendation**

→ **Report**

The interface can be as creative as Amin wants.

The underlying functionality must remain real, explainable, and connected to the analysis pipeline.
