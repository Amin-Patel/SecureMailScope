# SecureMailScope

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![React 19](https://img.shields.io/badge/Frontend-React%2019-61DAFB.svg)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Bundler-Vite-646CFF.svg)](https://vitejs.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Styling-Tailwind%20CSS-38B2AC.svg)](https://tailwindcss.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**SecureMailScope** is a high-performance network forensics analyzer and cryptographic compliance auditing platform for email protocols (SMTP, IMAP, POP3). Built for security analysts, incident responders, and compliance engineers, SecureMailScope dissects PCAP and PCAPNG network captures to identify plaintext credential leakage, STARTTLS downgrade attacks, weak cipher suites, certificate anomalies, and protocol vulnerabilities.

---

## Key Features & Unique Selling Propositions (USPs)

### 1. Cryptographic State Reasoning Engine
- **Deterministic State Transition Tracking**: Models every email session through a state machine (`PLAINTEXT` $\rightarrow$ `UPGRADE_REQUESTED` $\rightarrow$ `HANDSHAKE_IN_PROGRESS` $\rightarrow$ `ENCRYPTED` / `DOWNGRADE_DETECTED`).
- **RFC Compliance Mapping**: Audits sessions against RFC 8314 (Implicit TLS default), RFC 3207 (SMTP STARTTLS), RFC 7525 (TLS BCP), and RFC 2595 (IMAP/POP3 TLS).
- **Security Posture Scoring**: Evaluates protocol-level security status (`SECURE_MODERN`, `LEGACY_ACCEPTABLE`, `VULNERABLE_PLAINTEXT`, `DOWNGRADE_ATTACK_DETECTED`).

### 2. Tri-State Evidence Assessment Engine
- **Verifiable Forensic Classification**: Replaces opaque severity guesses with deterministic tri-state evaluations:
  - `VERIFIED`: Confirmed cryptographic strength or explicit vulnerability backed by definitive frame evidence.
  - `SUSPICIOUS`: Anomalous protocol behavior, unexpected resets, or partial handshakes indicating potential tampering.
  - `INCONCLUSIVE`: Traffic lacking necessary frames (e.g., truncated captures, missing client hellos) preventing a definitive verdict.
- **Evidence Binding**: Every assessment binds directly to packet frame numbers, timestamps, cipher hex identifiers, and SHA-256 capture hashes.

### 3. Interactive Evidence Provenance Graph
- **Bi-Directional Directed Acyclic Graph (DAG)**: Built on React Flow, visualizes the complete forensic chain of custody:
  $$\text{PCAP File} \longrightarrow \text{Sessions} \longrightarrow \text{Packets / Frames} \longrightarrow \text{Cryptographic States} \longrightarrow \text{Findings}$$
- **Direct Frame Inspection**: Click any node in the graph to inspect exact packet payloads, TLS handshake parameters, or remediation steps.

### 4. Comprehensive Protocol & Vulnerability Coverage
- **Protocols Supported**: SMTP (25, 465, 587), IMAP (143, 993), POP3 (110, 995).
- **Attack Detection**: STARTTLS stripping (MITM), plaintext authentication (`AUTH PLAIN`, `AUTH LOGIN`), SSLv3 / TLS 1.0 / TLS 1.1 usage, RC4 / 3DES / export ciphers, expired/self-signed certificates, and cleartext credential transmission.

---

## Repository Structure

```text
SecureMailScope/
├── README.md                      # Primary project overview and quickstart
├── LICENSE                        # MIT Open Source License
├── .gitignore                     # Repository ignore rules (caches, uploads, results)
├── .env.example                   # Environment configuration template
├── start.bat                      # Windows launcher (runs backend and frontend simultaneously)
├── start.ps1                      # PowerShell launcher
│
├── docs/                          # Comprehensive project documentation
│   ├── README.md                  # Central documentation index
│   ├── architecture/              # System architecture and functionality maps
│   ├── setup/                     # Setup, prerequisites, and environment guides
│   ├── guides/                    # User guides and demo walkthroughs
│   ├── features/                  # Cryptographic engine specifications and RFC rules
│   ├── testing/                   # Test reports, validation matrices, and PCAP fixtures
│   ├── reports/                   # Audit reports, cleanup summaries, and milestone records
│   ├── implementation/            # Active and completed implementation task sheets
│   └── archive/                   # Superseded documentation retained for audit
│
├── frontend/                      # React 19 + Vite frontend application
│   ├── src/                       # Source components, pages, context, and styles
│   │   ├── components/            # UI components (ProvenanceGraph, Assessments, etc.)
│   │   ├── pages/                 # Route pages (Dashboard, Analysis, History, etc.)
│   │   ├── context/               # Global state (Auth, Theme)
│   │   └── utils/                 # API client, graph layout, helpers
│   ├── public/                    # Static assets
│   ├── tests/                     # Frontend integration and unit tests
│   └── package.json               # Frontend dependencies and npm scripts
│
├── backend/                       # FastAPI + PyShark backend application
│   ├── app/                       # Core backend package
│   │   ├── api/                   # API routes and endpoints
│   │   ├── core/                  # Analysis engines (PCAP analyzer, Crypto state, Assessment)
│   │   └── services/              # Provenance graph, Gemini AI remediation, Supabase
│   ├── tests/                     # Pytest test suite
│   ├── test-data/                 # Canonical demo PCAP captures and validation scripts
│   ├── requirements.txt           # Python backend dependencies
│   └── main.py                    # FastAPI entry point
│
├── database/                      # Database schemas and migration scripts
│   └── supabase_schema.sql        # Supabase PostgreSQL schema for auth & history
│
├── deployment/                    # Remote server deployment scripts
│   └── deploy-to-server.ps1       # Automated Tailscale SSH deployment script
│
├── scripts/                       # Development, testing, and maintenance utilities
│   ├── development/               # Dev helper scripts
│   ├── testing/                   # Test presets and validation utilities
│   └── maintenance/               # Cleanup and maintenance scripts
│
├── test-data/                     # Raw PCAP captures, keys, and test fixtures
└── archive/                       # Archived legacy scripts and obsolete artifacts
```

---

## Getting Started

### Prerequisites

- **Python 3.10+**: with `pip`
- **Node.js 18+**: with `npm`
- **Wireshark / TShark**: Required for PCAP packet parsing (`tshark` must be in system PATH)

### Quick Start (One-Click Launch)

On Windows, launch both the FastAPI backend and the Vite frontend with one command:

```cmd
start.bat
```

Or via PowerShell:

```powershell
.\start.ps1
```

Once running:
- **Web UI**: [http://localhost:5173](http://localhost:5173)
- **API Documentation**: [http://localhost:8001/docs](http://localhost:8001/docs)

---

### Manual Setup

#### 1. Backend Setup

```bash
cd backend

# Create and activate virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start FastAPI server
python main.py
```
*Backend runs on `http://localhost:8001`.*

#### 2. Frontend Setup

```bash
cd frontend

# Install npm dependencies
npm install

# Start Vite dev server
npm run dev
```
*Frontend runs on `http://localhost:5173`.*

---

## Pre-Loaded Demo PCAP Captures

SecureMailScope includes pre-configured email traffic captures in `backend/test-data/` to demonstrate forensic workflows without requiring external packet traces:

| Demo Sample | Protocol | Description | Forensic Finding |
|---|---|---|---|
| **Vulnerable SMTP** | SMTP (Port 25) | Cleartext transmission | Plaintext credentials (`AUTH LOGIN`) and unencrypted email content |
| **Legacy SSLv3** | SMTPS (Port 465) | Obsolete cryptographic protocol | Deprecated SSL 3.0 negotiation and weak cipher suites |
| **Secure Enterprise** | Submission (Port 587) | Modern TLS 1.3 configuration | Fully encrypted session adhering to RFC 8314 BCP standards |
| **Comprehensive Multi-Session** | Mixed (SMTP/IMAP/POP3) | Multi-session enterprise scenario | Concurrent analysis of downgrade attacks, legacy protocols, and secure sessions |

Load any sample instantly via the UI (**Analysis** $\rightarrow$ **Load Preset**) or API:
```http
POST /api/demo/load/{preset_id}
```

---

## Testing & Verification

### Backend Automated Tests

Run the complete backend test suite using `pytest`:

```bash
cd backend
python -m pytest tests/ -v
```

### Frontend Automated Tests

Run frontend component and logic tests using Node's test runner:

```bash
cd frontend
node --test tests/evidence_assessment_ui.test.mjs
node --test tests/crypto_state_ui.test.mjs
```

### Production Build Verification

Verify that the frontend builds without errors:

```bash
cd frontend
npm run build
```

---

## Documentation

For full technical specifications, architecture diagrams, testing matrices, and implementation histories, explore the [Documentation Index](docs/README.md).

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
