"""
Gemini AI Service for SecureMailScope
Uses the modern `google-genai` SDK with `gemini-3.6-flash`.
Enriches deterministic security findings with contextual explanations and remediation.
Includes an intelligent offline fallback engine.
"""

import os
import json
from typing import Dict, List, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

try:
    from google import genai
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False


class GeminiSecurityAssistant:
    """Contextual security assistant using google-genai and gemini-3.6-flash."""

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "").strip()
        self.model_name = os.getenv("GEMINI_MODEL", "gemini-3.6-flash").strip()
        self.client = None
        self.is_online = False

        if HAS_GENAI and self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
                
                # Test connectivity with a lightweight ping
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents="Ping"
                )
                if response and response.text:
                    self.is_online = True
                    print(f"[+] Gemini AI Service initialized via google-genai (Active Model: {self.model_name})")
                else:
                    self._try_fallback_models()
            except Exception as e:
                print(f"[*] Primary model ({self.model_name}) note: {e}. Searching fallback candidate...")
                self._try_fallback_models()
        else:
            print("[*] No Gemini API key detected. Using High-Fidelity Offline Engine.")

    def _try_fallback_models(self):
        """Try other available models if the primary model fails."""
        candidates = ["gemini-3.6-flash", "gemini-flash-latest", "gemini-3.7-flash", "gemini-2.5-flash", "gemini-pro-latest"]
        for cand in candidates:
            try:
                res = self.client.models.generate_content(model=cand, contents="Ping")
                if res and res.text:
                    self.model_name = cand
                    self.is_online = True
                    print(f"[+] Gemini AI Service connected using candidate: {self.model_name}")
                    return
            except Exception:
                continue
        print("[!] All online model queries failed. Using Offline Intelligence Engine.")
        self.is_online = False

    def explain_finding(self, finding: Dict) -> Dict:
        """Generate contextual threat explanation and risk impact."""
        if self.is_online and self.client:
            try:
                prompt = (
                    "You are a Principal Cybersecurity Analyst specialized in email infrastructure, PKI, and transport cryptography. "
                    "Analyze this security finding extracted from network packet forensics:\n\n"
                    f"Title: {finding.get('title')}\n"
                    f"Severity: {finding.get('severity')}\n"
                    f"Type: {finding.get('type')}\n"
                    f"Description: {finding.get('description')}\n"
                    f"Forensic Evidence: {finding.get('evidence')}\n\n"
                    "Respond with a JSON object containing exactly two fields:\n"
                    "1. 'ai_explanation': A high-impact 2-sentence explanation covering technical attack vectors (e.g. MITM, credential harvesting, protocol downgrade) and organizational compliance impact.\n"
                    "2. 'ai_confidence': 'HIGH'\n"
                    "Return ONLY valid JSON without markdown code fences."
                )

                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt
                )
                raw_text = response.text.strip()

                # Clean markdown formatting if present
                if raw_text.startswith("```json"):
                    raw_text = raw_text[7:]
                if raw_text.startswith("```"):
                    raw_text = raw_text[3:]
                if raw_text.endswith("```"):
                    raw_text = raw_text[:-3]

                parsed = json.loads(raw_text.strip())
                return {
                    "ai_explanation": parsed.get("ai_explanation", self._fallback_explanation(finding)),
                    "ai_confidence": "HIGH",
                    "ai_source": f"Google Gemini ({self.model_name})"
                }
            except Exception as e:
                print(f"[!] AI generation fallback for {finding.get('id')}: {e}")
                return self._offline_enrich_finding(finding)
        else:
            return self._offline_enrich_finding(finding)

    def generate_executive_summary(self, summary: Dict, findings: List[Dict], risk: Dict) -> str:
        """Generate a CISO-level executive summary."""
        if self.is_online and self.client:
            try:
                prompt = (
                    "You are a CISO delivering an executive summary for an email security posture assessment report.\n"
                    f"Total Monitored Email Packets: {summary.get('total_packets')}\n"
                    f"Unencrypted Packet Ratio: {100 - int(summary.get('encryption_ratio', 0) * 100)}%\n"
                    f"Evaluated Risk Score: {risk.get('risk_score')}/100 ({risk.get('risk_level')})\n"
                    f"Critical/High Vulnerabilities: {[f.get('title') for f in findings]}\n\n"
                    "Provide a concise 2-3 sentence executive briefing assessing organizational risk posture and mandatory remediation priority."
                )

                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt
                )
                return response.text.strip()
            except Exception as e:
                print(f"[!] Executive summary fallback: {e}")
                return self._fallback_executive_summary(summary, risk, findings)
        else:
            return self._fallback_executive_summary(summary, risk, findings)

    # ─── OFFLINE DETERMINISTIC INTELLIGENCE ENGINE ───

    def _offline_enrich_finding(self, finding: Dict) -> Dict:
        return {
            "ai_explanation": self._fallback_explanation(finding),
            "ai_confidence": "DETERMINISTIC_BASELINE",
            "ai_source": "SecureMailScope-Intelligence-Engine"
        }

    def _fallback_explanation(self, finding: Dict) -> str:
        ftype = finding.get("type", "")
        if ftype == "plaintext_protocol":
            return (
                "Transmitting email traffic over cleartext protocols allows active or passive network eavesdroppers "
                "to intercept sensitive communications, exfiltrate credentials via MITM attacks, and violate regulatory "
                "mandates (such as GDPR, HIPAA, and PCI DSS)."
            )
        elif ftype == "deprecated_protocol":
            return (
                "Deprecated cryptographic protocols (SSL 3.0, TLS 1.0/1.1) lack modern cipher suites and are susceptible "
                "to protocol-downgrade attacks and cryptanalytic vulnerabilities (e.g., POODLE, BEAST). Modern standards mandate TLS 1.2+."
            )
        elif ftype == "weak_cipher":
            return (
                "The negotiated cipher suites utilize legacy ciphers (e.g., RC4, 3DES, CBC-mode ciphers) that suffer from "
                "known mathematical weaknesses, enabling plaintext recovery via collision or padding-oracle exploits."
            )
        elif ftype == "missing_starttls":
            return (
                "The mail transfer agent fails to negotiate STARTTLS during SMTP handshake initiation, exposing message "
                "routing headers, authentication tokens, and message payloads across untrusted intermediate relays."
            )
        elif ftype == "expired_certificate":
            return (
                "The presented X.509 certificate has passed its validity period, causing client-side trust warnings, broken automated "
                "mail exchange validation, and exposure to spoofing."
            )
        elif ftype == "self_signed_certificate":
            return (
                "The server certificate is not rooted in a trusted public or private Certificate Authority (CA). Mail clients cannot "
                "cryptographically verify host identity, leaving connections vulnerable to intercepting proxies."
            )
        return (
            "The observed cryptographic parameters deviate from NIST SP 800-52r2 guidelines, creating security exposure "
            "in transport layer integrity and confidentiality."
        )

    def _fallback_executive_summary(self, summary: Dict, risk: Dict, findings: List[Dict]) -> str:
        score = risk.get("risk_score", 0)
        finding_count = len(findings)
        level = risk.get("risk_level", "LOW")

        if level in ["CRITICAL", "HIGH"]:
            return (
                f"CRITICAL POSTURE ALERT: Network analysis identified high-severity cryptographic vulnerabilities resulting in a "
                f"Risk Score of {score}/100. Key risks include unencrypted email transmissions and non-compliant protocol negotiations. "
                f"Immediate implementation of TLS 1.3 and STARTTLS enforcement is strongly advised to prevent data leakage."
            )
        elif level == "MEDIUM":
            return (
                f"MODERATE SECURITY POSTURE: The email infrastructure scored {score}/100 with {finding_count} detected issue(s). "
                f"While basic encryption is active, improvements in certificate lifecycle management and cipher suite hardening "
                f"are required to meet industry compliance baselines."
            )
        else:
            return (
                f"STRONG SECURITY POSTURE: The inspected mail traffic demonstrates robust cryptographic controls with a low Risk Score "
                f"of {score}/100. Encryption standards and handshake parameters comply with modern secure transport recommendations."
            )