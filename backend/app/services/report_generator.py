"""
Forensic Report Generator for SecureMailScope
Generates self-contained, publication-grade HTML and structured JSON reports.
"""

import html as _html
import json
from datetime import datetime
from typing import Dict


class ReportGenerator:
    """Renders comprehensive cybersecurity forensic reports."""

    @staticmethod
    def generate_pdf_report(data: Dict) -> bytes:
        """Render the HTML report to PDF bytes (pure-Python xhtml2pdf, no system libs)."""
        from io import BytesIO
        from xhtml2pdf import pisa

        import re
        html = ReportGenerator.generate_html_report(data)
        # The built-in PDF fonts have no emoji glyphs; they render as boxes.
        html = re.sub(r"[☀-➿🀀-🫿️]", "", html)
        buffer = BytesIO()
        result = pisa.CreatePDF(html, dest=buffer, encoding="utf-8")
        if result.err:
            raise RuntimeError("PDF rendering failed")
        return buffer.getvalue()

    @staticmethod
    def generate_html_report(data: Dict) -> str:
        """Generate a self-contained, print-ready HTML forensic report."""
        summary = data.get("summary", {})
        risk = data.get("risk", {})
        findings = data.get("findings", [])
        sessions = data.get("sessions", [])
        certificates = data.get("certificates", [])
        ai_summary = data.get("ai_summary", "No AI executive summary available.")
        capture_id = data.get("capture_id", "UNKNOWN")
        filename = data.get("original_filename", data.get("filename", "capture.pcap"))
        timestamp = data.get("upload_timestamp", datetime.now().isoformat())

        # Severity Badge Colors
        severity_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#d97706",
            "LOW": "#16a34a"
        }

        # Build Findings HTML
        findings_html = ""
        for f in findings:
            sev = f.get("severity", "LOW")
            color = severity_colors.get(sev, "#64748b")
            ai_exp = f.get("ai_explanation", "Standard deterministic finding rule.")
            remediation = f.get("remediation", "Apply transport layer hardening.").replace("\n", "<br>")

            findings_html += f"""
            <div class="finding-card" style="border-left: 5px solid {color};">
                <div class="finding-header">
                    <span class="badge" style="background-color: {color}; color: white;">{sev}</span>
                    <span class="finding-id">[{f.get('id', 'N/A')}]</span>
                    <h3 class="finding-title">{f.get('title', 'Security Finding')}</h3>
                </div>
                <div class="finding-body">
                    <p><strong>Technical Description:</strong> {f.get('description', '')}</p>
                    <div class="evidence-box">
                        <strong>Forensic Evidence:</strong> <code>{f.get('evidence', '')}</code>
                    </div>
                    <div class="ai-box">
                        <strong>🤖 AI Threat Analysis:</strong>
                        <p>{ai_exp}</p>
                    </div>
                    <div class="remediation-box">
                        <strong>Mandatory Remediation:</strong>
                        <p>{remediation}</p>
                    </div>
                </div>
            </div>
            """

        if not findings:
            findings_html = "<p class='clean-state'>✅ No cryptographic vulnerabilities or cleartext email transmissions detected.</p>"

        # Build Sessions Table HTML
        sessions_html = ""
        for s in sessions:
            enc_badge = '<span class="badge-sm badge-green">TLS Encrypted</span>' if s.get("encrypted") else '<span class="badge-sm badge-red">Cleartext Plaintext</span>'
            tls_ver = ", ".join(s.get("tls_versions", [])) or "None"
            sessions_html += f"""
            <tr>
                <td><strong>{s.get('id', '')}</strong></td>
                <td><span class="protocol-tag">{s.get('protocol', '')}</span></td>
                <td><code>{s.get('src', '')}</code></td>
                <td><code>{s.get('dst', '')}</code></td>
                <td>{s.get('packet_count', 0)}</td>
                <td>{enc_badge}</td>
                <td><code>{tls_ver}</code></td>
            </tr>
            """

        if not sessions:
            sessions_html = "<tr><td colspan='7' style='text-align:center;'>No email sessions reconstructed.</td></tr>"

        # Build Certificates Table HTML
        certs_html = ""
        for c in certificates:
            self_signed = "⚠️ Yes" if c.get("is_self_signed") else "No (CA Verified)"
            expired = "🚨 Expired" if c.get("is_expired") else "Valid"
            certs_html += f"""
            <tr>
                <td>{c.get('subject', 'Unknown')}</td>
                <td>{c.get('issuer', 'Unknown')}</td>
                <td>{c.get('signature_algorithm', 'N/A')}</td>
                <td>{c.get('key_size', 'N/A')} bits</td>
                <td>{self_signed}</td>
                <td>{expired}</td>
            </tr>
            """

        if not certificates:
            certs_html = "<tr><td colspan='6' style='text-align:center;'>No X.509 certificates extracted from handshake records.</td></tr>"

        # Build Email Authentication (passive SPF/DKIM/DMARC) section.
        # Values originate from captured packets, so everything is escaped.
        esc = lambda v: _html.escape(str(v if v is not None else ""))
        email_auth = data.get("email_auth") or {}
        ea_summary = email_auth.get("summary") or {}
        ea_rows = ""
        for m in email_auth.get("messages", []):
            dkim = m.get("dkim", {})
            dkim_txt = ", ".join(dkim.get("results", [])) or (
                "signed (unverified)" if dkim.get("signatures") else "unsigned")
            sigs = "<br>".join(
                f"d={esc(sg.get('domain'))} s={esc(sg.get('selector'))} {esc(sg.get('algorithm'))}"
                + ("" if sg.get("aligned_with_from") else " (not aligned with From)")
                for sg in dkim.get("signatures", []))
            ea_rows += f"""
            <tr>
                <td>{esc(m.get('from_domain') or 'unknown')}</td>
                <td>{esc(m.get('protocol'))} / stream {esc(m.get('stream_id'))}</td>
                <td>{esc(m.get('spf', {}).get('result') or 'not asserted')}</td>
                <td>{esc(dkim_txt)}<br><small>{sigs}</small></td>
                <td>{esc(m.get('dmarc', {}).get('result') or 'not asserted')}</td>
            </tr>"""
        ea_dns_rows = "".join(f"""
            <tr>
                <td>{esc(r.get('kind', '').upper())}</td>
                <td>{esc(r.get('domain'))}</td>
                <td>{esc(r.get('frame'))}</td>
                <td><code>{esc((r.get('record') or '')[:160])}</code></td>
            </tr>""" for r in email_auth.get("dns_records", []))
        ea_notes = "".join(f"<li>{esc(n)}</li>" for n in email_auth.get("limitations", []))

        email_auth_html = ""
        if ea_summary:
            enc_streams = ea_summary.get("encrypted_mail_streams", 0)
            enc_note = f", {esc(enc_streams)} encrypted stream(s) could not be inspected" if enc_streams else ""
            msg_table = (
                "<table><thead><tr><th>From Domain</th><th>Protocol</th><th>SPF</th>"
                "<th>DKIM</th><th>DMARC</th></tr></thead><tbody>" + ea_rows + "</tbody></table>"
            ) if ea_rows else ""
            dns_table = (
                "<table><thead><tr><th>Type</th><th>Domain</th><th>Frame</th>"
                "<th>Record</th></tr></thead><tbody>" + ea_dns_rows + "</tbody></table>"
            ) if ea_dns_rows else ""
            empty_note = "" if (ea_rows or ea_dns_rows) else (
                "<p class='clean-state'>No SPF/DKIM/DMARC evidence found in this capture.</p>")
            email_auth_html = (
                '<h2 class="section-title">Email Authentication Evidence (SPF / DKIM / DMARC)</h2>'
                '<p style="font-size:13px;color:#475569;">Passive analysis of this capture only: '
                f"{esc(ea_summary.get('messages_analyzed', 0))} plaintext message(s) inspected, "
                f"{esc(ea_summary.get('dns_records_found', 0))} DNS authentication record(s) observed{enc_note}.</p>"
                + msg_table + dns_table + empty_note
                + f'<ul style="font-size:12px;color:#64748b;">{ea_notes}</ul>'
            )

        risk_score = risk.get("risk_score", 0)
        risk_level = risk.get("risk_level", "LOW")
        risk_color = severity_colors.get(risk_level, "#16a34a")
        risk_grade = risk.get("risk_grade", "")

        # Full HTML Document
        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureMailScope Forensic Report - {capture_id}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
        body {{ background: #f8fafc; color: #0f172a; padding: 40px 20px; line-height: 1.6; }}
        .report-container {{ max-width: 1000px; margin: 0 auto; background: #ffffff; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); padding: 40px; border: 1px solid #e2e8f0; }}
        .header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #e2e8f0; padding-bottom: 24px; margin-bottom: 30px; }}
        .logo-title h1 {{ font-size: 26px; color: #0f172a; font-weight: 800; display: flex; align-items: center; gap: 10px; }}
        .logo-title p {{ color: #64748b; font-size: 14px; margin-top: 4px; }}
        .meta-box {{ text-align: right; font-size: 13px; color: #64748b; }}
        .meta-box span {{ display: block; }}
        .section-title {{ font-size: 18px; font-weight: 700; color: #1e293b; margin: 30px 0 15px 0; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 25px; }}
        .card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; text-align: center; }}
        .card h4 {{ font-size: 12px; text-transform: uppercase; color: #64748b; letter-spacing: 0.5px; }}
        .card .val {{ font-size: 28px; font-weight: 800; margin-top: 6px; }}
        .executive-box {{ background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 20px; margin-bottom: 30px; }}
        .executive-box h3 {{ font-size: 15px; color: #1e40af; margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }}
        .executive-box p {{ font-size: 14px; color: #1e3a8a; line-height: 1.5; }}
        .finding-card {{ background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
        .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }}
        .badge {{ font-size: 11px; font-weight: 700; padding: 4px 8px; border-radius: 4px; text-transform: uppercase; }}
        .badge-sm {{ font-size: 11px; font-weight: 600; padding: 2px 6px; border-radius: 4px; }}
        .badge-green {{ background: #dcfce7; color: #15803d; }}
        .badge-red {{ background: #fee2e2; color: #b91c1c; }}
        .finding-id {{ font-size: 12px; font-weight: 700; color: #64748b; }}
        .finding-title {{ font-size: 16px; font-weight: 700; color: #0f172a; }}
        .finding-body p {{ font-size: 14px; color: #334155; margin-bottom: 10px; }}
        .evidence-box {{ background: #f1f5f9; border-left: 3px solid #64748b; padding: 10px 14px; border-radius: 4px; font-size: 13px; margin: 10px 0; color: #1e293b; }}
        .ai-box {{ background: #faf5ff; border: 1px solid #e9d5ff; border-radius: 6px; padding: 12px 14px; margin: 10px 0; font-size: 13px; color: #581c87; }}
        .remediation-box {{ background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 12px 14px; font-size: 13px; color: #14532d; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
        th {{ background: #f8fafc; color: #475569; font-weight: 700; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }}
        code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background: #e2e8f0; padding: 2px 5px; border-radius: 4px; font-size: 12px; }}
        .protocol-tag {{ background: #0f172a; color: white; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
        .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #94a3b8; }}
        @media print {{
            body {{ padding: 0; background: white; }}
            .report-container {{ box-shadow: none; border: none; padding: 0; }}
            .no-print {{ display: none; }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <!-- Report Header -->
        <div class="header">
            <div class="logo-title">
                <h1>🛡️ SecureMailScope</h1>
                <p>AI-Driven Email Security Assessment & Cryptographic Forensics</p>
            </div>
            <div class="meta-box">
                <span><strong>Capture ID:</strong> {capture_id}</span>
                <span><strong>Analyzed File:</strong> {filename}</span>
                <span><strong>Date:</strong> {timestamp[:19].replace('T', ' ')}</span>
            </div>
        </div>

        <!-- Executive Briefing -->
        <div class="executive-box">
            <h3>🤖 CISO Executive Briefing (AI-Synthesized)</h3>
            <p>{ai_summary}</p>
        </div>

        <!-- Metric Cards -->
        <div class="summary-grid">
            <div class="card">
                <h4>Security Posture</h4>
                <div class="val" style="color: {risk_color};">{risk_score}/100</div>
                <span class="badge" style="background-color: {risk_color}; color: white;">{risk_level}</span>
                {f'<div class="val" style="color: {risk_color};">Grade {risk_grade}</div>' if risk_grade else ''}
            </div>
            <div class="card">
                <h4>Email Packets</h4>
                <div class="val">{summary.get('total_packets', 0)}</div>
                <small>{summary.get('plaintext_packets', 0)} Cleartext</small>
            </div>
            <div class="card">
                <h4>Security Findings</h4>
                <div class="val" style="color: #dc2626;">{len(findings)}</div>
                <small>{risk.get('critical_count', 0)} Critical | {risk.get('high_count', 0)} High</small>
            </div>
            <div class="card">
                <h4>Reconstructed Sessions</h4>
                <div class="val">{summary.get('session_count', 0)}</div>
                <small>{summary.get('handshake_count', 0)} TLS Handshakes</small>
            </div>
        </div>

        <!-- Findings Breakdown -->
        <h2 class="section-title">Prioritized Security Findings & Remediation Plan</h2>
        {findings_html}

        <!-- Session Forensics -->
        <h2 class="section-title">Reconstructed Email Session Forensics</h2>
        <table>
            <thead>
                <tr>
                    <th>Session ID</th>
                    <th>Protocol</th>
                    <th>Source Endpoint</th>
                    <th>Destination Endpoint</th>
                    <th>Packets</th>
                    <th>Encryption</th>
                    <th>TLS Version</th>
                </tr>
            </thead>
            <tbody>
                {sessions_html}
            </tbody>
        </table>

        <!-- Certificates -->
        <h2 class="section-title">X.509 Cryptographic Certificate Audit</h2>
        <table>
            <thead>
                <tr>
                    <th>Subject</th>
                    <th>Issuer</th>
                    <th>Signature Algorithm</th>
                    <th>Key Size</th>
                    <th>Self-Signed</th>
                    <th>Expiry Status</th>
                </tr>
            </thead>
            <tbody>
                {certs_html}
            </tbody>
        </table>

        {email_auth_html}
        <!-- Footer -->
        <div class="footer">
            <p>Generated by SecureMailScope Automated Forensics Engine | Smart India Hackathon Prototype</p>
            <p>Confidential Security Assessment — RFC 8996 & NIST SP 800-52r2 Aligned</p>
        </div>
    </div>
</body>
</html>
"""
        return html_doc