"""
Professional PDF Report Generation Service for SecureMailScope

Generates publication-quality, formal forensic and cryptographic drift reports:
- Report A: Historical Cryptographic Forensics Report
- Report B: Cryptographic Drift & Baseline Comparison Report
- Report C: Combined Cryptographic Investigation Report

Uses ReportLab with custom styling, running headers, running footers,
and dynamic "Page X of Y" pagination.
"""

import io
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and print running headers,
    running footers, and total page count ('Page X of Y').
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        # Suppress headers/footers on cover page
        if self._pageNumber > 1:
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#475569"))
            self.drawString(54, 755, "SECUREMAILSCOPE")
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748b"))
            self.drawString(140, 755, "|  Automated Cryptographic Forensics & Drift Audit")

            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.75)
            self.line(54, 747, 558, 747)

            # Footer
            self.line(54, 45, 558, 45)
            self.setFont("Helvetica", 7.5)
            self.setFillColor(colors.HexColor("#64748b"))
            self.drawString(54, 33, "CONFIDENTIAL & PRIVILEGED  •  SECUREMAILSCOPE VERIFIED AUDIT")
            page_text = f"Page {self._pageNumber} of {page_count}"
            self.drawRightString(558, 33, page_text)
        self.restoreState()


class PDFReportGenerator:
    """
    Dedicated document generator for formal security and compliance reports.
    """

    @classmethod
    def _create_styles(cls):
        styles = getSampleStyleSheet()

        styles.add(ParagraphStyle(
            'CoverPreTitle',
            fontName='Helvetica-Bold',
            fontSize=10,
            leading=12,
            textColor=colors.HexColor('#6366f1'),
            spaceAfter=8,
            textTransform='uppercase'
        ))
        styles.add(ParagraphStyle(
            'CoverTitle',
            fontName='Helvetica-Bold',
            fontSize=24,
            leading=28,
            textColor=colors.HexColor('#0f172a'),
            spaceAfter=12
        ))
        styles.add(ParagraphStyle(
            'CoverSubtitle',
            fontName='Helvetica',
            fontSize=12,
            leading=16,
            textColor=colors.HexColor('#475569'),
            spaceAfter=24
        ))
        styles.add(ParagraphStyle(
            'ReportSectionHeading',
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#0f172a'),
            spaceBefore=14,
            spaceAfter=8,
            keepWithNext=True
        ))
        styles.add(ParagraphStyle(
            'ReportSubSectionHeading',
            fontName='Helvetica-Bold',
            fontSize=11,
            leading=15,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=10,
            spaceAfter=6,
            keepWithNext=True
        ))
        styles.add(ParagraphStyle(
            'ReportBody',
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=colors.HexColor('#334155'),
            spaceAfter=6
        ))
        styles.add(ParagraphStyle(
            'ReportBodyBold',
            fontName='Helvetica-Bold',
            fontSize=9,
            leading=13,
            textColor=colors.HexColor('#0f172a'),
            spaceAfter=6
        ))
        styles.add(ParagraphStyle(
            'ReportMetaLabel',
            fontName='Helvetica-Bold',
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor('#475569')
        ))
        styles.add(ParagraphStyle(
            'ReportMetaValue',
            fontName='Helvetica',
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor('#0f172a')
        ))
        styles.add(ParagraphStyle(
            'ReportTableCell',
            fontName='Helvetica',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#1e293b')
        ))
        styles.add(ParagraphStyle(
            'ReportTableCellBold',
            fontName='Helvetica-Bold',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#0f172a')
        ))
        styles.add(ParagraphStyle(
            'ReportTableMono',
            fontName='Courier',
            fontSize=7.5,
            leading=9,
            textColor=colors.HexColor('#0f172a')
        ))
        styles.add(ParagraphStyle(
            'CalloutBox',
            fontName='Helvetica',
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor('#1e293b')
        ))

        return styles

    @classmethod
    def generate_forensic_report_pdf(
        cls,
        analysis_data: Dict[str, Any],
        forensics_data: Optional[Dict[str, Any]] = None
    ) -> bytes:
        """
        Generates Report A: Historical Cryptographic Forensics Report (PDF)
        """
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54
        )
        styles = cls._create_styles()
        story = []

        capture_id = analysis_data.get("capture_id") or "CAPTURE-N/A"
        filename = analysis_data.get("original_filename") or analysis_data.get("filename") or "evidence.pcap"
        summary = analysis_data.get("summary", {})
        findings = analysis_data.get("findings", [])
        sessions = analysis_data.get("sessions", [])
        certificates = analysis_data.get("certificates", [])
        handshakes = analysis_data.get("tls_handshakes", [])
        crypto_state = analysis_data.get("cryptographic_state_assessment", {})
        timeline_events = (forensics_data or {}).get("timeline_events", [])

        report_id = f"FRN-{uuid.uuid4().hex[:8].upper()}"
        gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

        # ─── COVER PAGE ───
        story.append(Spacer(1, 40))
        story.append(Paragraph("SECUREMAILSCOPE FORENSIC REPORT", styles['CoverPreTitle']))
        story.append(Paragraph("Historical Cryptographic Forensics Report", styles['CoverTitle']))
        story.append(Paragraph(
            f"Automated forensic reconstruction of email protocol transitions, cryptographic handshakes, and transport security posture for network capture <b>{filename}</b>.",
            styles['CoverSubtitle']
        ))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#6366f1'), spaceAfter=20))

        # Metadata Table
        meta_data = [
            [Paragraph("Report ID:", styles['ReportMetaLabel']), Paragraph(report_id, styles['ReportMetaValue']),
             Paragraph("Generated At:", styles['ReportMetaLabel']), Paragraph(gen_time, styles['ReportMetaValue'])],
            [Paragraph("Target Capture:", styles['ReportMetaLabel']), Paragraph(filename, styles['ReportMetaValue']),
             Paragraph("Capture ID:", styles['ReportMetaLabel']), Paragraph(capture_id, styles['ReportMetaValue'])],
            [Paragraph("Total Packets:", styles['ReportMetaLabel']), Paragraph(str(summary.get("total_packets", 0)), styles['ReportMetaValue']),
             Paragraph("Reconstructed Flows:", styles['ReportMetaLabel']), Paragraph(str(len(sessions)), styles['ReportMetaValue'])],
            [Paragraph("Cryptographic State:", styles['ReportMetaLabel']), Paragraph(crypto_state.get("overall_state_label", "Evaluated"), styles['ReportMetaValue']),
             Paragraph("Overall Risk Score:", styles['ReportMetaLabel']), Paragraph(f"{summary.get('risk_score', 0)}/100 ({summary.get('risk_level', 'N/A')})", styles['ReportMetaValue'])],
        ]
        meta_table = Table(meta_data, colWidths=[100, 150, 110, 144])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#e2e8f0')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#f1f5f9')),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(meta_table)

        story.append(Spacer(1, 24))
        story.append(Paragraph("<b>CONFIDENTIALITY NOTICE:</b> The information contained in this document is derived from passive network packet telemetry. It includes forensic protocol evidence, cryptographic parameters, and security vulnerability findings intended exclusively for authorized audit personnel.", styles['ReportBody']))
        story.append(PageBreak())

        # ─── SECTION 1: EXECUTIVE SUMMARY ───
        story.append(Paragraph("1. Executive Summary", styles['ReportSectionHeading']))
        story.append(Paragraph(
            f"An automated deep forensic investigation was performed on packet capture <b>{filename}</b> (Capture ID: <code>{capture_id}</code>). "
            f"The analyzer inspected {summary.get('total_packets', 0)} network packets and successfully reconstructed {len(sessions)} email session flow(s) "
            f"across detected protocols ({', '.join(summary.get('protocols_detected', [])) or 'None'}).",
            styles['ReportBody']
        ))

        score = summary.get("risk_score", 0)
        risk_color = '#ef4444' if score >= 70 else ('#f59e0b' if score >= 40 else '#10b981')
        summary_callout = [
            [
                Paragraph(f"<b>Overall Security Assessment:</b> {crypto_state.get('overall_state_label', 'Evaluated')}<br/>"
                          f"<b>Forensic Risk Score:</b> <font color='{risk_color}'><b>{score} / 100</b></font> ({summary.get('risk_level', 'UNKNOWN')})<br/>"
                          f"<b>Identified Vulnerabilities:</b> {len(findings)} confirmed security finding(s)<br/>"
                          f"<b>Traffic Encryption Ratio:</b> {summary.get('encrypted_packets', 0)} Encrypted / {summary.get('plaintext_packets', 0)} Cleartext ({summary.get('encryption_ratio', 0)*100:.1f}%)",
                          styles['CalloutBox'])
            ]
        ]
        callout_table = Table(summary_callout, colWidths=[504])
        callout_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 1.5, colors.HexColor(risk_color)),
            ('PADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(callout_table)
        story.append(Spacer(1, 14))

        # ─── SECTION 2: SESSION RECONSTRUCTION ───
        story.append(Paragraph("2. Reconstructed Email Transport Sessions", styles['ReportSectionHeading']))
        story.append(Paragraph("The following network sessions were reconstructed from TCP streams, evaluating protocol upgrade mechanisms and encryption status:", styles['ReportBody']))

        session_headers = [
            Paragraph("<b>Session ID</b>", styles['ReportTableCellBold']),
            Paragraph("<b>Source</b>", styles['ReportTableCellBold']),
            Paragraph("<b>Destination</b>", styles['ReportTableCellBold']),
            Paragraph("<b>Protocol</b>", styles['ReportTableCellBold']),
            Paragraph("<b>STARTTLS Status</b>", styles['ReportTableCellBold']),
            Paragraph("<b>Encrypted</b>", styles['ReportTableCellBold'])
        ]
        session_rows = [session_headers]
        for s in sessions:
            enc_str = "<font color='#10b981'><b>YES</b></font>" if s.get("encrypted") else "<font color='#ef4444'><b>NO</b></font>"
            st_status = s.get("starttls_status", "NOT_ATTEMPTED")
            st_color = '#10b981' if st_status == 'UPGRADED_SUCCESSFUL' else ('#ef4444' if st_status in ('REJECTED', 'INCOMPLETE') else '#64748b')

            session_rows.append([
                Paragraph(s.get("id", "s1"), styles['ReportTableMono']),
                Paragraph(f"{s.get('src')}:{s.get('src_port', '')}", styles['ReportTableCell']),
                Paragraph(f"{s.get('dst')}:{s.get('dst_port', '')}", styles['ReportTableCell']),
                Paragraph(s.get("protocol", "SMTP"), styles['ReportTableCell']),
                Paragraph(f"<font color='{st_color}'>{st_status}</font>", styles['ReportTableCellBold']),
                Paragraph(enc_str, styles['ReportTableCellBold'])
            ])

        sess_table = Table(session_rows, colWidths=[65, 110, 110, 75, 95, 49])
        sess_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
            ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(sess_table)
        story.append(Spacer(1, 14))

        # ─── SECTION 3: FORENSIC TIMELINE ───
        if timeline_events:
            story.append(KeepTogether([
                Paragraph("3. Historical Cryptographic Event Timeline", styles['ReportSectionHeading']),
                Paragraph("Chronological reconstruction of protocol and cryptographic state events observed on the wire:", styles['ReportBody'])
            ]))
            tl_headers = [
                Paragraph("<b>Frame</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Time (s)</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Flow / Stream</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Event Type</b>", styles['ReportTableCellBold']),
                Paragraph("<b>State Transition / Description</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Evidence</b>", styles['ReportTableCellBold'])
            ]
            tl_rows = [tl_headers]
            for ev in timeline_events[:30]:  # Cap at first 30 events to maintain readability
                raw_ts = ev.get('timestamp') or "0.0"
                try:
                    ts_str = f"{float(raw_ts):.3f}s"
                except Exception:
                    ts_str = str(raw_ts).split("T")[-1][:10] if "T" in str(raw_ts) else str(raw_ts)[:10]

                tl_rows.append([
                    Paragraph(str(ev.get("frame_number", "--")), styles['ReportTableMono']),
                    Paragraph(ts_str, styles['ReportTableCell']),
                    Paragraph(f"Stream {ev.get('stream_id', 0)}", styles['ReportTableCell']),
                    Paragraph(ev.get("event_type", ""), styles['ReportTableCellBold']),
                    Paragraph(ev.get("summary", ""), styles['ReportTableCell']),
                    Paragraph(ev.get("evidence_ref", ""), styles['ReportTableMono'])
                ])
            tl_table = Table(tl_rows, colWidths=[40, 48, 65, 110, 185, 56])
            tl_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
                ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0, 0), (-1, -1), 4),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(tl_table)
            story.append(Spacer(1, 14))

        # ─── SECTION 4: CERTIFICATES & PKI ───
        if certificates:
            story.append(KeepTogether([
                Paragraph("4. X.509 Certificate Chain Analysis", styles['ReportSectionHeading']),
                Paragraph("Cryptographic validation of server certificates extracted from captured TLS handshakes:", styles['ReportBody'])
            ]))
            cert_headers = [
                Paragraph("<b>Subject DN</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Issuer DN</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Algorithm</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Key Size</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Validity</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Trust</b>", styles['ReportTableCellBold'])
            ]
            cert_rows = [cert_headers]
            for c in certificates:
                exp_text = "<font color='#ef4444'>EXPIRED</font>" if c.get("is_expired") else "<font color='#10b981'>ACTIVE</font>"
                trust_text = "<font color='#f59e0b'>SELF-SIGNED</font>" if c.get("is_self_signed") else "<font color='#10b981'>CA-SIGNED</font>"
                ksize = f"{c.get('key_size')} bits" if c.get('key_size') else "Unknown"

                cert_rows.append([
                    Paragraph(c.get("subject", "N/A"), styles['ReportTableCell']),
                    Paragraph(c.get("issuer", "N/A"), styles['ReportTableCell']),
                    Paragraph(c.get("public_key_algorithm", "RSA"), styles['ReportTableCell']),
                    Paragraph(ksize, styles['ReportTableCellBold']),
                    Paragraph(exp_text, styles['ReportTableCell']),
                    Paragraph(trust_text, styles['ReportTableCell'])
                ])
            cert_table = Table(cert_rows, colWidths=[120, 120, 55, 65, 65, 79])
            cert_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
                ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(cert_table)
            story.append(Spacer(1, 14))

        # ─── SECTION 5: FINDINGS & AUDIT RESULTS ───
        story.append(KeepTogether([
            Paragraph("5. Detailed Security Findings & Risk Analysis", styles['ReportSectionHeading']),
            Paragraph(f"Identified {len(findings)} security non-compliance issue(s) evaluated against RFC 8314, RFC 3207, and NIST SP 800-52r2:", styles['ReportBody'])
        ]))

        if findings:
            find_headers = [
                Paragraph("<b>ID</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Severity</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Title & Description</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Forensic Evidence</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Remediation</b>", styles['ReportTableCellBold'])
            ]
            find_rows = [find_headers]
            for f in findings:
                sev = (f.get("severity") or "LOW").upper()
                s_color = '#ef4444' if sev == 'CRITICAL' else ('#f97316' if sev == 'HIGH' else ('#f59e0b' if sev == 'MEDIUM' else '#10b981'))

                find_rows.append([
                    Paragraph(f.get("id", "--"), styles['ReportTableMono']),
                    Paragraph(f"<font color='{s_color}'><b>{sev}</b></font>", styles['ReportTableCellBold']),
                    Paragraph(f"<b>{f.get('title', '')}</b><br/>{f.get('description', '')}", styles['ReportTableCell']),
                    Paragraph(f.get("evidence", ""), styles['ReportTableMono']),
                    Paragraph(f.get("remediation", "").replace("\n", "<br/>"), styles['ReportTableCell'])
                ])
            find_table = Table(find_rows, colWidths=[55, 60, 150, 115, 124])
            find_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
                ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(find_table)
        else:
            story.append(Paragraph("<b>No security issues detected.</b> All observed email flows and cryptographic handshakes comply with security baselines.", styles['ReportBody']))

        story.append(Spacer(1, 14))

        # ─── SECTION 6: FORENSIC BOUNDARIES & UNCERTAINTY ───
        story.append(KeepTogether([
            Paragraph("6. Forensic Boundaries & Evidentiary Uncertainty", styles['ReportSectionHeading']),
            Paragraph(
                "In compliance with ISO/IEC 27037 forensic standards, SecureMailScope discloses technical analysis boundaries:<br/>"
                "• <b>Client Trust Roots:</b> Local client operating system root trust stores cannot be verified purely from passive network wire data.<br/>"
                "• <b>Encrypted Payloads:</b> Once TLS establishes encrypted Application Data, message contents and authentication credentials are cryptographically protected.<br/>"
                "• <b>Incomplete Captures:</b> Packets starting mid-stream without handshakes are treated as evidentiary limitations rather than attacks.",
                styles['ReportBody']
            )
        ]))

        doc.build(story, canvasmaker=NumberedCanvas)
        return buf.getvalue()

    @classmethod
    def generate_drift_report_pdf(
        cls,
        comparison_data: Dict[str, Any]
    ) -> bytes:
        """
        Generates Report B: Cryptographic Drift & Baseline Comparison Report (PDF)
        """
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54
        )
        styles = cls._create_styles()
        story = []

        cmp_id = comparison_data.get("comparison_id", "CMP-N/A")
        baseline_name = comparison_data.get("baseline_name", "Corporate Security Baseline")
        baseline_ver = comparison_data.get("baseline_version", "1.0")
        filename = comparison_data.get("filename", "evidence.pcap")
        target_ep = comparison_data.get("target_endpoint", "ALL_SERVICES")
        comp_time = comparison_data.get("compared_at", datetime.now().isoformat())
        overall_status = comparison_data.get("overall_status", "EVALUATED")
        summary_desc = comparison_data.get("summary_description", "")
        metrics = comparison_data.get("metrics", {})
        diffs = comparison_data.get("property_diffs", [])

        report_id = f"DRF-{uuid.uuid4().hex[:8].upper()}"

        # ─── COVER PAGE ───
        story.append(Spacer(1, 40))
        story.append(Paragraph("SECUREMAILSCOPE DRIFT AUDIT", styles['CoverPreTitle']))
        story.append(Paragraph("Cryptographic Drift & Baseline Comparison Report", styles['CoverTitle']))
        story.append(Paragraph(
            f"Formal comparative evaluation measuring configuration drift, cryptographic regressions, and policy compliance of <b>{filename}</b> against reference baseline <b>{baseline_name} (v{baseline_ver})</b>.",
            styles['CoverSubtitle']
        ))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#f59e0b'), spaceAfter=20))

        # Metadata Table
        meta_data = [
            [Paragraph("Report ID:", styles['ReportMetaLabel']), Paragraph(report_id, styles['ReportMetaValue']),
             Paragraph("Generated At:", styles['ReportMetaLabel']), Paragraph(comp_time[:19].replace("T", " "), styles['ReportMetaValue'])],
            [Paragraph("Baseline Target:", styles['ReportMetaLabel']), Paragraph(f"{baseline_name} (v{baseline_ver})", styles['ReportMetaValue']),
             Paragraph("Comparison ID:", styles['ReportMetaLabel']), Paragraph(cmp_id, styles['ReportMetaValue'])],
            [Paragraph("Target Endpoint:", styles['ReportMetaLabel']), Paragraph(target_ep, styles['ReportMetaValue']),
             Paragraph("Analyzed Capture:", styles['ReportMetaLabel']), Paragraph(filename, styles['ReportMetaValue'])],
            [Paragraph("Overall Drift Status:", styles['ReportMetaLabel']), Paragraph(overall_status, styles['ReportMetaValue']),
             Paragraph("Properties Evaluated:", styles['ReportMetaLabel']), Paragraph(str(metrics.get("total_properties", 0)), styles['ReportMetaValue'])],
        ]
        meta_table = Table(meta_data, colWidths=[110, 140, 110, 144])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#e2e8f0')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#f1f5f9')),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(meta_table)

        story.append(Spacer(1, 24))
        story.append(Paragraph("<b>AUDIT INTEGRITY NOTICE:</b> Cryptographic drift is evaluated across transport protocols, cipher suites, public key strengths, and certificate identities. An observed difference is forensically distinguished from a confirmed security violation.", styles['ReportBody']))
        story.append(PageBreak())

        # ─── SECTION 1: EXECUTIVE SUMMARY ───
        story.append(Paragraph("1. Executive Summary & Drift Assessment", styles['ReportSectionHeading']))
        status_color = '#ef4444' if 'DEGRADATION' in overall_status else ('#f59e0b' if 'DRIFT' in overall_status else '#10b981')

        summary_callout = [
            [
                Paragraph(f"<b>Overall Drift Conclusion:</b> <font color='{status_color}'><b>{overall_status}</b></font><br/>"
                          f"<b>Assessment Summary:</b> {summary_desc}<br/>"
                          f"<b>Metric Breakdown:</b> {metrics.get('unchanged_count', 0)} Unchanged  •  {metrics.get('changed_count', 0)} Changed  •  "
                          f"<font color='#ef4444'><b>{metrics.get('weakened_count', 0)} Weakened / Violations</b></font>  •  "
                          f"<font color='#10b981'><b>{metrics.get('strengthened_count', 0)} Strengthened</b></font>",
                          styles['CalloutBox'])
            ]
        ]
        callout_table = Table(summary_callout, colWidths=[504])
        callout_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 1.5, colors.HexColor(status_color)),
            ('PADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(callout_table)
        story.append(Spacer(1, 14))

        # ─── SECTION 2: DETAILED PROPERTY-BY-PROPERTY COMPARISON ───
        story.append(KeepTogether([
            Paragraph("2. Property-by-Property Cryptographic Drift Matrix", styles['ReportSectionHeading']),
            Paragraph(f"Direct comparison of observed wire parameters against the baseline requirements of <b>{baseline_name}</b>:", styles['ReportBody'])
        ]))

        diff_headers = [
            Paragraph("<b>Property</b>", styles['ReportTableCellBold']),
            Paragraph("<b>Baseline Expected</b>", styles['ReportTableCellBold']),
            Paragraph("<b>Observed Value</b>", styles['ReportTableCellBold']),
            Paragraph("<b>Diff Type</b>", styles['ReportTableCellBold']),
            Paragraph("<b>Security Significance</b>", styles['ReportTableCellBold']),
            Paragraph("<b>Explanation</b>", styles['ReportTableCellBold'])
        ]
        diff_rows = [diff_headers]
        for d in diffs:
            sig = d.get("security_significance", "UNRESOLVED")
            sig_color = '#ef4444' if sig in ('POTENTIALLY_WEAKENED', 'POLICY_VIOLATION') else ('#10b981' if sig in ('POTENTIALLY_STRENGTHENED', 'POLICY_COMPLIANT') else '#64748b')

            b_val = str(d.get("baseline_value", ""))
            c_val = str(d.get("current_value", ""))
            if len(b_val) > 40: b_val = b_val[:37] + "..."
            if len(c_val) > 40: c_val = c_val[:37] + "..."

            diff_rows.append([
                Paragraph(f"<b>{d.get('property', '')}</b>", styles['ReportTableCellBold']),
                Paragraph(b_val, styles['ReportTableCell']),
                Paragraph(c_val, styles['ReportTableCell']),
                Paragraph(d.get("diff_type", "UNCHANGED"), styles['ReportTableMono']),
                Paragraph(f"<font color='{sig_color}'><b>{sig}</b></font>", styles['ReportTableCellBold']),
                Paragraph(d.get("explanation", ""), styles['ReportTableCell'])
            ])

        diff_table = Table(diff_rows, colWidths=[90, 80, 80, 64, 90, 100])
        diff_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
            ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(diff_table)
        story.append(Spacer(1, 14))

        # ─── SECTION 3: RECOMMENDATIONS & POLICY ENFORCEMENT ───
        story.append(KeepTogether([
            Paragraph("3. Recommendations & Drift Remediation Guidance", styles['ReportSectionHeading']),
            Paragraph(
                "• <b>Protocol Regressions:</b> If deprecated versions (SSL 3.0 / TLS 1.0) were negotiated, immediately disable them in MTA configurations (e.g., Postfix <code>smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1</code>).<br/>"
                "• <b>Cipher Weakening:</b> Enforce AEAD ciphers (GCM, ChaCha20-Poly1305) to eliminate vulnerability to SWEET32, BEAST, or RC4 bias attacks.<br/>"
                "• <b>Certificate Replacements:</b> Verify new certificate fingerprints through out-of-band certificate logs or public CT logs to rule out MITM proxy injection.<br/>"
                "• <b>STARTTLS Enforcement:</b> Mandate strict MTA-STS or DANE TLSA policies to prevent active adversaries from executing cleartext downgrade attacks.",
                styles['ReportBody']
            )
        ]))

        doc.build(story, canvasmaker=NumberedCanvas)
        return buf.getvalue()

    @classmethod
    def generate_combined_report_pdf(
        cls,
        analysis_data: Dict[str, Any],
        forensics_data: Optional[Dict[str, Any]],
        comparison_data: Dict[str, Any]
    ) -> bytes:
        """
        Generates Report C: Combined Cryptographic Investigation Report (PDF)
        """
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54
        )
        styles = cls._create_styles()
        story = []

        report_id = f"CMB-{uuid.uuid4().hex[:8].upper()}"
        gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        filename = analysis_data.get("original_filename") or analysis_data.get("filename") or "evidence.pcap"

        # ─── COVER PAGE ───
        story.append(Spacer(1, 40))
        story.append(Paragraph("SECUREMAILSCOPE COMPREHENSIVE AUDIT", styles['CoverPreTitle']))
        story.append(Paragraph("Combined Cryptographic Investigation Report", styles['CoverTitle']))
        story.append(Paragraph(
            f"Integrated technical assessment combining <b>Historical Cryptographic Forensics (USP 1)</b> and <b>Cryptographic Drift Analysis (USP 6)</b> for network capture <b>{filename}</b>.",
            styles['CoverSubtitle']
        ))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#10b981'), spaceAfter=20))

        # Metadata Table
        meta_data = [
            [Paragraph("Report ID:", styles['ReportMetaLabel']), Paragraph(report_id, styles['ReportMetaValue']),
             Paragraph("Generated At:", styles['ReportMetaLabel']), Paragraph(gen_time, styles['ReportMetaValue'])],
            [Paragraph("Target Capture:", styles['ReportMetaLabel']), Paragraph(filename, styles['ReportMetaValue']),
             Paragraph("Capture ID:", styles['ReportMetaLabel']), Paragraph(analysis_data.get("capture_id", "N/A"), styles['ReportMetaValue'])],
            [Paragraph("Reference Baseline:", styles['ReportMetaLabel']), Paragraph(comparison_data.get("baseline_name", "Baseline"), styles['ReportMetaValue']),
             Paragraph("Drift Status:", styles['ReportMetaLabel']), Paragraph(comparison_data.get("overall_status", "Evaluated"), styles['ReportMetaValue'])],
        ]
        meta_table = Table(meta_data, colWidths=[110, 140, 110, 144])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#e2e8f0')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#f1f5f9')),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(meta_table)

        story.append(Spacer(1, 24))
        story.append(Paragraph("<b>EXECUTIVE AUDIT NOTICE:</b> This combined report unifies raw wire-level forensic evidence, reconstructed state progressions, X.509 PKI properties, and longitudinal baseline deviations into a single authoritative audit document.", styles['ReportBody']))
        story.append(PageBreak())

        # Include Forensic Findings
        story.append(Paragraph("Part I: Cryptographic Forensics & Security Findings", styles['ReportSectionHeading']))
        findings = analysis_data.get("findings", [])
        if findings:
            find_headers = [
                Paragraph("<b>ID</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Severity</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Title & Description</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Forensic Evidence</b>", styles['ReportTableCellBold'])
            ]
            find_rows = [find_headers]
            for f in findings:
                sev = (f.get("severity") or "LOW").upper()
                s_color = '#ef4444' if sev == 'CRITICAL' else ('#f97316' if sev == 'HIGH' else ('#f59e0b' if sev == 'MEDIUM' else '#10b981'))
                find_rows.append([
                    Paragraph(f.get("id", "--"), styles['ReportTableMono']),
                    Paragraph(f"<font color='{s_color}'><b>{sev}</b></font>", styles['ReportTableCellBold']),
                    Paragraph(f"<b>{f.get('title', '')}</b><br/>{f.get('description', '')}", styles['ReportTableCell']),
                    Paragraph(f.get("evidence", ""), styles['ReportTableMono'])
                ])
            ft = Table(find_rows, colWidths=[55, 65, 230, 154])
            ft.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
                ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(ft)

        story.append(Spacer(1, 16))

        # Include Baseline Drift Matrix
        story.append(Paragraph("Part II: Cryptographic Drift vs Baseline", styles['ReportSectionHeading']))
        diffs = comparison_data.get("property_diffs", [])
        if diffs:
            diff_headers = [
                Paragraph("<b>Property</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Baseline Expected</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Observed Value</b>", styles['ReportTableCellBold']),
                Paragraph("<b>Significance</b>", styles['ReportTableCellBold'])
            ]
            diff_rows = [diff_headers]
            for d in diffs:
                sig = d.get("security_significance", "UNRESOLVED")
                sig_color = '#ef4444' if sig in ('POTENTIALLY_WEAKENED', 'POLICY_VIOLATION') else ('#10b981' if sig in ('POTENTIALLY_STRENGTHENED', 'POLICY_COMPLIANT') else '#64748b')
                b_val = str(d.get("baseline_value", ""))[:35]
                c_val = str(d.get("current_value", ""))[:35]
                diff_rows.append([
                    Paragraph(d.get("property", ""), styles['ReportTableCellBold']),
                    Paragraph(b_val, styles['ReportTableCell']),
                    Paragraph(c_val, styles['ReportTableCell']),
                    Paragraph(f"<font color='{sig_color}'><b>{sig}</b></font>", styles['ReportTableCellBold'])
                ])
            dt = Table(diff_rows, colWidths=[120, 120, 120, 144])
            dt.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
                ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(dt)

        doc.build(story, canvasmaker=NumberedCanvas)
        return buf.getvalue()
