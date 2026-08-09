"""
multi_pdf_report.py
-------------------
Generates a single professional PDF report covering GCP, AWS, and Azure
IAM/RBAC scan results — all in one document.

Public API
  generate_multi_pdf(gcp_file, aws_file, azure_file, output_path, no_ai) -> None
"""

from __future__ import annotations
import os
from pathlib import Path
from datetime import datetime


# ---------------------------------------------------------------------------
# Data collection (same pattern as multi_dashboard.py)
# ---------------------------------------------------------------------------

def _collect_gcp(file_path: str) -> dict:
    try:
        from parser import GCPIAMParser
        from graph import IAMGraph
        from detection import DetectionEngine
        from risk_score import RiskScorer
        from blast_radius import BlastRadiusCalculator

        policy   = GCPIAMParser().parse_file(file_path)
        graph    = IAMGraph.from_policy(policy)
        findings = DetectionEngine().run(graph)
        risk     = RiskScorer().score(findings)
        blast    = BlastRadiusCalculator(graph, findings).calculate_all()

        return {
            "cloud": "GCP", "color": (0.26, 0.52, 0.96),
            "score": risk.score, "rating": risk.rating.value,
            "findings": findings, "blast": blast,
            "principals": len(graph.principal_ids()),
            "file": file_path, "error": None,
        }
    except Exception as exc:
        return _err("GCP", (0.26, 0.52, 0.96), file_path, str(exc))


def _collect_aws(file_path: str) -> dict:
    try:
        from aws_parser import AWSIAMParser
        from aws_graph import AWSIAMGraph
        from aws_detection import AWSDetectionEngine
        from risk_score import RiskScorer
        from detection import Finding as GF, Severity as GS

        policy   = AWSIAMParser().parse_file(file_path)
        graph    = AWSIAMGraph.from_policy(policy)
        findings = AWSDetectionEngine().run(graph)

        gcp_f = []
        for f in findings:
            gcp_f.append(GF(
                rule_id=f.rule_id, title=f.title,
                severity=GS(int(f.severity)),
                principal_id=f.principal_id,
                description=f.description,
                mitre_technique_id=f.mitre_technique_id,
                mitre_technique_name=f.mitre_technique_name,
                evidence=f.evidence,
            ))
        risk  = RiskScorer().score(gcp_f)
        stats = policy.summary()

        return {
            "cloud": "AWS", "color": (1.0, 0.6, 0.0),
            "score": risk.score, "rating": risk.rating.value,
            "findings": gcp_f, "blast": [],
            "principals": stats["total_principals"],
            "file": file_path, "error": None,
        }
    except Exception as exc:
        return _err("AWS", (1.0, 0.6, 0.0), file_path, str(exc))


def _collect_azure(file_path: str) -> dict:
    try:
        from azure_parser import parse_azure_file
        from azure_detection import run_azure_detections
        from azure_risk_score import score_azure
        from azure_blast_radius import calculate_azure_blast_radius
        from detection import Finding as GF, Severity as GS

        iam      = parse_azure_file(file_path)
        az_f     = run_azure_detections(iam)
        score    = score_azure(az_f, iam)
        blast    = calculate_azure_blast_radius(iam)

        sev_map  = {"CRITICAL": GS.CRITICAL, "HIGH": GS.HIGH,
                    "MEDIUM": GS.MEDIUM, "LOW": GS.LOW}
        gcp_f = []
        for f in az_f:
            gcp_f.append(GF(
                rule_id=f.rule_id, title=f.title,
                severity=sev_map.get(f.severity, GS.LOW),
                principal_id=f.principal_name,
                description=f.description,
                mitre_technique_id=f.mitre_technique,
                mitre_technique_name=f.mitre_tactic,
                evidence=(f.role,),
            ))

        unique = {a.principal_name for a in iam.assignments}
        return {
            "cloud": "Azure", "color": (0.0, 0.47, 0.83),
            "score": score.score, "rating": score.grade,
            "findings": gcp_f, "blast": blast,
            "principals": len(unique),
            "file": file_path, "error": None,
        }
    except Exception as exc:
        return _err("Azure", (0.0, 0.47, 0.83), file_path, str(exc))


def _err(cloud, color, file, error):
    return {"cloud": cloud, "color": color, "score": 0, "rating": "Error",
            "findings": [], "blast": [], "principals": 0,
            "file": file, "error": error}


# ---------------------------------------------------------------------------
# PDF builder
# ---------------------------------------------------------------------------

def _build_pdf(clouds: list[dict], output_path: str, no_ai: bool = True) -> None:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import cm
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, PageBreak,
        )
        from reportlab.graphics.shapes import Drawing, Rect, String
        from reportlab.graphics import renderPDF
        from reportlab.graphics.charts.barcharts import VerticalBarChart
    except ImportError:
        raise ImportError("reportlab not installed. Run: pip install reportlab")

    W, H   = A4
    margin = 2 * cm
    doc    = SimpleDocTemplate(
        str(output_path), pagesize=A4,
        leftMargin=margin, rightMargin=margin,
        topMargin=margin, bottomMargin=margin,
        title="CloudSentrix Multi-Cloud Security Report",
        author="CloudSentrix",
    )

    styles = getSampleStyleSheet()
    active = [c for c in clouds if not c["error"]]

    # Custom styles
    def style(name, **kw):
        return ParagraphStyle(name, **kw)

    S = {
        "cover_title": style("ct", fontSize=32, fontName="Helvetica-Bold",
                             textColor=colors.white, alignment=TA_CENTER, leading=40),
        "cover_sub":   style("cs", fontSize=14, fontName="Helvetica",
                             textColor=colors.HexColor("#90caf9"), alignment=TA_CENTER),
        "cover_meta":  style("cm", fontSize=10, fontName="Helvetica",
                             textColor=colors.HexColor("#bbdefb"), alignment=TA_CENTER),
        "h1":          style("h1", fontSize=18, fontName="Helvetica-Bold",
                             textColor=colors.HexColor("#1565c0"), spaceAfter=8),
        "h2":          style("h2", fontSize=13, fontName="Helvetica-Bold",
                             textColor=colors.HexColor("#1976d2"), spaceAfter=6),
        "body":        style("body", fontSize=9, fontName="Helvetica",
                             textColor=colors.HexColor("#333333"), leading=14),
        "small":       style("small", fontSize=8, fontName="Helvetica",
                             textColor=colors.HexColor("#666666")),
        "finding":     style("finding", fontSize=8.5, fontName="Helvetica",
                             textColor=colors.HexColor("#222222"), leading=13),
        "cloud_title": style("cloud_title", fontSize=16, fontName="Helvetica-Bold",
                             textColor=colors.white, alignment=TA_LEFT),
    }

    SEV_COLOR = {
        "CRITICAL": colors.HexColor("#e53935"),
        "HIGH":     colors.HexColor("#fb8c00"),
        "MEDIUM":   colors.HexColor("#fdd835"),
        "LOW":      colors.HexColor("#43a047"),
    }

    CLOUD_HEX = {
        "GCP":   colors.HexColor("#4285f4"),
        "AWS":   colors.HexColor("#ff9900"),
        "Azure": colors.HexColor("#0078d4"),
    }

    story = []

    # ── Cover Page ──────────────────────────────────────────────────────────
    # Dark background block (simulated with a table)
    cover_bg = colors.HexColor("#0d1b4b")
    cover_data = [[Paragraph("🔐 CloudSentrix", S["cover_title"])]]
    cover_table = Table(cover_data, colWidths=[W - 2 * margin])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), cover_bg),
        ("TOPPADDING",    (0, 0), (-1, -1), 60),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 20),
        ("LEFTPADDING",   (0, 0), (-1, -1), 20),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 20),
        ("ROUNDEDCORNERS", [10]),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 0.3 * cm))

    sub_data = [[Paragraph("Multi-Cloud Security Report", S["cover_sub"])]]
    sub_table = Table(sub_data, colWidths=[W - 2 * margin])
    sub_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), cover_bg),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(sub_table)
    story.append(Spacer(1, 0.3 * cm))

    meta_text = (
        f"GCP · AWS · Azure  |  "
        f"{len(active)} cloud(s) scanned  |  "
        f"{sum(len(c['findings']) for c in active)} total findings  |  "
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    )
    meta_data = [[Paragraph(meta_text, S["cover_meta"])]]
    meta_table = Table(meta_data, colWidths=[W - 2 * margin])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), cover_bg),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 30),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 1 * cm))

    # ── Executive Summary ───────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", S["h1"]))
    story.append(HRFlowable(width="100%", thickness=1.5,
                            color=colors.HexColor("#1565c0"), spaceAfter=10))

    # Score cards table
    score_rows = []
    header_row = [
        Paragraph("<b>Cloud</b>", S["body"]),
        Paragraph("<b>Score</b>", S["body"]),
        Paragraph("<b>Rating</b>", S["body"]),
        Paragraph("<b>Critical</b>", S["body"]),
        Paragraph("<b>High</b>", S["body"]),
        Paragraph("<b>Total Findings</b>", S["body"]),
        Paragraph("<b>Principals</b>", S["body"]),
    ]
    score_rows.append(header_row)

    for c in clouds:
        counts = {}
        for f in c["findings"]:
            sev = f.severity.name if hasattr(f.severity, "name") else str(f.severity)
            counts[sev] = counts.get(sev, 0) + 1

        score_color = (colors.HexColor("#e53935") if c["score"] < 40
                       else colors.HexColor("#fb8c00") if c["score"] < 70
                       else colors.HexColor("#43a047"))
        err = f"ERROR: {c['error'][:30]}" if c["error"] else ""
        score_rows.append([
            Paragraph(f"<b>{c['cloud']}</b>", S["body"]),
            Paragraph(f"<font color='{'red' if c['score'] < 40 else 'orange' if c['score'] < 70 else 'green'}'><b>{c['score']}/100</b></font>" if not err else "N/A", S["body"]),
            Paragraph(c["rating"], S["body"]),
            Paragraph(f"<font color='red'><b>{counts.get('CRITICAL', 0)}</b></font>", S["body"]),
            Paragraph(f"<font color='orange'><b>{counts.get('HIGH', 0)}</b></font>", S["body"]),
            Paragraph(str(len(c["findings"])), S["body"]),
            Paragraph(str(c["principals"]), S["body"]),
        ])

    score_table = Table(score_rows, colWidths=[
        2.5*cm, 2.2*cm, 2*cm, 2*cm, 2*cm, 2.8*cm, 2.5*cm
    ])
    score_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1565c0")),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f8ff")]),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("ROUNDEDCORNERS",[4]),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 0.8 * cm))

    # Total findings summary line
    total_critical = sum(
        sum(1 for f in c["findings"]
            if (f.severity.name if hasattr(f.severity,"name") else str(f.severity)) == "CRITICAL")
        for c in active
    )
    total_findings = sum(len(c["findings"]) for c in active)
    summary_para = Paragraph(
        f"<b>Total across all clouds:</b> {total_findings} finding(s) — "
        f"<font color='red'><b>{total_critical} CRITICAL</b></font> require immediate attention.",
        S["body"]
    )
    story.append(summary_para)
    story.append(Spacer(1, 1.2 * cm))

    # ── Per-Cloud Sections ──────────────────────────────────────────────────
    for c in clouds:
        story.append(PageBreak())

        # Cloud header banner
        cloud_color = CLOUD_HEX.get(c["cloud"], colors.HexColor("#333333"))
        banner_data = [[Paragraph(
            f"{c['cloud']} IAM Security Report",
            S["cloud_title"]
        )]]
        banner = Table(banner_data, colWidths=[W - 2 * margin])
        banner.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), cloud_color),
            ("TOPPADDING",    (0, 0), (-1, -1), 16),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
            ("LEFTPADDING",   (0, 0), (-1, -1), 20),
            ("ROUNDEDCORNERS", [8]),
        ]))
        story.append(banner)
        story.append(Spacer(1, 0.5 * cm))

        if c["error"]:
            story.append(Paragraph(f"Error: {c['error']}", S["body"]))
            continue

        # Score + meta
        counts = {}
        for f in c["findings"]:
            sev = f.severity.name if hasattr(f.severity, "name") else str(f.severity)
            counts[sev] = counts.get(sev, 0) + 1

        meta = (
            f"<b>File:</b> {c['file']}  |  "
            f"<b>Score:</b> {c['score']}/100 ({c['rating']})  |  "
            f"<b>Principals:</b> {c['principals']}  |  "
            f"<b>Findings:</b> {len(c['findings'])}"
        )
        story.append(Paragraph(meta, S["body"]))
        story.append(Spacer(1, 0.4 * cm))

        if not c["findings"]:
            story.append(Paragraph("✅ No findings detected.", S["body"]))
            story.append(Spacer(1, 0.5 * cm))
            continue

        # Findings table
        story.append(Paragraph(f"Findings ({len(c['findings'])} total)", S["h2"]))
        story.append(Spacer(1, 0.2 * cm))

        f_header = [
            Paragraph("<b>Rule</b>", S["small"]),
            Paragraph("<b>Title</b>", S["small"]),
            Paragraph("<b>Severity</b>", S["small"]),
            Paragraph("<b>Principal</b>", S["small"]),
            Paragraph("<b>MITRE</b>", S["small"]),
        ]
        f_rows = [f_header]

        row_styles = []
        for i, f in enumerate(c["findings"], start=1):
            sev  = f.severity.name if hasattr(f.severity, "name") else str(f.severity)
            sc   = SEV_COLOR.get(sev, colors.grey)
            pid  = (f.principal_id if hasattr(f, "principal_id")
                    else getattr(f, "principal_name", ""))
            mitre = (f.mitre_technique_id if hasattr(f, "mitre_technique_id")
                     else getattr(f, "mitre_technique", ""))
            f_rows.append([
                Paragraph(f.rule_id, S["small"]),
                Paragraph(f.title[:45], S["finding"]),
                Paragraph(f"<b>{sev}</b>", S["small"]),
                Paragraph(pid[:35], S["small"]),
                Paragraph(mitre, S["small"]),
            ])
            if sev == "CRITICAL":
                row_styles.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fff5f5")))
            elif sev == "HIGH":
                row_styles.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fff8f0")))

        f_table = Table(f_rows, colWidths=[1.8*cm, 5.5*cm, 2*cm, 4*cm, 2.7*cm])
        f_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1976d2")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#f9f9f9")]),
            ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#e0e0e0")),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            *row_styles,
        ]))
        story.append(f_table)
        story.append(Spacer(1, 0.8 * cm))

        # Blast radius (GCP/Azure)
        if c["blast"]:
            story.append(Paragraph("Blast Radius — Top 5 Principals", S["h2"]))
            story.append(Spacer(1, 0.2 * cm))

            b_header = [
                Paragraph("<b>Principal</b>", S["small"]),
                Paragraph("<b>Score</b>", S["small"]),
                Paragraph("<b>Level</b>", S["small"]),
            ]
            b_rows = [b_header]

            blast_list = c["blast"]
            # GCP blast results have different fields than Azure
            for b in blast_list[:5]:
                if hasattr(b, "blast_score"):
                    # Azure BlastResult
                    b_rows.append([
                        Paragraph(b.principal_name[:40], S["small"]),
                        Paragraph(str(b.blast_score), S["small"]),
                        Paragraph(b.blast_level, S["small"]),
                    ])
                else:
                    # GCP BlastRadiusResult fields:
                    # principal_id, reachable_principals, total_others, percentage
                    reach_count = len(b.reachable_principals)
                    b_rows.append([
                        Paragraph(b.principal_id[:40], S["small"]),
                        Paragraph(f"{b.percentage}%", S["small"]),
                        Paragraph(f"{reach_count}/{b.total_others}", S["small"]),
                    ])

            b_table = Table(b_rows, colWidths=[8*cm, 3*cm, 5*cm])
            b_table.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1976d2")),
                ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#f9f9f9")]),
                ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#e0e0e0")),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ]))
            story.append(b_table)
            story.append(Spacer(1, 0.5 * cm))

    # ── Footer page ─────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Spacer(1, 2 * cm))
    story.append(Paragraph("Report Summary", S["h1"]))
    story.append(HRFlowable(width="100%", thickness=1.5,
                            color=colors.HexColor("#1565c0"), spaceAfter=12))

    story.append(Paragraph(
        f"This report was generated by <b>CloudSentrix</b> on "
        f"{datetime.now().strftime('%Y-%m-%d at %H:%M')}.",
        S["body"]
    ))
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph(
        f"<b>Clouds scanned:</b> {', '.join(c['cloud'] for c in active)}  |  "
        f"<b>Total findings:</b> {total_findings}  |  "
        f"<b>Critical:</b> {total_critical}",
        S["body"]
    ))
    story.append(Spacer(1, 0.6 * cm))
    story.append(Paragraph(
        "All findings are mapped to the <b>MITRE ATT&CK Cloud Matrix</b>. "
        "Remediate CRITICAL findings immediately. HIGH findings should be "
        "addressed within 72 hours.",
        S["body"]
    ))
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph(
        "Generated by <b>CloudSentrix</b> — "
        "github.com/Talha-Imran-cloud/cloudsentrix",
        S["small"]
    ))

    doc.build(story)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_multi_pdf(
    gcp_file:   str | None,
    aws_file:   str | None,
    azure_file: str | None,
    output_path: str,
    no_ai: bool = True,
) -> tuple[int, int]:
    """
    Generate a multi-cloud PDF report.

    Returns (clouds_scanned, total_findings).
    """
    clouds: list[dict] = []

    if gcp_file:
        print(f"  [multi-pdf] Scanning GCP   : {gcp_file}")
        clouds.append(_collect_gcp(gcp_file))
    if aws_file:
        print(f"  [multi-pdf] Scanning AWS   : {aws_file}")
        clouds.append(_collect_aws(aws_file))
    if azure_file:
        print(f"  [multi-pdf] Scanning Azure : {azure_file}")
        clouds.append(_collect_azure(azure_file))

    if not clouds:
        raise ValueError("At least one cloud file must be provided.")

    print(f"  [multi-pdf] Building PDF   : {output_path}")
    _build_pdf(clouds, output_path, no_ai)

    active = [c for c in clouds if not c["error"]]
    return len(active), sum(len(c["findings"]) for c in active)


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    s, f = generate_multi_pdf(
        gcp_file   = "sample_data/sample_gcp_iam.json",
        aws_file   = "sample_data/sample_aws_iam.json",
        azure_file = "sample_data/sample_azure_rbac.json",
        output_path= "multi_cloud_report.pdf",
    )
    print(f"\nPDF generated: {s} cloud(s), {f} finding(s)")
    print("Open: multi_cloud_report.pdf")
