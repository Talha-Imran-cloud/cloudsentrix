"""
PDF Report Generator
========================
Builds a client-ready PDF report from a scan's results: executive summary
(score + optional AI-generated plain-language paragraph), a findings
table, and a blast-radius table.

Uses reportlab (pure Python, free/BSD-licensed, no system dependencies)
so this works the same way on Windows, macOS, and Linux with just
`pip install reportlab`.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

logger = logging.getLogger(__name__)

_SEVERITY_COLOR = {
    "CRITICAL": colors.HexColor("#dc2626"),
    "HIGH": colors.HexColor("#ea580c"),
    "MEDIUM": colors.HexColor("#ca8a04"),
    "LOW": colors.HexColor("#6b7280"),
}

_RATING_COLOR = {
    "Excellent": colors.HexColor("#16a34a"),
    "Good": colors.HexColor("#22c55e"),
    "Fair": colors.HexColor("#ca8a04"),
    "Poor": colors.HexColor("#ea580c"),
    "Critical": colors.HexColor("#dc2626"),
}

_HEADER_BG = colors.HexColor("#1e293b")
_ROW_ALT_BG = colors.HexColor("#f1f5f9")


def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("ReportTitle", parent=base["Title"], fontSize=20, spaceAfter=4),
        "subtitle": ParagraphStyle("ReportSubtitle", parent=base["Normal"], textColor=colors.grey, fontSize=10),
        "h2": ParagraphStyle("ReportH2", parent=base["Heading2"], spaceBefore=18, spaceAfter=8),
        "body": ParagraphStyle("ReportBody", parent=base["Normal"], fontSize=10, leading=14),
        "cell": ParagraphStyle("ReportCell", parent=base["Normal"], fontSize=8, leading=10),
        "cell_header": ParagraphStyle(
            "ReportCellHeader", parent=base["Normal"], fontSize=8, leading=10,
            textColor=colors.white, fontName="Helvetica-Bold",
        ),
    }


def _findings_table(findings: list[dict], styles: dict[str, ParagraphStyle]) -> Table:
    header = ["Severity", "Finding", "Principal", "MITRE", "Details"]
    rows = [[Paragraph(h, styles["cell_header"]) for h in header]]

    for f in findings:
        severity_cell = Paragraph(
            f'<font color="{_SEVERITY_COLOR.get(f["severity"], colors.black).hexval()}"><b>{f["severity"]}</b></font>',
            styles["cell"],
        )
        rows.append([
            severity_cell,
            Paragraph(f"{f['title']} ({f['rule_id']})", styles["cell"]),
            Paragraph(f["principal_id"], styles["cell"]),
            Paragraph(f["mitre_technique_id"], styles["cell"]),
            Paragraph(f["description"], styles["cell"]),
        ])

    table = Table(rows, colWidths=[0.7 * inch, 1.6 * inch, 1.6 * inch, 0.8 * inch, 2.3 * inch], repeatRows=1)
    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for i in range(1, len(rows)):
        if i % 2 == 0:
            style_commands.append(("BACKGROUND", (0, i), (-1, i), _ROW_ALT_BG))
    table.setStyle(TableStyle(style_commands))
    return table


def _blast_radius_table(blast_radius: list[dict], styles: dict[str, ParagraphStyle], top_n: int = 10) -> Table:
    header = ["Principal", "Blast Radius", "Can Reach"]
    rows = [[Paragraph(h, styles["cell_header"]) for h in header]]

    for r in blast_radius[:top_n]:
        reaches = ", ".join(r["reachable_principals"]) if r["reachable_principals"] else "(nothing further)"
        rows.append([
            Paragraph(r["principal_id"], styles["cell"]),
            Paragraph(f"{r['percentage']:.1f}%", styles["cell"]),
            Paragraph(reaches, styles["cell"]),
        ])

    table = Table(rows, colWidths=[2.2 * inch, 1.1 * inch, 3.7 * inch], repeatRows=1)
    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for i in range(1, len(rows)):
        if i % 2 == 0:
            style_commands.append(("BACKGROUND", (0, i), (-1, i), _ROW_ALT_BG))
    table.setStyle(TableStyle(style_commands))
    return table


def generate_pdf_report(
    source_file: str,
    risk_score: int,
    rating: str,
    finding_counts: dict[str, int],
    findings: list[dict],
    blast_radius: list[dict],
    output_path: Path,
    ai_summary: str | None = None,
) -> None:
    """Renders a full PDF report to output_path.

    All inputs are plain dicts/primitives (not the dataclasses from
    detection.py/risk_score.py/blast_radius.py) so this module has zero
    import dependency on the rest of the engine — it only knows how to
    lay out data it's handed, via cli.py's *_to_dict() helpers.
    """
    styles = _build_styles()
    doc = SimpleDocTemplate(
        str(output_path), pagesize=LETTER,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
    )

    story = []
    story.append(Paragraph("CloudSentrix Security Report", styles["title"]))
    story.append(Paragraph(
        f"Source: {source_file} &nbsp;|&nbsp; Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        styles["subtitle"],
    ))
    story.append(Spacer(1, 16))

    # Executive summary
    story.append(Paragraph("Executive Summary", styles["h2"]))
    rating_color = _RATING_COLOR.get(rating, colors.black).hexval()
    story.append(Paragraph(
        f'Overall Security Score: <font color="{rating_color}"><b>{risk_score}/100 ({rating})</b></font>',
        styles["body"],
    ))
    story.append(Paragraph(
        f"Findings: {finding_counts.get('CRITICAL', 0)} Critical, {finding_counts.get('HIGH', 0)} High, "
        f"{finding_counts.get('MEDIUM', 0)} Medium, {finding_counts.get('LOW', 0)} Low",
        styles["body"],
    ))
    story.append(Spacer(1, 8))

    if ai_summary:
        story.append(Paragraph(ai_summary, styles["body"]))

    # Findings
    story.append(Paragraph(f"Findings ({len(findings)})", styles["h2"]))
    if findings:
        story.append(_findings_table(findings, styles))
    else:
        story.append(Paragraph("No findings.", styles["body"]))

    # Blast radius
    story.append(Paragraph("Blast Radius (top 10)", styles["h2"]))
    if blast_radius:
        story.append(_blast_radius_table(blast_radius, styles))
    else:
        story.append(Paragraph("No data.", styles["body"]))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc.build(story)
    logger.info("Wrote PDF report to %s", output_path)
