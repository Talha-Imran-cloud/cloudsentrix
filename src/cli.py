"""
CloudSentrix CLI
===================
The command-line entry point that wires every engine module (parser,
graph, detection, risk scoring, blast radius) into a set of commands
with colored terminal output and CI-friendly exit codes.

Commands:
    scan            Full pipeline scan: findings + risk score + blast radius
    blast-radius    Blast radius for one specific principal
    rules           List every detection rule the engine checks for
    list-principals Quick inventory: every principal and the roles it holds
    validate        Check a file is a well-formed GCP IAM policy export
    score           Print only the overall security score (CI/badge use)
    compare         Compare two IAM exports and show what risk changed
    principal-path  Show the escalation path (if any) from one principal to another
    mitre-map       Map every finding onto the MITRE ATT&CK Cloud Matrix
    remediate       Generate gcloud CLI commands that fix each finding
    export          Export a scan's results to JSON, CSV, or HTML
    watch           Monitor a file/folder and auto re-scan on every change

Exit codes:
    0 = command completed, no CRITICAL findings (or command has no findings concept)
    1 = scan completed, at least one CRITICAL finding (fail a CI pipeline on this)
    2 = the command could not be completed (bad file, bad JSON, unexpected error)

    Per-command nuances on "1":
        compare         -> 1 if the NEW file introduces a new CRITICAL finding
        score           -> 1 if --min-score is given and the score falls below it
        principal-path  -> 1 if an escalation path was found (0 if none, 2 if
                            either principal doesn't exist in the graph)
        watch           -> runs until Ctrl+C; exits 0 on a clean stop, 2 if the
                            watched path doesn't exist
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from rich.console import Console

from parser import GCPIAMParser, IAMParserError, MemberType, ParsedIAMPolicy
from graph import GraphBuildError, IAMGraph
from detection import DetectionEngine, Finding, Severity
from risk_score import RiskRating, RiskScore, RiskScorer
from blast_radius import BlastRadiusCalculator, BlastRadiusResult
from watch_handler import watch as watch_files
from live_scanner import fetch_live_iam_policy, save_policy_to_file, LiveScanError
from pdf_report import generate_pdf_report
from ai_summary import generate_ai_summary, build_fallback_summary, AISummaryError

logger = logging.getLogger(__name__)

__version__ = "1.0.0"

SEVERITY_CHOICES: dict[str, Severity] = {
    "all": Severity.LOW,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold yellow",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim white",
}

RATING_COLOR: dict[RiskRating, str] = {
    RiskRating.EXCELLENT: "bold green",
    RiskRating.GOOD: "green",
    RiskRating.FAIR: "yellow",
    RiskRating.POOR: "bold yellow",
    RiskRating.CRITICAL: "bold red",
}

CLOUD_LOGO = (
    "       .--.    \n"
    "    .-(    ).  \n"
    "   (___.__)__) "
)

# Placeholder used in generated `remediate` commands when the user doesn't
# pass --project. Left deliberately obvious so nobody accidentally runs it.
DEFAULT_PROJECT_PLACEHOLDER = "YOUR_PROJECT_ID"


# ---------------------------------------------------------------------------
# Output layer — a thin wrapper around rich.Console
# ---------------------------------------------------------------------------

_MARKUP_RE = re.compile(r"\[(/?[a-z#/@][^\[\]]*)\]")


class OutputWriter:
    """Wraps rich.Console so the rest of the CLI never talks to rich
    directly. Also implements --no-color ourselves (stripping markup
    tags) so behavior doesn't depend on a specific Console constructor flag.
    """

    def __init__(self, console: Console, use_color: bool = True) -> None:
        self._console = console
        self._use_color = use_color

    def print(self, text: str = "") -> None:
        self._console.print(text if self._use_color else _MARKUP_RE.sub("", text))


# ---------------------------------------------------------------------------
# Core logic — no printing here, so it's directly unit-testable
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    source_file: str
    cloud: str
    policy: ParsedIAMPolicy
    graph: IAMGraph
    findings: list[Finding]
    risk: RiskScore
    blast_radius: list[BlastRadiusResult]
    escalation_edges: list[tuple[str, str, str]]


def run_scan(file_path: str, cloud: str = "gcp") -> ScanResult:
    """Runs the full pipeline: parse -> graph -> detect -> score -> blast radius.

    Raises:
        ValueError: If `cloud` isn't a supported provider.
        IAMParserError (and subclasses): If the file can't be parsed.
        GraphBuildError: If the graph can't be built from the parsed policy.
    """
    if cloud != "gcp":
        raise ValueError(f"Unsupported cloud provider: {cloud!r}. Only 'gcp' is supported today.")

    policy = GCPIAMParser().parse_file(file_path)
    graph = IAMGraph.from_policy(policy)
    findings = DetectionEngine().run(graph)
    risk = RiskScorer().score(findings)
    _calc = BlastRadiusCalculator(graph, findings)
    blast_radius = _calc.calculate_all()
    escalation_edges = _calc.escalation_edges()

    return ScanResult(
        source_file=file_path,
        cloud=cloud,
        policy=policy,
        graph=graph,
        findings=findings,
        risk=risk,
        blast_radius=blast_radius,
        escalation_edges=escalation_edges,
    )


def run_list_principals(file_path: str, cloud: str = "gcp") -> IAMGraph:
    """Parses a file and builds its graph only — no detection, for a
    lightweight inventory view."""
    if cloud != "gcp":
        raise ValueError(f"Unsupported cloud provider: {cloud!r}. Only 'gcp' is supported today.")
    policy = GCPIAMParser().parse_file(file_path)
    return IAMGraph.from_policy(policy)


def filter_by_severity(findings: list[Finding], minimum: Severity) -> list[Finding]:
    """Findings at or above `minimum` severity. DetectionEngine.run()
    already returns findings sorted most-severe-first; filtering preserves
    that order."""
    return [f for f in findings if f.severity >= minimum]


def determine_exit_code(findings: list[Finding]) -> int:
    """1 if any CRITICAL finding exists (regardless of display filtering),
    else 0. Evaluated against ALL findings, not just what was displayed,
    so a --severity filter can never silently hide a failing exit code."""
    return 1 if any(f.severity == Severity.CRITICAL for f in findings) else 0


def find_blast_radius_for(results: list[BlastRadiusResult], principal_id: str) -> BlastRadiusResult | None:
    """Looks up one principal's precomputed blast radius result, or None
    if that principal isn't in the graph."""
    return next((r for r in results if r.principal_id == principal_id), None)


# -- validate -----------------------------------------------------------------

def run_validate(file_path: str) -> tuple[ParsedIAMPolicy, list[str]]:
    """Validates a GCP IAM policy file's structure ONLY — no graph, no
    detection. Returns the parsed policy plus a list of non-fatal warning
    messages (e.g. unrecognized member type prefixes, empty bindings).

    Raises the same exceptions GCPIAMParser raises on genuinely malformed
    input (missing 'bindings' key, invalid JSON, etc.) — those are fatal,
    not warnings.
    """
    policy = GCPIAMParser().parse_file(file_path)
    warnings: list[str] = []

    if not policy.bindings:
        warnings.append("Policy contains zero bindings — nothing to analyze.")

    for i, binding in enumerate(policy.bindings):
        if not binding.members:
            warnings.append(f"bindings[{i}] ('{binding.role}') has no members.")
        for member in binding.members:
            if member.type == MemberType.UNKNOWN:
                warnings.append(
                    f"bindings[{i}] ('{binding.role}'): unrecognized member type in '{member.raw}'."
                )

    return policy, warnings


# -- mitre-map ------------------------------------------------------------------

def group_findings_by_mitre(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Groups findings by MITRE technique id, e.g. 'T1098.001' -> [Finding, ...]."""
    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.mitre_technique_id, []).append(f)
    return grouped


# -- compare --------------------------------------------------------------------

@dataclass(frozen=True)
class ComparisonResult:
    old_file: str
    new_file: str
    new_findings: list[Finding]
    resolved_findings: list[Finding]
    persistent_findings: list[Finding]
    old_score: RiskScore
    new_score: RiskScore


def _finding_key(f: Finding) -> tuple[str, str]:
    """Identifies 'the same risk' across two scans: same rule, same
    principal. (Wording of `description`/`evidence` can shift slightly
    between scans without this being a genuinely new or resolved risk.)"""
    return (f.rule_id, f.principal_id)


def run_compare(old_file: str, new_file: str, cloud: str = "gcp") -> ComparisonResult:
    """Scans two IAM policy exports and classifies every finding as new,
    resolved, or persistent between them."""
    old_result = run_scan(old_file, cloud=cloud)
    new_result = run_scan(new_file, cloud=cloud)

    old_by_key = {_finding_key(f): f for f in old_result.findings}
    new_by_key = {_finding_key(f): f for f in new_result.findings}

    new_findings = [f for k, f in new_by_key.items() if k not in old_by_key]
    resolved_findings = [f for k, f in old_by_key.items() if k not in new_by_key]
    persistent_findings = [f for k, f in new_by_key.items() if k in old_by_key]

    # dict iteration order isn't severity order — sort explicitly, same
    # convention as DetectionEngine.run() (most-severe-first).
    new_findings.sort(key=lambda f: f.severity, reverse=True)
    resolved_findings.sort(key=lambda f: f.severity, reverse=True)
    persistent_findings.sort(key=lambda f: f.severity, reverse=True)

    return ComparisonResult(
        old_file=old_file,
        new_file=new_file,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        persistent_findings=persistent_findings,
        old_score=old_result.risk,
        new_score=new_result.risk,
    )


# -- principal-path -------------------------------------------------------------

def run_principal_path(
    file_path: str, source: str, target: str, cloud: str = "gcp"
) -> tuple[ScanResult, list[str] | None]:
    """Runs the full scan, then asks the blast-radius escalation graph for
    the shortest privilege-escalation path from source to target."""
    result = run_scan(file_path, cloud=cloud)
    calculator = BlastRadiusCalculator(result.graph, result.findings)
    path = calculator.find_path(source, target)
    return result, path


# -- remediate --------------------------------------------------------------------

_MEMBER_TYPE_PREFIX: dict[MemberType, str] = {
    MemberType.USER: "user:",
    MemberType.SERVICE_ACCOUNT: "serviceAccount:",
    MemberType.GROUP: "group:",
    MemberType.DOMAIN: "domain:",
    MemberType.ALL_USERS: "",
    MemberType.ALL_AUTHENTICATED_USERS: "",
}


def _gcloud_member(principal_id: str, graph: IAMGraph) -> str:
    """Builds the '--member' value gcloud expects (e.g. 'user:a@b.com'),
    from a bare principal id, using the graph to look up its member type."""
    principal = graph.get_principal(principal_id)
    if principal is None:
        return principal_id
    prefix = _MEMBER_TYPE_PREFIX.get(principal.member_type, "")
    return f"{prefix}{principal_id}"


def _remediate_gcp_001(finding: Finding, graph: IAMGraph, project: str) -> list[str]:
    member = _gcloud_member(finding.principal_id, graph)
    return [
        f'gcloud projects remove-iam-policy-binding {project} --member="{member}" --role="{role}"'
        for role in finding.evidence
    ]


def _remediate_gcp_002(finding: Finding, graph: IAMGraph, project: str) -> list[str]:
    member = _gcloud_member(finding.principal_id, graph)
    role = finding.evidence[0] if finding.evidence else "roles/iam.serviceAccountTokenCreator"
    return [
        f'gcloud projects remove-iam-policy-binding {project} --member="{member}" --role="{role}"',
        "# If this access is genuinely needed, re-grant it scoped to ONE service account instead:",
        f'# gcloud iam service-accounts add-iam-policy-binding TARGET_SA@{project}.iam.gserviceaccount.com \\',
        f'#     --member="{member}" --role="roles/iam.serviceAccountTokenCreator"',
    ]


def _remediate_gcp_003(finding: Finding, graph: IAMGraph, project: str) -> list[str]:
    member = _gcloud_member(finding.principal_id, graph)
    role = finding.evidence[0] if finding.evidence else "roles/iam.serviceAccountKeyAdmin"
    return [
        f'gcloud projects remove-iam-policy-binding {project} --member="{member}" --role="{role}"',
        "# Also audit and rotate/delete any long-lived keys this principal may already have created:",
        "# gcloud iam service-accounts keys list --iam-account=TARGET_SA@PROJECT_ID.iam.gserviceaccount.com",
    ]


def _remediate_gcp_004(finding: Finding, graph: IAMGraph, project: str) -> list[str]:
    member = _gcloud_member(finding.principal_id, graph)
    role = finding.evidence[0] if finding.evidence else "roles/owner"
    return [
        f"# '{finding.principal_id}' can modify IAM policy directly — confirm it truly needs '{role}'.",
        f'gcloud projects remove-iam-policy-binding {project} --member="{member}" --role="{role}"',
        "# Consider a narrower role instead of Owner, e.g.:",
        f'# gcloud projects add-iam-policy-binding {project} --member="{member}" \\',
        '#     --role="roles/resourcemanager.projectIamAdmin"',
    ]


def _remediate_gcp_005(finding: Finding, graph: IAMGraph, project: str) -> list[str]:
    member = _gcloud_member(finding.principal_id, graph)
    return [
        f'gcloud projects remove-iam-policy-binding {project} --member="{member}" --role="roles/iam.serviceAccountUser"',
        "# If resource-attach access is required, scope it to ONE specific service account instead:",
        f'# gcloud iam service-accounts add-iam-policy-binding TARGET_SA@{project}.iam.gserviceaccount.com \\',
        f'#     --member="{member}" --role="roles/iam.serviceAccountUser"',
    ]


REMEDIATION_GENERATORS: dict[str, Callable[[Finding, IAMGraph, str], list[str]]] = {
    "GCP-001": _remediate_gcp_001,
    "GCP-002": _remediate_gcp_002,
    "GCP-003": _remediate_gcp_003,
    "GCP-004": _remediate_gcp_004,
    "GCP-005": _remediate_gcp_005,
}


def generate_remediation(finding: Finding, graph: IAMGraph, project: str) -> list[str]:
    """Returns one or more gcloud CLI command lines (some may be '#'
    comments with guidance) that address the given finding. Falls back to
    a generic manual-review note for any rule_id without a specific
    generator, so a new detection rule never crashes this command."""
    generator = REMEDIATION_GENERATORS.get(finding.rule_id)
    if generator is None:
        return [f"# No automated fix available for {finding.rule_id} — review '{finding.principal_id}' manually."]
    return generator(finding, graph, project)


# -- export -----------------------------------------------------------------------

def finding_to_dict(f: Finding) -> dict:
    return {
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity.name,
        "principal_id": f.principal_id,
        "description": f.description,
        "mitre_technique_id": f.mitre_technique_id,
        "mitre_technique_name": f.mitre_technique_name,
        "evidence": list(f.evidence),
    }


def blast_radius_to_dict(r: BlastRadiusResult) -> dict:
    return {
        "principal_id": r.principal_id,
        "percentage": r.percentage,
        "total_others": r.total_others,
        "reachable_principals": list(r.reachable_principals),
    }


def scan_result_to_dict(result: ScanResult) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": result.source_file,
        "cloud": result.cloud,
        "risk_score": {
            "score": result.risk.score,
            "rating": result.risk.rating.value,
            "finding_counts": result.risk.finding_counts,
            "penalty_breakdown": result.risk.penalty_breakdown,
        },
        "findings": [finding_to_dict(f) for f in result.findings],
        "blast_radius": [blast_radius_to_dict(r) for r in result.blast_radius],
    }


def export_json(result: ScanResult, output_path: Path) -> None:
    output_path.write_text(json.dumps(scan_result_to_dict(result), indent=2), encoding="utf-8")


def export_csv(result: ScanResult, output_path: Path) -> None:
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "rule_id", "title", "severity", "principal_id",
            "description", "mitre_technique_id", "mitre_technique_name", "evidence",
        ])
        for f in result.findings:
            writer.writerow([
                f.rule_id, f.title, f.severity.name, f.principal_id,
                f.description, f.mitre_technique_id, f.mitre_technique_name,
                "; ".join(f.evidence),
            ])


_HTML_SEVERITY_COLOR: dict[str, str] = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#6b7280",
}


def _html_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def export_html(result: ScanResult, output_path: Path) -> None:
    rows = []
    for f in result.findings:
        color = _HTML_SEVERITY_COLOR.get(f.severity.name, "#6b7280")
        rows.append(
            "<tr>"
            f"<td><span class='badge' style='background:{color}'>{f.severity.name}</span></td>"
            f"<td>{_html_escape(f.title)} ({_html_escape(f.rule_id)})</td>"
            f"<td>{_html_escape(f.principal_id)}</td>"
            f"<td>{_html_escape(f.mitre_technique_id)} — {_html_escape(f.mitre_technique_name)}</td>"
            f"<td>{_html_escape(f.description)}</td>"
            "</tr>"
        )

    blast_rows = []
    for r in result.blast_radius[:10]:
        reaches = ", ".join(r.reachable_principals) if r.reachable_principals else "(nothing further)"
        blast_rows.append(
            f"<tr><td>{_html_escape(r.principal_id)}</td><td>{r.percentage:.1f}%</td>"
            f"<td>{_html_escape(reaches)}</td></tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CloudSentrix Report — {_html_escape(result.source_file)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:2rem; }}
  h1 {{ font-size:1.4rem; }}
  h2 {{ font-size:1.1rem; margin-top:2rem; }}
  .score {{ font-size:2rem; font-weight:bold; }}
  table {{ width:100%; border-collapse:collapse; margin-top:1rem; }}
  th, td {{ text-align:left; padding:.5rem .75rem; border-bottom:1px solid #334155; font-size:.9rem; vertical-align:top; }}
  th {{ color:#94a3b8; text-transform:uppercase; font-size:.75rem; }}
  .badge {{ color:white; padding:.15rem .5rem; border-radius:.25rem; font-size:.75rem; font-weight:600; white-space:nowrap; }}
  .meta {{ color:#94a3b8; font-size:.85rem; }}
</style>
</head>
<body>
  <h1>CloudSentrix — GCP IAM Privilege-Escalation Report</h1>
  <p class="meta">Source: {_html_escape(result.source_file)} &nbsp;|&nbsp; Generated: {datetime.now(timezone.utc).isoformat()}</p>
  <p class="score">{result.risk.score}/100 — {_html_escape(result.risk.rating.value)}</p>
  <h2>Findings ({len(result.findings)})</h2>
  <table>
    <tr><th>Severity</th><th>Finding</th><th>Principal</th><th>MITRE</th><th>Details</th></tr>
    {''.join(rows) if rows else '<tr><td colspan="5">No findings.</td></tr>'}
  </table>
  <h2>Blast Radius (top 10)</h2>
  <table>
    <tr><th>Principal</th><th>%</th><th>Can Reach</th></tr>
    {''.join(blast_rows) if blast_rows else '<tr><td colspan="3">No data.</td></tr>'}
  </table>
</body>
</html>
"""
    output_path.write_text(html, encoding="utf-8")


def export_sarif(result: ScanResult, output_path: Path) -> None:
    """Exports findings as SARIF 2.1.0 — compatible with GitHub Code Scanning,
    VS Code SARIF Viewer, and any SARIF-aware security tool."""
    rules = []
    results = []
    seen_rules = {}

    for f in result.findings:
        if f.rule_id not in seen_rules:
            seen_rules[f.rule_id] = True
            rules.append({
                "id": f.rule_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "helpUri": f"https://attack.mitre.org/techniques/{f.mitre_technique_id.replace('.', '/')}/",
                "properties": {
                    "tags": ["security", "gcp", "iam", f.mitre_technique_id],
                    "precision": "high",
                    "problem.severity": f.severity.name.lower(),
                },
            })
        level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(f.severity.name, "note")
        results.append({
            "ruleId": f.rule_id,
            "level": level,
            "message": {"text": f.description},
            "locations": [{"logicalLocations": [{"name": f.principal_id, "kind": "gcp/iam/principal"}]}],
            "properties": {
                "severity": f.severity.name,
                "mitre": f"{f.mitre_technique_id} — {f.mitre_technique_name}",
                "evidence": list(f.evidence),
            },
        })

    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CloudSentrix",
                    "version": __version__,
                    "informationUri": "https://github.com/Talha-Imran-cloud/cloudsentrix",
                    "rules": rules,
                }
            },
            "results": results,
            "properties": {
                "securityScore": result.risk.score,
                "securityRating": result.risk.rating.value,
                "sourceFile": result.source_file,
            },
        }],
    }
    output_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")


_EXPORT_EXTENSION_FORMAT: dict[str, str] = {".json": "json", ".csv": "csv", ".html": "html", ".htm": "html", ".sarif": "sarif"}
_EXPORTERS: dict[str, Callable[[ScanResult, Path], None]] = {
    "json": export_json,
    "csv": export_csv,
    "html": export_html,
    "sarif": export_sarif,
}


def _member_prefix(principal_id: str) -> str:
    """Returns the GCP member type prefix for a principal id string.
    Service accounts contain '.iam.gserviceaccount.com', everything else is user."""
    if principal_id.endswith(".iam.gserviceaccount.com"):
        return "serviceAccount"
    return "user"


def build_remediation_command(finding: Finding) -> str:
    """Returns a single gcloud CLI string for a finding (used in JSON export).
    For multi-line remediation, use generate_remediation() instead."""
    from graph import IAMGraph  # local import — avoid circular at module level
    lines = REMEDIATION_GENERATORS.get(finding.rule_id, lambda f, g, p: [
        f"# No automated fix for {finding.rule_id} — review '{finding.principal_id}' manually."
    ])(finding, _EmptyGraph(), DEFAULT_PROJECT_PLACEHOLDER)
    return " && ".join(l for l in lines if not l.startswith("#")) or lines[0]


class _EmptyGraph:
    """Minimal stub so build_remediation_command works without a real graph."""
    def get_principal(self, _): return None


def build_json_export(result: "ScanResult") -> dict:
    """Returns a JSON-serializable dict of the full scan result, suitable
    for saving to a .json file or embedding in tests."""
    findings_with_remediation = []
    for f in result.findings:
        d = finding_to_dict(f)
        d["remediation"] = build_remediation_command(f)
        findings_with_remediation.append(d)

    return {
        "cloudsentrix_version": __version__,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "source_file": result.source_file,
        "cloud": result.cloud,
        "summary": {
            "score": result.risk.score,
            "rating": result.risk.rating.value,
            "finding_counts": result.risk.finding_counts,
            "penalty_breakdown": result.risk.penalty_breakdown,
        },
        "findings": findings_with_remediation,
        "blast_radius": [blast_radius_to_dict(r) for r in result.blast_radius],
    }


def build_html_export(result: "ScanResult") -> str:
    import json as _json

    nodes = []
    edges = []

    for pid in result.graph.principal_ids():
        p = result.graph.get_principal(pid)
        mtype = p.member_type.value if p else "unknown"
        is_critical = any(f.principal_id == pid and f.severity.name == "CRITICAL" for f in result.findings)
        is_high = any(f.principal_id == pid and f.severity.name == "HIGH" for f in result.findings)
        color = "#dc2626" if is_critical else "#ea580c" if is_high else "#3b82f6"
        nodes.append({"id": pid, "label": pid.split("@")[0], "title": pid, "color": color, "shape": "ellipse"})

    for rid in result.graph.role_ids():
        nodes.append({"id": rid, "label": rid.replace("roles/", ""), "title": rid, "color": "#475569", "shape": "box"})

    for pid in result.graph.principal_ids():
        for role in result.graph.roles_of(pid):
            edges.append({"from": pid, "to": role, "color": "#475569", "dashes": False, "label": ""})

    for src, tgt, rule_id in result.escalation_edges:
        edges.append({"from": src, "to": tgt, "color": "#dc2626", "dashes": True, "label": rule_id})

    sev_counts = result.risk.finding_counts
    findings_rows = ""
    for f in result.findings:
        c = {"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#ca8a04","LOW":"#6b7280"}.get(f.severity.name,"#6b7280")
        findings_rows += f"<tr><td><span class='badge' style='background:{c}'>{f.severity.name}</span></td><td>{_html_escape(f.title)}<br><small>{f.rule_id}</small></td><td>{_html_escape(f.principal_id)}</td><td>{f.mitre_technique_id}</td><td>{_html_escape(f.description)}</td></tr>"

    blast_rows = ""
    for r in result.blast_radius[:10]:
        reaches = ", ".join(r.reachable_principals) if r.reachable_principals else "(nothing further)"
        pct_color = "#dc2626" if r.percentage>=75 else "#ea580c" if r.percentage>=33 else "#22c55e"
        blast_rows += f"<tr><td>{_html_escape(r.principal_id)}</td><td style='color:{pct_color};font-weight:bold'>{r.percentage:.1f}%</td><td>{_html_escape(reaches)}</td></tr>"

    graph_data = _json.dumps({"nodes": nodes, "edges": edges})
    rating_color = {"Excellent":"#22c55e","Good":"#22c55e","Fair":"#ca8a04","Poor":"#ea580c","Critical":"#dc2626"}.get(result.risk.rating.value,"#f59e0b")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CloudSentrix Dashboard</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:1.5rem;min-height:100vh}}
.header{{margin-bottom:1.5rem}}
.header h1{{font-size:1.5rem;font-weight:700;color:#f8fafc}}
.header .meta{{color:#64748b;font-size:.82rem;margin-top:.2rem}}
.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.5rem}}
.card{{background:#1e293b;border-radius:8px;padding:1rem;border:1px solid #334155}}
.card .label{{font-size:.72rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em}}
.card .value{{font-size:1.6rem;font-weight:700;margin-top:.2rem}}
.card .sub{{font-size:.78rem;color:#94a3b8;margin-top:.1rem}}
.section{{background:#1e293b;border-radius:8px;padding:1.2rem;border:1px solid #334155;margin-bottom:1.2rem}}
.section h2{{font-size:1rem;font-weight:600;margin-bottom:1rem;color:#f1f5f9}}
.legend{{display:flex;gap:1.2rem;margin-bottom:.75rem;flex-wrap:wrap}}
.legend-item{{display:flex;align-items:center;gap:.4rem;font-size:.78rem;color:#94a3b8}}
.dot{{width:11px;height:11px;border-radius:50%;display:inline-block}}
#graph-canvas{{width:100%;height:460px;background:#0f172a;border-radius:6px;display:block;cursor:grab}}
#graph-canvas:active{{cursor:grabbing}}
.graph-hint{{font-size:.72rem;color:#475569;margin-top:.4rem}}
table{{width:100%;border-collapse:collapse}}
th{{text-align:left;padding:.5rem .75rem;font-size:.72rem;color:#64748b;text-transform:uppercase;border-bottom:1px solid #334155}}
td{{padding:.55rem .75rem;font-size:.82rem;border-bottom:1px solid #1e293b;vertical-align:top}}
tr:hover td{{background:#1e293b}}
.badge{{color:#fff;padding:.15rem .5rem;border-radius:.25rem;font-size:.72rem;font-weight:700;white-space:nowrap}}
small{{color:#64748b;display:block}}
</style>
</head>
<body>
<div class="header">
  <h1>☁️ CloudSentrix — GCP IAM Security Dashboard</h1>
  <div class="meta">Source: {_html_escape(result.source_file)} &nbsp;|&nbsp; Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>
</div>

<div class="cards">
  <div class="card">
    <div class="label">Security Score</div>
    <div class="value" style="color:{rating_color}">{result.risk.score}/100</div>
    <div class="sub">{result.risk.rating.value}</div>
  </div>
  <div class="card">
    <div class="label">Critical Findings</div>
    <div class="value" style="color:#dc2626">{sev_counts.get('CRITICAL',0)}</div>
    <div class="sub">Immediate action needed</div>
  </div>
  <div class="card">
    <div class="label">High Findings</div>
    <div class="value" style="color:#ea580c">{sev_counts.get('HIGH',0)}</div>
    <div class="sub">Prioritize soon</div>
  </div>
  <div class="card">
    <div class="label">Principals</div>
    <div class="value" style="color:#3b82f6">{len(result.graph.principal_ids())}</div>
    <div class="sub">{len(result.graph.role_ids())} roles</div>
  </div>
</div>

<div class="section">
  <h2>🔴 Interactive Attack Graph</h2>
  <div class="legend">
    <span class="legend-item"><span class="dot" style="background:#dc2626"></span>CRITICAL</span>
    <span class="legend-item"><span class="dot" style="background:#ea580c"></span>HIGH</span>
    <span class="legend-item"><span class="dot" style="background:#3b82f6"></span>Normal</span>
    <span class="legend-item"><span class="dot" style="background:#475569;border-radius:2px"></span>Role</span>
    <span class="legend-item"><span style="color:#dc2626">---&gt;</span>&nbsp;Escalation path</span>
  </div>
  <canvas id="graph-canvas"></canvas>
  <div class="graph-hint">Drag to pan &nbsp;|&nbsp; Scroll to zoom &nbsp;|&nbsp; Drag nodes to rearrange &nbsp;|&nbsp; Hover for details</div>
</div>

<div class="section">
  <h2>🎯 Findings ({len(result.findings)})</h2>
  <table>
    <tr><th>Severity</th><th>Finding</th><th>Principal</th><th>MITRE</th><th>Details</th></tr>
    {findings_rows or '<tr><td colspan="5" style="color:#64748b">No findings.</td></tr>'}
  </table>
</div>

<div class="section">
  <h2>💥 Blast Radius</h2>
  <table>
    <tr><th>Principal</th><th>Blast Radius</th><th>Can Reach</th></tr>
    {blast_rows or '<tr><td colspan="3" style="color:#64748b">No data.</td></tr>'}
  </table>
</div>

<script>
(function(){{
var DATA={graph_data};
var canvas=document.getElementById("graph-canvas");
var ctx=canvas.getContext("2d");
var W,H,zoom=1,pan={{x:0,y:0}};
var nodeMap={{}};
var dragging=null,dragOX=0,dragOY=0;
var panning=false,panStart={{x:0,y:0}},panBase={{x:0,y:0}};
var hover=null;

function setup(){{
  W=canvas.offsetWidth||900; H=460;
  canvas.width=W; canvas.height=H;
  var cx=W/2,cy=H/2;
  var ellipseNodes=DATA.nodes.filter(n=>n.shape==="ellipse");
  var boxNodes=DATA.nodes.filter(n=>n.shape==="box");
  var outerR=Math.min(W,H)*0.35;
  var innerR=Math.min(W,H)*0.14;
  ellipseNodes.forEach((n,i)=>{{
    var a=(i/Math.max(ellipseNodes.length,1))*2*Math.PI-Math.PI/2;
    nodeMap[n.id]={{...n,x:cx+outerR*Math.cos(a),y:cy+outerR*Math.sin(a),rx:36,ry:22}};
  }});
  boxNodes.forEach((n,i)=>{{
    var a=(i/Math.max(boxNodes.length,1))*2*Math.PI-Math.PI/2;
    nodeMap[n.id]={{...n,x:cx+innerR*Math.cos(a),y:cy+innerR*Math.sin(a),rx:28,ry:14}};
  }});
  draw();
}}

function ws(x,y){{return{{x:x*zoom+pan.x,y:y*zoom+pan.y}};}}
function sw(x,y){{return{{x:(x-pan.x)/zoom,y:(y-pan.y)/zoom}};}}

function hitNode(sx,sy){{
  var w=sw(sx,sy);
  return Object.values(nodeMap).find(n=>{{
    var dx=(w.x-n.x)/((n.rx+6)*zoom)*zoom,dy=(w.y-n.y)/((n.ry+6)*zoom)*zoom;
    return dx*dx+dy*dy<=1;
  }})||null;
}}

function draw(){{
  ctx.clearRect(0,0,W,H);

  // edges
  DATA.edges.forEach(e=>{{
    var a=nodeMap[e.from],b=nodeMap[e.to];
    if(!a||!b)return;
    var sa=ws(a.x,a.y),sb=ws(b.x,b.y);
    var dx=sb.x-sa.x,dy=sb.y-sa.y,dist=Math.sqrt(dx*dx+dy*dy);
    if(dist<2)return;
    var ux=dx/dist,uy=dy/dist;
    var x1=sa.x+ux*a.rx*zoom,y1=sa.y+uy*a.ry*zoom;
    var x2=sb.x-ux*b.rx*zoom,y2=sb.y-uy*b.ry*zoom;
    ctx.save();
    ctx.strokeStyle=e.color;
    ctx.lineWidth=e.dashes?2:1.2;
    if(e.dashes)ctx.setLineDash([7,4]);
    ctx.beginPath();ctx.moveTo(x1,y1);ctx.lineTo(x2,y2);ctx.stroke();
    ctx.setLineDash([]);
    // arrowhead
    var ang=Math.atan2(y2-y1,x2-x1),hs=9;
    ctx.fillStyle=e.color;
    ctx.beginPath();ctx.moveTo(x2,y2);
    ctx.lineTo(x2-hs*Math.cos(ang-.4),y2-hs*Math.sin(ang-.4));
    ctx.lineTo(x2-hs*Math.cos(ang+.4),y2-hs*Math.sin(ang+.4));
    ctx.closePath();ctx.fill();
    // edge label
    if(e.dashes&&e.label){{
      ctx.fillStyle="#fca5a5";ctx.font=`bold ${{Math.max(9,10*zoom)}}px sans-serif`;
      ctx.textAlign="center";ctx.textBaseline="middle";
      ctx.fillText(e.label,(x1+x2)/2,(y1+y2)/2-7);
    }}
    ctx.restore();
  }});

  // nodes
  Object.values(nodeMap).forEach(n=>{{
    var s=ws(n.x,n.y);
    var rx=n.rx*zoom,ry=n.ry*zoom;
    var isHover=(hover&&hover.id===n.id);
    ctx.save();
    ctx.shadowColor=n.color;ctx.shadowBlur=isHover?18:6;
    ctx.fillStyle=n.color;
    ctx.beginPath();
    if(n.shape==="box"){{
      var bw=rx*2,bh=ry*2;
      ctx.roundRect(s.x-bw/2,s.y-bh/2,bw,bh,4);
    }}else{{
      ctx.ellipse(s.x,s.y,rx,ry,0,0,2*Math.PI);
    }}
    ctx.fill();
    ctx.shadowBlur=0;
    // label
    var fs=Math.max(9,Math.min(13,11*zoom));
    ctx.fillStyle="#fff";ctx.font=`${{n.shape==="box"?"":"bold "}}${{fs}}px sans-serif`;
    ctx.textAlign="center";ctx.textBaseline="middle";
    var maxW=rx*1.8,txt=n.label;
    if(ctx.measureText(txt).width>maxW)txt=txt.slice(0,Math.floor(txt.length*maxW/ctx.measureText(txt).width)-1)+"…";
    ctx.fillText(txt,s.x,s.y);
    ctx.restore();
  }});

  // tooltip
  if(hover){{
    var s=ws(hover.x,hover.y);
    var txt=hover.title;
    ctx.save();
    ctx.font="12px sans-serif";
    var tw=ctx.measureText(txt).width+16,th=24;
    var tx=Math.min(s.x+hover.rx*zoom+4,W-tw-4),ty=s.y-th/2;
    ctx.fillStyle="rgba(15,23,42,.96)";ctx.strokeStyle="#475569";ctx.lineWidth=1;
    ctx.beginPath();ctx.roundRect(tx,ty,tw,th,4);ctx.fill();ctx.stroke();
    ctx.fillStyle="#e2e8f0";ctx.textAlign="left";ctx.textBaseline="middle";
    ctx.fillText(txt,tx+8,ty+th/2);
    ctx.restore();
  }}
}}

canvas.addEventListener("mousedown",e=>{{
  var r=canvas.getBoundingClientRect(),mx=e.clientX-r.left,my=e.clientY-r.top;
  var n=hitNode(mx,my);
  if(n){{dragging=n;var s=ws(n.x,n.y);dragOX=mx-s.x;dragOY=my-s.y;}}
  else{{panning=true;panStart={{x:mx,y:my}};panBase={{x:pan.x,y:pan.y}};}}
}});
canvas.addEventListener("mousemove",e=>{{
  var r=canvas.getBoundingClientRect(),mx=e.clientX-r.left,my=e.clientY-r.top;
  if(dragging){{var w=sw(mx-dragOX,my-dragOY);dragging.x=w.x;dragging.y=w.y;draw();}}
  else if(panning){{pan.x=panBase.x+(mx-panStart.x);pan.y=panBase.y+(my-panStart.y);draw();}}
  else{{var n=hitNode(mx,my);if(n!==hover){{hover=n;draw();}}}}
}});
canvas.addEventListener("mouseup",()=>{{dragging=null;panning=false;}});
canvas.addEventListener("mouseleave",()=>{{dragging=null;panning=false;hover=null;draw();}});
canvas.addEventListener("wheel",e=>{{
  e.preventDefault();
  var r=canvas.getBoundingClientRect(),mx=e.clientX-r.left,my=e.clientY-r.top;
  var f=e.deltaY<0?1.12:.89;
  pan.x=(pan.x-mx)*f+mx;pan.y=(pan.y-my)*f+my;
  zoom=Math.max(.2,Math.min(5,zoom*f));draw();
}},{{passive:false}});
window.addEventListener("resize",()=>{{W=canvas.offsetWidth;canvas.width=W;canvas.height=H;draw();}});
setup();
}})();
</script>
</body>
</html>"""

def infer_export_format(output_path: Path, explicit_format: str | None) -> str:
    if explicit_format:
        return explicit_format
    fmt = _EXPORT_EXTENSION_FORMAT.get(output_path.suffix.lower())
    if fmt is None:
        raise ValueError(
            f"Could not infer export format from '{output_path.name}'. Pass --format json|csv|html explicitly."
        )
    return fmt


def run_export(file_path: str, output: str, fmt: str | None, cloud: str = "gcp") -> tuple[ScanResult, str, Path]:
    result = run_scan(file_path, cloud=cloud)
    output_path = Path(output)
    resolved_format = infer_export_format(output_path, fmt)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _EXPORTERS[resolved_format](result, output_path)
    return result, resolved_format, output_path


# ---------------------------------------------------------------------------
# Rendering — the only layer that touches OutputWriter/rich
# ---------------------------------------------------------------------------

def render_banner(writer: OutputWriter) -> None:
    for line in CLOUD_LOGO.splitlines():
        writer.print(f"[bold cyan]{line}[/bold cyan]")

    title_lines = [
        f"CloudSentrix v{__version__}",
        "GCP IAM Privilege-Escalation Attack-Path Analyzer",
    ]
    width = max(len(line) for line in title_lines) + 4
    writer.print(f"[bold cyan]{'╔' + '═' * width + '╗'}[/bold cyan]")
    for line in title_lines:
        writer.print(f"[bold cyan]║{line.center(width)}║[/bold cyan]")
    writer.print(f"[bold cyan]{'╚' + '═' * width + '╝'}[/bold cyan]")
    writer.print("")


def render_findings(writer: OutputWriter, findings: list[Finding]) -> None:
    writer.print("[bold]── Findings ──────────────────────────────────────────[/bold]")
    if not findings:
        writer.print("[bold green]No findings at or above the selected severity.[/bold green]\n")
        return

    for f in findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        writer.print(f"[{color}]{f.severity}[/{color}] — {f.title} ({f.rule_id})")
        writer.print(f"  Principal : {f.principal_id}")
        writer.print(f"  MITRE     : {f.mitre_technique_id} - {f.mitre_technique_name}")
        writer.print(f"  Details   : {f.description}")
        writer.print("")


def render_risk_score(writer: OutputWriter, risk: RiskScore) -> None:
    color = RATING_COLOR.get(risk.rating, "white")
    writer.print("[bold]── Overall Risk ──────────────────────────────────────[/bold]")
    writer.print(f"[{color}]Security Score: {risk.score}/100 ({risk.rating.value})[/{color}]")
    counts = risk.finding_counts
    writer.print(
        f"Findings: {counts['CRITICAL']} Critical, {counts['HIGH']} High, "
        f"{counts['MEDIUM']} Medium, {counts['LOW']} Low\n"
    )


def render_blast_radius(writer: OutputWriter, results: list[BlastRadiusResult], top_n: int) -> None:
    writer.print("[bold]── Blast Radius (highest risk first) ─────────────────[/bold]")
    shown = results[: max(0, top_n)]
    if not shown:
        writer.print("(no principals to show)\n")
        return
    for r in shown:
        reaches = ", ".join(r.reachable_principals) if r.reachable_principals else "(nothing further)"
        writer.print(f"  {r.principal_id:<45} [bold]{r.percentage:>6.1f}%[/bold]  -> {reaches}")
    writer.print("")


def render_single_blast_radius(writer: OutputWriter, result: BlastRadiusResult) -> None:
    reaches = ", ".join(result.reachable_principals) if result.reachable_principals else "(nothing further)"
    writer.print(f"[bold]{result.principal_id}[/bold]")
    writer.print(f"Blast radius : [bold]{result.percentage:.1f}%[/bold] of {result.total_others} other principal(s)")
    writer.print(f"Can reach    : {reaches}\n")


def render_rules_list(writer: OutputWriter) -> None:
    writer.print("[bold]── Detection Rules ───────────────────────────────────[/bold]")
    for rule in DetectionEngine().rules:
        color = SEVERITY_COLOR.get(rule.severity, "white")
        writer.print(f"[{color}]{rule.rule_id}[/{color}] {rule.title}  ({rule.severity})")
        writer.print(f"  MITRE: {rule.mitre_technique_id} - {rule.mitre_technique_name}")
    writer.print("")


def render_principals_list(writer: OutputWriter, graph: IAMGraph) -> None:
    writer.print("[bold]── Principals ────────────────────────────────────────[/bold]")
    for principal_id in sorted(graph.principal_ids()):
        p = graph.get_principal(principal_id)
        member_type = p.member_type.value if p is not None else "unknown"
        writer.print(f"[bold]{principal_id}[/bold] ({member_type})")
        for role in sorted(graph.roles_of(principal_id)):
            writer.print(f"    - {role}")
    writer.print("")


def render_validate(writer: OutputWriter, file_path: str, policy: ParsedIAMPolicy, warnings: list[str]) -> None:
    stats = policy.summary()
    writer.print("[bold]── Validation ────────────────────────────────────────[/bold]")
    writer.print(f"[bold green]VALID[/bold green] — {file_path} is a well-formed GCP IAM policy export.")
    writer.print(
        f"Bindings: {stats['total_bindings']}  |  Member entries: {stats['total_member_entries']}  |  "
        f"Unique members: {stats['unique_members']}"
    )
    if warnings:
        writer.print(f"\n[bold yellow]{len(warnings)} warning(s):[/bold yellow]")
        for w in warnings:
            writer.print(f"  [yellow]•[/yellow] {w}")
    writer.print("")


def render_score_only(writer: OutputWriter, risk: RiskScore) -> None:
    color = RATING_COLOR.get(risk.rating, "white")
    writer.print(f"[{color}]{risk.score}/100 ({risk.rating.value})[/{color}]")


def render_compare(writer: OutputWriter, comparison: ComparisonResult) -> None:
    writer.print("[bold]── Comparison ────────────────────────────────────────[/bold]")
    writer.print(f"Old : {comparison.old_file}  ({comparison.old_score.score}/100, {comparison.old_score.rating.value})")
    writer.print(f"New : {comparison.new_file}  ({comparison.new_score.score}/100, {comparison.new_score.rating.value})")

    delta = comparison.new_score.score - comparison.old_score.score
    delta_color = "bold red" if delta < 0 else ("bold green" if delta > 0 else "white")
    sign = "+" if delta > 0 else ""
    writer.print(f"Score change: [{delta_color}]{sign}{delta}[/{delta_color}]\n")

    writer.print(f"[bold red]New risks ({len(comparison.new_findings)})[/bold red]")
    if not comparison.new_findings:
        writer.print("  (none)")
    for f in comparison.new_findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        writer.print(f"  [{color}]{f.severity.name}[/{color}] {f.title} — {f.principal_id} ({f.rule_id})")
    writer.print("")

    writer.print(f"[bold green]Resolved risks ({len(comparison.resolved_findings)})[/bold green]")
    if not comparison.resolved_findings:
        writer.print("  (none)")
    for f in comparison.resolved_findings:
        writer.print(f"  {f.title} — {f.principal_id} ({f.rule_id})")
    writer.print("")

    writer.print(f"Persistent risks (still present): {len(comparison.persistent_findings)}\n")


def render_principal_path(
    writer: OutputWriter, source: str, target: str, source_exists: bool, target_exists: bool, path: list[str] | None
) -> None:
    writer.print("[bold]── Escalation Path ───────────────────────────────────[/bold]")
    if not source_exists:
        writer.print(f"[bold red]'{source}' was not found in the graph.[/bold red]\n")
        return
    if not target_exists:
        writer.print(f"[bold red]'{target}' was not found in the graph.[/bold red]\n")
        return
    if path is None:
        writer.print(f"[bold green]No escalation path found from '{source}' to '{target}'.[/bold green]\n")
        return

    writer.print(f"[bold red]Path found[/bold red] ({len(path) - 1} hop(s)):")
    writer.print("  " + "  ->  ".join(path))
    writer.print("")


def render_mitre_map(writer: OutputWriter, findings: list[Finding]) -> None:
    writer.print("[bold]── MITRE ATT&CK Cloud Matrix Mapping ─────────────────[/bold]")
    if not findings:
        writer.print("[bold green]No findings to map.[/bold green]\n")
        return

    grouped = group_findings_by_mitre(findings)
    ordered_techniques = sorted(
        grouped.items(), key=lambda item: max(f.severity for f in item[1]), reverse=True,
    )

    for technique_id, technique_findings in ordered_techniques:
        technique_name = technique_findings[0].mitre_technique_name
        writer.print(f"[bold]{technique_id}[/bold] — {technique_name}  ({len(technique_findings)} finding(s))")
        for f in technique_findings:
            color = SEVERITY_COLOR.get(f.severity, "white")
            writer.print(f"    [{color}]{f.severity.name}[/{color}] {f.principal_id} — {f.title} ({f.rule_id})")
        writer.print("")


def render_remediate(writer: OutputWriter, findings: list[Finding], graph: IAMGraph, project: str) -> None:
    writer.print("[bold]── Remediation Commands ──────────────────────────────[/bold]")
    if not findings:
        writer.print("[bold green]No findings to remediate.[/bold green]\n")
        return
    if project == DEFAULT_PROJECT_PLACEHOLDER:
        writer.print(
            f"[yellow]Note: no --project given — commands use the placeholder "
            f"'{DEFAULT_PROJECT_PLACEHOLDER}'. Replace it, or re-run with --project YOUR_REAL_PROJECT.[/yellow]\n"
        )

    for f in findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        writer.print(f"[{color}]{f.severity.name}[/{color}] {f.title} — {f.principal_id} ({f.rule_id})")
        for line in generate_remediation(f, graph, project):
            writer.print(f"  {line}")
        writer.print("")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudsentrix",
        description="CloudSentrix — GCP IAM privilege-escalation attack-path analyzer.",
    )
    parser.add_argument("--version", action="version", version=f"CloudSentrix {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a GCP IAM policy export for privilege-escalation risk.")
    scan_parser.add_argument("--file", "-f", required=True, help="Path to a GCP IAM policy JSON export.")
    scan_parser.add_argument(
        "--cloud", default="gcp", choices=["gcp"],
        help="Cloud provider (only 'gcp' is supported today).",
    )
    scan_parser.add_argument(
        "--severity", default="all", choices=sorted(SEVERITY_CHOICES),
        help="Minimum severity to display (default: all).",
    )
    scan_parser.add_argument(
        "--top", type=int, default=5,
        help="Number of blast-radius rows to display (default: 5).",
    )
    scan_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    scan_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    blast_parser = subparsers.add_parser(
        "blast-radius", help="Show the blast radius for one specific principal."
    )
    blast_parser.add_argument("--file", "-f", required=True, help="Path to a GCP IAM policy JSON export.")
    blast_parser.add_argument("--principal", "-p", required=True, help="Principal id (e.g. an email) to check.")
    blast_parser.add_argument("--cloud", default="gcp", choices=["gcp"], help="Cloud provider.")
    blast_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    blast_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    rules_parser = subparsers.add_parser("rules", help="List every detection rule this tool checks for.")
    rules_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    rules_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    list_parser = subparsers.add_parser(
        "list-principals", help="Quick inventory: every principal and the roles it holds."
    )
    list_parser.add_argument("--file", "-f", required=True, help="Path to a GCP IAM policy JSON export.")
    list_parser.add_argument("--cloud", default="gcp", choices=["gcp"], help="Cloud provider.")
    list_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    list_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    validate_parser = subparsers.add_parser(
        "validate", help="Check that a file is a well-formed GCP IAM policy export, before scanning it."
    )
    validate_parser.add_argument("--file", "-f", required=True, help="Path to a GCP IAM policy JSON export.")
    validate_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    validate_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    score_parser = subparsers.add_parser(
        "score", help="Print only the overall security score — useful for CI badges/checks."
    )
    score_parser.add_argument("--file", "-f", required=True, help="Path to a GCP IAM policy JSON export.")
    score_parser.add_argument("--cloud", default="gcp", choices=["gcp"], help="Cloud provider.")
    score_parser.add_argument(
        "--min-score", type=int, default=None, metavar="N",
        help="Exit 1 if the score falls below N (overrides the default CRITICAL-based exit code).",
    )
    score_parser.add_argument("--json", action="store_true", help="Output as a single line of JSON.")
    score_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    score_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    compare_parser = subparsers.add_parser(
        "compare", help="Compare two IAM policy exports and show what risk changed between them."
    )
    compare_parser.add_argument("--old", required=True, help="Path to the earlier/baseline IAM policy JSON export.")
    compare_parser.add_argument("--new", required=True, help="Path to the newer IAM policy JSON export.")
    compare_parser.add_argument("--cloud", default="gcp", choices=["gcp"], help="Cloud provider.")
    compare_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    compare_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    path_parser = subparsers.add_parser(
        "principal-path", help="Show the escalation path (if any) from one principal to another."
    )
    path_parser.add_argument("--file", "-f", required=True, help="Path to a GCP IAM policy JSON export.")
    path_parser.add_argument("--source", "-s", required=True, help="Starting principal id (e.g. an email).")
    path_parser.add_argument("--target", "-t", required=True, help="Target principal id to try to reach.")
    path_parser.add_argument("--cloud", default="gcp", choices=["gcp"], help="Cloud provider.")
    path_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    path_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    mitre_parser = subparsers.add_parser(
        "mitre-map", help="Map every finding onto the MITRE ATT&CK Cloud Matrix."
    )
    mitre_parser.add_argument("--file", "-f", required=True, help="Path to a GCP IAM policy JSON export.")
    mitre_parser.add_argument("--cloud", default="gcp", choices=["gcp"], help="Cloud provider.")
    mitre_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    mitre_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    remediate_parser = subparsers.add_parser(
        "remediate", help="Generate gcloud CLI commands that fix each finding."
    )
    remediate_parser.add_argument("--file", "-f", required=True, help="Path to a GCP IAM policy JSON export.")
    remediate_parser.add_argument(
        "--project", default=DEFAULT_PROJECT_PLACEHOLDER,
        help="GCP project id to use in generated commands (default: a placeholder you must replace).",
    )
    remediate_parser.add_argument(
        "--severity", default="all", choices=sorted(SEVERITY_CHOICES),
        help="Minimum severity to generate fixes for (default: all).",
    )
    remediate_parser.add_argument("--cloud", default="gcp", choices=["gcp"], help="Cloud provider.")
    remediate_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    remediate_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    export_parser = subparsers.add_parser(
        "export", help="Run a scan and export the results to a file (json, csv, or html)."
    )
    export_parser.add_argument("--file", "-f", required=True, help="Path to a GCP IAM policy JSON export.")
    export_parser.add_argument("--output", "-o", required=True, help="Output file path.")
    export_parser.add_argument(
        "--format", choices=["json", "csv", "html", "sarif"], default=None,
        help="Output format (default: inferred from --output's extension).",
    )
    export_parser.add_argument("--cloud", default="gcp", choices=["gcp"], help="Cloud provider.")
    export_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    export_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    watch_parser = subparsers.add_parser(
        "watch", help="Monitor a file or folder and automatically re-scan whenever it changes."
    )
    watch_parser.add_argument(
        "--path", "-d", required=True,
        help="A single IAM policy JSON file, or a directory containing *.json exports.",
    )
    watch_parser.add_argument(
        "--interval", type=float, default=2.0, metavar="SECONDS",
        help="Poll interval in seconds (default: 2.0).",
    )
    watch_parser.add_argument(
        "--severity", default="all", choices=sorted(SEVERITY_CHOICES),
        help="Minimum severity to display on each re-scan (default: all).",
    )
    watch_parser.add_argument(
        "--top", type=int, default=5,
        help="Number of blast-radius rows to display on each re-scan (default: 5).",
    )
    watch_parser.add_argument("--cloud", default="gcp", choices=["gcp"], help="Cloud provider.")
    watch_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    watch_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    report_parser = subparsers.add_parser(
        "report",
        help="Generate a client-ready PDF report with an optional Gemini AI summary.",
    )
    report_parser.add_argument("--file", "-f", required=True, help="Path to a GCP IAM policy JSON export.")
    report_parser.add_argument(
        "--output", "-o", default="report.pdf",
        help="Output PDF file path (default: report.pdf).",
    )
    report_parser.add_argument(
        "--no-ai", action="store_true",
        help="Skip the Gemini AI summary and use the built-in template summary instead.",
    )
    report_parser.add_argument("--cloud", default="gcp", choices=["gcp"], help="Cloud provider.")
    report_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    report_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    live_scan_parser = subparsers.add_parser(
        "live-scan",
        help="Fetch live IAM policy from GCP and scan it directly (requires gcloud CLI).",
    )
    live_scan_parser.add_argument(
        "--project", "-p", required=True,
        help="GCP Project ID to fetch and scan (e.g. my-project-123).",
    )
    live_scan_parser.add_argument(
        "--save", default=None, metavar="PATH",
        help="Optionally save the fetched policy to a JSON file.",
    )
    live_scan_parser.add_argument(
        "--severity", default="all", choices=sorted(SEVERITY_CHOICES),
        help="Minimum severity to display (default: all).",
    )
    live_scan_parser.add_argument(
        "--top", type=int, default=5,
        help="Number of blast-radius rows to display (default: 5).",
    )
    live_scan_parser.add_argument("--cloud", default="gcp", choices=["gcp"], help="Cloud provider.")
    live_scan_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    live_scan_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    return parser


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def _handle_scan(writer: OutputWriter, args: argparse.Namespace) -> int:
    result = run_scan(args.file, cloud=args.cloud)
    min_severity = SEVERITY_CHOICES[args.severity]
    displayed = filter_by_severity(result.findings, min_severity)

    render_findings(writer, displayed)
    render_risk_score(writer, result.risk)
    render_blast_radius(writer, result.blast_radius, args.top)

    return determine_exit_code(result.findings)


def _handle_blast_radius(writer: OutputWriter, args: argparse.Namespace) -> int:
    result = run_scan(args.file, cloud=args.cloud)
    match = find_blast_radius_for(result.blast_radius, args.principal)
    if match is None:
        writer.print(f"[bold red]Error:[/bold red] '{args.principal}' was not found in {args.file}.")
        return 2
    render_single_blast_radius(writer, match)
    return 0


def _handle_rules(writer: OutputWriter) -> int:
    render_rules_list(writer)
    return 0


def _handle_list_principals(writer: OutputWriter, args: argparse.Namespace) -> int:
    graph = run_list_principals(args.file, cloud=args.cloud)
    render_principals_list(writer, graph)
    return 0


def _handle_validate(writer: OutputWriter, args: argparse.Namespace) -> int:
    try:
        policy, warnings = run_validate(args.file)
    except IAMParserError as exc:
        writer.print("[bold]── Validation ────────────────────────────────────────[/bold]")
        writer.print(f"[bold red]INVALID[/bold red] — {exc}")
        return 2
    render_validate(writer, args.file, policy, warnings)
    return 0


def _handle_score(writer: OutputWriter, args: argparse.Namespace) -> int:
    result = run_scan(args.file, cloud=args.cloud)

    if args.json:
        payload = {
            "score": result.risk.score,
            "rating": result.risk.rating.value,
            "findings": result.risk.finding_counts,
        }
        writer.print(json.dumps(payload))
    else:
        render_score_only(writer, result.risk)

    if args.min_score is not None:
        return 0 if result.risk.score >= args.min_score else 1
    return determine_exit_code(result.findings)


def _handle_compare(writer: OutputWriter, args: argparse.Namespace) -> int:
    comparison = run_compare(args.old, args.new, cloud=args.cloud)
    render_compare(writer, comparison)
    new_critical = any(f.severity == Severity.CRITICAL for f in comparison.new_findings)
    return 1 if new_critical else 0


def _handle_principal_path(writer: OutputWriter, args: argparse.Namespace) -> int:
    result, path = run_principal_path(args.file, args.source, args.target, cloud=args.cloud)
    source_exists = result.graph.has_principal(args.source)
    target_exists = result.graph.has_principal(args.target)

    render_principal_path(writer, args.source, args.target, source_exists, target_exists, path)

    if not source_exists or not target_exists:
        return 2
    return 1 if path is not None else 0


def _handle_mitre_map(writer: OutputWriter, args: argparse.Namespace) -> int:
    result = run_scan(args.file, cloud=args.cloud)
    render_mitre_map(writer, result.findings)
    return determine_exit_code(result.findings)


def _handle_remediate(writer: OutputWriter, args: argparse.Namespace) -> int:
    result = run_scan(args.file, cloud=args.cloud)
    min_severity = SEVERITY_CHOICES[args.severity]
    displayed = filter_by_severity(result.findings, min_severity)
    render_remediate(writer, displayed, result.graph, args.project)
    return determine_exit_code(result.findings)


def _handle_watch(writer: OutputWriter, args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        writer.print(f"[bold red]Error:[/bold red] '{args.path}' does not exist.")
        return 2

    min_severity = SEVERITY_CHOICES[args.severity]

    def scan_and_render(file_path: Path) -> None:
        writer.print(f"\n[bold cyan]── Change detected: {file_path} ──[/bold cyan]\n")
        try:
            result = run_scan(str(file_path), cloud=args.cloud)
        except IAMParserError as exc:
            writer.print(f"[bold red]Error:[/bold red] {exc}\n")
            return
        except GraphBuildError as exc:
            writer.print(f"[bold red]Error building graph:[/bold red] {exc}\n")
            return
        displayed = filter_by_severity(result.findings, min_severity)
        render_findings(writer, displayed)
        render_risk_score(writer, result.risk)
        render_blast_radius(writer, result.blast_radius, args.top)

    writer.print(f"[bold]Watching {path} (every {args.interval:.1f}s) — press Ctrl+C to stop.[/bold]\n")

    try:
        if path.is_file():
            scan_and_render(path)  # baseline scan up front; a directory has no single "current" target yet
        watch_files(path, on_change=scan_and_render, poll_interval=args.interval)
    except FileNotFoundError as exc:
        writer.print(f"[bold red]Error:[/bold red] {exc}")
        return 2
    except KeyboardInterrupt:
        pass

    writer.print("\n[bold]Watch stopped.[/bold]")
    return 0


def _handle_export(writer: OutputWriter, args: argparse.Namespace) -> int:
    result, fmt, output_path = run_export(args.file, args.output, args.format, cloud=args.cloud)
    writer.print(f"[bold green]Exported[/bold green] {len(result.findings)} finding(s) as {fmt.upper()} -> {output_path}")
    return determine_exit_code(result.findings)


def _handle_report(writer: OutputWriter, args: argparse.Namespace) -> int:
    result = run_scan(args.file, cloud=args.cloud)

    findings_dicts = [finding_to_dict(f) for f in result.findings]
    blast_dicts = [blast_radius_to_dict(r) for r in result.blast_radius]

    # AI summary — try Gemini first, fall back to template silently
    ai_summary: str | None = None
    if not args.no_ai:
        try:
            ai_summary = generate_ai_summary(
                risk_score=result.risk.score,
                rating=result.risk.rating.value,
                finding_counts=result.risk.finding_counts,
                top_findings=findings_dicts[:5],
            )
            writer.print("[bold green]AI summary generated via Gemini.[/bold green]")
        except AISummaryError as exc:
            writer.print(f"[yellow]Gemini unavailable ({exc}) — using built-in summary.[/yellow]")
            ai_summary = build_fallback_summary(
                result.risk.score, result.risk.rating.value, result.risk.finding_counts
            )
    else:
        ai_summary = build_fallback_summary(
            result.risk.score, result.risk.rating.value, result.risk.finding_counts
        )

    output_path = Path(args.output)
    generate_pdf_report(
        source_file=args.file,
        risk_score=result.risk.score,
        rating=result.risk.rating.value,
        finding_counts=result.risk.finding_counts,
        findings=findings_dicts,
        blast_radius=blast_dicts,
        output_path=output_path,
        ai_summary=ai_summary,
    )

    writer.print(f"[bold green]Report saved:[/bold green] {output_path.resolve()}")
    writer.print(
        f"Findings: {result.risk.finding_counts['CRITICAL']} Critical, "
        f"{result.risk.finding_counts['HIGH']} High, "
        f"{result.risk.finding_counts['MEDIUM']} Medium, "
        f"{result.risk.finding_counts['LOW']} Low"
    )
    writer.print(f"Score: {result.risk.score}/100 ({result.risk.rating.value})")
    return determine_exit_code(result.findings)


def _handle_live_scan(writer: OutputWriter, args: argparse.Namespace) -> int:
    writer.print(f"[bold cyan]Fetching live IAM policy for project:[/bold cyan] [bold]{args.project}[/bold]")
    try:
        policy_data = fetch_live_iam_policy(args.project)
    except LiveScanError as exc:
        writer.print(f"[bold red]Error:[/bold red] {exc}")
        return 2

    writer.print(f"[bold green]Policy fetched:[/bold green] {len(policy_data.get('bindings', []))} binding(s) found.")

    if args.save:
        save_path = Path(args.save)
        save_policy_to_file(policy_data, save_path)
        writer.print(f"[bold green]Saved to:[/bold green] {save_path.resolve()}")

    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tmp:
        import json as _json
        _json.dump(policy_data, tmp)
        tmp_path = tmp.name

    try:
        result = run_scan(tmp_path, cloud=args.cloud)
    except Exception as exc:
        writer.print(f"[bold red]Scan error:[/bold red] {exc}")
        return 2
    finally:
        os.unlink(tmp_path)

    min_severity = SEVERITY_CHOICES[args.severity]
    displayed = filter_by_severity(result.findings, min_severity)
    render_findings(writer, displayed)
    render_risk_score(writer, result.risk)
    render_blast_radius(writer, result.blast_radius, args.top)
    return determine_exit_code(result.findings)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    parser = build_arg_parser()
    args = parser.parse_args(argv)

    writer = OutputWriter(Console(), use_color=not getattr(args, "no_color", False))
    if not getattr(args, "no_banner", False):
        render_banner(writer)

    try:
        if args.command == "scan":
            return _handle_scan(writer, args)
        if args.command == "blast-radius":
            return _handle_blast_radius(writer, args)
        if args.command == "rules":
            return _handle_rules(writer)
        if args.command == "list-principals":
            return _handle_list_principals(writer, args)
        if args.command == "validate":
            return _handle_validate(writer, args)
        if args.command == "score":
            return _handle_score(writer, args)
        if args.command == "compare":
            return _handle_compare(writer, args)
        if args.command == "principal-path":
            return _handle_principal_path(writer, args)
        if args.command == "mitre-map":
            return _handle_mitre_map(writer, args)
        if args.command == "remediate":
            return _handle_remediate(writer, args)
        if args.command == "export":
            return _handle_export(writer, args)
        if args.command == "watch":
            return _handle_watch(writer, args)
        if args.command == "report":
            return _handle_report(writer, args)
        if args.command == "live-scan":
            return _handle_live_scan(writer, args)

        parser.print_help()
        return 2

    except IAMParserError as exc:
        writer.print(f"[bold red]Error:[/bold red] {exc}")
        return 2
    except GraphBuildError as exc:
        writer.print(f"[bold red]Error building graph:[/bold red] {exc}")
        return 2
    except ValueError as exc:
        writer.print(f"[bold red]Error:[/bold red] {exc}")
        return 2
    except Exception:
        logger.exception("Unexpected error.")
        writer.print("[bold red]An unexpected error occurred. See logs for details.[/bold red]")
        return 2


if __name__ == "__main__":
    sys.exit(main())
