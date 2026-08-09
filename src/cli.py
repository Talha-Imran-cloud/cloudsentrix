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

# AWS support
from aws_parser import AWSIAMParser, AWSParserError
from aws_graph import AWSIAMGraph
from aws_detection import AWSDetectionEngine, AWSFinding, summarize_aws_findings
from aws_live_scanner import AWSLiveScanner, AWSLiveScanError

# Azure support
from azure_parser import parse_azure_file, AzureIAMData

# Multi-cloud dashboard
from multi_dashboard import generate_multi_dashboard

# Notifications
from notifier import send_notification

# Multi-cloud PDF
from multi_pdf_report import generate_multi_pdf
from azure_detection import run_azure_detections, AzureFinding, get_azure_rules
from azure_risk_score import score_azure, AzureScoreResult
from azure_blast_radius import calculate_azure_blast_radius
from azure_exporter import export_azure
from azure_live_scanner import fetch_azure_live

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
    # Azure-specific fields (None for GCP/AWS scans)
    _az_findings: list = None  # type: ignore
    _az_score: object = None
    _az_blast: list = None     # type: ignore
    _az_iam: object = None


def run_scan(file_path: str, cloud: str = "gcp") -> ScanResult:
    """Runs the full pipeline: parse -> graph -> detect -> score -> blast radius.

    Raises:
        ValueError: If `cloud` isn't a supported provider.
        IAMParserError / AWSParserError: If the file can't be parsed.
        GraphBuildError: If the graph can't be built from the parsed policy.
    """
    if cloud == "aws":
        return _run_scan_aws(file_path)
    if cloud == "azure":
        return _run_scan_azure(file_path)
    if cloud != "gcp":
        raise ValueError(f"Unsupported cloud provider: {cloud!r}. Supported: 'gcp', 'aws', 'azure'.")

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


def _run_scan_aws(file_path: str) -> ScanResult:
    """AWS scan pipeline: parse -> graph -> detect -> score.
    Blast radius and escalation edges are not yet supported for AWS
    (GCP blast_radius.py is GCP-graph-specific); stubs are returned so
    the rest of the CLI (render_findings, render_risk_score, export) works
    identically for both clouds.
    """
    from detection import Severity as GCPSeverity  # reuse for RiskScorer

    aws_policy = AWSIAMParser().parse_file(file_path)
    aws_graph = AWSIAMGraph.from_policy(aws_policy)
    aws_findings = AWSDetectionEngine().run(aws_graph)

    # Convert AWSFindings -> GCP Finding shape so RiskScorer + renderers work unchanged
    gcp_findings = _aws_findings_to_gcp(aws_findings)
    risk = RiskScorer().score(gcp_findings)

    # Return a ScanResult with stubs for GCP-only fields
    return ScanResult(
        source_file=file_path,
        cloud="aws",
        policy=aws_policy,      # type: ignore[arg-type]  — renderers use .summary() only
        graph=aws_graph,        # type: ignore[arg-type]  — renderers use findings directly
        findings=gcp_findings,
        risk=risk,
        blast_radius=[],
        escalation_edges=[],
    )


def _run_scan_azure(file_path: str) -> ScanResult:
    """Azure scan pipeline: parse -> detect -> score -> blast radius."""
    from detection import Finding as GCPFinding, Severity as GCPSeverity

    iam = parse_azure_file(file_path)
    az_findings = run_azure_detections(iam)
    az_score = score_azure(az_findings, iam)
    az_blast = calculate_azure_blast_radius(iam)

    # Convert AzureFindings -> GCP Finding shape for RiskScorer + renderers
    gcp_findings = _azure_findings_to_gcp(az_findings)
    risk = RiskScorer().score(gcp_findings)

    return ScanResult(
        source_file=file_path,
        cloud="azure",
        policy=iam,           # type: ignore[arg-type]
        graph=iam,            # type: ignore[arg-type]  renderers check cloud
        findings=gcp_findings,
        risk=risk,
        blast_radius=[],
        escalation_edges=[],
        _az_findings=az_findings,
        _az_score=az_score,
        _az_blast=az_blast,
        _az_iam=iam,
    )


def _azure_findings_to_gcp(az_findings: list[AzureFinding]) -> list[Finding]:
    """Convert AzureFinding -> GCP Finding shape for shared renderers."""
    from detection import Finding as GCPFinding, Severity as GCPSeverity
    sev_map = {"CRITICAL": GCPSeverity.CRITICAL, "HIGH": GCPSeverity.HIGH,
               "MEDIUM": GCPSeverity.MEDIUM, "LOW": GCPSeverity.LOW}
    result = []
    for f in az_findings:
        result.append(GCPFinding(
            rule_id=f.rule_id,
            title=f.title,
            severity=sev_map.get(f.severity, GCPSeverity.LOW),
            principal_id=f.principal_name,
            description=f.description,
            mitre_technique_id=f.mitre_technique,
            mitre_technique_name=f.mitre_tactic,
            evidence=(f.role,),
        ))
    return result


def _aws_findings_to_gcp(aws_findings: list[AWSFinding]) -> list[Finding]:
    """Convert AWSFinding objects to GCP Finding shape.
    Both dataclasses share the same fields — this is a straight mapping.
    Severity IntEnum values are identical so we cast by value.
    """
    from detection import Finding as GCPFinding, Severity as GCPSeverity
    result = []
    for f in aws_findings:
        result.append(GCPFinding(
            rule_id=f.rule_id,
            title=f.title,
            severity=GCPSeverity(int(f.severity)),
            principal_id=f.principal_id,
            description=f.description,
            mitre_technique_id=f.mitre_technique_id,
            mitre_technique_name=f.mitre_technique_name,
            evidence=f.evidence,
        ))
    return result


def run_list_principals(file_path: str, cloud: str = "gcp") -> IAMGraph:
    """Parses a file and builds its graph only — no detection, for a
    lightweight inventory view."""
    if cloud == "aws":
        aws_policy = AWSIAMParser().parse_file(file_path)
        return AWSIAMGraph.from_policy(aws_policy)  # type: ignore[return-value]
    if cloud == "azure":
        return parse_azure_file(file_path)  # type: ignore[return-value]
    if cloud != "gcp":
        raise ValueError(f"Unsupported cloud provider: {cloud!r}. Supported: 'gcp', 'aws', 'azure'.")
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
    output_path.write_text(build_html_export(result), encoding="utf-8")


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


RULE_CATEGORY: dict[str, str] = {
    # GCP rules
    "GCP-001": "Public Access",
    "GCP-002": "Service Account Risks",
    "GCP-003": "Service Account Risks",
    "GCP-004": "Overly Permissive Roles",
    "GCP-005": "Privilege Escalation",
    # AWS rules
    "AWS-001": "Overly Permissive Roles",
    "AWS-002": "Privilege Escalation",
    "AWS-003": "Privilege Escalation",
    "AWS-004": "Public Access",
    "AWS-005": "Credential Risks",
    "AWS-006": "Backdoor Creation",
    "AWS-007": "Overly Permissive Roles",
    # Azure rules
    "AZ-001": "Overly Permissive Roles",
    "AZ-002": "Service Principal Risks",
    "AZ-003": "Guest Access Risks",
    "AZ-004": "Privilege Escalation",
    "AZ-005": "Custom Role Risks",
}

CATEGORY_COLOR: dict[str, str] = {
    "Privilege Escalation": "#dc2626",
    "Overly Permissive Roles": "#ea580c",
    "Service Account Risks": "#ca8a04",
    "Public Access": "#3b82f6",
}

SEVERITY_HEX: dict[str, str] = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#22c55e",
}

DASHBOARD_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0b1120;color:#e2e8f0;padding:1.75rem;min-height:100vh}
.header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:1.5rem;flex-wrap:wrap;gap:.75rem}
.header h1{font-size:1.55rem;font-weight:700;color:#f8fafc}
.header .meta{color:#64748b;font-size:.82rem;margin-top:.25rem}

.score-row{display:grid;grid-template-columns:1.4fr repeat(5,1fr);gap:1rem;margin-bottom:1.25rem}
.score-card{background:#141b2d;border-radius:10px;padding:1.1rem 1.2rem;border:1px solid #23304a}
.score-card .label{font-size:.72rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em;display:flex;align-items:center;gap:.4rem}
.score-card .value{font-size:1.75rem;font-weight:700;margin-top:.35rem;line-height:1}
.score-card .sub{font-size:.76rem;color:#94a3b8;margin-top:.3rem}
.score-bar-bg{background:#1e293b;border-radius:4px;height:6px;margin-top:.6rem;overflow:hidden}
.score-bar-fill{height:100%;border-radius:4px}

.grid-3{display:grid;grid-template-columns:1fr 1.3fr 1.3fr;gap:1.1rem;margin-bottom:1.1rem}
.panel{background:#141b2d;border-radius:10px;padding:1.15rem 1.25rem;border:1px solid #23304a}
.panel h2{font-size:.95rem;font-weight:600;color:#f1f5f9;margin-bottom:1rem}

.donut-wrap{display:flex;align-items:center;gap:1.3rem}
.donut{width:130px;height:130px;border-radius:50%;position:relative;flex-shrink:0}
.donut::after{content:"";position:absolute;inset:20px;background:#141b2d;border-radius:50%;
  display:flex;align-items:center;justify-content:center}
.donut-center{position:absolute;inset:20px;display:flex;flex-direction:column;align-items:center;
  justify-content:center;text-align:center}
.donut-center .n{font-size:1.5rem;font-weight:700}
.donut-center .t{font-size:.62rem;color:#64748b;text-transform:uppercase}
.donut-legend{display:flex;flex-direction:column;gap:.5rem}
.donut-legend-item{display:flex;align-items:center;gap:.5rem;font-size:.8rem}
.donut-legend-item .dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.donut-legend-item .pct{margin-left:auto;color:#64748b;font-size:.74rem}

.cat-row{display:flex;align-items:center;gap:.7rem;margin-bottom:.7rem;font-size:.8rem}
.cat-row .cat-label{width:150px;flex-shrink:0;color:#cbd5e1}
.cat-bar-bg{flex:1;background:#1e293b;border-radius:4px;height:9px;overflow:hidden}
.cat-bar-fill{height:100%;border-radius:4px}
.cat-count{width:24px;text-align:right;color:#94a3b8;font-weight:600}

.risky-row{display:flex;justify-content:space-between;align-items:center;padding:.55rem 0;
  border-bottom:1px solid #1e293b;font-size:.8rem}
.risky-row:last-child{border-bottom:none}
.risky-id{color:#cbd5e1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-right:.6rem}
.badge{color:#fff;padding:.18rem .55rem;border-radius:.3rem;font-size:.68rem;font-weight:700;white-space:nowrap;flex-shrink:0}

.legend{display:flex;gap:1.2rem;margin-bottom:.75rem;flex-wrap:wrap}
.legend-item{display:flex;align-items:center;gap:.4rem;font-size:.78rem;color:#94a3b8}
.dot{width:11px;height:11px;border-radius:50%;display:inline-block}
#graph-canvas{width:100%;height:440px;background:#0b1120;border-radius:6px;display:block;cursor:grab}
#graph-canvas:active{cursor:grabbing}
.graph-hint{font-size:.72rem;color:#475569;margin-top:.5rem}

table{width:100%;border-collapse:collapse}
th{text-align:left;padding:.5rem .75rem;font-size:.7rem;color:#64748b;text-transform:uppercase;border-bottom:1px solid #23304a}
td{padding:.55rem .75rem;font-size:.81rem;border-bottom:1px solid #1a2540;vertical-align:top}
tr:hover td{background:#182135}
small{color:#64748b;display:block;margin-top:.1rem}

.overview-row{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.1rem}
.overview-card{background:#141b2d;border:1px solid #23304a;border-radius:10px;padding:1rem 1.1rem;
  display:flex;align-items:center;gap:.8rem}
.overview-icon{font-size:1.5rem}
.overview-card .n{font-size:1.3rem;font-weight:700}
.overview-card .t{font-size:.72rem;color:#94a3b8}

.crit-list{list-style:none}
.crit-item{display:flex;align-items:center;gap:.6rem;padding:.55rem 0;border-bottom:1px solid #1e293b;font-size:.82rem}
.crit-item:last-child{border-bottom:none}
.crit-dot{width:8px;height:8px;border-radius:50%;background:#dc2626;flex-shrink:0}
.crit-text{flex:1;color:#e2e8f0}
.crit-principal{color:#64748b;font-size:.74rem}
"""


def build_html_export(result: "ScanResult") -> str:
    import json as _json
    from collections import Counter

    findings = result.findings
    risk = result.risk
    graph = result.graph
    sev_counts = risk.finding_counts
    total = max(len(findings), 1)

    # -- attack graph data (canvas) — same logic as before, unchanged --------
    nodes, edges = [], []
    for pid in graph.principal_ids():
        p = graph.get_principal(pid)
        is_critical = any(f.principal_id == pid and f.severity.name == "CRITICAL" for f in findings)
        is_high = any(f.principal_id == pid and f.severity.name == "HIGH" for f in findings)
        color = "#dc2626" if is_critical else "#ea580c" if is_high else "#3b82f6"
        nodes.append({"id": pid, "label": pid.split("@")[0], "title": pid, "color": color, "shape": "ellipse"})
    # GCP graph has role_ids()/roles_of() — AWS graph has permission_ids()/permissions_of()
    _is_aws = hasattr(graph, "permission_ids")
    if _is_aws:
        for perm in graph.permission_ids():
            short = perm.replace("managed-policy:arn:aws:iam::aws:policy/", "policy/")
            short = short.replace("managed-policy:", "")[:40]
            nodes.append({"id": perm, "label": short, "title": perm, "color": "#475569", "shape": "box"})
        for pid in graph.principal_ids():
            for perm in graph.permissions_of(pid):
                edges.append({"from": pid, "to": perm, "color": "#475569", "dashes": False, "label": ""})
    else:
        for rid in graph.role_ids():
            nodes.append({"id": rid, "label": rid.replace("roles/", ""), "title": rid, "color": "#475569", "shape": "box"})
        for pid in graph.principal_ids():
            for role in graph.roles_of(pid):
                edges.append({"from": pid, "to": role, "color": "#475569", "dashes": False, "label": ""})
    for src, tgt, rule_id in result.escalation_edges:
        edges.append({"from": src, "to": tgt, "color": "#dc2626", "dashes": True, "label": rule_id})
    graph_data = _json.dumps({"nodes": nodes, "edges": edges})

    # -- score cards row -------------------------------------------------------
    rating_color = {"Excellent": "#22c55e", "Good": "#22c55e", "Fair": "#ca8a04",
                     "Poor": "#ea580c", "Critical": "#dc2626"}.get(risk.rating.value, "#f59e0b")

    def _mini_card(label: str, value, color: str, sub: str) -> str:
        return (f'<div class="score-card"><div class="label">{label}</div>'
                f'<div class="value" style="color:{color}">{value}</div>'
                f'<div class="sub">{sub}</div></div>')

    score_cards = (
        f'<div class="score-card"><div class="label">🛡️ Security Score</div>'
        f'<div class="value" style="color:{rating_color}">{risk.score}/100</div>'
        f'<div class="sub">{risk.rating.value}</div>'
        f'<div class="score-bar-bg"><div class="score-bar-fill" '
        f'style="width:{risk.score}%;background:{rating_color}"></div></div></div>'
        + _mini_card("📋 Total Findings", len(findings), "#60a5fa", "Across all severity levels")
        + _mini_card("🔴 Critical", sev_counts.get("CRITICAL", 0), SEVERITY_HEX["CRITICAL"],
                     f"{round(sev_counts.get('CRITICAL', 0) / total * 100)}% of findings")
        + _mini_card("🟠 High", sev_counts.get("HIGH", 0), SEVERITY_HEX["HIGH"],
                     f"{round(sev_counts.get('HIGH', 0) / total * 100)}% of findings")
        + _mini_card("🟡 Medium", sev_counts.get("MEDIUM", 0), SEVERITY_HEX["MEDIUM"],
                     f"{round(sev_counts.get('MEDIUM', 0) / total * 100)}% of findings")
        + _mini_card("🟢 Low", sev_counts.get("LOW", 0), SEVERITY_HEX["LOW"],
                     f"{round(sev_counts.get('LOW', 0) / total * 100)}% of findings")
    )

    # -- donut chart (findings by severity) -------------------------------------
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    cum = 0.0
    stops = []
    for sev in order:
        cnt = sev_counts.get(sev, 0)
        if cnt == 0:
            continue
        start = cum
        cum += (cnt / total) * 100
        stops.append(f"{SEVERITY_HEX[sev]} {start:.2f}% {cum:.2f}%")
    gradient = ", ".join(stops) if stops else "#1e293b 0% 100%"

    donut_legend = "".join(
        f'<div class="donut-legend-item"><span class="dot" style="background:{SEVERITY_HEX[sev]}"></span>'
        f'{sev.title()}<span class="pct">{sev_counts.get(sev, 0)} ({round(sev_counts.get(sev, 0) / total * 100)}%)</span></div>'
        for sev in order
    )

    donut_html = (
        '<div class="panel"><h2>Findings by Severity</h2><div class="donut-wrap">'
        f'<div class="donut" style="background:conic-gradient({gradient})">'
        f'<div class="donut-center"><div class="n">{len(findings)}</div><div class="t">Total</div></div>'
        '</div>'
        f'<div class="donut-legend">{donut_legend}</div>'
        '</div></div>'
    )

    # -- findings by category (bars) ---------------------------------------------
    cat_counts: Counter = Counter(RULE_CATEGORY.get(f.rule_id, "Other") for f in findings)
    max_cat = max(cat_counts.values(), default=1)
    cat_rows = "".join(
        f'<div class="cat-row"><span class="cat-label">{_html_escape(cat)}</span>'
        f'<div class="cat-bar-bg"><div class="cat-bar-fill" style="width:{cnt / max_cat * 100:.0f}%;'
        f'background:{CATEGORY_COLOR.get(cat, "#64748b")}"></div></div>'
        f'<span class="cat-count">{cnt}</span></div>'
        for cat, cnt in cat_counts.most_common()
    )
    _no_findings_html = "<p style='color:#64748b;font-size:.8rem'>No findings.</p>"
    category_html = f'<div class="panel"><h2>Findings by Category</h2>{cat_rows or _no_findings_html}</div>'

    # -- top 5 risky principals -----------------------------------------------
    worst_severity: dict[str, Severity] = {}
    for f in findings:
        cur = worst_severity.get(f.principal_id)
        if cur is None or f.severity > cur:
            worst_severity[f.principal_id] = f.severity
    blast_by_id = {r.principal_id: r for r in result.blast_radius}
    ranked = sorted(
        worst_severity.items(),
        key=lambda kv: (kv[1], blast_by_id[kv[0]].percentage if kv[0] in blast_by_id else 0),
        reverse=True,
    )[:5]
    risky_rows = "".join(
        f'<div class="risky-row"><span class="risky-id">{_html_escape(pid)}</span>'
        f'<span class="badge" style="background:{SEVERITY_HEX.get(sev.name, "#64748b")}">{sev.name}</span></div>'
        for pid, sev in ranked
    )
    top_risky_html = f'<div class="panel"><h2>Top 5 Risky Principals</h2>{risky_rows or _no_findings_html}</div>'

    # -- MITRE ATT&CK mapping table -----------------------------------------------
    mitre_counts: Counter = Counter()
    mitre_names: dict[str, str] = {}
    for f in findings:
        mitre_counts[f.mitre_technique_id] += 1
        mitre_names[f.mitre_technique_id] = f.mitre_technique_name
    mitre_rows = "".join(
        f'<tr><td>{_html_escape(mitre_names[tid])}</td><td><code>{tid}</code></td>'
        f'<td style="text-align:right;font-weight:700">{cnt}</td></tr>'
        for tid, cnt in mitre_counts.most_common()
    )
    mitre_html = (
        '<div class="panel"><h2>MITRE ATT&CK Mapping</h2><table>'
        '<tr><th>Technique</th><th>ID</th><th style="text-align:right">Count</th></tr>'
        + (mitre_rows or '<tr><td colspan="3" style="color:#64748b">No findings.</td></tr>')
        + '</table></div>'
    )

    # -- blast radius overview cards -----------------------------------------------
    at_risk = [r for r in result.blast_radius if r.percentage > 0]
    sa_at_risk = sum(
        1 for r in at_risk
        if (p := graph.get_principal(r.principal_id)) is not None and p.member_type.value == "serviceAccount"
    )
    max_blast = max((r.percentage for r in result.blast_radius), default=0.0)
    overview_html = (
        '<div class="overview-row">'
        f'<div class="overview-card"><span class="overview-icon">🧭</span><div><div class="n">{len(at_risk)}</div>'
        '<div class="t">Principals at Risk</div></div></div>'
        f'<div class="overview-card"><span class="overview-icon">🤖</span><div><div class="n">{sa_at_risk}</div>'
        '<div class="t">Service Accounts at Risk</div></div></div>'
        f'<div class="overview-card"><span class="overview-icon">🔗</span><div><div class="n">{len(result.escalation_edges)}</div>'
        '<div class="t">Escalation Paths</div></div></div>'
        f'<div class="overview-card"><span class="overview-icon">💥</span><div><div class="n">{max_blast:.0f}%</div>'
        '<div class="t">Max Blast Radius</div></div></div>'
        '</div>'
    )

    # -- recent critical/high findings list -----------------------------------------
    top_findings = [f for f in findings if f.severity.name in ("CRITICAL", "HIGH")][:5]
    crit_items = "".join(
        f'<li class="crit-item"><span class="crit-dot" style="background:{SEVERITY_HEX[f.severity.name]}"></span>'
        f'<span class="crit-text">{_html_escape(f.title)}<div class="crit-principal">{_html_escape(f.principal_id)}</div></span></li>'
        for f in top_findings
    )
    _no_crit_html = "<p style='color:#64748b;font-size:.8rem'>No critical or high findings.</p>"
    critical_list_html = (
        '<div class="panel"><h2>Recent Critical Findings</h2>'
        f'<ul class="crit-list">{crit_items or _no_crit_html}</ul>'
        '</div>'
    )

    # -- full findings + blast radius tables (unchanged from before) ------------------
    findings_rows = ""
    for f in findings:
        c = SEVERITY_HEX.get(f.severity.name, "#6b7280")
        findings_rows += (
            f"<tr><td><span class='badge' style='background:{c}'>{f.severity.name}</span></td>"
            f"<td>{_html_escape(f.title)}<br><small>{f.rule_id}</small></td>"
            f"<td>{_html_escape(f.principal_id)}</td><td>{f.mitre_technique_id}</td>"
            f"<td>{_html_escape(f.description)}</td></tr>"
        )
    blast_rows = ""
    for r in result.blast_radius[:10]:
        reaches = ", ".join(r.reachable_principals) if r.reachable_principals else "(nothing further)"
        pct_color = "#dc2626" if r.percentage >= 75 else "#ea580c" if r.percentage >= 33 else "#22c55e"
        blast_rows += (
            f"<tr><td>{_html_escape(r.principal_id)}</td>"
            f"<td style='color:{pct_color};font-weight:bold'>{r.percentage:.1f}%</td>"
            f"<td>{_html_escape(reaches)}</td></tr>"
        )

    graph_script = """
(function(){
var DATA=__GRAPH_DATA__;
var canvas=document.getElementById("graph-canvas");
var ctx=canvas.getContext("2d");
var W,H,zoom=1,pan={x:0,y:0};
var nodeMap={};
var dragging=null,dragOX=0,dragOY=0;
var panning=false,panStart={x:0,y:0},panBase={x:0,y:0};
var hover=null;

function setup(){
  W=canvas.offsetWidth||900; H=440;
  canvas.width=W; canvas.height=H;
  var cx=W/2,cy=H/2;
  var ellipseNodes=DATA.nodes.filter(function(n){return n.shape==="ellipse";});
  var boxNodes=DATA.nodes.filter(function(n){return n.shape==="box";});
  var outerR=Math.min(W,H)*0.35;
  var innerR=Math.min(W,H)*0.14;
  ellipseNodes.forEach(function(n,i){
    var a=(i/Math.max(ellipseNodes.length,1))*2*Math.PI-Math.PI/2;
    nodeMap[n.id]=Object.assign({},n,{x:cx+outerR*Math.cos(a),y:cy+outerR*Math.sin(a),rx:36,ry:22});
  });
  boxNodes.forEach(function(n,i){
    var a=(i/Math.max(boxNodes.length,1))*2*Math.PI-Math.PI/2;
    nodeMap[n.id]=Object.assign({},n,{x:cx+innerR*Math.cos(a),y:cy+innerR*Math.sin(a),rx:28,ry:14});
  });
  draw();
}

function ws(x,y){return {x:x*zoom+pan.x,y:y*zoom+pan.y};}
function sw(x,y){return {x:(x-pan.x)/zoom,y:(y-pan.y)/zoom};}

function hitNode(sx,sy){
  var w=sw(sx,sy);
  var found=null;
  Object.keys(nodeMap).forEach(function(k){
    var n=nodeMap[k];
    var dx=(w.x-n.x)/(n.rx+6),dy=(w.y-n.y)/(n.ry+6);
    if(dx*dx+dy*dy<=1) found=n;
  });
  return found;
}

function draw(){
  ctx.clearRect(0,0,W,H);
  DATA.edges.forEach(function(e){
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
    var ang=Math.atan2(y2-y1,x2-x1),hs=9;
    ctx.fillStyle=e.color;
    ctx.beginPath();ctx.moveTo(x2,y2);
    ctx.lineTo(x2-hs*Math.cos(ang-.4),y2-hs*Math.sin(ang-.4));
    ctx.lineTo(x2-hs*Math.cos(ang+.4),y2-hs*Math.sin(ang+.4));
    ctx.closePath();ctx.fill();
    if(e.dashes&&e.label){
      ctx.fillStyle="#fca5a5";ctx.font="bold "+Math.max(9,10*zoom)+"px sans-serif";
      ctx.textAlign="center";ctx.textBaseline="middle";
      ctx.fillText(e.label,(x1+x2)/2,(y1+y2)/2-7);
    }
    ctx.restore();
  });
  Object.keys(nodeMap).forEach(function(k){
    var n=nodeMap[k];
    var s=ws(n.x,n.y);
    var rx=n.rx*zoom,ry=n.ry*zoom;
    var isHover=(hover&&hover.id===n.id);
    ctx.save();
    ctx.shadowColor=n.color;ctx.shadowBlur=isHover?18:6;
    ctx.fillStyle=n.color;
    ctx.beginPath();
    if(n.shape==="box"){
      var bw=rx*2,bh=ry*2;
      ctx.roundRect(s.x-bw/2,s.y-bh/2,bw,bh,4);
    }else{
      ctx.ellipse(s.x,s.y,rx,ry,0,0,2*Math.PI);
    }
    ctx.fill();
    ctx.shadowBlur=0;
    var fs=Math.max(9,Math.min(13,11*zoom));
    ctx.fillStyle="#fff";ctx.font=(n.shape==="box"?"":"bold ")+fs+"px sans-serif";
    ctx.textAlign="center";ctx.textBaseline="middle";
    var maxW=rx*1.8,txt=n.label;
    if(ctx.measureText(txt).width>maxW)txt=txt.slice(0,Math.floor(txt.length*maxW/ctx.measureText(txt).width)-1)+"…";
    ctx.fillText(txt,s.x,s.y);
    ctx.restore();
  });
  if(hover){
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
  }
}

canvas.addEventListener("mousedown",function(e){
  var r=canvas.getBoundingClientRect(),mx=e.clientX-r.left,my=e.clientY-r.top;
  var n=hitNode(mx,my);
  if(n){dragging=n;var s=ws(n.x,n.y);dragOX=mx-s.x;dragOY=my-s.y;}
  else{panning=true;panStart={x:mx,y:my};panBase={x:pan.x,y:pan.y};}
});
canvas.addEventListener("mousemove",function(e){
  var r=canvas.getBoundingClientRect(),mx=e.clientX-r.left,my=e.clientY-r.top;
  if(dragging){var w=sw(mx-dragOX,my-dragOY);dragging.x=w.x;dragging.y=w.y;draw();}
  else if(panning){pan.x=panBase.x+(mx-panStart.x);pan.y=panBase.y+(my-panStart.y);draw();}
  else{var n=hitNode(mx,my);if(n!==hover){hover=n;draw();}}
});
canvas.addEventListener("mouseup",function(){dragging=null;panning=false;});
canvas.addEventListener("mouseleave",function(){dragging=null;panning=false;hover=null;draw();});
canvas.addEventListener("wheel",function(e){
  e.preventDefault();
  var r=canvas.getBoundingClientRect(),mx=e.clientX-r.left,my=e.clientY-r.top;
  var f=e.deltaY<0?1.12:.89;
  pan.x=(pan.x-mx)*f+mx;pan.y=(pan.y-my)*f+my;
  zoom=Math.max(.2,Math.min(5,zoom*f));draw();
},{passive:false});
window.addEventListener("resize",function(){W=canvas.offsetWidth;canvas.width=W;canvas.height=H;draw();});
setup();
})();
""".replace("__GRAPH_DATA__", graph_data)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CloudSentrix Dashboard</title>
<style>{DASHBOARD_CSS}</style>
</head>
<body>
<div class="header">
  <div>
    <h1>Dashboard</h1>
    <div class="meta">Overview of your GCP security posture</div>
  </div>
  <div class="meta" style="text-align:right">
    Source: {_html_escape(result.source_file)}<br>Generated: {generated_at}
  </div>
</div>

<div class="score-row">{score_cards}</div>

<div class="grid-3">{donut_html}{category_html}{top_risky_html}</div>

<div class="panel" style="margin-bottom:1.1rem">
  <h2>🔴 Interactive Attack Graph</h2>
  <div class="legend">
    <span class="legend-item"><span class="dot" style="background:#dc2626"></span>Critical</span>
    <span class="legend-item"><span class="dot" style="background:#ea580c"></span>High</span>
    <span class="legend-item"><span class="dot" style="background:#3b82f6"></span>Normal</span>
    <span class="legend-item"><span class="dot" style="background:#475569;border-radius:2px"></span>Role</span>
    <span class="legend-item"><span style="color:#dc2626">┈┈&gt;</span>&nbsp;Escalation path</span>
  </div>
  <canvas id="graph-canvas"></canvas>
  <div class="graph-hint">Drag canvas to pan &nbsp;|&nbsp; Scroll to zoom &nbsp;|&nbsp; Drag a node to move it &nbsp;|&nbsp; Hover for details</div>
</div>

<div class="grid-3" style="grid-template-columns:1.3fr 1fr">{mitre_html}{critical_list_html}</div>

<div style="margin-bottom:.75rem"><h2 style="font-size:.95rem;color:#f1f5f9">Blast Radius Overview</h2></div>
{overview_html}

<div class="panel" style="margin-bottom:1.1rem">
  <h2>🎯 All Findings ({len(findings)})</h2>
  <table>
    <tr><th>Severity</th><th>Finding</th><th>Principal</th><th>MITRE</th><th>Details</th></tr>
    {findings_rows or '<tr><td colspan="5" style="color:#64748b">No findings.</td></tr>'}
  </table>
</div>

<div class="panel">
  <h2>💥 Blast Radius</h2>
  <table>
    <tr><th>Principal</th><th>Blast Radius</th><th>Can Reach</th></tr>
    {blast_rows or '<tr><td colspan="3" style="color:#64748b">No data.</td></tr>'}
  </table>
</div>

<script>{graph_script}</script>
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
    writer.print("[bold]── GCP Detection Rules ───────────────────────────────[/bold]")
    for rule in DetectionEngine().rules:
        color = SEVERITY_COLOR.get(rule.severity, "white")
        writer.print(f"[{color}]{rule.rule_id}[/{color}] {rule.title}  ({rule.severity})")
        writer.print(f"  MITRE: {rule.mitre_technique_id} - {rule.mitre_technique_name}")
    writer.print("")

    writer.print("[bold]── AWS Detection Rules ───────────────────────────────[/bold]")
    from aws_detection import AWSDetectionEngine
    for rule in AWSDetectionEngine()._default_rules():
        color = SEVERITY_COLOR.get(rule.severity, "white")
        writer.print(f"[{color}]{rule.rule_id}[/{color}] {rule.title}  ({rule.severity})")
        writer.print(f"  MITRE: {rule.mitre_technique_id} - {rule.mitre_technique_name}")
    writer.print("")

    writer.print("[bold]── Azure Detection Rules ─────────────────────────────[/bold]")
    sev_color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "green"}
    for rule in get_azure_rules():
        color = sev_color.get(rule["severity"], "white")
        writer.print(f"[{color}]{rule['id']}[/{color}] {rule['title']}  ({rule['severity']})")
        writer.print(f"  MITRE: {rule['mitre']}")
    writer.print("")


def render_principals_list(writer: OutputWriter, graph) -> None:
    writer.print("[bold]── Principals ────────────────────────────────────────[/bold]")
    _is_aws = hasattr(graph, "permission_ids")
    _is_azure = hasattr(graph, "assignments")  # AzureIAMData

    if _is_azure:
        # Azure — group assignments by principal
        from collections import defaultdict
        groups: dict = defaultdict(list)
        for assign in graph.assignments:
            groups[assign.principal_name].append(assign)
        for name in sorted(groups):
            assigns = groups[name]
            ptype = assigns[0].principal_type
            writer.print(f"[bold]{name}[/bold] ({ptype})")
            for a in assigns[:3]:
                writer.print(f"    - {a.role_definition_name} @ {a.scope_level}")
        writer.print("")
        return

    for principal_id in sorted(graph.principal_ids()):
        p = graph.get_principal(principal_id)
        if _is_aws:
            ptype = p.principal_type.value if p is not None else "unknown"
            writer.print(f"[bold]{principal_id}[/bold] ({ptype})")
            for perm in sorted(graph.permissions_of(principal_id))[:5]:
                short = perm.replace("managed-policy:arn:aws:iam::aws:policy/", "policy/")
                writer.print(f"    - {short}")
        else:
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

    scan_parser = subparsers.add_parser("scan", help="Scan a GCP or AWS IAM policy export for privilege-escalation risk.")
    scan_parser.add_argument("--file", "-f", required=True, help="Path to a GCP or AWS IAM policy JSON export.")
    scan_parser.add_argument(
        "--cloud", default="gcp", choices=["gcp", "aws", "azure"],
        help="Cloud provider: 'gcp' (default) or 'aws'.",
    )
    scan_parser.add_argument(
        "--severity", default="all", choices=sorted(SEVERITY_CHOICES),
        help="Minimum severity to display (default: all).",
    )
    scan_parser.add_argument(
        "--top", type=int, default=5,
        help="Number of blast-radius rows to display (default: 5).",
    )
    scan_parser.add_argument(
        "--notify", default=None, choices=["slack", "teams"],
        help="Send findings to Slack or Teams after scan.",
    )
    scan_parser.add_argument(
        "--webhook", default=None, metavar="URL",
        help="Webhook URL (overrides env vars CLOUDSENTRIX_SLACK_WEBHOOK / CLOUDSENTRIX_TEAMS_WEBHOOK).",
    )
    scan_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    scan_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    blast_parser = subparsers.add_parser(
        "blast-radius", help="Show the blast radius for one specific principal."
    )
    blast_parser.add_argument("--file", "-f", required=True, help="Path to a GCP IAM policy JSON export.")
    blast_parser.add_argument("--principal", "-p", required=True, help="Principal id (e.g. an email) to check.")
    blast_parser.add_argument("--cloud", default="gcp", choices=["gcp", "aws", "azure"], help="Cloud provider.")
    blast_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    blast_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    # report-multi command
    rmp = subparsers.add_parser(
        "report-multi",
        help="Generate a single PDF report covering GCP, AWS, and Azure in one document.",
    )
    rmp.add_argument("--gcp",   default=None, metavar="FILE", help="GCP IAM JSON export.")
    rmp.add_argument("--aws",   default=None, metavar="FILE", help="AWS IAM JSON export.")
    rmp.add_argument("--azure", default=None, metavar="FILE", help="Azure RBAC JSON export.")
    rmp.add_argument("--output", "-o", default="multi_cloud_report.pdf",
                     help="Output PDF file (default: multi_cloud_report.pdf).")
    rmp.add_argument("--no-ai", action="store_true", default=True,
                     help="Skip Gemini AI summary (default: True).")
    rmp.add_argument("--no-color",  action="store_true", help="Disable colored output.")
    rmp.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    # dashboard command
    dash_parser = subparsers.add_parser(
        "dashboard",
        help="Generate a single multi-cloud HTML dashboard comparing GCP, AWS, and Azure.",
    )
    dash_parser.add_argument("--gcp",   default=None, metavar="FILE", help="GCP IAM JSON export file.")
    dash_parser.add_argument("--aws",   default=None, metavar="FILE", help="AWS IAM JSON export file.")
    dash_parser.add_argument("--azure", default=None, metavar="FILE", help="Azure RBAC JSON export file.")
    dash_parser.add_argument("--output", "-o", default="multi_cloud_dashboard.html", metavar="FILE",
                             help="Output HTML file (default: multi_cloud_dashboard.html).")
    dash_parser.add_argument("--no-color",  action="store_true", help="Disable colored output.")
    dash_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    rules_parser = subparsers.add_parser("rules", help="List every detection rule this tool checks for.")
    rules_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    rules_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    list_parser = subparsers.add_parser(
        "list-principals", help="Quick inventory: every principal and the roles it holds."
    )
    list_parser.add_argument("--file", "-f", required=True, help="Path to a GCP IAM policy JSON export.")
    list_parser.add_argument("--cloud", default="gcp", choices=["gcp", "aws", "azure"], help="Cloud provider.")
    list_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    list_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    validate_parser = subparsers.add_parser(
        "validate", help="Check that a file is a well-formed GCP IAM policy export, before scanning it."
    )
    validate_parser.add_argument("--file", "-f", required=True, help="Path to a GCP or AWS IAM policy JSON export.")
    validate_parser.add_argument("--cloud", default="gcp", choices=["gcp", "aws", "azure"], help="Cloud provider.")
    validate_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    validate_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    score_parser = subparsers.add_parser(
        "score", help="Print only the overall security score — useful for CI badges/checks."
    )
    score_parser.add_argument("--file", "-f", required=True, help="Path to a GCP IAM policy JSON export.")
    score_parser.add_argument("--cloud", default="gcp", choices=["gcp", "aws", "azure"], help="Cloud provider.")
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
    compare_parser.add_argument("--cloud", default="gcp", choices=["gcp", "aws", "azure"], help="Cloud provider.")
    compare_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    compare_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    path_parser = subparsers.add_parser(
        "principal-path", help="Show the escalation path (if any) from one principal to another."
    )
    path_parser.add_argument("--file", "-f", required=True, help="Path to a GCP IAM policy JSON export.")
    path_parser.add_argument("--source", "-s", required=True, help="Starting principal id (e.g. an email).")
    path_parser.add_argument("--target", "-t", required=True, help="Target principal id to try to reach.")
    path_parser.add_argument("--cloud", default="gcp", choices=["gcp", "aws", "azure"], help="Cloud provider.")
    path_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    path_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    mitre_parser = subparsers.add_parser(
        "mitre-map", help="Map every finding onto the MITRE ATT&CK Cloud Matrix."
    )
    mitre_parser.add_argument("--file", "-f", required=True, help="Path to a GCP IAM policy JSON export.")
    mitre_parser.add_argument("--cloud", default="gcp", choices=["gcp", "aws", "azure"], help="Cloud provider.")
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
    remediate_parser.add_argument("--cloud", default="gcp", choices=["gcp", "aws", "azure"], help="Cloud provider.")
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
    export_parser.add_argument("--cloud", default="gcp", choices=["gcp", "aws", "azure"], help="Cloud provider.")
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
    watch_parser.add_argument("--cloud", default="gcp", choices=["gcp", "aws", "azure"], help="Cloud provider.")
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
    report_parser.add_argument("--cloud", default="gcp", choices=["gcp", "aws", "azure"], help="Cloud provider.")
    report_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    report_parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner.")

    live_scan_parser = subparsers.add_parser(
        "live-scan",
        help="Fetch live IAM policy from GCP or AWS and scan it directly.",
    )
    live_scan_parser.add_argument(
        "--project", "-p", default=None,
        help="GCP Project ID to fetch and scan (e.g. my-project-123). Required for --cloud gcp.",
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
    live_scan_parser.add_argument(
        "--cloud", default="gcp", choices=["gcp", "aws", "azure"],
        help="Cloud provider to scan (default: gcp).",
    )
    # AWS-specific options
    live_scan_parser.add_argument(
        "--profile", default=None,
        help="[AWS] AWS CLI profile name (from ~/.aws/credentials). Default: use env vars.",
    )
    live_scan_parser.add_argument(
        "--region", default="us-east-1",
        help="[AWS] AWS region (default: us-east-1).",
    )
    live_scan_parser.add_argument(
        "--endpoint", default=None,
        help="[AWS] Override endpoint URL — use http://localhost:4566 for LocalStack testing.",
    )
    # Azure-specific options
    live_scan_parser.add_argument(
        "--subscription", default=None,
        help="[Azure] Azure subscription ID or name. Default: uses currently active subscription.",
    )
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

    # Send notification if requested
    notify = getattr(args, "notify", None)
    if notify:
        webhook = getattr(args, "webhook", None)
        writer.print(f"[bold cyan]Sending {notify.title()} notification...[/bold cyan]")
        ok = send_notification(notify, result.findings, result.risk,
                               args.cloud, args.file, webhook)
        if not ok:
            writer.print(
                f"[yellow]Tip:[/yellow] Set env var "
                f"CLOUDSENTRIX_SLACK_WEBHOOK or CLOUDSENTRIX_TEAMS_WEBHOOK, "
                f"or pass --webhook <url>"
            )

    return determine_exit_code(result.findings)


def _handle_blast_radius(writer: OutputWriter, args: argparse.Namespace) -> int:
    result = run_scan(args.file, cloud=args.cloud)
    match = find_blast_radius_for(result.blast_radius, args.principal)
    if match is None:
        writer.print(f"[bold red]Error:[/bold red] '{args.principal}' was not found in {args.file}.")
        return 2
    render_single_blast_radius(writer, match)
    return 0


def _handle_report_multi(writer: OutputWriter, args: argparse.Namespace) -> int:
    """Generate a multi-cloud PDF report."""
    gcp   = getattr(args, "gcp", None)
    aws   = getattr(args, "aws", None)
    azure = getattr(args, "azure", None)
    out   = getattr(args, "output", "multi_cloud_report.pdf")
    no_ai = getattr(args, "no_ai", True)

    if not any([gcp, aws, azure]):
        writer.print("[bold red]Error:[/bold red] Provide at least one cloud file.")
        writer.print("  --gcp my_gcp.json  --aws my_aws.json  --azure my_azure.json")
        return 2

    writer.print("[bold cyan]Generating Multi-Cloud PDF Report...[/bold cyan]")
    if gcp:   writer.print(f"  GCP   -> {gcp}")
    if aws:   writer.print(f"  AWS   -> {aws}")
    if azure: writer.print(f"  Azure -> {azure}")

    try:
        scanned, total = generate_multi_pdf(
            gcp_file=gcp, aws_file=aws, azure_file=azure,
            output_path=out, no_ai=no_ai,
        )
    except ImportError as exc:
        writer.print(f"[bold red]Error:[/bold red] {exc}")
        return 2
    except Exception as exc:
        writer.print(f"[bold red]Error:[/bold red] {exc}")
        return 2

    writer.print(f"[bold green]PDF generated![/bold green] {scanned} cloud(s) - {total} finding(s)")
    writer.print(f"[bold green]Output:[/bold green] {out}")
    return 0


def _handle_dashboard(writer: OutputWriter, args: argparse.Namespace) -> int:
    """Generate multi-cloud HTML dashboard."""
    gcp   = getattr(args, "gcp", None)
    aws   = getattr(args, "aws", None)
    azure = getattr(args, "azure", None)
    out   = getattr(args, "output", "multi_cloud_dashboard.html")

    if not any([gcp, aws, azure]):
        writer.print("[bold red]Error:[/bold red] Provide at least one cloud file.")
        writer.print("  --gcp my_gcp.json  --aws my_aws.json  --azure my_azure.json")
        return 2

    writer.print("[bold cyan]Generating Multi-Cloud Dashboard...[/bold cyan]")
    if gcp:
        writer.print(f"  GCP   → {gcp}")
    if aws:
        writer.print(f"  AWS   → {aws}")
    if azure:
        writer.print(f"  Azure → {azure}")

    try:
        scanned, total = generate_multi_dashboard(
            gcp_file=gcp,
            aws_file=aws,
            azure_file=azure,
            output_path=out,
        )
    except Exception as exc:
        writer.print(f"[bold red]Error:[/bold red] {exc}")
        return 2

    writer.print(
        f"[bold green]Dashboard generated![/bold green] "
        f"{scanned} cloud(s) - {total} finding(s)"
    )
    writer.print(f"[bold green]📄 Output:[/bold green] {out}")
    writer.print("[dim]Open the file in your browser to view the dashboard.[/dim]")
    return 0


def _handle_rules(writer: OutputWriter) -> int:
    render_rules_list(writer)
    return 0


def _handle_list_principals(writer: OutputWriter, args: argparse.Namespace) -> int:
    graph = run_list_principals(args.file, cloud=args.cloud)
    render_principals_list(writer, graph)
    return 0


def _handle_validate(writer: OutputWriter, args: argparse.Namespace) -> int:
    cloud = getattr(args, "cloud", "gcp")
    writer.print("[bold]── Validation ────────────────────────────────────────[/bold]")
    if cloud == "aws":
        try:
            from aws_parser import AWSIAMParser, AWSParserError
            policy = AWSIAMParser().parse_file(args.file)
            stats = policy.summary()
            writer.print(f"[bold green]VALID[/bold green] — {args.file} is a valid AWS IAM authorization-details export.")
            writer.print(f"  Principals : {stats['total_principals']} ({stats['users']} users, {stats['groups']} groups, {stats['roles']} roles)")
            writer.print(f"  Permissions: {stats['total_permissions']} total")
        except Exception as exc:
            writer.print(f"[bold red]INVALID[/bold red] — {exc}")
            return 2
        return 0
    if cloud == "azure":
        try:
            iam = parse_azure_file(args.file)
            unique = {a.principal_name for a in iam.assignments}
            writer.print(f"[bold green]VALID[/bold green] — {args.file} is a valid Azure RBAC export.")
            writer.print(f"  Assignments     : {len(iam.assignments)}")
            writer.print(f"  Unique Principals: {len(unique)}")
            writer.print(f"  Role Definitions : {len(iam.definitions)}")
            writer.print(f"  Service Principals: {len(iam.service_principals)}")
        except Exception as exc:
            writer.print(f"[bold red]INVALID[/bold red] — {exc}")
            return 2
        return 0
    try:
        policy, warnings = run_validate(args.file)
    except IAMParserError as exc:
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


def _handle_export_azure(writer: OutputWriter, args: argparse.Namespace) -> int:
    """Azure export — uses azure_exporter directly (supports JSON/CSV/SARIF/HTML)."""
    try:
        iam = parse_azure_file(args.file)
    except Exception as exc:
        writer.print(f"[bold red]Error parsing Azure file:[/bold red] {exc}")
        return 2

    az_findings = run_azure_detections(iam)
    az_score = score_azure(az_findings, iam)
    az_blast = calculate_azure_blast_radius(iam)

    output_path = args.output or "azure_export.json"
    try:
        export_azure(az_findings, az_score, az_blast, iam, output_path)
        writer.print(
            f"[bold green]Exported[/bold green] {len(az_findings)} finding(s) "
            f"-> {output_path}"
        )
    except Exception as exc:
        writer.print(f"[bold red]Export error:[/bold red] {exc}")
        return 2
    return 0


def _handle_export(writer: OutputWriter, args: argparse.Namespace) -> int:
    cloud = getattr(args, "cloud", "gcp")
    if cloud == "azure":
        return _handle_export_azure(writer, args)
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
    cloud = getattr(args, "cloud", "gcp")

    # ── AWS live scan ────────────────────────────────────────────────────────
    if cloud == "aws":
        profile  = getattr(args, "profile", None)
        region   = getattr(args, "region", "us-east-1")
        endpoint = getattr(args, "endpoint", None)

        writer.print(
            f"[bold cyan]Fetching live AWS IAM data[/bold cyan] "
            f"(profile={profile or 'default'}, region={region}"
            + (f", endpoint={endpoint}" if endpoint else "") + ")"
        )
        try:
            scanner = AWSLiveScanner()
            aws_policy = scanner.scan(
                profile=profile,
                region=region,
                endpoint_url=endpoint,
                save_to=getattr(args, "save", None),
            )
        except AWSLiveScanError as exc:
            writer.print(f"[bold red]AWS Error:[/bold red] {exc}")
            return 2

        stats = aws_policy.summary()
        writer.print(
            f"[bold green]Fetched:[/bold green] "
            f"{stats['users']} user(s), {stats['groups']} group(s), "
            f"{stats['roles']} role(s)"
        )
        if getattr(args, "save", None):
            writer.print(f"[bold green]Saved to:[/bold green] {Path(args.save).resolve()}")

        # Run detection on the fetched policy
        from aws_graph import AWSIAMGraph as _AWSGraph
        aws_graph = _AWSGraph.from_policy(aws_policy)
        aws_findings = AWSDetectionEngine().run(aws_graph)
        gcp_findings = _aws_findings_to_gcp(aws_findings)
        risk = RiskScorer().score(gcp_findings)

        min_severity = SEVERITY_CHOICES[args.severity]
        displayed = filter_by_severity(gcp_findings, min_severity)
        render_findings(writer, displayed)
        render_risk_score(writer, risk)
        return determine_exit_code(gcp_findings)

    # ── Azure live scan ─────────────────────────────────────────────────────
    if cloud == "azure":
        subscription = getattr(args, "subscription", None)
        writer.print(
            f"[bold cyan]Fetching live Azure RBAC data[/bold cyan] "
            f"(subscription={subscription or 'current active'})"
        )
        try:
            iam = fetch_azure_live(
                subscription=subscription,
                save_path=getattr(args, "save", None),
            )
        except SystemExit:
            return 2
        except Exception as exc:
            writer.print(f"[bold red]Azure Error:[/bold red] {exc}")
            return 2

        unique = {a.principal_name for a in iam.assignments}
        writer.print(
            f"[bold green]Fetched:[/bold green] "
            f"{len(iam.assignments)} assignment(s), {len(unique)} unique principal(s)"
        )
        az_findings = run_azure_detections(iam)
        az_score = score_azure(az_findings, iam)
        gcp_findings = _azure_findings_to_gcp(az_findings)
        risk = RiskScorer().score(gcp_findings)
        min_severity = SEVERITY_CHOICES[args.severity]
        displayed = filter_by_severity(gcp_findings, min_severity)
        render_findings(writer, displayed)
        render_risk_score(writer, risk)
        return determine_exit_code(gcp_findings)

    # ── GCP live scan (original, unchanged) ──────────────────────────────────
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
        if args.command == "report-multi":
            return _handle_report_multi(writer, args)
        if args.command == "dashboard":
            return _handle_dashboard(writer, args)
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
