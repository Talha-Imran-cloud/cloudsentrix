"""
azure_risk_score.py
-------------------
Calculates a 0-100 security posture score for an Azure RBAC scan,
mirroring the GCP risk_score.py conventions.

Score starts at 100 and deductions are applied per finding.
Additional bonuses are applied for good hygiene signals.

Public API
  score_azure(findings: list[AzureFinding], iam: AzureIAMData) -> AzureScoreResult
"""

from __future__ import annotations

from dataclasses import dataclass, field

from azure_detection import AzureFinding
from azure_parser import AzureIAMData


# ---------------------------------------------------------------------------
# Deduction weights per severity
# ---------------------------------------------------------------------------

DEDUCTIONS: dict[str, int] = {
    "CRITICAL": 20,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
}

# Cap total deductions per severity bucket so a flooded scan
# doesn't push below 0 unfairly.
MAX_DEDUCTIONS: dict[str, int] = {
    "CRITICAL": 60,
    "HIGH": 30,
    "MEDIUM": 15,
    "LOW": 8,
}


@dataclass
class AzureScoreResult:
    score: int                               # 0–100
    grade: str                               # A / B / C / D / F
    summary: str                             # one-line verdict
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_assignments: int
    total_principals: int
    deductions_breakdown: dict[str, int] = field(default_factory=dict)
    bonus_breakdown: dict[str, int] = field(default_factory=dict)


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _summary(score: int, critical: int, high: int) -> str:
    if critical > 0:
        return (
            f"CRITICAL risk — {critical} critical finding(s) require immediate attention."
        )
    if high > 0:
        return f"Elevated risk — {high} high-severity finding(s) detected."
    if score >= 90:
        return "Low risk — Azure RBAC posture is strong."
    return "Moderate risk — review findings and apply remediations."


def score_azure(
    findings: list[AzureFinding],
    iam: AzureIAMData,
) -> AzureScoreResult:
    """Compute the 0-100 security score."""

    # Count by severity
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    # Apply deductions (capped per bucket)
    deductions: dict[str, int] = {}
    total_deduction = 0
    for sev, weight in DEDUCTIONS.items():
        raw = counts.get(sev, 0) * weight
        capped = min(raw, MAX_DEDUCTIONS[sev])
        deductions[sev] = capped
        total_deduction += capped

    # Hygiene bonuses (max +10)
    bonuses: dict[str, int] = {}
    bonus_total = 0

    # Bonus: no assignments at Tenant scope
    tenant_scope = [a for a in iam.assignments if a.scope_level == "Tenant"]
    if not tenant_scope:
        bonuses["No Tenant-scope assignments"] = 5
        bonus_total += 5

    # Bonus: no guest users with roles
    guests = [a for a in iam.assignments if a.is_guest]
    if not guests:
        bonuses["No guest user role assignments"] = 3
        bonus_total += 3

    # Bonus: no custom roles (simpler to audit)
    custom_roles = [d for d in iam.definitions if d.is_custom]
    if not custom_roles:
        bonuses["No custom role definitions"] = 2
        bonus_total += 2

    bonus_total = min(bonus_total, 10)

    raw_score = 100 - total_deduction + bonus_total
    final_score = max(0, min(100, raw_score))

    unique_principals = {a.principal_name for a in iam.assignments}

    return AzureScoreResult(
        score=final_score,
        grade=_grade(final_score),
        summary=_summary(final_score, counts["CRITICAL"], counts["HIGH"]),
        total_findings=len(findings),
        critical_count=counts["CRITICAL"],
        high_count=counts["HIGH"],
        medium_count=counts["MEDIUM"],
        low_count=counts["LOW"],
        total_assignments=len(iam.assignments),
        total_principals=len(unique_principals),
        deductions_breakdown=deductions,
        bonus_breakdown=bonuses,
    )
