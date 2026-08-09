"""
azure_blast_radius.py
---------------------
Calculates the blast radius for Azure principals:
"If this account is compromised, what can an attacker access?"

Works on role-assignment data — no live Azure calls needed.

Public API
  calculate_azure_blast_radius(iam: AzureIAMData) -> list[AzureBlastResult]
  blast_radius_for_principal(iam: AzureIAMData, principal: str) -> AzureBlastResult | None
"""

from __future__ import annotations

from dataclasses import dataclass, field

from azure_parser import AzureIAMData, AzureRoleAssignment


# ---------------------------------------------------------------------------
# Risk weights per role (higher = more dangerous)
# ---------------------------------------------------------------------------

ROLE_RISK_WEIGHT: dict[str, int] = {
    "Owner": 100,
    "Contributor": 80,
    "User Access Administrator": 90,
    "Role Based Access Control Administrator": 85,
    "Security Admin": 75,
    "Global Administrator": 100,
    "Privileged Role Administrator": 90,
    "Application Administrator": 70,
}

SCOPE_MULTIPLIER: dict[str, float] = {
    "Tenant": 1.0,
    "Subscription": 0.85,
    "ResourceGroup": 0.50,
    "Resource": 0.25,
}


@dataclass
class AzureBlastResult:
    principal_name: str
    principal_type: str
    blast_score: int                         # 0–100
    blast_level: str                         # Critical / High / Medium / Low
    roles: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    scope_levels: list[str] = field(default_factory=list)
    reachable_scope_levels: list[str] = field(default_factory=list)
    is_guest: bool = False
    summary: str = ""


def _blast_level(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _compute_blast_score(assignments: list[AzureRoleAssignment]) -> int:
    """
    Score = max single-assignment weight × scope multiplier,
    capped at 100, then adjusted upward for multiple broad assignments.
    """
    if not assignments:
        return 0

    max_score = 0
    for assign in assignments:
        role_weight = ROLE_RISK_WEIGHT.get(assign.role_definition_name, 40)
        multiplier = SCOPE_MULTIPLIER.get(assign.scope_level, 0.25)
        score = int(role_weight * multiplier)
        max_score = max(max_score, score)

    # Bonus for having MULTIPLE high-scope assignments (compounding risk)
    broad = [a for a in assignments if a.scope_level in ("Tenant", "Subscription")]
    if len(broad) > 1:
        max_score = min(100, max_score + 10 * (len(broad) - 1))

    return min(100, max_score)


def calculate_azure_blast_radius(iam: AzureIAMData) -> list[AzureBlastResult]:
    """Return blast-radius result for every unique principal."""
    # Group assignments by principal
    principal_map: dict[str, list[AzureRoleAssignment]] = {}
    for assign in iam.assignments:
        principal_map.setdefault(assign.principal_name, []).append(assign)

    results: list[AzureBlastResult] = []
    for principal, assigns in principal_map.items():
        score = _compute_blast_score(assigns)
        scope_levels = list({a.scope_level for a in assigns})

        # What can an attacker "reach" from each scope level?
        reachable: set[str] = set()
        for lvl in scope_levels:
            if lvl == "Tenant":
                reachable.update(["Tenant", "Subscription", "ResourceGroup", "Resource"])
            elif lvl == "Subscription":
                reachable.update(["Subscription", "ResourceGroup", "Resource"])
            elif lvl == "ResourceGroup":
                reachable.update(["ResourceGroup", "Resource"])
            else:
                reachable.add("Resource")

        sample = assigns[0]
        result = AzureBlastResult(
            principal_name=principal,
            principal_type=sample.principal_type,
            blast_score=score,
            blast_level=_blast_level(score),
            roles=list({a.role_definition_name for a in assigns}),
            scopes=list({a.scope for a in assigns}),
            scope_levels=scope_levels,
            reachable_scope_levels=sorted(reachable),
            is_guest=sample.is_guest,
            summary=(
                f"If '{principal}' is compromised, an attacker can reach: "
                f"{', '.join(sorted(reachable))}."
            ),
        )
        results.append(result)

    # Sort by blast score descending
    results.sort(key=lambda r: -r.blast_score)
    return results


def blast_radius_for_principal(
    iam: AzureIAMData,
    principal: str,
) -> AzureBlastResult | None:
    """Return blast-radius for one specific principal (partial name match)."""
    all_results = calculate_azure_blast_radius(iam)
    principal_lower = principal.lower()
    for result in all_results:
        if principal_lower in result.principal_name.lower():
            return result
    return None
