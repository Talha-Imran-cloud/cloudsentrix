"""
aws_blast_radius.py
-------------------
Calculates blast radius for AWS IAM principals:
"If this account is compromised, what can an attacker access?"

Works on AWSIAMGraph + AWSDetectionEngine findings.
Mirrors GCP blast_radius.py conventions.

Public API
  calculate_aws_blast_radius(graph, findings) -> list[AWSBlastResult]
  aws_blast_radius_for_principal(graph, findings, principal_id) -> AWSBlastResult | None
"""

from __future__ import annotations

from dataclasses import dataclass, field
from aws_graph import AWSIAMGraph, AWSPrincipalType


# ---------------------------------------------------------------------------
# Risk weights
# ---------------------------------------------------------------------------

# Actions that give broad reach — more dangerous = higher weight
ACTION_RISK_WEIGHT: dict[str, int] = {
    "managed-policy:arn:aws:iam::aws:policy/AdministratorAccess": 100,
    "*": 100,
    "iam:*": 95,
    "managed-policy:arn:aws:iam::aws:policy/IAMFullAccess": 90,
    "managed-policy:arn:aws:iam::aws:policy/PowerUserAccess": 80,
    "iam:passrole": 75,
    "iam:attachrolepolicy": 70,
    "iam:putrolepolicy": 70,
    "iam:createrole": 65,
    "iam:createuser": 65,
    "iam:createaccesskey": 60,
    "sts:assumerole": 60,
    "trust:sts:assumerole": 55,
}

# Rules that indicate escalation paths
ESCALATION_RULES = frozenset({
    "AWS-001",  # AdministratorAccess
    "AWS-002",  # PassRole
    "AWS-003",  # IAM Policy Manipulation
    "AWS-004",  # Public AssumeRole
    "AWS-006",  # Backdoor user
    "AWS-007",  # IAMFullAccess
})


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class AWSBlastResult:
    principal_id: str
    principal_name: str
    principal_type: str             # user | group | role
    blast_score: int                # 0–100
    blast_level: str                # Critical | High | Medium | Low
    reachable_actions: list[str]    # dangerous actions this principal holds
    reachable_principals: list[str] # other principals reachable via escalation
    total_principals: int
    percentage: float               # % of other principals reachable
    has_admin: bool
    has_passrole: bool
    has_iam_full: bool
    summary: str


def _blast_level(score: int) -> str:
    if score >= 75: return "Critical"
    if score >= 50: return "High"
    if score >= 25: return "Medium"
    return "Low"


def _compute_score(graph: AWSIAMGraph, principal_id: str, findings: list) -> tuple[int, list[str]]:
    """Compute blast score based on dangerous actions held."""
    perms = set(graph.permissions_of(principal_id))
    max_score = 0
    dangerous = []

    for action, weight in ACTION_RISK_WEIGHT.items():
        if action in perms:
            dangerous.append(action)
            max_score = max(max_score, weight)

    # Bonus for multiple dangerous actions
    if len(dangerous) > 2:
        max_score = min(100, max_score + 5 * (len(dangerous) - 2))

    # Bonus for having findings
    principal_findings = [f for f in findings if f.principal_id == principal_id]
    if any(f.rule_id in ESCALATION_RULES for f in principal_findings):
        max_score = min(100, max_score + 10)

    return min(100, max_score), dangerous


def _find_reachable(graph: AWSIAMGraph, principal_id: str, findings: list) -> list[str]:
    """
    Find which other principals this principal can reach via escalation.
    - Admin / IAMFullAccess → can reach ALL principals
    - PassRole + launch → can reach roles
    - CreateAccessKey → can reach users
    - CreateUser + AttachPolicy → can create new principals
    """
    perms = set(graph.permissions_of(principal_id))
    all_principals = graph.principal_ids()
    reachable: set[str] = set()

    # Full admin — reaches everyone
    admin_perms = {
        "managed-policy:arn:aws:iam::aws:policy/AdministratorAccess",
        "*",
        "managed-policy:arn:aws:iam::aws:policy/IAMFullAccess",
        "iam:*",
    }
    if perms & admin_perms:
        return [p for p in all_principals if p != principal_id]

    # PassRole — can reach roles
    if "iam:passrole" in perms:
        roles = graph.principals_by_type(AWSPrincipalType.ROLE)
        reachable.update(r for r in roles if r != principal_id)

    # CreateAccessKey — can reach users
    if "iam:createaccesskey" in perms:
        users = graph.principals_by_type(AWSPrincipalType.USER)
        reachable.update(u for u in users if u != principal_id)

    # AttachRolePolicy / PutRolePolicy — can modify roles
    if "iam:attachrolepolicy" in perms or "iam:putrolepolicy" in perms:
        roles = graph.principals_by_type(AWSPrincipalType.ROLE)
        reachable.update(r for r in roles if r != principal_id)

    # STS AssumeRole — can assume roles
    if "sts:assumerole" in perms or "trust:sts:assumerole" in perms:
        roles = graph.principals_by_type(AWSPrincipalType.ROLE)
        reachable.update(r for r in roles if r != principal_id)

    return list(reachable)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def calculate_aws_blast_radius(
    graph: AWSIAMGraph,
    findings: list,
) -> list[AWSBlastResult]:
    """Calculate blast radius for every AWS principal. Worst-first."""
    all_principals = graph.principal_ids()
    total = len(all_principals)
    results: list[AWSBlastResult] = []

    for pid in all_principals:
        node = graph.get_principal(pid)
        if node is None:
            continue

        score, dangerous = _compute_score(graph, pid, findings)
        reachable = _find_reachable(graph, pid, findings)
        total_others = total - 1
        pct = round((len(reachable) / total_others) * 100, 1) if total_others > 0 else 0.0

        perms = set(graph.permissions_of(pid))
        has_admin = bool(perms & {
            "managed-policy:arn:aws:iam::aws:policy/AdministratorAccess", "*"
        })
        has_passrole = "iam:passrole" in perms
        has_iam_full = bool(perms & {
            "managed-policy:arn:aws:iam::aws:policy/IAMFullAccess", "iam:*"
        })

        summary = (
            f"If '{node.name}' is compromised, an attacker can reach "
            f"{len(reachable)}/{total_others} other principals ({pct}%)."
        )
        if has_admin:
            summary += " Full admin access — complete account takeover possible."

        results.append(AWSBlastResult(
            principal_id=pid,
            principal_name=node.name,
            principal_type=node.principal_type.value,
            blast_score=score,
            blast_level=_blast_level(score),
            reachable_actions=dangerous[:10],
            reachable_principals=reachable,
            total_principals=total_others,
            percentage=pct,
            has_admin=has_admin,
            has_passrole=has_passrole,
            has_iam_full=has_iam_full,
            summary=summary,
        ))

    results.sort(key=lambda r: -r.blast_score)
    return results


def aws_blast_radius_for_principal(
    graph: AWSIAMGraph,
    findings: list,
    principal_id: str,
) -> AWSBlastResult | None:
    """Blast radius for one specific principal (partial name match)."""
    all_results = calculate_aws_blast_radius(graph, findings)
    pid_lower = principal_id.lower()
    for r in all_results:
        if pid_lower in r.principal_id.lower() or pid_lower in r.principal_name.lower():
            return r
    return None


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from aws_parser import AWSIAMParser
    from aws_graph import AWSIAMGraph
    from aws_detection import AWSDetectionEngine

    policy   = AWSIAMParser().parse_file("sample_data/sample_aws_iam.json")
    graph    = AWSIAMGraph.from_policy(policy)
    findings = AWSDetectionEngine().run(graph)
    results  = calculate_aws_blast_radius(graph, findings)

    print(f"\n{'Principal':<45} {'Score':>6}  {'Level':<10} {'Reaches'}")
    print("-" * 85)
    for r in results:
        print(f"{r.principal_name:<45} {r.blast_score:>5}%  {r.blast_level:<10} {r.percentage}% of principals")
