"""
GCP Privilege Escalation Detection Engine
===========================================
Applies a set of known GCP IAM privilege-escalation patterns against an
IAMGraph and produces structured, severity-ranked Findings, each mapped
to a MITRE ATT&CK Cloud Matrix technique where one genuinely applies.

Detection rules operate on ROLE NAMES (not raw IAM permissions), since
our graph is built from role bindings, not individual permissions. A
small set of predefined GCP roles are documented — by Google and by
public cloud security research — to grant escalation-relevant
capabilities on their own; this engine checks for those roles and for
known dangerous combinations of them.

References (verified against attack.mitre.org):
    - T1078.004  Valid Accounts: Cloud Accounts
    - T1098.001  Account Manipulation: Additional Cloud Credentials
    - T1098.003  Account Manipulation: Additional Cloud Roles
    - T1548.005  Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum

from graph import IAMGraph

logger = logging.getLogger(__name__)


class Severity(IntEnum):
    """Ordered so CRITICAL sorts highest — enables direct numeric comparison
    and sorting without a separate lookup table."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class Finding:
    """A single detected privilege-escalation risk."""
    rule_id: str
    title: str
    severity: Severity
    principal_id: str
    description: str
    mitre_technique_id: str
    mitre_technique_name: str
    evidence: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Rule base classes
# ---------------------------------------------------------------------------

class DetectionRule(ABC):
    """Base interface every detection rule implements.

    Subclasses set rule_id / title / severity / mitre_technique_id /
    mitre_technique_name as class attributes, and implement evaluate().
    """
    rule_id: str = ""
    title: str = ""
    severity: Severity = Severity.LOW
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""

    @abstractmethod
    def evaluate(self, graph: IAMGraph) -> list[Finding]:
        """Inspect the graph and return zero or more Findings."""
        raise NotImplementedError


class SingleRoleRule(DetectionRule):
    """Base class for rules that fire whenever a principal holds ANY role
    from a fixed set of trigger roles. Covers the common case where a
    single predefined role is dangerous on its own."""
    trigger_roles: frozenset[str] = frozenset()

    def evaluate(self, graph: IAMGraph) -> list[Finding]:
        findings: list[Finding] = []
        for role in self.trigger_roles:
            for principal_id in graph.principals_with_role(role):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        principal_id=principal_id,
                        description=self.describe(principal_id, role),
                        mitre_technique_id=self.mitre_technique_id,
                        mitre_technique_name=self.mitre_technique_name,
                        evidence=(role,),
                    )
                )
        return findings

    def describe(self, principal_id: str, role: str) -> str:
        """Override for a rule-specific explanation; falls back to a generic one."""
        return f"'{principal_id}' holds '{role}'."


# ---------------------------------------------------------------------------
# Concrete rules
# ---------------------------------------------------------------------------

class PublicAccessRule(DetectionRule):
    """Any role granted to allUsers / allAuthenticatedUsers is reachable
    by anyone on the internet — no valid credential required at all."""
    rule_id = "GCP-001"
    title = "Publicly Accessible Role Binding"
    severity = Severity.CRITICAL
    mitre_technique_id = "T1078.004"
    mitre_technique_name = "Valid Accounts: Cloud Accounts"

    PUBLIC_PRINCIPALS = ("allUsers", "allAuthenticatedUsers")

    def evaluate(self, graph: IAMGraph) -> list[Finding]:
        findings: list[Finding] = []
        for principal_id in self.PUBLIC_PRINCIPALS:
            if not graph.has_principal(principal_id):
                continue
            roles = graph.roles_of(principal_id)
            if not roles:
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    principal_id=principal_id,
                    description=(
                        f"'{principal_id}' requires no authentication at all, yet holds "
                        f"{len(roles)} role(s): {', '.join(roles)}."
                    ),
                    mitre_technique_id=self.mitre_technique_id,
                    mitre_technique_name=self.mitre_technique_name,
                    evidence=tuple(roles),
                )
            )
        return findings


class ServiceAccountTokenCreatorRule(SingleRoleRule):
    """roles/iam.serviceAccountTokenCreator lets its holder mint a live
    OAuth access token for the target service account directly — the
    most direct impersonation path GCP IAM offers."""
    rule_id = "GCP-002"
    title = "Service Account Token Creator"
    severity = Severity.CRITICAL
    mitre_technique_id = "T1098.001"
    mitre_technique_name = "Account Manipulation: Additional Cloud Credentials"
    trigger_roles = frozenset({"roles/iam.serviceAccountTokenCreator"})

    def describe(self, principal_id: str, role: str) -> str:
        return (
            f"'{principal_id}' holds '{role}' at project level, letting it mint "
            "short-lived access tokens for any service account in the project — "
            "effectively becoming that service account, no key required."
        )


class ServiceAccountKeyAdminRule(SingleRoleRule):
    """roles/iam.serviceAccountKeyAdmin lets its holder create long-lived,
    exportable key files for service accounts — unlike tokens (~1 hour),
    keys stay valid until manually revoked."""
    rule_id = "GCP-003"
    title = "Service Account Key Admin"
    severity = Severity.CRITICAL
    mitre_technique_id = "T1098.001"
    mitre_technique_name = "Account Manipulation: Additional Cloud Credentials"
    trigger_roles = frozenset({"roles/iam.serviceAccountKeyAdmin"})

    def describe(self, principal_id: str, role: str) -> str:
        return (
            f"'{principal_id}' holds '{role}', letting it create long-lived, "
            "exportable key files for service accounts in the project — a "
            "standing-access risk since keys do not expire on their own."
        )


class IAMPolicyAdminRule(SingleRoleRule):
    """Roles that can call setIamPolicy can grant ANY role — including
    Owner — to ANY principal, including themselves: the most direct
    self-escalation path in GCP."""
    rule_id = "GCP-004"
    title = "IAM Policy Administrator"
    severity = Severity.CRITICAL
    mitre_technique_id = "T1098.003"
    mitre_technique_name = "Account Manipulation: Additional Cloud Roles"
    trigger_roles = frozenset({
        "roles/owner",
        "roles/resourcemanager.projectIamAdmin",
        "roles/iam.securityAdmin",
    })

    def describe(self, principal_id: str, role: str) -> str:
        return (
            f"'{principal_id}' holds '{role}', which can modify the project's IAM "
            "policy directly — including granting itself or any other principal "
            "additional roles."
        )


class ServiceAccountImpersonationRule(DetectionRule):
    """roles/iam.serviceAccountUser alone only lets a principal ATTACH a
    service account to a resource it creates. Combined with a role that
    can create compute resources (Editor/Owner), it becomes a full
    impersonation path: deploy a resource, attach the service account,
    run code as it."""
    rule_id = "GCP-005"
    title = "Service Account Impersonation via Resource Attach"
    severity = Severity.HIGH
    mitre_technique_id = "T1548.005"
    mitre_technique_name = "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access"

    ATTACH_ROLE = "roles/iam.serviceAccountUser"
    RESOURCE_CREATE_ROLES = frozenset({"roles/editor", "roles/owner"})

    def evaluate(self, graph: IAMGraph) -> list[Finding]:
        findings: list[Finding] = []
        for principal_id in graph.principals_with_role(self.ATTACH_ROLE):
            held_roles = set(graph.roles_of(principal_id))
            enabling_roles = sorted(held_roles & self.RESOURCE_CREATE_ROLES)
            if not enabling_roles:
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    principal_id=principal_id,
                    description=(
                        f"'{principal_id}' holds '{self.ATTACH_ROLE}' and can also create "
                        f"new resources via {', '.join(enabling_roles)}. It can deploy a "
                        "new resource (e.g. a VM or Cloud Function), attach a service "
                        "account to it, and run as that service account."
                    ),
                    mitre_technique_id=self.mitre_technique_id,
                    mitre_technique_name=self.mitre_technique_name,
                    evidence=(self.ATTACH_ROLE, *enabling_roles),
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class DetectionEngine:
    """Runs a set of DetectionRules against an IAMGraph and returns
    Findings sorted most-severe-first.

    A single misbehaving rule cannot take down the whole scan: each
    rule runs in isolation, and a rule that raises is logged and skipped.
    """

    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        self.rules: list[DetectionRule] = rules if rules is not None else self._default_rules()

    @staticmethod
    def _default_rules() -> list[DetectionRule]:
        return [
            PublicAccessRule(),
            ServiceAccountTokenCreatorRule(),
            ServiceAccountKeyAdminRule(),
            IAMPolicyAdminRule(),
            ServiceAccountImpersonationRule(),
        ]

    def run(self, graph: IAMGraph) -> list[Finding]:
        all_findings: list[Finding] = []
        for rule in self.rules:
            try:
                rule_findings = rule.evaluate(graph)
            except Exception:
                logger.exception(
                    "Rule %s (%s) raised an exception — skipping it, continuing scan.",
                    rule.rule_id, rule.title,
                )
                continue
            logger.info("Rule %s (%s): %d finding(s)", rule.rule_id, rule.title, len(rule_findings))
            all_findings.extend(rule_findings)

        all_findings.sort(key=lambda f: f.severity, reverse=True)
        return all_findings


def summarize_findings(findings: list[Finding]) -> dict[str, int]:
    """Counts of findings per severity level, plus a total."""
    counts = {severity.name: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity.name] += 1
    counts["TOTAL"] = len(findings)
    return counts


# ---------------------------------------------------------------------------
# Manual smoke test — runs only when this file is executed directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    from parser import GCPIAMParser

    policy = GCPIAMParser().parse_file("sample_data/sample_gcp_iam.json")
    graph = IAMGraph.from_policy(policy)

    engine = DetectionEngine()
    findings = engine.run(graph)

    print(f"\n{'=' * 60}")
    print(f"  DETECTION RESULTS — {summarize_findings(findings)}")
    print(f"{'=' * 60}\n")

    for f in findings:
        print(f"[{f.severity}] {f.title} ({f.rule_id})")
        print(f"  Principal : {f.principal_id}")
        print(f"  MITRE     : {f.mitre_technique_id} - {f.mitre_technique_name}")
        print(f"  Details   : {f.description}")
        print()