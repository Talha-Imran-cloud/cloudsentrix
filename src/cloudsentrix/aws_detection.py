"""
AWS Privilege Escalation Detection Engine
==========================================
Applies known AWS IAM privilege-escalation patterns against an AWSIAMGraph
and produces structured, severity-ranked Findings — each mapped to a
MITRE ATT&CK Cloud Matrix technique.

Detection rules operate on IAM ACTIONS and MANAGED POLICY ARNs (not role
names like GCP), because AWS IAM grants individual permissions rather than
named roles. A principal is flagged when it holds a dangerous action or
combination of actions that enables privilege escalation.

AWS-specific escalation paths detected:
    AWS-001  Administrator Access (wildcard * or AdministratorAccess policy)
    AWS-002  IAM PassRole (iam:PassRole — can hand powerful roles to services)
    AWS-003  IAM Policy Manipulation (create/attach/put policy on any principal)
    AWS-004  STS AssumeRole — publicly assumable role (trust principal = *)
    AWS-005  Access Key Creation (iam:CreateAccessKey on any user)
    AWS-006  New User + Policy Attach (create user AND attach policy = backdoor)
    AWS-007  IAMFullAccess managed policy attached

References (verified against attack.mitre.org):
    T1078.004  Valid Accounts: Cloud Accounts
    T1098.001  Account Manipulation: Additional Cloud Credentials
    T1098.003  Account Manipulation: Additional Cloud Roles
    T1548.005  Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum

from aws_graph import AWSIAMGraph, AWSPrincipalType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity  (same as GCP detection.py — shared later by risk_score.py)
# ---------------------------------------------------------------------------

class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name


# ---------------------------------------------------------------------------
# Finding  (mirrors GCP Finding exactly so risk_score.py works unchanged)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AWSFinding:
    rule_id: str
    title: str
    severity: Severity
    principal_id: str
    description: str
    mitre_technique_id: str
    mitre_technique_name: str
    evidence: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Rule base classes  (mirrors GCP DetectionRule / SingleRoleRule)
# ---------------------------------------------------------------------------

class AWSDetectionRule(ABC):
    rule_id: str = ""
    title: str = ""
    severity: Severity = Severity.LOW
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""

    @abstractmethod
    def evaluate(self, graph: AWSIAMGraph) -> list[AWSFinding]:
        raise NotImplementedError


class SingleActionRule(AWSDetectionRule):
    """Fires when a principal holds ANY action from a fixed trigger set."""
    trigger_actions: frozenset[str] = frozenset()

    def evaluate(self, graph: AWSIAMGraph) -> list[AWSFinding]:
        findings: list[AWSFinding] = []
        for action in self.trigger_actions:
            for principal_id in graph.principals_with_permission(action):
                findings.append(AWSFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    principal_id=principal_id,
                    description=self.describe(principal_id, action),
                    mitre_technique_id=self.mitre_technique_id,
                    mitre_technique_name=self.mitre_technique_name,
                    evidence=(action,),
                ))
        return findings

    def describe(self, principal_id: str, action: str) -> str:
        return f"'{principal_id}' holds '{action}'."


# ---------------------------------------------------------------------------
# Concrete rules
# ---------------------------------------------------------------------------

class AdminAccessRule(AWSDetectionRule):
    """
    AWS-001 — AdministratorAccess or wildcard '*' action.

    A principal with AdministratorAccess managed policy or an inline '*'
    action has unrestricted access to every AWS service and resource.
    This is the most dangerous permission state in AWS IAM.
    """
    rule_id = "AWS-001"
    title = "Administrator Access — Full AWS Control"
    severity = Severity.CRITICAL
    mitre_technique_id = "T1078.004"
    mitre_technique_name = "Valid Accounts: Cloud Accounts"

    ADMIN_POLICY_ARN = "managed-policy:arn:aws:iam::aws:policy/AdministratorAccess"
    WILDCARD_ACTION = "*"

    def evaluate(self, graph: AWSIAMGraph) -> list[AWSFinding]:
        findings: list[AWSFinding] = []
        seen: set[str] = set()

        # Check for AdministratorAccess managed policy
        for principal_id in graph.principals_with_permission(self.ADMIN_POLICY_ARN):
            if principal_id in seen:
                continue
            seen.add(principal_id)
            node = graph.get_principal(principal_id)
            name = node.name if node else principal_id
            findings.append(AWSFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                principal_id=principal_id,
                description=(
                    f"'{name}' has the AWS AdministratorAccess managed policy attached, "
                    "granting unrestricted access to all AWS services and resources — "
                    "equivalent to root-level access."
                ),
                mitre_technique_id=self.mitre_technique_id,
                mitre_technique_name=self.mitre_technique_name,
                evidence=("arn:aws:iam::aws:policy/AdministratorAccess",),
            ))

        # Check for inline wildcard '*' action
        for principal_id in graph.principals_with_permission(self.WILDCARD_ACTION):
            if principal_id in seen:
                continue
            seen.add(principal_id)
            node = graph.get_principal(principal_id)
            name = node.name if node else principal_id
            findings.append(AWSFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                principal_id=principal_id,
                description=(
                    f"'{name}' has an inline policy with Action: '*' — "
                    "granting full access to every AWS API call."
                ),
                mitre_technique_id=self.mitre_technique_id,
                mitre_technique_name=self.mitre_technique_name,
                evidence=("Action: *",),
            ))

        return findings


class PassRoleRule(AWSDetectionRule):
    """
    AWS-002 — iam:PassRole privilege escalation.

    iam:PassRole lets a principal attach an IAM role to an AWS service
    (EC2, Lambda, etc.). If the passed role has more permissions than the
    principal, the principal effectively escalates by running code as that
    role. Combined with ec2:RunInstances or lambda:CreateFunction this
    becomes a full escalation path.
    """
    rule_id = "AWS-002"
    title = "IAM PassRole — Privilege Escalation via Service"
    severity = Severity.CRITICAL
    mitre_technique_id = "T1098.003"
    mitre_technique_name = "Account Manipulation: Additional Cloud Roles"

    PASS_ROLE_ACTION = "iam:passrole"
    # Any of these + PassRole = full escalation path
    ESCALATION_ACTIONS = frozenset({
        "ec2:runinstances",
        "lambda:createfunction",
        "lambda:*",
        "glue:createjob",
        "sagemaker:createtrainingjob",
        "ecs:runtask",
        "ec2:*",
    })

    def evaluate(self, graph: AWSIAMGraph) -> list[AWSFinding]:
        findings: list[AWSFinding] = []
        for principal_id in graph.principals_with_permission(self.PASS_ROLE_ACTION):
            node = graph.get_principal(principal_id)
            name = node.name if node else principal_id

            # Check if they also have a service-launch action (full path)
            enabling = graph.has_any_permission(principal_id, self.ESCALATION_ACTIONS)

            if enabling:
                findings.append(AWSFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    principal_id=principal_id,
                    description=(
                        f"'{name}' holds iam:PassRole AND can launch AWS services "
                        f"({', '.join(enabling)}). It can attach a high-privilege role "
                        "to a new EC2 instance or Lambda function and run code as that "
                        "role — escalating beyond its own permissions."
                    ),
                    mitre_technique_id=self.mitre_technique_id,
                    mitre_technique_name=self.mitre_technique_name,
                    evidence=(self.PASS_ROLE_ACTION, *enabling),
                ))
            else:
                # PassRole alone is HIGH — full path needs a launch action too
                findings.append(AWSFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.HIGH,
                    principal_id=principal_id,
                    description=(
                        f"'{name}' holds iam:PassRole, allowing it to pass IAM roles "
                        "to AWS services. Without a service-launch permission this is "
                        "not immediately exploitable, but is a significant risk if "
                        "additional permissions are granted later."
                    ),
                    mitre_technique_id=self.mitre_technique_id,
                    mitre_technique_name=self.mitre_technique_name,
                    evidence=(self.PASS_ROLE_ACTION,),
                ))
        return findings


class IAMPolicyManipulationRule(AWSDetectionRule):
    """
    AWS-003 — IAM policy manipulation (create/attach/put policy).

    A principal that can create policies AND attach them to users, roles,
    or groups can grant itself or any other principal any permission —
    including AdministratorAccess. This is a self-escalation path.
    """
    rule_id = "AWS-003"
    title = "IAM Policy Manipulation — Self-Escalation Path"
    severity = Severity.CRITICAL
    mitre_technique_id = "T1098.003"
    mitre_technique_name = "Account Manipulation: Additional Cloud Roles"

    CREATE_ACTIONS = frozenset({
        "iam:createpolicy",
        "iam:putrolepolicy",
        "iam:putuserpolicy",
        "iam:putgrouppolicy",
    })
    ATTACH_ACTIONS = frozenset({
        "iam:attachrolepolicy",
        "iam:attachuserpolicy",
        "iam:attachgrouppolicy",
    })

    def evaluate(self, graph: AWSIAMGraph) -> list[AWSFinding]:
        findings: list[AWSFinding] = []
        all_principals = graph.principal_ids()

        for principal_id in all_principals:
            node = graph.get_principal(principal_id)
            name = node.name if node else principal_id

            create_held = graph.has_any_permission(principal_id, self.CREATE_ACTIONS)
            attach_held = graph.has_any_permission(principal_id, self.ATTACH_ACTIONS)

            if create_held and attach_held:
                evidence = tuple(create_held + attach_held)
                findings.append(AWSFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    principal_id=principal_id,
                    description=(
                        f"'{name}' can both create/modify IAM policies "
                        f"({', '.join(create_held)}) AND attach them "
                        f"({', '.join(attach_held)}). It can create a policy granting "
                        "AdministratorAccess and attach it to itself or any other principal."
                    ),
                    mitre_technique_id=self.mitre_technique_id,
                    mitre_technique_name=self.mitre_technique_name,
                    evidence=evidence,
                ))
            elif attach_held:
                # Attach alone is HIGH — can attach existing admin policies
                findings.append(AWSFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.HIGH,
                    principal_id=principal_id,
                    description=(
                        f"'{name}' can attach existing IAM policies to principals "
                        f"({', '.join(attach_held)}). It could attach "
                        "AdministratorAccess to itself or any other principal."
                    ),
                    mitre_technique_id=self.mitre_technique_id,
                    mitre_technique_name=self.mitre_technique_name,
                    evidence=tuple(attach_held),
                ))
        return findings


class PublicAssumeRoleRule(AWSDetectionRule):
    """
    AWS-004 — Publicly assumable role (trust principal = '*').

    A role whose trust policy allows Principal: '*' can be assumed by
    ANYONE — including unauthenticated external principals. If the role
    also has high permissions (e.g. AdministratorAccess), this is a
    critical exposure.
    """
    rule_id = "AWS-004"
    title = "Publicly Assumable Role — Trust Policy Allows Anyone"
    severity = Severity.CRITICAL
    mitre_technique_id = "T1078.004"
    mitre_technique_name = "Valid Accounts: Cloud Accounts"

    PUBLIC_TRUST_ACTION = "trust:sts:assumerole"
    PUBLIC_PRINCIPAL = "*"

    def evaluate(self, graph: AWSIAMGraph) -> list[AWSFinding]:
        findings: list[AWSFinding] = []
        for principal_id in graph.principals_by_type(AWSPrincipalType.ROLE):
            node = graph.get_principal(principal_id)
            name = node.name if node else principal_id

            # Check edge: principal_id -> trust:sts:assumerole with resource='*'
            underlying = graph.underlying()
            if not underlying.has_edge(principal_id, self.PUBLIC_TRUST_ACTION):
                continue

            edge_data = underlying.edges[principal_id, self.PUBLIC_TRUST_ACTION]
            resource = edge_data.get("resource", "")

            if resource == self.PUBLIC_PRINCIPAL:
                # Check if this role also has admin access — makes it worse
                has_admin = graph.has_managed_policy(
                    principal_id,
                    "arn:aws:iam::aws:policy/AdministratorAccess"
                )
                suffix = (
                    " This role also has AdministratorAccess — "
                    "a complete account takeover is possible."
                    if has_admin else ""
                )
                findings.append(AWSFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    principal_id=principal_id,
                    description=(
                        f"Role '{name}' has a trust policy with Principal: '*', "
                        "meaning ANY AWS identity — or anonymous caller — can call "
                        f"sts:AssumeRole on it without restriction.{suffix}"
                    ),
                    mitre_technique_id=self.mitre_technique_id,
                    mitre_technique_name=self.mitre_technique_name,
                    evidence=("trust:Principal:*",),
                ))
        return findings


class AccessKeyCreationRule(SingleActionRule):
    """
    AWS-005 — iam:CreateAccessKey on any user.

    A principal with iam:CreateAccessKey can generate long-lived
    programmatic credentials for any IAM user — including admins.
    Unlike console passwords, access keys don't require MFA and
    work directly with the AWS CLI and APIs.
    """
    rule_id = "AWS-005"
    title = "Access Key Creation — Long-Lived Credential Backdoor"
    severity = Severity.CRITICAL
    mitre_technique_id = "T1098.001"
    mitre_technique_name = "Account Manipulation: Additional Cloud Credentials"
    trigger_actions = frozenset({"iam:createaccesskey"})

    def describe(self, principal_id: str, action: str) -> str:
        return (
            f"'{principal_id}' holds iam:CreateAccessKey, allowing it to generate "
            "long-lived programmatic credentials (access key + secret) for any IAM "
            "user — including admin users. These keys persist until manually revoked "
            "and bypass MFA requirements."
        )


class BackdoorUserRule(AWSDetectionRule):
    """
    AWS-006 — Create new IAM user + attach policy (backdoor account).

    A principal that can create new IAM users AND attach policies to them
    can create a hidden backdoor account with any permissions it chooses —
    including AdministratorAccess — that persists even if the original
    principal's access is revoked.
    """
    rule_id = "AWS-006"
    title = "Backdoor IAM User Creation"
    severity = Severity.CRITICAL
    mitre_technique_id = "T1136.003"
    mitre_technique_name = "Create Account: Cloud Account"

    CREATE_USER_ACTION = "iam:createuser"
    ATTACH_ACTIONS = frozenset({
        "iam:attachuserpolicy",
        "iam:putuserpolicy",
    })

    def evaluate(self, graph: AWSIAMGraph) -> list[AWSFinding]:
        findings: list[AWSFinding] = []
        for principal_id in graph.principals_with_permission(self.CREATE_USER_ACTION):
            node = graph.get_principal(principal_id)
            name = node.name if node else principal_id

            attach_held = graph.has_any_permission(principal_id, self.ATTACH_ACTIONS)
            if not attach_held:
                continue

            findings.append(AWSFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                principal_id=principal_id,
                description=(
                    f"'{name}' can create new IAM users (iam:CreateUser) AND attach "
                    f"policies to them ({', '.join(attach_held)}). It can create a "
                    "hidden backdoor account with AdministratorAccess that persists "
                    "independently of this principal's own access."
                ),
                mitre_technique_id=self.mitre_technique_id,
                mitre_technique_name=self.mitre_technique_name,
                evidence=(self.CREATE_USER_ACTION, *attach_held),
            ))
        return findings


class IAMFullAccessRule(AWSDetectionRule):
    """
    AWS-007 — IAMFullAccess managed policy.

    IAMFullAccess grants iam:* — full control over all IAM resources.
    A principal with this policy can modify any user, role, group, or
    policy in the account — effectively controlling who can do what.
    """
    rule_id = "AWS-007"
    title = "IAMFullAccess — Complete IAM Control"
    severity = Severity.CRITICAL
    mitre_technique_id = "T1098.003"
    mitre_technique_name = "Account Manipulation: Additional Cloud Roles"

    IAM_FULL_ACCESS_ARN = "managed-policy:arn:aws:iam::aws:policy/IAMFullAccess"
    IAM_WILDCARD_ACTION = "iam:*"

    def evaluate(self, graph: AWSIAMGraph) -> list[AWSFinding]:
        findings: list[AWSFinding] = []
        seen: set[str] = set()

        # Check IAMFullAccess managed policy
        for principal_id in graph.principals_with_permission(self.IAM_FULL_ACCESS_ARN):
            seen.add(principal_id)
            node = graph.get_principal(principal_id)
            name = node.name if node else principal_id
            findings.append(AWSFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                principal_id=principal_id,
                description=(
                    f"'{name}' has the IAMFullAccess managed policy, granting iam:* — "
                    "full control over every IAM resource in the account including "
                    "users, roles, groups, and policies. This principal can escalate "
                    "any other principal's permissions."
                ),
                mitre_technique_id=self.mitre_technique_id,
                mitre_technique_name=self.mitre_technique_name,
                evidence=("arn:aws:iam::aws:policy/IAMFullAccess",),
            ))

        # Check inline iam:* action
        for principal_id in graph.principals_with_permission(self.IAM_WILDCARD_ACTION):
            if principal_id in seen:
                continue
            node = graph.get_principal(principal_id)
            name = node.name if node else principal_id
            findings.append(AWSFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                principal_id=principal_id,
                description=(
                    f"'{name}' has an inline policy with Action: 'iam:*', "
                    "granting full control over all IAM resources."
                ),
                mitre_technique_id=self.mitre_technique_id,
                mitre_technique_name=self.mitre_technique_name,
                evidence=("iam:*",),
            ))

        return findings


# ---------------------------------------------------------------------------
# Engine  (mirrors GCP DetectionEngine exactly)
# ---------------------------------------------------------------------------

class AWSDetectionEngine:
    """Runs all AWS detection rules against an AWSIAMGraph.
    A misbehaving rule is logged and skipped — it cannot crash the scan.
    """

    def __init__(self, rules: list[AWSDetectionRule] | None = None) -> None:
        self.rules = rules if rules is not None else self._default_rules()

    @staticmethod
    def _default_rules() -> list[AWSDetectionRule]:
        return [
            AdminAccessRule(),
            PassRoleRule(),
            IAMPolicyManipulationRule(),
            PublicAssumeRoleRule(),
            AccessKeyCreationRule(),
            BackdoorUserRule(),
            IAMFullAccessRule(),
        ]

    def run(self, graph: AWSIAMGraph) -> list[AWSFinding]:
        all_findings: list[AWSFinding] = []
        for rule in self.rules:
            try:
                rule_findings = rule.evaluate(graph)
            except Exception:
                logger.exception(
                    "Rule %s (%s) raised an exception — skipping, continuing scan.",
                    rule.rule_id, rule.title,
                )
                continue
            logger.info(
                "Rule %s (%s): %d finding(s)", rule.rule_id, rule.title, len(rule_findings)
            )
            all_findings.extend(rule_findings)

        all_findings.sort(key=lambda f: f.severity, reverse=True)
        return all_findings


def summarize_aws_findings(findings: list[AWSFinding]) -> dict[str, int]:
    counts = {s.name: 0 for s in Severity}
    for f in findings:
        counts[f.severity.name] += 1
    counts["TOTAL"] = len(findings)
    return counts


# ---------------------------------------------------------------------------
# Manual smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    from aws_parser import AWSIAMParser
    from aws_graph import AWSIAMGraph

    policy = AWSIAMParser().parse_file("sample_data/sample_aws_iam.json")
    graph = AWSIAMGraph.from_policy(policy)
    findings = AWSDetectionEngine().run(graph)

    print(f"\n{'=' * 65}")
    print(f"  AWS DETECTION RESULTS — {summarize_aws_findings(findings)}")
    print(f"{'=' * 65}\n")

    for f in findings:
        print(f"[{f.severity}] {f.title} ({f.rule_id})")
        print(f"  Principal : {f.principal_id}")
        print(f"  MITRE     : {f.mitre_technique_id} — {f.mitre_technique_name}")
        print(f"  Details   : {f.description}")
        print(f"  Evidence  : {', '.join(f.evidence)}")
        print()
