"""
azure_detection.py
------------------
Detects Azure RBAC privilege-escalation patterns.

Detection rules (mapped to MITRE ATT&CK Cloud Matrix)
  AZ-001  Owner / Contributor Abuse                  CRITICAL  T1078.004
  AZ-002  Service Principal with High Privilege       CRITICAL  T1098.001
  AZ-003  Guest User with Elevated Role              HIGH      T1078.006
  AZ-004  Wildcard / Over-permissive Role Assignment HIGH      T1548.005
  AZ-005  Custom Role with Dangerous Permissions      HIGH      T1098.003

Public API
  run_azure_detections(iam: AzureIAMData) -> list[AzureFinding]
  get_azure_rules()                        -> list[dict]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from azure_parser import AzureIAMData, AzureRoleAssignment, AzureRoleDefinition


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class AzureFinding:
    rule_id: str
    title: str
    severity: str                    # CRITICAL | HIGH | MEDIUM | LOW
    description: str
    principal_name: str
    principal_type: str
    scope: str
    scope_level: str
    role: str
    mitre_technique: str
    mitre_tactic: str
    remediation_steps: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Dangerous permission patterns for AZ-005
# ---------------------------------------------------------------------------

DANGEROUS_ACTION_PATTERNS: list[str] = [
    "*",                                    # full wildcard
    "*/write",                              # write on everything
    "*/delete",                             # delete on everything
    "Microsoft.Authorization/*/write",      # can assign any role
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/policyAssignments/write",
    "Microsoft.Authorization/elevateAccess/action",
    "Microsoft.Compute/virtualMachines/runCommand/action",
    "Microsoft.Storage/storageAccounts/listKeys/action",
    "Microsoft.KeyVault/vaults/secrets/*",
    "Microsoft.AAD/*/write",
    "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",
]

# Roles that are inherently over-privileged at broad scopes
HIGH_PRIV_ROLES: set[str] = {
    "Owner",
    "Contributor",
    "User Access Administrator",
    "Role Based Access Control Administrator",
    "Security Admin",
    "Global Administrator",          # Entra ID / AAD
    "Privileged Role Administrator",
    "Application Administrator",
}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _matches_dangerous_action(actions: list[str]) -> list[str]:
    """Return subset of actions that are considered dangerous."""
    matched: list[str] = []
    for action in actions:
        action_lower = action.lower()
        for pattern in DANGEROUS_ACTION_PATTERNS:
            p_lower = pattern.lower()
            if p_lower == action_lower:
                matched.append(action)
                break
            # simple glob: pattern ends with *
            if p_lower.endswith("*") and action_lower.startswith(p_lower[:-1]):
                matched.append(action)
                break
    return matched


# ---------------------------------------------------------------------------
# AZ-001 — Owner / Contributor Abuse
# ---------------------------------------------------------------------------

def _detect_owner_contributor(iam: AzureIAMData) -> list[AzureFinding]:
    findings: list[AzureFinding] = []
    for assign in iam.assignments:
        if assign.role_definition_name not in ("Owner", "Contributor",
                                               "User Access Administrator"):
            continue
        # Flag broad-scope (Tenant or Subscription) assignments
        if assign.scope_level not in ("Tenant", "Subscription"):
            continue

        severity = "CRITICAL" if assign.role_definition_name == "Owner" else "HIGH"
        findings.append(
            AzureFinding(
                rule_id="AZ-001",
                title="Owner / Contributor at Broad Scope",
                severity=severity,
                description=(
                    f"'{assign.principal_name}' ({assign.principal_type}) holds "
                    f"'{assign.role_definition_name}' at scope '{assign.scope}'. "
                    "This grants near-unrestricted access and is a prime "
                    "privilege-escalation vector."
                ),
                principal_name=assign.principal_name,
                principal_type=assign.principal_type,
                scope=assign.scope,
                scope_level=assign.scope_level,
                role=assign.role_definition_name,
                mitre_technique="T1078.004",
                mitre_tactic="Persistence / Privilege Escalation",
                remediation_steps=[
                    f"az role assignment delete --assignee \"{assign.principal_name}\" "
                    f"--role \"{assign.role_definition_name}\" --scope \"{assign.scope}\"",
                    "Replace with a least-privilege custom role scoped to the required resource group.",
                    "Review all Owner assignments monthly via Azure PIM (Privileged Identity Management).",
                ],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# AZ-002 — Service Principal with High Privilege
# ---------------------------------------------------------------------------

def _detect_privileged_service_principal(iam: AzureIAMData) -> list[AzureFinding]:
    findings: list[AzureFinding] = []
    for assign in iam.assignments:
        if assign.principal_type != "ServicePrincipal":
            continue
        if assign.role_definition_name not in HIGH_PRIV_ROLES:
            continue

        findings.append(
            AzureFinding(
                rule_id="AZ-002",
                title="Service Principal with High-Privilege Role",
                severity="CRITICAL",
                description=(
                    f"Service Principal '{assign.principal_name}' has been granted "
                    f"'{assign.role_definition_name}' at scope '{assign.scope}'. "
                    "Compromised service principal credentials allow full subscription takeover."
                ),
                principal_name=assign.principal_name,
                principal_type=assign.principal_type,
                scope=assign.scope,
                scope_level=assign.scope_level,
                role=assign.role_definition_name,
                mitre_technique="T1098.001",
                mitre_tactic="Persistence / Credential Access",
                remediation_steps=[
                    f"az role assignment delete --assignee \"{assign.principal_id}\" "
                    f"--role \"{assign.role_definition_name}\" --scope \"{assign.scope}\"",
                    "Use Managed Identity instead of Service Principal where possible.",
                    "Enable credential rotation and certificate-based auth.",
                    "Enable Azure AD Conditional Access for service principals.",
                ],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# AZ-003 — Guest User with Elevated Role
# ---------------------------------------------------------------------------

def _detect_guest_elevated(iam: AzureIAMData) -> list[AzureFinding]:
    findings: list[AzureFinding] = []
    for assign in iam.assignments:
        if not assign.is_guest:
            continue
        # Any role beyond Reader is a risk for guests
        if assign.role_definition_name.lower() in ("reader", ""):
            continue

        severity = "CRITICAL" if assign.role_definition_name in HIGH_PRIV_ROLES else "HIGH"
        findings.append(
            AzureFinding(
                rule_id="AZ-003",
                title="Guest User with Elevated Role",
                severity=severity,
                description=(
                    f"External / guest user '{assign.principal_name}' holds "
                    f"'{assign.role_definition_name}' at scope '{assign.scope}'. "
                    "Guest accounts are outside your tenant's security boundary and "
                    "are a high-risk attack surface."
                ),
                principal_name=assign.principal_name,
                principal_type=assign.principal_type,
                scope=assign.scope,
                scope_level=assign.scope_level,
                role=assign.role_definition_name,
                mitre_technique="T1078.006",
                mitre_tactic="Initial Access / Privilege Escalation",
                remediation_steps=[
                    f"az role assignment delete --assignee \"{assign.principal_name}\" "
                    f"--role \"{assign.role_definition_name}\" --scope \"{assign.scope}\"",
                    "Review all guest (B2B) user role assignments quarterly.",
                    "Enable Guest Access Reviews in Azure AD Identity Governance.",
                    "Apply Conditional Access policies restricting guest user capabilities.",
                ],
                extra={"is_guest": True},
            )
        )
    return findings


# ---------------------------------------------------------------------------
# AZ-004 — Wildcard / Over-permissive Scope Assignment
# ---------------------------------------------------------------------------

def _detect_wildcard_scope(iam: AzureIAMData) -> list[AzureFinding]:
    """
    Flag any non-Owner/Contributor role assigned at Tenant or Subscription scope
    that is not clearly justified (i.e. not a standard reader or monitoring role).
    """
    ALLOWED_BROAD_ROLES = {
        "Reader", "Monitoring Reader", "Security Reader",
        "Billing Reader", "Cost Management Reader",
    }

    findings: list[AzureFinding] = []
    for assign in iam.assignments:
        if assign.scope_level not in ("Tenant", "Subscription"):
            continue
        if assign.role_definition_name in ALLOWED_BROAD_ROLES:
            continue
        if assign.role_definition_name in ("Owner", "Contributor",
                                           "User Access Administrator"):
            continue  # already caught by AZ-001

        findings.append(
            AzureFinding(
                rule_id="AZ-004",
                title="Wildcard / Over-permissive Role Scope",
                severity="HIGH",
                description=(
                    f"'{assign.principal_name}' has role '{assign.role_definition_name}' "
                    f"scoped to the entire {assign.scope_level} ('{assign.scope}'). "
                    "Broad scopes violate least-privilege and expand blast radius."
                ),
                principal_name=assign.principal_name,
                principal_type=assign.principal_type,
                scope=assign.scope,
                scope_level=assign.scope_level,
                role=assign.role_definition_name,
                mitre_technique="T1548.005",
                mitre_tactic="Privilege Escalation",
                remediation_steps=[
                    f"az role assignment delete --assignee \"{assign.principal_name}\" "
                    f"--role \"{assign.role_definition_name}\" --scope \"{assign.scope}\"",
                    "Re-assign the role at the narrowest required scope (resource group or resource).",
                    "Use Azure Policy to deny new broad-scope assignments.",
                ],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# AZ-005 — Custom Role with Dangerous Permissions
# ---------------------------------------------------------------------------

def _detect_dangerous_custom_roles(iam: AzureIAMData) -> list[AzureFinding]:
    findings: list[AzureFinding] = []

    # Build a set of principals using custom roles
    custom_role_names: set[str] = {
        d.role_name for d in iam.definitions if d.is_custom
    }

    for assign in iam.assignments:
        role_name = assign.role_definition_name
        if role_name not in custom_role_names:
            continue

        defn: AzureRoleDefinition | None = iam.definition_map.get(role_name)
        if defn is None:
            continue

        matched = _matches_dangerous_action(defn.permissions_actions)
        if not matched:
            continue

        findings.append(
            AzureFinding(
                rule_id="AZ-005",
                title="Custom Role with Dangerous Permissions",
                severity="HIGH",
                description=(
                    f"Custom role '{role_name}' assigned to '{assign.principal_name}' "
                    f"contains dangerous actions: {', '.join(matched[:5])}. "
                    "Over-permissive custom roles are frequently exploited for "
                    "lateral movement and privilege escalation."
                ),
                principal_name=assign.principal_name,
                principal_type=assign.principal_type,
                scope=assign.scope,
                scope_level=assign.scope_level,
                role=role_name,
                mitre_technique="T1098.003",
                mitre_tactic="Persistence / Privilege Escalation",
                remediation_steps=[
                    f"# Review custom role definition:",
                    f"az role definition show --name \"{role_name}\"",
                    f"# Remove dangerous actions and update:",
                    f"az role definition update --role-definition '{{\"Name\": \"{role_name}\", "
                    f"\"Actions\": [\"<safe-actions-only>\"]}}'",
                    "Audit all custom roles monthly: az role definition list --custom-role-only true",
                ],
                extra={"dangerous_actions": matched},
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_azure_detections(iam: AzureIAMData) -> list[AzureFinding]:
    """Run all detection rules and return a flat list of findings."""
    findings: list[AzureFinding] = []
    findings.extend(_detect_owner_contributor(iam))
    findings.extend(_detect_privileged_service_principal(iam))
    findings.extend(_detect_guest_elevated(iam))
    findings.extend(_detect_wildcard_scope(iam))
    findings.extend(_detect_dangerous_custom_roles(iam))

    # Sort: CRITICAL first, then HIGH, then by principal name
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 99), f.principal_name))
    return findings


def get_azure_rules() -> list[dict]:
    """Return rule metadata (used by the 'rules' CLI command)."""
    return [
        {
            "id": "AZ-001",
            "title": "Owner / Contributor at Broad Scope",
            "severity": "CRITICAL",
            "mitre": "T1078.004",
            "description": "Owner or Contributor role at Tenant or Subscription scope.",
        },
        {
            "id": "AZ-002",
            "title": "Service Principal with High-Privilege Role",
            "severity": "CRITICAL",
            "mitre": "T1098.001",
            "description": "Service Principal granted Owner, Contributor, or UAA role.",
        },
        {
            "id": "AZ-003",
            "title": "Guest User with Elevated Role",
            "severity": "HIGH",
            "mitre": "T1078.006",
            "description": "B2B guest (external) user assigned role beyond Reader.",
        },
        {
            "id": "AZ-004",
            "title": "Wildcard / Over-permissive Role Scope",
            "severity": "HIGH",
            "mitre": "T1548.005",
            "description": "Any sensitive role scoped to the full Tenant or Subscription.",
        },
        {
            "id": "AZ-005",
            "title": "Custom Role with Dangerous Permissions",
            "severity": "HIGH",
            "mitre": "T1098.003",
            "description": "Custom role definition contains wildcard or dangerous action patterns.",
        },
    ]
