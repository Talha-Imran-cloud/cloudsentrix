"""
azure_ad_detection.py
---------------------
Detects risky Azure AD / Entra ID app registrations and service principals.

Detection Rules:
  AZAD-001  Dangerous OAuth Permission (Graph API admin-level scope)
  AZAD-002  Orphaned App Registration (no owners)
  AZAD-003  Multi-Tenant App with Broad Permissions
  AZAD-004  Expired App Credentials (secret/certificate)
  AZAD-005  App with No Credential Expiry (never-expiring secret)
  AZAD-006  Service Principal with High-Privilege App Roles

Public API
  run_azure_ad_detections(data: AzureADData) -> list[AzureADFinding]
  get_azure_ad_rules() -> list[dict]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from azure_ad_parser import (
    AzureADData, AzureADApp, AzureADServicePrincipal,
    DANGEROUS_GRAPH_SCOPES, MS_GRAPH_APP_ID,
)


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AzureADFinding:
    rule_id: str
    title: str
    severity: str               # CRITICAL | HIGH | MEDIUM | LOW
    principal_name: str         # app display name or SP name
    principal_type: str         # App | ServicePrincipal
    description: str
    mitre_technique: str
    mitre_tactic: str
    remediation_steps: str
    evidence: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def _rule_azad001(data: AzureADData) -> list[AzureADFinding]:
    """AZAD-001 — Dangerous OAuth Permission."""
    findings = []
    for app in data.apps:
        for perm in app.oauth_permissions:
            # Match by scope name if available, or check known dangerous scopes
            scope_name = perm.scope
            # Try to get human-readable scope from app data
            # The scope field may be a GUID (from az cli) or a name (from Graph API)
            is_dangerous = (
                scope_name in DANGEROUS_GRAPH_SCOPES
                or any(d.lower() in scope_name.lower() for d in DANGEROUS_GRAPH_SCOPES)
            )
            if not is_dangerous:
                continue

            findings.append(AzureADFinding(
                rule_id="AZAD-001",
                title="Dangerous OAuth Permission",
                severity="CRITICAL",
                principal_name=app.display_name,
                principal_type="App",
                description=(
                    f"App '{app.display_name}' has requested a high-privilege "
                    f"OAuth permission '{scope_name}' ({perm.permission_type}) "
                    f"on {perm.resource_name}. This grants the app extensive "
                    f"access to your tenant's data."
                ),
                mitre_technique="T1528",
                mitre_tactic="Steal Application Access Token",
                remediation_steps=(
                    f"Review and remove unnecessary permission '{scope_name}' "
                    f"from app '{app.display_name}' in Azure AD -> App registrations -> "
                    f"API permissions. Apply least-privilege principle."
                ),
                evidence=(scope_name, perm.resource_name, perm.permission_type),
            ))
    return findings


def _rule_azad002(data: AzureADData) -> list[AzureADFinding]:
    """AZAD-002 — Orphaned App Registration (no owners)."""
    findings = []
    for app in data.apps:
        if app.owners:
            continue
        findings.append(AzureADFinding(
            rule_id="AZAD-002",
            title="Orphaned App Registration",
            severity="HIGH",
            principal_name=app.display_name,
            principal_type="App",
            description=(
                f"App '{app.display_name}' ({app.app_id}) has no owners. "
                "Orphaned apps cannot be managed or audited by a responsible "
                "owner — attackers can register as owners and take control."
            ),
            mitre_technique="T1098.001",
            mitre_tactic="Account Manipulation: Additional Cloud Credentials",
            remediation_steps=(
                f"Assign at least one owner to app '{app.display_name}' in "
                "Azure AD -> App registrations -> Owners. "
                "If the app is unused, consider deleting it."
            ),
            evidence=(app.app_id,),
        ))
    return findings


def _rule_azad003(data: AzureADData) -> list[AzureADFinding]:
    """AZAD-003 — Multi-Tenant App with Dangerous Permissions."""
    findings = []
    for app in data.apps:
        if not app.is_multi_tenant:
            continue
        dangerous_perms = [
            p for p in app.oauth_permissions
            if p.scope in DANGEROUS_GRAPH_SCOPES
            or any(d.lower() in p.scope.lower() for d in DANGEROUS_GRAPH_SCOPES)
        ]
        if not dangerous_perms:
            continue
        scopes = [p.scope for p in dangerous_perms]
        findings.append(AzureADFinding(
            rule_id="AZAD-003",
            title="Multi-Tenant App with Broad Permissions",
            severity="CRITICAL",
            principal_name=app.display_name,
            principal_type="App",
            description=(
                f"App '{app.display_name}' is accessible by external tenants "
                f"(signInAudience: {app.sign_in_audience}) AND has dangerous "
                f"permissions: {', '.join(scopes[:3])}. External organizations "
                "could consent to this app and gain access to your tenant."
            ),
            mitre_technique="T1199",
            mitre_tactic="Trusted Relationship",
            remediation_steps=(
                f"Restrict '{app.display_name}' to single-tenant "
                "(AzureADMyOrg) unless multi-tenant is required. "
                "Remove unnecessary broad permissions immediately."
            ),
            evidence=tuple(scopes[:5]),
        ))
    return findings


def _rule_azad004(data: AzureADData) -> list[AzureADFinding]:
    """AZAD-004 — Expired App Credentials."""
    findings = []
    for app in data.apps:
        expired = [c for c in app.credentials if c.is_expired]
        if not expired:
            continue
        findings.append(AzureADFinding(
            rule_id="AZAD-004",
            title="Expired App Credentials",
            severity="MEDIUM",
            principal_name=app.display_name,
            principal_type="App",
            description=(
                f"App '{app.display_name}' has {len(expired)} expired "
                f"credential(s) (secrets/certificates) that have not been "
                "removed. Expired credentials are a hygiene risk and may "
                "indicate the app is unmaintained."
            ),
            mitre_technique="T1552.001",
            mitre_tactic="Unsecured Credentials",
            remediation_steps=(
                f"Remove expired credentials from '{app.display_name}' in "
                "Azure AD -> App registrations -> Certificates & secrets. "
                "Rotate active credentials if the app is still in use."
            ),
            evidence=tuple(c.key_id for c in expired[:3]),
        ))
    return findings


def _rule_azad005(data: AzureADData) -> list[AzureADFinding]:
    """AZAD-005 — App with No Expiry on Credentials."""
    findings = []
    for app in data.apps:
        no_expiry = [c for c in app.credentials if not c.end_date]
        if not no_expiry:
            continue
        findings.append(AzureADFinding(
            rule_id="AZAD-005",
            title="App Credential With No Expiry",
            severity="HIGH",
            principal_name=app.display_name,
            principal_type="App",
            description=(
                f"App '{app.display_name}' has {len(no_expiry)} credential(s) "
                "with no expiry date set. Long-lived or permanent secrets are "
                "a significant risk if leaked — they never automatically rotate."
            ),
            mitre_technique="T1528",
            mitre_tactic="Steal Application Access Token",
            remediation_steps=(
                f"Set expiry dates on all credentials for '{app.display_name}'. "
                "Microsoft recommends a maximum of 1-2 years. "
                "Consider using certificates instead of secrets."
            ),
            evidence=tuple(c.key_id for c in no_expiry[:3]),
        ))
    return findings


def _rule_azad006(data: AzureADData) -> list[AzureADFinding]:
    """AZAD-006 — Service Principal with High-Privilege App Roles."""
    DANGEROUS_ROLES = {
        "Directory.ReadWrite.All", "Application.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All",
        "Policy.ReadWrite.ConditionalAccess", "Mail.ReadWrite",
        "User.ReadWrite.All", "Group.ReadWrite.All",
    }
    findings = []
    for sp in data.service_principals:
        dangerous = [r for r in sp.app_role_assignments if r in DANGEROUS_ROLES]
        if not dangerous:
            continue
        findings.append(AzureADFinding(
            rule_id="AZAD-006",
            title="Service Principal with High-Privilege App Roles",
            severity="CRITICAL",
            principal_name=sp.display_name,
            principal_type="ServicePrincipal",
            description=(
                f"Service principal '{sp.display_name}' has been granted "
                f"dangerous app roles: {', '.join(dangerous[:3])}. "
                "These application permissions are tenant-wide and do not "
                "require user consent — compromise of this SP gives "
                "broad access to your entire tenant."
            ),
            mitre_technique="T1098.003",
            mitre_tactic="Account Manipulation: Additional Cloud Roles",
            remediation_steps=(
                f"Review and revoke unnecessary app roles from '{sp.display_name}' "
                "in Azure AD -> Enterprise Applications -> Permissions. "
                "Apply least-privilege — use delegated permissions where possible."
            ),
            evidence=tuple(dangerous[:5]),
        ))
    return findings


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

_RULES = [
    _rule_azad001,
    _rule_azad002,
    _rule_azad003,
    _rule_azad004,
    _rule_azad005,
    _rule_azad006,
]


def run_azure_ad_detections(data: AzureADData) -> list[AzureADFinding]:
    """Run all Azure AD detection rules. Returns findings sorted by severity."""
    SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings: list[AzureADFinding] = []
    for rule_fn in _RULES:
        try:
            all_findings.extend(rule_fn(data))
        except Exception as exc:
            print(f"[azure-ad-detection] Rule {rule_fn.__name__} error: {exc}")
    all_findings.sort(key=lambda f: SEV.get(f.severity, 9))
    return all_findings


def get_azure_ad_rules() -> list[dict]:
    """Return rule metadata for the `rules` CLI command."""
    return [
        {"id": "AZAD-001", "title": "Dangerous OAuth Permission",
         "severity": "CRITICAL", "mitre": "T1528"},
        {"id": "AZAD-002", "title": "Orphaned App Registration",
         "severity": "HIGH",     "mitre": "T1098.001"},
        {"id": "AZAD-003", "title": "Multi-Tenant App with Broad Permissions",
         "severity": "CRITICAL", "mitre": "T1199"},
        {"id": "AZAD-004", "title": "Expired App Credentials",
         "severity": "MEDIUM",   "mitre": "T1552.001"},
        {"id": "AZAD-005", "title": "App Credential With No Expiry",
         "severity": "HIGH",     "mitre": "T1528"},
        {"id": "AZAD-006", "title": "Service Principal with High-Privilege App Roles",
         "severity": "CRITICAL", "mitre": "T1098.003"},
    ]


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from azure_ad_parser import parse_azure_ad_file

    data     = parse_azure_ad_file("sample_data/sample_azure_ad.json")
    findings = run_azure_ad_detections(data)

    print(f"\n{'='*60}")
    print(f"  AZURE AD RESULTS — {len(findings)} finding(s)")
    print(f"{'='*60}\n")

    for f in findings:
        print(f"[{f.severity}] {f.title} ({f.rule_id})")
        print(f"  App/SP    : {f.principal_name}")
        print(f"  MITRE     : {f.mitre_technique} — {f.mitre_tactic}")
        print(f"  Details   : {f.description[:100]}...")
        print(f"  Fix       : {f.remediation_steps[:80]}...")
        print()
