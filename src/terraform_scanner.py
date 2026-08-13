"""
terraform_scanner.py
--------------------
Scans Terraform (.tf) files for IAM misconfigurations and
privilege-escalation risks across GCP, AWS, and Azure.

Detects dangerous IAM patterns BEFORE they are deployed —
shift-left security for DevSecOps pipelines.

Detection Rules:
  TF-001  AWS IAM policy with wildcard Action (*) and Resource (*)
  TF-002  AWS IAM role with overly permissive trust policy (Principal: *)
  TF-003  AWS admin policy attached directly to user/role
  TF-004  GCP project IAM binding with allUsers / allAuthenticatedUsers
  TF-005  GCP owner/editor role binding
  TF-006  Azure role assignment with Owner at subscription scope
  TF-007  Hardcoded secrets / access keys in Terraform files
  TF-008  IAM policy with NotAction (allows everything except listed)
  TF-009  AWS IAM user with inline policy (should use roles)
  TF-010  Missing MFA condition on sensitive AWS IAM policies

Public API
  scan_terraform_file(path: str) -> list[TerraformFinding]
  scan_terraform_directory(directory: str) -> list[TerraformFinding]
"""

from __future__ import annotations

import json
import re
import os
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TerraformFinding:
    rule_id: str
    title: str
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW
    file_path: str
    line_number: int
    resource_name: str      # terraform resource block name
    resource_type: str      # e.g. aws_iam_policy, google_project_iam_binding
    description: str
    mitre_technique: str
    mitre_tactic: str
    remediation: str
    evidence: str           # the offending line/snippet


# ---------------------------------------------------------------------------
# Simple HCL helpers (no external parser needed)
# ---------------------------------------------------------------------------

def _read_file(path: str) -> list[str]:
    try:
        return Path(path).read_text(encoding="utf-8").splitlines()
    except Exception:
        return []


def _find_resource_name(lines: list[str], block_start: int) -> tuple[str, str]:
    """Extract resource type and name from 'resource "type" "name" {' line."""
    line = lines[block_start] if block_start < len(lines) else ""
    m = re.match(r'\s*resource\s+"([^"]+)"\s+"([^"]+)"', line)
    if m:
        return m.group(1), m.group(2)
    return "unknown_resource", "unknown_name"


def _find_blocks(lines: list[str], resource_type: str) -> list[tuple[int, int]]:
    """Find all blocks of a given resource type. Returns (start, end) line pairs."""
    blocks = []
    i = 0
    while i < len(lines):
        if re.match(rf'\s*resource\s+"{re.escape(resource_type)}"', lines[i]):
            start = i
            depth = 0
            for j in range(i, len(lines)):
                depth += lines[j].count("{") - lines[j].count("}")
                if depth == 0 and j > i:
                    blocks.append((start, j))
                    i = j + 1
                    break
            else:
                i += 1
        else:
            i += 1
    return blocks


def _block_text(lines: list[str], start: int, end: int) -> str:
    return "\n".join(lines[start:end + 1])


def _find_line(lines: list[str], pattern: str, start: int, end: int) -> int:
    """Return first line number matching pattern within block, or start."""
    for i in range(start, min(end + 1, len(lines))):
        if re.search(pattern, lines[i], re.IGNORECASE):
            return i + 1  # 1-indexed
    return start + 1


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

def _tf001_aws_wildcard_policy(lines: list[str], path: str) -> list[TerraformFinding]:
    """TF-001 — AWS IAM policy with Action=* and Resource=*"""
    findings = []
    # Look for inline JSON policy documents
    full_text = "\n".join(lines)
    
    # Find aws_iam_policy and aws_iam_role_policy blocks
    for res_type in ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy",
                     "aws_iam_group_policy"]:
        for start, end in _find_blocks(lines, res_type):
            block = _block_text(lines, start, end)
            _, res_name = _find_resource_name(lines, start)
            
            has_wildcard_action   = bool(re.search(r'"Action"\s*:\s*["\[]?\s*"\*"', block))
            has_wildcard_resource = bool(re.search(r'"Resource"\s*:\s*["\[]?\s*"\*"', block))
            has_effect_allow      = bool(re.search(r'"Effect"\s*:\s*"Allow"', block))

            if has_wildcard_action and has_wildcard_resource and has_effect_allow:
                ln = _find_line(lines, r'"Action".*"\*"', start, end)
                findings.append(TerraformFinding(
                    rule_id="TF-001",
                    title="AWS IAM Wildcard Policy — Action:* Resource:*",
                    severity="CRITICAL",
                    file_path=path,
                    line_number=ln,
                    resource_name=res_name,
                    resource_type=res_type,
                    description=(
                        f"Resource '{res_name}' ({res_type}) has Action: '*' with "
                        "Resource: '*' and Effect: Allow — grants full access to every "
                        "AWS API on every resource. Equivalent to AdministratorAccess."
                    ),
                    mitre_technique="T1078.004",
                    mitre_tactic="Valid Accounts: Cloud Accounts",
                    remediation=(
                        "Replace '*' with specific actions and resources. "
                        "Apply least-privilege principle. "
                        "Example: 'Action': ['s3:GetObject'], 'Resource': ['arn:aws:s3:::my-bucket/*']"
                    ),
                    evidence=f'Action: "*", Resource: "*" in {res_name}',
                ))
    return findings


def _tf002_aws_public_trust(lines: list[str], path: str) -> list[TerraformFinding]:
    """TF-002 — AWS IAM role with Principal: * in trust policy"""
    findings = []
    for start, end in _find_blocks(lines, "aws_iam_role"):
        block = _block_text(lines, start, end)
        _, res_name = _find_resource_name(lines, start)

        if re.search(r'"Principal"\s*:\s*["\[]?\s*"\*"', block):
            ln = _find_line(lines, r'"Principal".*"\*"', start, end)
            findings.append(TerraformFinding(
                rule_id="TF-002",
                title="AWS IAM Role — Public Trust Policy (Principal: *)",
                severity="CRITICAL",
                file_path=path,
                line_number=ln,
                resource_name=res_name,
                resource_type="aws_iam_role",
                description=(
                    f"IAM role '{res_name}' has a trust policy with Principal: '*', "
                    "meaning ANY AWS identity — including external accounts — can "
                    "assume this role without restriction."
                ),
                mitre_technique="T1078.004",
                mitre_tactic="Valid Accounts: Cloud Accounts",
                remediation=(
                    "Restrict Principal to specific AWS accounts, services, or ARNs. "
                    "Example: 'Principal': {'Service': 'ec2.amazonaws.com'}"
                ),
                evidence=f'Principal: "*" in trust policy of {res_name}',
            ))
    return findings


def _tf003_aws_admin_policy(lines: list[str], path: str) -> list[TerraformFinding]:
    """TF-003 — AWS AdministratorAccess policy attached"""
    findings = []
    admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"

    for res_type in ["aws_iam_role_policy_attachment",
                     "aws_iam_user_policy_attachment",
                     "aws_iam_group_policy_attachment"]:
        for start, end in _find_blocks(lines, res_type):
            block = _block_text(lines, start, end)
            _, res_name = _find_resource_name(lines, start)

            if admin_arn in block:
                ln = _find_line(lines, "AdministratorAccess", start, end)
                findings.append(TerraformFinding(
                    rule_id="TF-003",
                    title="AWS AdministratorAccess Policy Attached",
                    severity="CRITICAL",
                    file_path=path,
                    line_number=ln,
                    resource_name=res_name,
                    resource_type=res_type,
                    description=(
                        f"'{res_name}' attaches AdministratorAccess — the most "
                        "permissive AWS managed policy. Grants full access to all "
                        "AWS services and resources."
                    ),
                    mitre_technique="T1078.004",
                    mitre_tactic="Valid Accounts: Cloud Accounts",
                    remediation=(
                        "Replace AdministratorAccess with a least-privilege custom policy. "
                        "Grant only the specific actions required for the role's function."
                    ),
                    evidence=f"policy_arn = {admin_arn}",
                ))
    return findings


def _tf004_gcp_public_binding(lines: list[str], path: str) -> list[TerraformFinding]:
    """TF-004 — GCP IAM binding with allUsers / allAuthenticatedUsers"""
    findings = []
    for res_type in ["google_project_iam_binding", "google_project_iam_member",
                     "google_storage_bucket_iam_binding", "google_storage_bucket_iam_member"]:
        for start, end in _find_blocks(lines, res_type):
            block = _block_text(lines, start, end)
            _, res_name = _find_resource_name(lines, start)

            if re.search(r'allUsers|allAuthenticatedUsers', block):
                ln = _find_line(lines, r'allUsers|allAuthenticatedUsers', start, end)
                findings.append(TerraformFinding(
                    rule_id="TF-004",
                    title="GCP IAM — Public Binding (allUsers / allAuthenticatedUsers)",
                    severity="CRITICAL",
                    file_path=path,
                    line_number=ln,
                    resource_name=res_name,
                    resource_type=res_type,
                    description=(
                        f"'{res_name}' grants access to allUsers or allAuthenticatedUsers — "
                        "anyone on the internet can access this resource. "
                        "No authentication required for allUsers."
                    ),
                    mitre_technique="T1078.004",
                    mitre_tactic="Valid Accounts: Cloud Accounts",
                    remediation=(
                        "Remove allUsers / allAuthenticatedUsers from IAM bindings. "
                        "Grant access to specific service accounts or users only."
                    ),
                    evidence='member = "allUsers" or "allAuthenticatedUsers"',
                ))
    return findings


def _tf005_gcp_owner_editor(lines: list[str], path: str) -> list[TerraformFinding]:
    """TF-005 — GCP owner or editor role binding"""
    findings = []
    for res_type in ["google_project_iam_binding", "google_project_iam_member"]:
        for start, end in _find_blocks(lines, res_type):
            block = _block_text(lines, start, end)
            _, res_name = _find_resource_name(lines, start)

            if re.search(r'roles/(owner|editor)', block, re.IGNORECASE):
                role_match = re.search(r'roles/(owner|editor)', block, re.IGNORECASE)
                role = role_match.group(0) if role_match else "owner/editor"
                ln = _find_line(lines, r'roles/(owner|editor)', start, end)
                findings.append(TerraformFinding(
                    rule_id="TF-005",
                    title=f"GCP Overly Permissive Role — {role}",
                    severity="HIGH",
                    file_path=path,
                    line_number=ln,
                    resource_name=res_name,
                    resource_type=res_type,
                    description=(
                        f"'{res_name}' grants '{role}' at project level. "
                        "Owner can modify IAM policies — equivalent to full project control. "
                        "Editor can modify almost all resources."
                    ),
                    mitre_technique="T1098.003",
                    mitre_tactic="Account Manipulation: Additional Cloud Roles",
                    remediation=(
                        f"Replace '{role}' with a specific predefined role. "
                        "Example: roles/storage.objectAdmin instead of roles/editor."
                    ),
                    evidence=f'role = "{role}"',
                ))
    return findings


def _tf006_azure_owner(lines: list[str], path: str) -> list[TerraformFinding]:
    """TF-006 — Azure Owner role assignment"""
    findings = []
    for start, end in _find_blocks(lines, "azurerm_role_assignment"):
        block = _block_text(lines, start, end)
        _, res_name = _find_resource_name(lines, start)

        if re.search(r'Owner|8e3af657-a8ff-443c-a75c-2fe8c4bcb635', block):
            ln = _find_line(lines, r'Owner|8e3af657', start, end)
            findings.append(TerraformFinding(
                rule_id="TF-006",
                title="Azure Owner Role Assignment",
                severity="CRITICAL",
                file_path=path,
                line_number=ln,
                resource_name=res_name,
                resource_type="azurerm_role_assignment",
                description=(
                    f"'{res_name}' assigns the Owner role, which grants full control "
                    "including the ability to change access permissions. "
                    "This is the most dangerous Azure RBAC role."
                ),
                mitre_technique="T1078.004",
                mitre_tactic="Valid Accounts: Cloud Accounts",
                remediation=(
                    "Replace Owner with Contributor (no access management) or a "
                    "custom role with only the required permissions."
                ),
                evidence='role_definition_name = "Owner"',
            ))
    return findings


def _tf007_hardcoded_secrets(lines: list[str], path: str) -> list[TerraformFinding]:
    """TF-007 — Hardcoded secrets / access keys"""
    findings = []
    SECRET_PATTERNS = [
        (r'access_key\s*=\s*"AKIA[A-Z0-9]{16}"', "AWS Access Key ID"),
        (r'secret_key\s*=\s*"[A-Za-z0-9/+]{40}"', "AWS Secret Access Key"),
        (r'password\s*=\s*"[^"${}][^"]{7,}"', "Hardcoded Password"),
        (r'private_key\s*=\s*"-----BEGIN', "Private Key"),
        (r'client_secret\s*=\s*"[^"${}][^"]{10,}"', "Client Secret"),
        (r'api_key\s*=\s*"[^"${}][^"]{10,}"', "API Key"),
    ]

    for i, line in enumerate(lines):
        for pattern, secret_type in SECRET_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                # Skip if it looks like a variable reference
                if "${var." in line or "${data." in line or "var." in line:
                    continue
                findings.append(TerraformFinding(
                    rule_id="TF-007",
                    title=f"Hardcoded Secret — {secret_type}",
                    severity="CRITICAL",
                    file_path=path,
                    line_number=i + 1,
                    resource_name="(inline)",
                    resource_type="(any)",
                    description=(
                        f"Potential {secret_type} hardcoded in Terraform file. "
                        "Secrets in .tf files are stored in state and version control — "
                        "a critical security risk."
                    ),
                    mitre_technique="T1552.001",
                    mitre_tactic="Unsecured Credentials: Credentials In Files",
                    remediation=(
                        "Use Terraform variables with sensitive=true, "
                        "environment variables, or a secrets manager "
                        "(AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)."
                    ),
                    evidence=line.strip()[:80],
                ))
                break
    return findings


def _tf008_not_action(lines: list[str], path: str) -> list[TerraformFinding]:
    """TF-008 — IAM policy with NotAction (allows everything except listed)"""
    findings = []
    full_text = "\n".join(lines)

    for res_type in ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"]:
        for start, end in _find_blocks(lines, res_type):
            block = _block_text(lines, start, end)
            _, res_name = _find_resource_name(lines, start)

            if '"NotAction"' in block:
                ln = _find_line(lines, '"NotAction"', start, end)
                findings.append(TerraformFinding(
                    rule_id="TF-008",
                    title="AWS IAM Policy Uses NotAction",
                    severity="HIGH",
                    file_path=path,
                    line_number=ln,
                    resource_name=res_name,
                    resource_type=res_type,
                    description=(
                        f"'{res_name}' uses NotAction — this allows ALL actions "
                        "EXCEPT those listed. Future new AWS services are automatically "
                        "allowed, which is rarely the intended behavior."
                    ),
                    mitre_technique="T1078.004",
                    mitre_tactic="Valid Accounts: Cloud Accounts",
                    remediation=(
                        "Replace NotAction with an explicit Action list. "
                        "Only grant the specific actions actually required."
                    ),
                    evidence='"NotAction" found in policy document',
                ))
    return findings


def _tf009_iam_user_inline(lines: list[str], path: str) -> list[TerraformFinding]:
    """TF-009 — AWS IAM user with inline policy"""
    findings = []
    for start, end in _find_blocks(lines, "aws_iam_user_policy"):
        _, res_name = _find_resource_name(lines, start)
        ln = start + 1
        findings.append(TerraformFinding(
            rule_id="TF-009",
            title="AWS IAM Inline Policy on User",
            severity="MEDIUM",
            file_path=path,
            line_number=ln,
            resource_name=res_name,
            resource_type="aws_iam_user_policy",
            description=(
                f"'{res_name}' attaches an inline policy directly to an IAM user. "
                "AWS best practice is to use roles, not users, for programmatic access. "
                "Inline policies on users are harder to audit and manage."
            ),
            mitre_technique="T1078.004",
            mitre_tactic="Valid Accounts: Cloud Accounts",
            remediation=(
                "Replace IAM user + inline policy with an IAM role. "
                "Use aws_iam_role + aws_iam_role_policy instead. "
                "For human users, use IAM Identity Center (SSO)."
            ),
            evidence=f"aws_iam_user_policy resource: {res_name}",
        ))
    return findings


def _tf010_no_mfa_condition(lines: list[str], path: str) -> list[TerraformFinding]:
    """TF-010 — Sensitive IAM policy missing MFA condition"""
    findings = []
    SENSITIVE_ACTIONS = ["iam:*", "sts:AssumeRole", "*"]

    for res_type in ["aws_iam_policy", "aws_iam_role_policy"]:
        for start, end in _find_blocks(lines, res_type):
            block = _block_text(lines, start, end)
            _, res_name = _find_resource_name(lines, start)

            has_sensitive = any(f'"{a}"' in block for a in SENSITIVE_ACTIONS)
            has_mfa = "MultiFactorAuthPresent" in block or "aws:MultiFactorAuthAge" in block

            if has_sensitive and not has_mfa:
                ln = start + 1
                findings.append(TerraformFinding(
                    rule_id="TF-010",
                    title="Sensitive IAM Policy Missing MFA Condition",
                    severity="MEDIUM",
                    file_path=path,
                    line_number=ln,
                    resource_name=res_name,
                    resource_type=res_type,
                    description=(
                        f"'{res_name}' grants sensitive actions without requiring MFA. "
                        "High-privilege operations should require MFA to prevent "
                        "credential theft attacks."
                    ),
                    mitre_technique="T1078.004",
                    mitre_tactic="Valid Accounts: Cloud Accounts",
                    remediation=(
                        'Add a Condition block: '
                        '"Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}'
                    ),
                    evidence=f"Sensitive actions without MFA condition in {res_name}",
                ))
    return findings


# ---------------------------------------------------------------------------
# All rules
# ---------------------------------------------------------------------------

_ALL_RULES = [
    _tf001_aws_wildcard_policy,
    _tf002_aws_public_trust,
    _tf003_aws_admin_policy,
    _tf004_gcp_public_binding,
    _tf005_gcp_owner_editor,
    _tf006_azure_owner,
    _tf007_hardcoded_secrets,
    _tf008_not_action,
    _tf009_iam_user_inline,
    _tf010_no_mfa_condition,
]

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def scan_terraform_file(path: str) -> list[TerraformFinding]:
    """Scan a single .tf file and return findings sorted by severity."""
    lines = _read_file(path)
    if not lines:
        return []

    findings: list[TerraformFinding] = []
    for rule_fn in _ALL_RULES:
        try:
            findings.extend(rule_fn(lines, path))
        except Exception as exc:
            print(f"[terraform-scan] Rule {rule_fn.__name__} error: {exc}")

    findings.sort(key=lambda f: SEV_ORDER.get(f.severity, 9))
    return findings


def scan_terraform_directory(directory: str) -> list[TerraformFinding]:
    """Recursively scan all .tf files in a directory."""
    all_findings: list[TerraformFinding] = []
    dir_path = Path(directory)

    tf_files = list(dir_path.rglob("*.tf"))
    if not tf_files:
        print(f"[terraform-scan] No .tf files found in {directory}")
        return []

    print(f"[terraform-scan] Found {len(tf_files)} .tf file(s)")
    for tf_file in tf_files:
        file_findings = scan_terraform_file(str(tf_file))
        if file_findings:
            print(f"  {tf_file.name}: {len(file_findings)} finding(s)")
        all_findings.extend(file_findings)

    all_findings.sort(key=lambda f: SEV_ORDER.get(f.severity, 9))
    return all_findings


def get_terraform_rules() -> list[dict]:
    """Return rule metadata for the `rules` CLI command."""
    return [
        {"id": "TF-001", "title": "AWS IAM Wildcard Policy (Action:* Resource:*)", "severity": "CRITICAL", "mitre": "T1078.004"},
        {"id": "TF-002", "title": "AWS IAM Role Public Trust Policy (Principal:*)", "severity": "CRITICAL", "mitre": "T1078.004"},
        {"id": "TF-003", "title": "AWS AdministratorAccess Policy Attached",        "severity": "CRITICAL", "mitre": "T1078.004"},
        {"id": "TF-004", "title": "GCP Public IAM Binding (allUsers)",              "severity": "CRITICAL", "mitre": "T1078.004"},
        {"id": "TF-005", "title": "GCP Owner/Editor Role Binding",                  "severity": "HIGH",     "mitre": "T1098.003"},
        {"id": "TF-006", "title": "Azure Owner Role Assignment",                    "severity": "CRITICAL", "mitre": "T1078.004"},
        {"id": "TF-007", "title": "Hardcoded Secrets / Access Keys",                "severity": "CRITICAL", "mitre": "T1552.001"},
        {"id": "TF-008", "title": "AWS IAM Policy Uses NotAction",                  "severity": "HIGH",     "mitre": "T1078.004"},
        {"id": "TF-009", "title": "AWS IAM Inline Policy on User",                  "severity": "MEDIUM",   "mitre": "T1078.004"},
        {"id": "TF-010", "title": "Sensitive Policy Missing MFA Condition",         "severity": "MEDIUM",   "mitre": "T1078.004"},
    ]


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_data/sample_terraform"

    if Path(path).is_dir():
        findings = scan_terraform_directory(path)
    else:
        findings = scan_terraform_file(path)

    print(f"\n{'='*60}")
    print(f"  TERRAFORM SCAN — {len(findings)} finding(s)")
    print(f"{'='*60}\n")

    for f in findings:
        print(f"[{f.severity}] {f.rule_id} — {f.title}")
        print(f"  File     : {f.file_path}:{f.line_number}")
        print(f"  Resource : {f.resource_type}.{f.resource_name}")
        print(f"  MITRE    : {f.mitre_technique}")
        print(f"  Fix      : {f.remediation[:80]}...")
        print()


# ---------------------------------------------------------------------------
# Terraform State File Scanner
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TfstateFinding:
    rule_id: str
    title: str
    severity: str
    file_path: str
    resource_type: str
    resource_name: str
    secret_type: str
    description: str
    mitre_technique: str
    remediation: str
    evidence: str


# Sensitive attribute names that indicate leaked secrets
SENSITIVE_ATTR_NAMES = frozenset({
    "password", "secret", "private_key", "secret_key", "access_key",
    "api_key", "token", "credential", "private_key_pem", "client_secret",
    "primary_access_key", "secondary_access_key", "connection_string",
    "sas_token", "shared_access_key", "auth_token", "secret_string",
    "secret_binary", "value",  # azure key vault secret value
})

# Resource types that commonly contain secrets
SECRET_RESOURCE_TYPES = frozenset({
    "aws_db_instance", "aws_rds_cluster", "aws_iam_access_key",
    "aws_secretsmanager_secret_version", "aws_ssm_parameter",
    "google_service_account_key", "google_sql_user",
    "azurerm_key_vault_secret", "azurerm_sql_server",
    "kubernetes_secret", "helm_release",
    "random_password",
})


def _is_real_secret(value: str) -> bool:
    """Check if value looks like a real secret (not a placeholder)."""
    if not isinstance(value, str):
        return False
    if len(value) < 8:
        return False
    placeholders = {"", "null", "none", "placeholder", "changeme",
                    "example", "xxxx", "****", "redacted"}
    if value.lower() in placeholders:
        return False
    if value.startswith("${"):  # Terraform reference
        return False
    return True


def _scan_attributes(attrs: dict, resource_type: str,
                     resource_name: str, path: str) -> list[TfstateFinding]:
    """Recursively scan resource attributes for secrets."""
    findings = []

    def _recurse(obj: Any, attr_path: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_path = f"{attr_path}.{k}" if attr_path else k
                k_lower = k.lower()
                if any(s in k_lower for s in SENSITIVE_ATTR_NAMES):
                    if _is_real_secret(str(v)):
                        masked = str(v)[:4] + "..." + str(v)[-2:] if len(str(v)) > 8 else "***"
                        findings.append(TfstateFinding(
                            rule_id="TFS-001",
                            title="Secret Leaked in Terraform State",
                            severity="CRITICAL",
                            file_path=path,
                            resource_type=resource_type,
                            resource_name=resource_name,
                            secret_type=k,
                            description=(
                                f"Resource '{resource_type}.{resource_name}' has "
                                f"attribute '{full_path}' containing a plaintext secret. "
                                "Terraform state files are stored unencrypted by default — "
                                "anyone with state access can read this secret."
                            ),
                            mitre_technique="T1552.001",
                            remediation=(
                                "1. Rotate this secret immediately. "
                                "2. Use remote state with encryption (S3+KMS, Azure Storage, GCS). "
                                "3. Use sensitive=true in Terraform variables. "
                                "4. Store secrets in Vault/AWS Secrets Manager, not in state."
                            ),
                            evidence=f"{full_path} = {masked}",
                        ))
                _recurse(v, full_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _recurse(item, f"{attr_path}[{i}]")

    _recurse(attrs)
    return findings


def scan_tfstate_file(path: str) -> list[TfstateFinding]:
    """
    Scan a Terraform state file (.tfstate) for leaked secrets.

    Terraform state files store the actual values of all resources —
    including passwords, private keys, and API keys — in plaintext JSON.
    This scanner detects those leaks.

    Args:
        path: Path to a .tfstate file

    Returns:
        list of TfstateFinding objects
    """
    try:
        state = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[tfstate-scan] Could not read {path}: {exc}")
        return []

    if not isinstance(state, dict):
        return []

    all_findings: list[TfstateFinding] = []
    resources = state.get("resources", [])

    print(f"[tfstate-scan] Scanning {len(resources)} resource(s) in {path}")

    for resource in resources:
        if not isinstance(resource, dict):
            continue
        res_type = resource.get("type", "unknown")
        res_name = resource.get("name", "unknown")

        for instance in resource.get("instances", []):
            attrs = instance.get("attributes", {})
            if not attrs:
                continue
            findings = _scan_attributes(attrs, res_type, res_name, path)
            all_findings.extend(findings)

    # Deduplicate
    seen: set[tuple] = set()
    unique: list[TfstateFinding] = []
    for f in all_findings:
        key = (f.resource_type, f.resource_name, f.secret_type)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    print(f"[tfstate-scan] Found {len(unique)} secret(s) in state file")
    return unique


def get_tfstate_rules() -> list[dict]:
    return [
        {"id": "TFS-001", "title": "Secret Leaked in Terraform State File",
         "severity": "CRITICAL", "mitre": "T1552.001"},
    ]
