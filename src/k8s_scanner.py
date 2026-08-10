"""
k8s_scanner.py
--------------
Kubernetes RBAC Security Scanner.

Scans Kubernetes RBAC resources for privilege-escalation risks:
  - ClusterRoles with dangerous permissions
  - ClusterRoleBindings granting admin to broad subjects
  - Roles with wildcard permissions
  - ServiceAccounts with excessive cluster-level access
  - Default service account misuse
  - Privileged namespace access

Supported input formats:
  - kubectl get clusterroles -o json > k8s_rbac.json
  - kubectl get clusterrolebindings -o json > k8s_rbac.json
  - Combined export (all resources in one file)
  - YAML files

Public API
  scan_k8s_file(path: str) -> list[K8sFinding]
  scan_k8s_directory(path: str) -> list[K8sFinding]
  get_k8s_rules() -> list[dict]
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class K8sFinding:
    rule_id: str
    title: str
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW
    resource_kind: str      # ClusterRole | ClusterRoleBinding | Role | RoleBinding
    resource_name: str
    namespace: str          # cluster-wide or specific namespace
    subject: str            # who is affected
    description: str
    mitre_technique: str
    mitre_tactic: str
    remediation: str
    evidence: tuple[str, ...]


# ---------------------------------------------------------------------------
# Dangerous permissions
# ---------------------------------------------------------------------------

DANGEROUS_VERBS       = frozenset({"*", "create", "delete", "patch", "update", "escalate", "bind"})
DANGEROUS_RESOURCES   = frozenset({
    "*", "pods", "secrets", "configmaps", "serviceaccounts",
    "clusterroles", "clusterrolebindings", "roles", "rolebindings",
    "deployments", "daemonsets", "statefulsets", "cronjobs",
    "persistentvolumes", "nodes", "namespaces",
})
SENSITIVE_API_GROUPS  = frozenset({"*", "rbac.authorization.k8s.io", ""})

# ClusterRoles that are dangerous by name
DANGEROUS_CLUSTER_ROLES = frozenset({
    "cluster-admin", "admin", "edit",
    "system:masters", "system:admin",
})

# Subjects that should never have cluster-admin
RISKY_SUBJECTS = frozenset({
    "system:anonymous",
    "system:unauthenticated",
    "system:authenticated",
})


# ---------------------------------------------------------------------------
# Parser helpers
# ---------------------------------------------------------------------------

def _load_k8s_file(path: str) -> list[dict]:
    """Load a K8s JSON or YAML file, return list of resource objects."""
    file_path = Path(path)
    content   = file_path.read_text(encoding="utf-8")

    try:
        data = json.loads(content)
        if isinstance(data, dict):
            if data.get("kind") == "List":
                return data.get("items", [])
            return [data]
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass

    # Try YAML
    try:
        import yaml  # optional
        docs = list(yaml.safe_load_all(content))
        return [d for d in docs if isinstance(d, dict)]
    except ImportError:
        # Simple YAML parser for basic K8s resources
        return _parse_simple_yaml(content)
    except Exception:
        return []


def _parse_simple_yaml(content: str) -> list[dict]:
    """Very basic YAML→dict for K8s resources (no external dep)."""
    # Just try to extract kind and name for identification
    resources = []
    current: dict = {}
    for line in content.splitlines():
        if line.startswith("---"):
            if current:
                resources.append(current)
            current = {}
        elif line.startswith("kind:"):
            current["kind"] = line.split(":", 1)[1].strip()
        elif line.strip().startswith("name:") and "metadata" in str(current):
            current.setdefault("metadata", {})["name"] = line.split(":", 1)[1].strip()
    if current:
        resources.append(current)
    return resources


def _get_meta(resource: dict, key: str, default: str = "") -> str:
    return resource.get("metadata", {}).get(key, default)


def _get_rules(resource: dict) -> list[dict]:
    return resource.get("rules", []) or []


def _get_subjects(binding: dict) -> list[dict]:
    return binding.get("subjects", []) or []


def _get_role_ref(binding: dict) -> dict:
    return binding.get("roleRef", {})


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

def _k8s001_cluster_admin_binding(resources: list[dict], path: str) -> list[K8sFinding]:
    """K8S-001 — ClusterRoleBinding to cluster-admin for broad subjects."""
    findings = []
    for r in resources:
        if r.get("kind") not in ("ClusterRoleBinding",):
            continue
        role_ref = _get_role_ref(r)
        if role_ref.get("name") != "cluster-admin":
            continue

        name = _get_meta(r, "name")
        for subj in _get_subjects(r):
            subj_name = subj.get("name", "")
            subj_kind = subj.get("kind", "")
            subj_ns   = subj.get("namespace", "cluster-wide")

            # Skip system components that legitimately need cluster-admin
            if subj_name.startswith("system:") and subj_name not in RISKY_SUBJECTS:
                if not any(risky in subj_name for risky in ["anonymous", "unauthenticated"]):
                    continue

            findings.append(K8sFinding(
                rule_id="K8S-001",
                title="ClusterRoleBinding to cluster-admin",
                severity="CRITICAL",
                resource_kind="ClusterRoleBinding",
                resource_name=name,
                namespace="cluster-wide",
                subject=f"{subj_kind}/{subj_name}",
                description=(
                    f"'{subj_kind}/{subj_name}' has cluster-admin via ClusterRoleBinding "
                    f"'{name}'. cluster-admin grants unrestricted access to ALL resources "
                    "in ALL namespaces — the most dangerous K8s permission."
                ),
                mitre_technique="T1078.001",
                mitre_tactic="Valid Accounts: Default Accounts",
                remediation=(
                    f"Remove or restrict ClusterRoleBinding '{name}'. "
                    "Replace cluster-admin with a least-privilege ClusterRole. "
                    "Use namespace-scoped RoleBindings where possible."
                ),
                evidence=(f"roleRef: cluster-admin", f"subject: {subj_kind}/{subj_name}"),
            ))
    return findings


def _k8s002_wildcard_permissions(resources: list[dict], path: str) -> list[K8sFinding]:
    """K8S-002 — ClusterRole/Role with wildcard verbs or resources."""
    findings = []
    for r in resources:
        if r.get("kind") not in ("ClusterRole", "Role"):
            continue

        name   = _get_meta(r, "name")
        ns     = _get_meta(r, "namespace", "cluster-wide")

        # Skip built-in system roles
        if name.startswith("system:") and "node" not in name:
            continue

        for rule in _get_rules(r):
            verbs     = rule.get("verbs", [])
            resources_list = rule.get("resources", [])
            api_groups = rule.get("apiGroups", [])

            has_wildcard_verb     = "*" in verbs
            has_wildcard_resource = "*" in resources_list
            has_wildcard_group    = "*" in api_groups

            if has_wildcard_verb and has_wildcard_resource:
                findings.append(K8sFinding(
                    rule_id="K8S-002",
                    title="Wildcard Permissions in Role",
                    severity="CRITICAL",
                    resource_kind=r.get("kind", "Role"),
                    resource_name=name,
                    namespace=ns,
                    subject=name,
                    description=(
                        f"Role '{name}' has verbs: ['*'] on resources: ['*'] — "
                        "grants full access to all API operations on all resources. "
                        "Functionally equivalent to cluster-admin."
                    ),
                    mitre_technique="T1078.001",
                    mitre_tactic="Valid Accounts: Default Accounts",
                    remediation=(
                        f"Replace '*' verbs and resources in '{name}' with "
                        "specific, minimal permissions required for the workload."
                    ),
                    evidence=(f"verbs: {verbs}", f"resources: {resources_list}"),
                ))
                break
            elif has_wildcard_verb:
                findings.append(K8sFinding(
                    rule_id="K8S-002",
                    title="Wildcard Verbs in Role",
                    severity="HIGH",
                    resource_kind=r.get("kind", "Role"),
                    resource_name=name,
                    namespace=ns,
                    subject=name,
                    description=(
                        f"Role '{name}' has verbs: ['*'] on {resources_list}. "
                        "Wildcard verbs allow any operation including delete and patch."
                    ),
                    mitre_technique="T1078.001",
                    mitre_tactic="Valid Accounts: Default Accounts",
                    remediation=(
                        f"Replace wildcard verbs in '{name}' with specific verbs "
                        "like ['get', 'list', 'watch']."
                    ),
                    evidence=(f"verbs: ['*']", f"resources: {resources_list}"),
                ))
    return findings


def _k8s003_secrets_access(resources: list[dict], path: str) -> list[K8sFinding]:
    """K8S-003 — Role with broad secrets access."""
    findings = []
    for r in resources:
        if r.get("kind") not in ("ClusterRole", "Role"):
            continue

        name = _get_meta(r, "name")
        ns   = _get_meta(r, "namespace", "cluster-wide")

        if name.startswith("system:"):
            continue

        for rule in _get_rules(r):
            verbs      = set(rule.get("verbs", []))
            res_list   = rule.get("resources", [])
            has_secrets = "secrets" in res_list or "*" in res_list
            has_read    = bool(verbs & {"get", "list", "watch", "*"})

            if has_secrets and has_read:
                findings.append(K8sFinding(
                    rule_id="K8S-003",
                    title="Role Can Read Kubernetes Secrets",
                    severity="HIGH",
                    resource_kind=r.get("kind", "Role"),
                    resource_name=name,
                    namespace=ns,
                    subject=name,
                    description=(
                        f"Role '{name}' can read Kubernetes Secrets "
                        f"(verbs: {sorted(verbs & {'get','list','watch','*'})}). "
                        "K8s Secrets contain credentials, tokens, and certificates "
                        "that can be used for lateral movement."
                    ),
                    mitre_technique="T1552.007",
                    mitre_tactic="Unsecured Credentials: Container API",
                    remediation=(
                        "Restrict secrets access to only the specific secrets needed. "
                        "Use resourceNames to limit which secrets can be read. "
                        "Consider using an external secrets manager instead."
                    ),
                    evidence=(f"resources: {res_list}", f"verbs: {sorted(verbs)}"),
                ))
                break
    return findings


def _k8s004_default_sa_binding(resources: list[dict], path: str) -> list[K8sFinding]:
    """K8S-004 — Default service account bound to powerful role."""
    findings = []
    for r in resources:
        if r.get("kind") not in ("ClusterRoleBinding", "RoleBinding"):
            continue

        name     = _get_meta(r, "name")
        role_ref = _get_role_ref(r)
        role_name= role_ref.get("name", "")

        for subj in _get_subjects(r):
            if (subj.get("kind") == "ServiceAccount" and
                    subj.get("name") == "default"):

                is_dangerous_role = (
                    role_name in DANGEROUS_CLUSTER_ROLES or
                    "admin" in role_name.lower() or
                    "cluster" in role_name.lower()
                )
                if not is_dangerous_role:
                    continue

                ns = subj.get("namespace", _get_meta(r, "namespace", "default"))
                findings.append(K8sFinding(
                    rule_id="K8S-004",
                    title="Default ServiceAccount Bound to Privileged Role",
                    severity="HIGH",
                    resource_kind=r.get("kind"),
                    resource_name=name,
                    namespace=ns,
                    subject=f"ServiceAccount/default ({ns})",
                    description=(
                        f"The 'default' ServiceAccount in namespace '{ns}' is bound "
                        f"to '{role_name}' via '{name}'. Every pod in '{ns}' that "
                        "doesn't specify a ServiceAccount automatically gets this "
                        "binding — giving all pods admin-level access."
                    ),
                    mitre_technique="T1078.001",
                    mitre_tactic="Valid Accounts: Default Accounts",
                    remediation=(
                        "Create dedicated ServiceAccounts for each workload. "
                        "Remove the default ServiceAccount from privileged roles. "
                        "Set automountServiceAccountToken: false on the default SA."
                    ),
                    evidence=(f"subject: default SA in {ns}", f"role: {role_name}"),
                ))
    return findings


def _k8s005_anonymous_access(resources: list[dict], path: str) -> list[K8sFinding]:
    """K8S-005 — Anonymous / unauthenticated access binding."""
    findings = []
    for r in resources:
        if r.get("kind") not in ("ClusterRoleBinding", "RoleBinding"):
            continue

        name = _get_meta(r, "name")
        for subj in _get_subjects(r):
            subj_name = subj.get("name", "")
            if subj_name in ("system:anonymous", "system:unauthenticated"):
                role_ref  = _get_role_ref(r)
                role_name = role_ref.get("name", "unknown")
                findings.append(K8sFinding(
                    rule_id="K8S-005",
                    title="Anonymous / Unauthenticated Access Granted",
                    severity="CRITICAL",
                    resource_kind=r.get("kind"),
                    resource_name=name,
                    namespace=_get_meta(r, "namespace", "cluster-wide"),
                    subject=subj_name,
                    description=(
                        f"'{subj_name}' is granted '{role_name}' via '{name}'. "
                        "This means ANYONE — without any authentication — can "
                        "perform these operations on your cluster. "
                        "Equivalent to a publicly accessible Kubernetes API."
                    ),
                    mitre_technique="T1078.001",
                    mitre_tactic="Valid Accounts: Default Accounts",
                    remediation=(
                        f"Immediately remove the binding '{name}' for '{subj_name}'. "
                        "Enable RBAC and disable anonymous authentication: "
                        "--anonymous-auth=false on the API server."
                    ),
                    evidence=(f"subject: {subj_name}", f"role: {role_name}"),
                ))
    return findings


def _k8s006_pod_exec_access(resources: list[dict], path: str) -> list[K8sFinding]:
    """K8S-006 — Role with pod exec/attach permissions."""
    findings = []
    for r in resources:
        if r.get("kind") not in ("ClusterRole", "Role"):
            continue

        name = _get_meta(r, "name")
        ns   = _get_meta(r, "namespace", "cluster-wide")

        if name.startswith("system:"):
            continue

        for rule in _get_rules(r):
            verbs     = set(rule.get("verbs", []))
            res_list  = rule.get("resources", [])
            has_exec  = bool(
                {"pods/exec", "pods/attach"} & set(res_list)
                or ("*" in res_list and bool(verbs & {"create", "*"}))
            )

            if has_exec and bool(verbs & {"create", "*"}):
                findings.append(K8sFinding(
                    rule_id="K8S-006",
                    title="Role Allows Pod Exec/Attach",
                    severity="HIGH",
                    resource_kind=r.get("kind"),
                    resource_name=name,
                    namespace=ns,
                    subject=name,
                    description=(
                        f"Role '{name}' allows exec/attach into running pods. "
                        "An attacker with this permission can execute arbitrary "
                        "commands inside any pod — gaining access to all secrets "
                        "mounted in that pod and its service account token."
                    ),
                    mitre_technique="T1609",
                    mitre_tactic="Container Administration Command",
                    remediation=(
                        "Remove pods/exec and pods/attach from non-admin roles. "
                        "Restrict exec access to specific namespaces using RoleBindings "
                        "instead of ClusterRoleBindings."
                    ),
                    evidence=(f"resources: {res_list}", f"verbs: {sorted(verbs)}"),
                ))
                break
    return findings


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

_ALL_RULES = [
    _k8s001_cluster_admin_binding,
    _k8s002_wildcard_permissions,
    _k8s003_secrets_access,
    _k8s004_default_sa_binding,
    _k8s005_anonymous_access,
    _k8s006_pod_exec_access,
]

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def scan_k8s_resources(resources: list[dict], path: str = "inline") -> list[K8sFinding]:
    """Scan a list of K8s resource dicts and return findings."""
    findings: list[K8sFinding] = []
    for rule_fn in _ALL_RULES:
        try:
            findings.extend(rule_fn(resources, path))
        except Exception as exc:
            print(f"[k8s-scan] Rule {rule_fn.__name__} error: {exc}")
    findings.sort(key=lambda f: SEV_ORDER.get(f.severity, 9))
    return findings


def scan_k8s_file(path: str) -> list[K8sFinding]:
    """Scan a single K8s JSON/YAML file."""
    resources = _load_k8s_file(path)
    if not resources:
        print(f"[k8s-scan] No resources found in {path}")
        return []
    print(f"[k8s-scan] Loaded {len(resources)} resource(s) from {path}")
    return scan_k8s_resources(resources, path)


def scan_k8s_directory(directory: str) -> list[K8sFinding]:
    """Scan all .json and .yaml/.yml files in a directory."""
    all_findings: list[K8sFinding] = []
    dir_path = Path(directory)

    files = list(dir_path.rglob("*.json")) + \
            list(dir_path.rglob("*.yaml")) + \
            list(dir_path.rglob("*.yml"))

    if not files:
        print(f"[k8s-scan] No K8s files found in {directory}")
        return []

    print(f"[k8s-scan] Found {len(files)} file(s)")
    for f in files:
        file_findings = scan_k8s_file(str(f))
        all_findings.extend(file_findings)

    all_findings.sort(key=lambda f: SEV_ORDER.get(f.severity, 9))
    return all_findings


def get_k8s_rules() -> list[dict]:
    """Return rule metadata for the `rules` CLI command."""
    return [
        {"id": "K8S-001", "title": "ClusterRoleBinding to cluster-admin",           "severity": "CRITICAL", "mitre": "T1078.001"},
        {"id": "K8S-002", "title": "Wildcard Permissions in Role",                   "severity": "CRITICAL", "mitre": "T1078.001"},
        {"id": "K8S-003", "title": "Role Can Read Kubernetes Secrets",               "severity": "HIGH",     "mitre": "T1552.007"},
        {"id": "K8S-004", "title": "Default ServiceAccount Bound to Privileged Role","severity": "HIGH",     "mitre": "T1078.001"},
        {"id": "K8S-005", "title": "Anonymous / Unauthenticated Access Granted",     "severity": "CRITICAL", "mitre": "T1078.001"},
        {"id": "K8S-006", "title": "Role Allows Pod Exec/Attach",                   "severity": "HIGH",     "mitre": "T1609"},
    ]


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_data/sample_k8s_rbac.json"
    findings = scan_k8s_file(path)

    print(f"\n{'='*60}")
    print(f"  K8S RBAC SCAN — {len(findings)} finding(s)")
    print(f"{'='*60}\n")

    for f in findings:
        print(f"[{f.severity}] {f.rule_id} — {f.title}")
        print(f"  Resource : {f.resource_kind}/{f.resource_name}")
        print(f"  Subject  : {f.subject}")
        print(f"  MITRE    : {f.mitre_technique}")
        print(f"  Fix      : {f.remediation[:80]}...")
        print()
