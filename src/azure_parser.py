"""
azure_parser.py
---------------
Parses Azure RBAC exports into a normalised internal format.

Supported input formats
  1. az role assignment list --all --output json
  2. az role definition list --output json
  3. az ad sp list --all --output json
  4. Combined dict  {"assignments": [...], "definitions": [...], "service_principals": [...]}

Public API
  parse_azure_file(path: str) -> AzureIAMData
  parse_azure_dict(data: dict | list) -> AzureIAMData
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Data-classes (mirror GCP parser conventions)
# ---------------------------------------------------------------------------

@dataclass
class AzureRoleAssignment:
    """Single role-assignment record from Azure RBAC."""
    principal_id: str
    principal_name: str          # UPN / display-name / SP app-id
    principal_type: str          # User | Group | ServicePrincipal | Unknown
    role_definition_name: str    # Owner, Contributor, Reader, custom …
    role_definition_id: str      # full resource-id or short name
    scope: str                   # / | /subscriptions/… | /resourceGroups/…
    scope_level: str             # Tenant | Subscription | ResourceGroup | Resource
    is_guest: bool               # true if UPN ends with #EXT# or type==Guest


@dataclass
class AzureRoleDefinition:
    """Custom or built-in role definition."""
    role_name: str
    role_id: str
    role_type: str               # BuiltInRole | CustomRole
    permissions_actions: list[str] = field(default_factory=list)
    permissions_not_actions: list[str] = field(default_factory=list)
    assignable_scopes: list[str] = field(default_factory=list)
    is_custom: bool = False


@dataclass
class AzureServicePrincipal:
    """Service principal record from az ad sp list."""
    app_id: str
    display_name: str
    object_id: str
    sp_type: str                 # Application | ManagedIdentity | Legacy
    enabled: bool
    app_roles: list[str] = field(default_factory=list)


@dataclass
class AzureIAMData:
    """Top-level container returned to the rest of the pipeline."""
    assignments: list[AzureRoleAssignment] = field(default_factory=list)
    definitions: list[AzureRoleDefinition] = field(default_factory=list)
    service_principals: list[AzureServicePrincipal] = field(default_factory=list)
    # quick-lookup maps built during parsing
    definition_map: dict[str, AzureRoleDefinition] = field(default_factory=dict)
    sp_map: dict[str, AzureServicePrincipal] = field(default_factory=dict)
    raw_source: str = "unknown"   # filename or "dict"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _scope_level(scope: str) -> str:
    """Classify an Azure scope string into a human-readable level."""
    if not scope or scope == "/":
        return "Tenant"
    parts = [p for p in scope.split("/") if p]
    if len(parts) == 2 and parts[0].lower() == "subscriptions":
        return "Subscription"
    if len(parts) == 4 and parts[2].lower() == "resourcegroups":
        return "ResourceGroup"
    return "Resource"


def _is_guest(upn: str, principal_type: str) -> bool:
    """Return True for Azure B2B guest users."""
    if "#EXT#" in upn:
        return True
    if principal_type and "guest" in principal_type.lower():
        return True
    return False


def _normalise_principal_type(raw: str) -> str:
    mapping = {
        "user": "User",
        "group": "Group",
        "serviceprincipal": "ServicePrincipal",
        "foreigngroup": "Group",
    }
    return mapping.get((raw or "").lower().replace(" ", ""), "Unknown")


# ---------------------------------------------------------------------------
# Assignment parser
# ---------------------------------------------------------------------------

def _parse_assignments(records: list[dict]) -> list[AzureRoleAssignment]:
    assignments: list[AzureRoleAssignment] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue

        # Principal info — field names differ between CLI versions
        principal_id = (
            rec.get("principalId")
            or rec.get("principal_id")
            or rec.get("objectId")
            or ""
        )
        principal_name = (
            rec.get("principalName")
            or rec.get("principal_name")
            or rec.get("signInName")
            or rec.get("displayName")
            or principal_id
        )
        raw_type = (
            rec.get("principalType")
            or rec.get("principal_type")
            or rec.get("objectType")
            or ""
        )
        principal_type = _normalise_principal_type(raw_type)

        # Role info
        role_name = (
            rec.get("roleDefinitionName")
            or rec.get("role_definition_name")
            or rec.get("roleName")
            or ""
        )
        role_id = (
            rec.get("roleDefinitionId")
            or rec.get("role_definition_id")
            or role_name
        )

        # Scope
        scope = rec.get("scope") or rec.get("Scope") or "/"
        scope_level = _scope_level(scope)

        assignments.append(
            AzureRoleAssignment(
                principal_id=principal_id,
                principal_name=principal_name,
                principal_type=principal_type,
                role_definition_name=role_name,
                role_definition_id=role_id,
                scope=scope,
                scope_level=scope_level,
                is_guest=_is_guest(principal_name, raw_type),
            )
        )
    return assignments


# ---------------------------------------------------------------------------
# Role-definition parser
# ---------------------------------------------------------------------------

def _parse_definitions(records: list[dict]) -> list[AzureRoleDefinition]:
    definitions: list[AzureRoleDefinition] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue

        role_name = rec.get("roleName") or rec.get("name") or ""
        role_id = rec.get("id") or rec.get("roleDefinitionId") or role_name
        role_type = rec.get("roleType") or rec.get("type") or "BuiltInRole"
        is_custom = "custom" in role_type.lower()

        # permissions block
        perms_list: list[dict] = rec.get("permissions") or []
        actions: list[str] = []
        not_actions: list[str] = []
        for perm in perms_list:
            if isinstance(perm, dict):
                actions.extend(perm.get("actions") or [])
                not_actions.extend(perm.get("notActions") or [])

        scopes: list[str] = rec.get("assignableScopes") or []

        definitions.append(
            AzureRoleDefinition(
                role_name=role_name,
                role_id=role_id,
                role_type=role_type,
                permissions_actions=actions,
                permissions_not_actions=not_actions,
                assignable_scopes=scopes,
                is_custom=is_custom,
            )
        )
    return definitions


# ---------------------------------------------------------------------------
# Service-principal parser
# ---------------------------------------------------------------------------

def _parse_service_principals(records: list[dict]) -> list[AzureServicePrincipal]:
    sps: list[AzureServicePrincipal] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue

        app_id = rec.get("appId") or rec.get("app_id") or ""
        display_name = rec.get("displayName") or rec.get("display_name") or app_id
        object_id = rec.get("id") or rec.get("objectId") or rec.get("object_id") or ""
        sp_type = rec.get("servicePrincipalType") or rec.get("type") or "Application"
        enabled = rec.get("accountEnabled", True)

        app_roles = [
            r.get("value") or r.get("displayName") or ""
            for r in (rec.get("appRoles") or [])
            if isinstance(r, dict)
        ]

        sps.append(
            AzureServicePrincipal(
                app_id=app_id,
                display_name=display_name,
                object_id=object_id,
                sp_type=sp_type,
                enabled=bool(enabled),
                app_roles=app_roles,
            )
        )
    return sps


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def _detect_format(data: Any) -> str:
    """
    Returns one of:
      'assignments'        – list of role-assignment objects
      'definitions'        – list of role-definition objects
      'service_principals' – list of service-principal objects
      'combined'           – dict with multiple keys
      'unknown'
    """
    if isinstance(data, dict):
        keys = {k.lower() for k in data.keys()}
        if keys & {"assignments", "definitions", "service_principals",
                   "roleassignments", "roledefinitions"}:
            return "combined"
        return "unknown"

    if isinstance(data, list) and data:
        sample = data[0]
        if not isinstance(sample, dict):
            return "unknown"
        sample_keys = {k.lower() for k in sample.keys()}

        # role-assignment keys
        if sample_keys & {"roledefinitionname", "roledefinitionid",
                          "principaltype", "principalname", "scope"}:
            return "assignments"

        # role-definition keys
        if sample_keys & {"rolename", "roletype", "permissions", "assignablescopes"}:
            return "definitions"

        # service-principal keys
        if sample_keys & {"appid", "serviceprincipaltype", "approles"}:
            return "service_principals"

    return "unknown"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_azure_dict(data: Any, source: str = "dict") -> AzureIAMData:
    """Parse an already-loaded Python object into AzureIAMData."""
    fmt = _detect_format(data)
    result = AzureIAMData(raw_source=source)

    if fmt == "assignments":
        result.assignments = _parse_assignments(data)

    elif fmt == "definitions":
        result.definitions = _parse_definitions(data)

    elif fmt == "service_principals":
        result.service_principals = _parse_service_principals(data)

    elif fmt == "combined":
        # normalise key names
        assignments_raw = (
            data.get("assignments")
            or data.get("roleAssignments")
            or data.get("role_assignments")
            or []
        )
        definitions_raw = (
            data.get("definitions")
            or data.get("roleDefinitions")
            or data.get("role_definitions")
            or []
        )
        sps_raw = (
            data.get("service_principals")
            or data.get("servicePrincipals")
            or []
        )
        result.assignments = _parse_assignments(assignments_raw)
        result.definitions = _parse_definitions(definitions_raw)
        result.service_principals = _parse_service_principals(sps_raw)

    else:
        raise ValueError(
            "Unrecognised Azure export format. "
            "Expected output of: az role assignment list, "
            "az role definition list, az ad sp list, or a combined dict."
        )

    # Build lookup maps
    result.definition_map = {d.role_name: d for d in result.definitions}
    result.sp_map = {sp.app_id: sp for sp in result.service_principals}

    return result


def parse_azure_file(path: str) -> AzureIAMData:
    """Load a JSON file and parse it."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if file_path.suffix.lower() != ".json":
        raise ValueError(f"Expected a .json file, got: {path}")

    with open(file_path, encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {path}: {exc}") from exc

    return parse_azure_dict(data, source=str(file_path))
