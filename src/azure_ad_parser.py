"""
azure_ad_parser.py
------------------
Parses Azure AD / Entra ID exports into structured objects.

Supported input formats:
  1. az ad app list --all --output json
  2. az ad sp list --all --output json
  3. Combined dict {"apps": [...], "service_principals": [...]}

Public API
  parse_azure_ad_file(path: str) -> AzureADData
  parse_azure_ad_dict(data: dict | list) -> AzureADData
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class AzureADAppCredential:
    """A secret or certificate attached to an app registration."""
    cred_type: str          # Secret | Certificate
    key_id: str
    display_name: str
    end_date: str           # ISO 8601 expiry
    is_expired: bool


@dataclass
class AzureADOAuthPermission:
    """An OAuth2 / Microsoft Graph permission requested by an app."""
    resource_app_id: str    # e.g. 00000003-0000-0000-c000-000000000000 = Graph
    resource_name: str      # Microsoft Graph, SharePoint, etc.
    scope: str              # e.g. Mail.ReadWrite, Directory.ReadWrite.All
    permission_type: str    # Delegated | Application
    is_admin_consent: bool


@dataclass
class AzureADApp:
    """Single Azure AD app registration."""
    app_id: str
    display_name: str
    object_id: str
    sign_in_audience: str       # AzureADMyOrg | AzureADMultipleOrgs | AzureADandPersonalMicrosoftAccount
    owners: list[str]           # owner object IDs — empty = orphaned
    credentials: list[AzureADAppCredential]
    oauth_permissions: list[AzureADOAuthPermission]
    is_multi_tenant: bool
    publisher_domain: str
    created_date: str


@dataclass
class AzureADServicePrincipal:
    """Service principal linked to an app registration."""
    sp_id: str
    app_id: str
    display_name: str
    sp_type: str            # Application | ManagedIdentity | Legacy
    enabled: bool
    owners: list[str]
    app_role_assignments: list[str]   # role value strings


@dataclass
class AzureADData:
    """Top-level container returned to the pipeline."""
    apps: list[AzureADApp] = field(default_factory=list)
    service_principals: list[AzureADServicePrincipal] = field(default_factory=list)
    raw_source: str = "unknown"

    def summary(self) -> dict:
        orphaned = sum(1 for a in self.apps if not a.owners)
        multi_tenant = sum(1 for a in self.apps if a.is_multi_tenant)
        with_creds = sum(1 for a in self.apps if a.credentials)
        expired_creds = sum(
            1 for a in self.apps
            for c in a.credentials if c.is_expired
        )
        return {
            "total_apps": len(self.apps),
            "orphaned_apps": orphaned,
            "multi_tenant_apps": multi_tenant,
            "apps_with_credentials": with_creds,
            "expired_credentials": expired_creds,
            "total_service_principals": len(self.service_principals),
        }


# ---------------------------------------------------------------------------
# Known dangerous OAuth scopes
# ---------------------------------------------------------------------------

DANGEROUS_GRAPH_SCOPES = frozenset({
    "Directory.ReadWrite.All",
    "Directory.Read.All",
    "RoleManagement.ReadWrite.Directory",
    "RoleManagement.Read.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Application.ReadWrite.OwnedBy",
    "Mail.ReadWrite",
    "Mail.Read",
    "MailboxSettings.ReadWrite",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess",
    "Policy.Read.All",
    "PrivilegedAccess.ReadWrite.AzureAD",
    "PrivilegedAccess.Read.AzureAD",
    "Sites.ReadWrite.All",
    "Files.ReadWrite.All",
    "AuditLog.Read.All",
    "SecurityEvents.ReadWrite.All",
})

# Microsoft Graph app ID
MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

RESOURCE_NAMES = {
    "00000003-0000-0000-c000-000000000000": "Microsoft Graph",
    "00000002-0000-0000-c000-000000000000": "Azure AD Graph (legacy)",
    "00000003-0000-ff61-ac00-000000000000": "Microsoft Teams",
    "00000002-0000-0ff1-ce00-000000000000": "SharePoint Online",
}


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_credentials(raw_app: dict) -> list[AzureADAppCredential]:
    creds = []
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)

    for raw in raw_app.get("passwordCredentials", []):
        end_str = raw.get("endDateTime") or raw.get("endDate") or ""
        expired = False
        if end_str:
            try:
                end_dt = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
                expired = end_dt < now
            except Exception:
                pass
        creds.append(AzureADAppCredential(
            cred_type="Secret",
            key_id=raw.get("keyId", ""),
            display_name=raw.get("displayName") or raw.get("hint", "Secret"),
            end_date=end_str,
            is_expired=expired,
        ))

    for raw in raw_app.get("keyCredentials", []):
        end_str = raw.get("endDateTime") or raw.get("endDate") or ""
        expired = False
        if end_str:
            try:
                end_dt = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
                expired = end_dt < now
            except Exception:
                pass
        creds.append(AzureADAppCredential(
            cred_type="Certificate",
            key_id=raw.get("keyId", ""),
            display_name=raw.get("displayName") or "Certificate",
            end_date=end_str,
            is_expired=expired,
        ))

    return creds


def _parse_oauth_permissions(raw_app: dict) -> list[AzureADOAuthPermission]:
    perms = []
    for resource in raw_app.get("requiredResourceAccess", []):
        res_app_id = resource.get("resourceAppId", "")
        res_name   = RESOURCE_NAMES.get(res_app_id, res_app_id)

        for access in resource.get("resourceAccess", []):
            scope = access.get("id", "")
            # access.type: "Scope" = delegated, "Role" = application
            perm_type = "Application" if access.get("type") == "Role" else "Delegated"
            perms.append(AzureADOAuthPermission(
                resource_app_id=res_app_id,
                resource_name=res_name,
                scope=scope,
                permission_type=perm_type,
                is_admin_consent=(perm_type == "Application"),
            ))

    return perms


def _parse_apps(records: list[dict]) -> list[AzureADApp]:
    apps = []
    for raw in records:
        if not isinstance(raw, dict):
            continue

        app_id     = raw.get("appId") or raw.get("applicationId") or ""
        obj_id     = raw.get("id") or raw.get("objectId") or ""
        name       = raw.get("displayName") or app_id
        audience   = raw.get("signInAudience") or "AzureADMyOrg"
        owners     = raw.get("owners") or raw.get("ownerIds") or []
        publisher  = raw.get("publisherDomain") or ""
        created    = raw.get("createdDateTime") or ""
        multi      = audience in (
            "AzureADMultipleOrgs",
            "AzureADandPersonalMicrosoftAccount",
            "PersonalMicrosoftAccount",
        )

        apps.append(AzureADApp(
            app_id=app_id,
            display_name=name,
            object_id=obj_id,
            sign_in_audience=audience,
            owners=owners if isinstance(owners, list) else [],
            credentials=_parse_credentials(raw),
            oauth_permissions=_parse_oauth_permissions(raw),
            is_multi_tenant=multi,
            publisher_domain=publisher,
            created_date=created,
        ))

    return apps


def _parse_service_principals(records: list[dict]) -> list[AzureADServicePrincipal]:
    sps = []
    for raw in records:
        if not isinstance(raw, dict):
            continue

        sp_type = raw.get("servicePrincipalType") or raw.get("type") or "Application"
        enabled = raw.get("accountEnabled", True)
        owners  = raw.get("owners") or raw.get("ownerIds") or []
        roles   = [
            r.get("principalDisplayName") or r.get("value") or ""
            for r in (raw.get("appRoleAssignments") or [])
            if isinstance(r, dict)
        ]

        sps.append(AzureADServicePrincipal(
            sp_id=raw.get("id") or raw.get("objectId") or "",
            app_id=raw.get("appId") or "",
            display_name=raw.get("displayName") or "",
            sp_type=sp_type,
            enabled=bool(enabled),
            owners=owners if isinstance(owners, list) else [],
            app_role_assignments=roles,
        ))

    return sps


def _detect_format(data: Any) -> str:
    if isinstance(data, dict):
        keys = {k.lower() for k in data.keys()}
        if keys & {"apps", "service_principals", "serviceprincipals"}:
            return "combined"
        return "unknown"
    if isinstance(data, list) and data:
        sample = data[0]
        if not isinstance(sample, dict):
            return "unknown"
        sk = {k.lower() for k in sample.keys()}
        if sk & {"appid", "requiresourceaccess", "passwordcredentials", "signinaudience"}:
            return "apps"
        if sk & {"serviceprincipaltype", "approleassignments"}:
            return "service_principals"
    return "unknown"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_azure_ad_dict(data: Any, source: str = "dict") -> AzureADData:
    fmt = _detect_format(data)
    result = AzureADData(raw_source=source)

    if fmt == "apps":
        result.apps = _parse_apps(data)
    elif fmt == "service_principals":
        result.service_principals = _parse_service_principals(data)
    elif fmt == "combined":
        apps_raw = data.get("apps") or data.get("applications") or []
        sps_raw  = data.get("service_principals") or data.get("servicePrincipals") or []
        result.apps = _parse_apps(apps_raw)
        result.service_principals = _parse_service_principals(sps_raw)
    else:
        raise ValueError(
            "Unrecognised Azure AD export format. "
            "Expected output of: az ad app list --all  or  az ad sp list --all"
        )
    return result


def parse_azure_ad_file(path: str) -> AzureADData:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
    return parse_azure_ad_dict(data, source=str(file_path))


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    data = parse_azure_ad_file("sample_data/sample_azure_ad.json")
    print("Summary:", data.summary())
    for app in data.apps:
        print(f"\n  App: {app.display_name} ({app.app_id})")
        print(f"    Owners: {len(app.owners)} | Creds: {len(app.credentials)} | Perms: {len(app.oauth_permissions)}")
        print(f"    Multi-tenant: {app.is_multi_tenant}")
