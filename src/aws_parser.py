"""
AWS IAM Policy Parser
======================
Parses AWS IAM exports (JSON) into structured, type-safe Python objects
for downstream analysis: graph building, privilege-escalation detection,
and risk scoring.

Expected input format (produced by):
    aws iam get-account-authorization-details --output json > aws_iam.json

The output is a large JSON object with these top-level keys:
    - UserDetailList       — IAM users with their attached/inline policies
    - GroupDetailList      — IAM groups with their attached/inline policies
    - RoleDetailList       — IAM roles with their attached/inline policies
    - Policies             — Customer-managed policies (with policy documents)

This parser flattens that structure into a list of AWSBinding objects
(principal -> permission), which the graph engine and detection engine
consume in exactly the same way as GCP bindings.

References:
    https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions  (mirrors GCP parser's exception hierarchy)
# ---------------------------------------------------------------------------

class AWSParserError(Exception):
    """Base exception for every error this parser can raise."""


class AWSFileNotFoundError(AWSParserError):
    """Raised when the given AWS IAM file path does not exist."""


class AWSFileReadError(AWSParserError):
    """Raised when the file exists but cannot be read."""


class InvalidAWSFormatError(AWSParserError):
    """Raised when the file content is not valid JSON or does not match
    the expected AWS IAM authorization-details schema."""


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class AWSPrincipalType(str, Enum):
    """The type of AWS IAM principal."""
    USER = "user"
    GROUP = "group"
    ROLE = "role"
    UNKNOWN = "unknown"


class AWSPermissionSource(str, Enum):
    """How the permission was granted to the principal."""
    MANAGED_POLICY = "managed_policy"    # AWS or customer-managed policy attached
    INLINE_POLICY = "inline_policy"      # Policy embedded directly on the principal
    GROUP_POLICY = "group_policy"        # Policy inherited via group membership


@dataclass(frozen=True)
class AWSPrincipal:
    """A single AWS IAM principal (user, group, or role).

    Attributes:
        principal_id:   Unique identifier (ARN preferred, name as fallback).
        name:           Human-readable name (e.g. "developer-alice").
        principal_type: USER, GROUP, or ROLE.
        arn:            Full AWS ARN, e.g. arn:aws:iam::123456789012:user/alice
    """
    principal_id: str       # ARN — globally unique
    name: str
    principal_type: AWSPrincipalType
    arn: str


@dataclass(frozen=True)
class AWSPermission:
    """A single permission (action) that a principal holds.

    AWS IAM permissions are individual actions like 'iam:PassRole' or
    'sts:AssumeRole', unlike GCP which uses named roles. We store both
    the raw action and the policy that granted it so the detection engine
    can report accurate evidence.

    Attributes:
        action:     The IAM action string, e.g. 'iam:PassRole' or '*'.
        resource:   The resource ARN the action applies to ('*' means all).
        effect:     'Allow' or 'Deny' — we only store Allow permissions.
        source:     How this permission was granted (managed/inline/group).
        policy_name: Name of the policy that granted this permission.
    """
    action: str
    resource: str
    effect: str             # Always 'Allow' — Deny entries are filtered out
    source: AWSPermissionSource
    policy_name: str


@dataclass(frozen=True)
class AWSBinding:
    """Maps one principal to the list of permissions it holds.

    This is the AWS equivalent of GCP's IAMBinding (role -> members),
    but inverted: here we track principal -> permissions, because AWS
    IAM attaches policies (containing permissions) to principals rather
    than binding roles to member lists.
    """
    principal: AWSPrincipal
    permissions: tuple[AWSPermission, ...]


@dataclass
class ParsedAWSPolicy:
    """The fully parsed representation of an AWS IAM authorization-details export."""
    source_file: Path
    bindings: list[AWSBinding] = field(default_factory=list)

    def all_principals(self) -> list[AWSPrincipal]:
        return [b.principal for b in self.bindings]

    def all_permissions(self) -> list[AWSPermission]:
        perms: list[AWSPermission] = []
        for binding in self.bindings:
            perms.extend(binding.permissions)
        return perms

    def permissions_for(self, principal_id: str) -> list[AWSPermission]:
        """All permissions for a given principal ARN."""
        for binding in self.bindings:
            if binding.principal.principal_id == principal_id:
                return list(binding.permissions)
        return []

    def summary(self) -> dict[str, int]:
        users = sum(1 for b in self.bindings if b.principal.principal_type == AWSPrincipalType.USER)
        groups = sum(1 for b in self.bindings if b.principal.principal_type == AWSPrincipalType.GROUP)
        roles = sum(1 for b in self.bindings if b.principal.principal_type == AWSPrincipalType.ROLE)
        return {
            "total_principals": len(self.bindings),
            "users": users,
            "groups": groups,
            "roles": roles,
            "total_permissions": len(self.all_permissions()),
        }


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

# At least one of these keys must exist for a valid AWS IAM export
REQUIRED_AWS_KEYS = {"UserDetailList", "GroupDetailList", "RoleDetailList"}

# AWS managed policy ARN prefix
AWS_MANAGED_POLICY_PREFIX = "arn:aws:iam::aws:"

# Admin-level AWS managed policies — tracked for detection
ADMIN_MANAGED_POLICIES = frozenset({
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
})


class AWSIAMParser:
    """Parses an AWS IAM get-account-authorization-details JSON export.

    Usage:
        parser = AWSIAMParser()
        policy = parser.parse_file("sample_data/sample_aws_iam.json")
    """

    def parse_file(self, file_path: str | Path) -> ParsedAWSPolicy:
        """Load and parse an AWS IAM authorization-details JSON file.

        Args:
            file_path: Path to a JSON file exported via
                `aws iam get-account-authorization-details --output json`.

        Returns:
            A ParsedAWSPolicy with structured bindings.

        Raises:
            AWSFileNotFoundError: The file does not exist.
            AWSFileReadError: The file exists but cannot be read.
            InvalidAWSFormatError: The content is not valid JSON or does
                not match the expected AWS IAM schema.
        """
        path = Path(file_path)
        logger.info("Loading AWS IAM policy from %s", path)

        raw_text = self._read_file(path)
        data = self._parse_json(raw_text, path)
        self._validate_schema(data, path)

        bindings: list[AWSBinding] = []
        bindings.extend(self._parse_users(data.get("UserDetailList", [])))
        bindings.extend(self._parse_groups(data.get("GroupDetailList", [])))
        bindings.extend(self._parse_roles(data.get("RoleDetailList", [])))

        parsed = ParsedAWSPolicy(source_file=path, bindings=bindings)
        stats = parsed.summary()
        logger.info(
            "Parsed %d principal(s) (%d users, %d groups, %d roles), "
            "%d total permission(s) from %s",
            stats["total_principals"], stats["users"], stats["groups"],
            stats["roles"], stats["total_permissions"], path,
        )
        return parsed

    # -- file helpers ----------------------------------------------------

    def _read_file(self, path: Path) -> str:
        if not path.exists():
            raise AWSFileNotFoundError(f"AWS IAM file not found: {path}")
        if not path.is_file():
            raise AWSFileReadError(f"Path exists but is not a file: {path}")
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise AWSFileReadError(f"Could not read {path} as UTF-8: {exc}") from exc
        except OSError as exc:
            raise AWSFileReadError(f"Could not read {path}: {exc}") from exc

    def _parse_json(self, raw_text: str, path: Path) -> Any:
        if not raw_text.strip():
            raise InvalidAWSFormatError(f"{path} is empty.")
        try:
            return json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise InvalidAWSFormatError(
                f"{path} is not valid JSON (line {exc.lineno}, col {exc.colno}): {exc.msg}"
            ) from exc

    def _validate_schema(self, data: Any, path: Path) -> None:
        if not isinstance(data, dict):
            raise InvalidAWSFormatError(
                f"{path}: expected a JSON object at the top level, got {type(data).__name__}."
            )
        if not REQUIRED_AWS_KEYS & data.keys():
            raise InvalidAWSFormatError(
                f"{path}: missing required keys. Expected at least one of "
                f"{sorted(REQUIRED_AWS_KEYS)}. "
                "Is this a valid `aws iam get-account-authorization-details` export?"
            )

    # -- principal parsers -----------------------------------------------

    def _parse_users(self, user_list: list[dict]) -> list[AWSBinding]:
        bindings: list[AWSBinding] = []
        for user in user_list:
            if not isinstance(user, dict):
                continue
            principal = AWSPrincipal(
                principal_id=user.get("Arn", user.get("UserName", "unknown-user")),
                name=user.get("UserName", "unknown"),
                principal_type=AWSPrincipalType.USER,
                arn=user.get("Arn", ""),
            )
            permissions = self._extract_permissions(
                attached=user.get("AttachedManagedPolicies", []),
                inline=user.get("UserPolicyList", []),
                source_prefix="user",
            )
            # Add group-inherited permissions
            for group_name in user.get("GroupList", []):
                permissions.extend(
                    AWSPermission(
                        action=f"(via-group:{group_name})",
                        resource="*",
                        effect="Allow",
                        source=AWSPermissionSource.GROUP_POLICY,
                        policy_name=group_name,
                    )
                    for _ in []  # placeholder — resolved by graph engine via group bindings
                )
            bindings.append(AWSBinding(principal=principal, permissions=tuple(permissions)))
        return bindings

    def _parse_groups(self, group_list: list[dict]) -> list[AWSBinding]:
        bindings: list[AWSBinding] = []
        for group in group_list:
            if not isinstance(group, dict):
                continue
            principal = AWSPrincipal(
                principal_id=group.get("Arn", group.get("GroupName", "unknown-group")),
                name=group.get("GroupName", "unknown"),
                principal_type=AWSPrincipalType.GROUP,
                arn=group.get("Arn", ""),
            )
            permissions = self._extract_permissions(
                attached=group.get("AttachedManagedPolicies", []),
                inline=group.get("GroupPolicyList", []),
                source_prefix="group",
            )
            bindings.append(AWSBinding(principal=principal, permissions=tuple(permissions)))
        return bindings

    def _parse_roles(self, role_list: list[dict]) -> list[AWSBinding]:
        bindings: list[AWSBinding] = []
        for role in role_list:
            if not isinstance(role, dict):
                continue
            principal = AWSPrincipal(
                principal_id=role.get("Arn", role.get("RoleName", "unknown-role")),
                name=role.get("RoleName", "unknown"),
                principal_type=AWSPrincipalType.ROLE,
                arn=role.get("Arn", ""),
            )
            permissions = self._extract_permissions(
                attached=role.get("AttachedManagedPolicies", []),
                inline=role.get("RolePolicyList", []),
                source_prefix="role",
            )
            # Parse trust policy (who can assume this role)
            trust_doc = role.get("AssumeRolePolicyDocument", {})
            permissions.extend(self._parse_trust_policy(trust_doc, role.get("RoleName", "")))

            bindings.append(AWSBinding(principal=principal, permissions=tuple(permissions)))
        return bindings

    # -- permission extractors -------------------------------------------

    def _extract_permissions(
        self,
        attached: list[dict],
        inline: list[dict],
        source_prefix: str,
    ) -> list[AWSPermission]:
        permissions: list[AWSPermission] = []

        # Attached managed policies (AWS or customer managed)
        for policy in attached:
            if not isinstance(policy, dict):
                continue
            policy_arn = policy.get("PolicyArn", "")
            policy_name = policy.get("PolicyName", policy_arn)
            # Store the policy ARN as an action so detection engine can
            # match admin-level managed policies by ARN
            permissions.append(AWSPermission(
                action=f"managed-policy:{policy_arn}",
                resource="*",
                effect="Allow",
                source=AWSPermissionSource.MANAGED_POLICY,
                policy_name=policy_name,
            ))

        # Inline policies — parse their policy documents for individual actions
        for policy_doc_wrapper in inline:
            if not isinstance(policy_doc_wrapper, dict):
                continue
            policy_name = policy_doc_wrapper.get("PolicyName", "inline-policy")
            doc = policy_doc_wrapper.get("PolicyDocument", {})
            permissions.extend(self._parse_policy_document(doc, policy_name,
                                                            AWSPermissionSource.INLINE_POLICY))

        return permissions

    def _parse_policy_document(
        self,
        doc: dict | str,
        policy_name: str,
        source: AWSPermissionSource,
    ) -> list[AWSPermission]:
        """Parse a policy document (dict or JSON string) into AWSPermission objects.
        Only Allow statements are kept — Deny statements are ignored because
        the detection engine flags risky grants, not effective permissions.
        """
        permissions: list[AWSPermission] = []

        if isinstance(doc, str):
            try:
                doc = json.loads(doc)
            except json.JSONDecodeError:
                logger.warning("Could not parse inline policy document for '%s'", policy_name)
                return permissions

        if not isinstance(doc, dict):
            return permissions

        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]  # single statement, not a list

        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            effect = stmt.get("Effect", "Allow")
            if effect != "Allow":
                continue  # skip Deny statements

            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", ["*"])

            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            for action in actions:
                if not isinstance(action, str):
                    continue
                resource = resources[0] if resources else "*"
                permissions.append(AWSPermission(
                    action=action.lower(),   # normalise to lowercase for detection matching
                    resource=resource,
                    effect="Allow",
                    source=source,
                    policy_name=policy_name,
                ))

        return permissions

    def _parse_trust_policy(self, trust_doc: dict | str, role_name: str) -> list[AWSPermission]:
        """Parse a role's trust policy (AssumeRolePolicyDocument).
        Trust policies define WHO can call sts:AssumeRole on this role.
        We record the trusted principals as special permissions so the
        detection engine can flag dangerously permissive trust policies.
        """
        permissions: list[AWSPermission] = []

        if isinstance(trust_doc, str):
            try:
                trust_doc = json.loads(trust_doc)
            except json.JSONDecodeError:
                return permissions

        if not isinstance(trust_doc, dict):
            return permissions

        statements = trust_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            if stmt.get("Effect") != "Allow":
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            principal = stmt.get("Principal", {})
            # Principal can be "*" (anyone), a dict, or a string
            if principal == "*":
                trusted = ["*"]
            elif isinstance(principal, str):
                trusted = [principal]
            elif isinstance(principal, dict):
                trusted = []
                for v in principal.values():
                    if isinstance(v, list):
                        trusted.extend(v)
                    elif isinstance(v, str):
                        trusted.append(v)
            else:
                trusted = []

            for action in actions:
                if not isinstance(action, str):
                    continue
                for trust_principal in trusted:
                    permissions.append(AWSPermission(
                        action=f"trust:{action.lower()}",
                        resource=trust_principal,
                        effect="Allow",
                        source=AWSPermissionSource.MANAGED_POLICY,
                        policy_name=f"trust-policy:{role_name}",
                    ))

        return permissions


# ---------------------------------------------------------------------------
# Manual smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = AWSIAMParser()
    result = parser.parse_file("sample_data/sample_aws_iam.json")

    print("\nSummary:", result.summary())
    print("\nPrincipals:")
    for binding in result.bindings:
        p = binding.principal
        print(f"  [{p.principal_type.value}] {p.name} ({p.arn})")
        for perm in binding.permissions[:3]:   # first 3 permissions only
            print(f"      {perm.action} on {perm.resource} [{perm.source.value}]")
