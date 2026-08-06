"""
GCP IAM Policy Parser
======================
Parses Google Cloud Platform IAM policy exports (JSON) into structured,
type-safe Python objects for downstream analysis: graph building,
privilege-escalation detection, and risk scoring.

Expected input format (produced by):
    gcloud projects get-iam-policy PROJECT_ID --format=json

    {
      "bindings": [
        {
          "role": "roles/editor",
          "members": ["user:alice@example.com", "serviceAccount:sa@project.iam.gserviceaccount.com"]
        }
      ]
    }
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
# Exceptions
# ---------------------------------------------------------------------------

class IAMParserError(Exception):
    """Base exception for every error this parser can raise."""


class IAMFileNotFoundError(IAMParserError):
    """Raised when the given IAM policy file path does not exist."""


class IAMFileReadError(IAMParserError):
    """Raised when the file exists but cannot be read (permissions, encoding, etc.)."""


class InvalidIAMFormatError(IAMParserError):
    """Raised when the file content is not valid JSON, or does not match
    the expected GCP IAM policy schema."""


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class MemberType(str, Enum):
    """The type of principal holding a role, taken from GCP's member prefix."""
    USER = "user"
    SERVICE_ACCOUNT = "serviceAccount"
    GROUP = "group"
    DOMAIN = "domain"
    ALL_USERS = "allUsers"
    ALL_AUTHENTICATED_USERS = "allAuthenticatedUsers"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Member:
    """A single IAM principal extracted from a binding's member list.

    GCP encodes members as "type:identifier", e.g. "user:alice@example.com".
    allUsers / allAuthenticatedUsers carry no identifier.
    """
    raw: str
    type: MemberType
    identifier: str

    @classmethod
    def from_raw(cls, raw: str) -> "Member":
        """Parse a raw GCP member string (e.g. 'user:alice@example.com')."""
        if ":" in raw:
            prefix, identifier = raw.split(":", 1)
        else:
            prefix, identifier = raw, ""

        try:
            member_type = MemberType(prefix)
        except ValueError:
            logger.warning("Unrecognized member type prefix '%s' in '%s'", prefix, raw)
            member_type = MemberType.UNKNOWN

        return cls(raw=raw, type=member_type, identifier=identifier)


@dataclass(frozen=True)
class IAMBinding:
    """One role bound to the list of members holding it."""
    role: str
    members: tuple[Member, ...]


@dataclass
class ParsedIAMPolicy:
    """The fully parsed representation of a GCP IAM policy document."""
    source_file: Path
    bindings: list[IAMBinding] = field(default_factory=list)

    def all_members(self) -> list[Member]:
        """Every member across every binding (duplicates possible if a
        member holds more than one role)."""
        result: list[Member] = []
        for binding in self.bindings:
            result.extend(binding.members)
        return result

    def roles_for_member(self, identifier: str) -> list[str]:
        """All roles held by a given member identifier (e.g. an email)."""
        return [
            binding.role
            for binding in self.bindings
            for member in binding.members
            if member.identifier == identifier
        ]

    def summary(self) -> dict[str, int]:
        """Quick counts, used for CLI summary output."""
        members = self.all_members()
        return {
            "total_bindings": len(self.bindings),
            "total_member_entries": len(members),
            "unique_members": len({m.identifier for m in members if m.identifier}),
        }


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

REQUIRED_TOP_LEVEL_KEY = "bindings"
REQUIRED_BINDING_KEYS = {"role", "members"}


class GCPIAMParser:
    """Parses a GCP IAM policy JSON export into a ParsedIAMPolicy.

    Usage:
        parser = GCPIAMParser()
        policy = parser.parse_file("sample_data/sample_gcp_iam.json")
    """

    def parse_file(self, file_path: str | Path) -> ParsedIAMPolicy:
        """Load and parse a GCP IAM policy JSON file.

        Args:
            file_path: Path to a JSON file exported via
                `gcloud projects get-iam-policy PROJECT_ID --format=json`.

        Returns:
            A ParsedIAMPolicy with structured bindings.

        Raises:
            IAMFileNotFoundError: The file does not exist.
            IAMFileReadError: The file exists but cannot be read.
            InvalidIAMFormatError: The content is not valid JSON, or does
                not match the expected GCP IAM policy schema.
        """
        path = Path(file_path)
        logger.info("Loading IAM policy from %s", path)

        raw_text = self._read_file(path)
        data = self._parse_json(raw_text, path)
        self._validate_schema(data, path)

        bindings = [self._parse_binding(b, i) for i, b in enumerate(data["bindings"])]
        policy = ParsedIAMPolicy(source_file=path, bindings=bindings)

        stats = policy.summary()
        logger.info(
            "Parsed %d binding(s) covering %d unique member(s) from %s",
            stats["total_bindings"], stats["unique_members"], path,
        )
        return policy

    # -- internal helpers -----------------------------------------------

    def _read_file(self, path: Path) -> str:
        if not path.exists():
            raise IAMFileNotFoundError(f"IAM policy file not found: {path}")
        if not path.is_file():
            raise IAMFileReadError(f"Path exists but is not a file: {path}")

        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise IAMFileReadError(f"Could not read {path} as UTF-8 text: {exc}") from exc
        except OSError as exc:
            raise IAMFileReadError(f"Could not read {path}: {exc}") from exc

    def _parse_json(self, raw_text: str, path: Path) -> Any:
        if not raw_text.strip():
            raise InvalidIAMFormatError(f"{path} is empty.")
        try:
            return json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise InvalidIAMFormatError(
                f"{path} is not valid JSON (line {exc.lineno}, col {exc.colno}): {exc.msg}"
            ) from exc

    def _validate_schema(self, data: Any, path: Path) -> None:
        if not isinstance(data, dict):
            raise InvalidIAMFormatError(
                f"{path}: expected a JSON object at the top level, got {type(data).__name__}."
            )
        if REQUIRED_TOP_LEVEL_KEY not in data:
            raise InvalidIAMFormatError(
                f"{path}: missing required top-level key '{REQUIRED_TOP_LEVEL_KEY}'. "
                "Is this a valid `gcloud projects get-iam-policy` export?"
            )
        if not isinstance(data["bindings"], list):
            raise InvalidIAMFormatError(
                f"{path}: 'bindings' must be a list, got {type(data['bindings']).__name__}."
            )
        if len(data["bindings"]) == 0:
            logger.warning("%s contains zero bindings — nothing to analyze.", path)

        for i, binding in enumerate(data["bindings"]):
            if not isinstance(binding, dict):
                raise InvalidIAMFormatError(
                    f"{path}: bindings[{i}] must be an object, got {type(binding).__name__}."
                )
            missing = REQUIRED_BINDING_KEYS - binding.keys()
            if missing:
                raise InvalidIAMFormatError(
                    f"{path}: bindings[{i}] is missing required key(s): {sorted(missing)}."
                )
            if not isinstance(binding["role"], str):
                raise InvalidIAMFormatError(f"{path}: bindings[{i}].role must be a string.")
            if not isinstance(binding["members"], list):
                raise InvalidIAMFormatError(f"{path}: bindings[{i}].members must be a list.")

    def _parse_binding(self, raw_binding: dict, index: int) -> IAMBinding:
        role = raw_binding["role"]
        raw_members = raw_binding["members"]
        members = tuple(Member.from_raw(m) for m in raw_members if isinstance(m, str))
        if len(members) != len(raw_members):
            logger.warning(
                "bindings[%d] (%s) contained non-string member entries — skipped.",
                index, role,
            )
        return IAMBinding(role=role, members=members)


# ---------------------------------------------------------------------------
# Manual smoke test — runs only when this file is executed directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = GCPIAMParser()
    result = parser.parse_file("sample_data/sample_gcp_iam.json")

    print("\nSummary:", result.summary())
    print("\nBindings:")
    for b in result.bindings:
        member_list = [m.raw for m in b.members]
        print(f"  {b.role}: {member_list}")