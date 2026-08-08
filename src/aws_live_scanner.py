"""
AWS Live Scanner
=================
Fetches IAM data directly from a live AWS account using boto3, then
returns it in the same ParsedAWSPolicy format that AWSIAMParser produces
from a file — so the rest of the pipeline (graph, detection, scoring,
export) works identically for both live and file-based scans.

Usage (real AWS account):
    scanner = AWSLiveScanner()
    policy = scanner.scan(profile="my-profile", region="us-east-1")

Usage (LocalStack — free local AWS simulation for testing):
    scanner = AWSLiveScanner()
    policy = scanner.scan(endpoint_url="http://localhost:4566")

Required AWS permissions (minimum):
    iam:GetAccountAuthorizationDetails
    iam:ListUsers
    iam:ListRoles
    iam:ListGroups

Install boto3:
    pip install boto3
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Any

from aws_parser import AWSIAMParser, ParsedAWSPolicy

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class AWSLiveScanError(Exception):
    """Raised when the live scan cannot complete."""


class AWSAuthError(AWSLiveScanError):
    """Raised when AWS credentials are missing or invalid."""


class AWSPermissionError(AWSLiveScanError):
    """Raised when the caller lacks iam:GetAccountAuthorizationDetails."""


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class AWSLiveScanner:
    """
    Fetches AWS IAM data from a live account (or LocalStack) using boto3.

    The scanner calls iam:GetAccountAuthorizationDetails — one API call
    that returns users, groups, roles, and policies in a single paginated
    response. The result is saved to a temp file and parsed by AWSIAMParser
    so the rest of the pipeline is identical to a file-based scan.
    """

    def scan(
        self,
        profile: str | None = None,
        region: str = "us-east-1",
        endpoint_url: str | None = None,
        save_to: str | Path | None = None,
    ) -> ParsedAWSPolicy:
        """
        Fetch and parse live AWS IAM data.

        Args:
            profile:      AWS CLI profile name (from ~/.aws/credentials).
                          None = use default credentials / environment variables.
            region:       AWS region (default: us-east-1).
            endpoint_url: Override endpoint — use "http://localhost:4566"
                          for LocalStack testing without a real AWS account.
            save_to:      Optional path to save the raw fetched JSON.
                          Useful for auditing or offline re-analysis.

        Returns:
            ParsedAWSPolicy — same object AWSIAMParser.parse_file() returns.

        Raises:
            AWSLiveScanError: boto3 is not installed.
            AWSAuthError:     No valid AWS credentials found.
            AWSPermissionError: Caller lacks required IAM permissions.
        """
        boto3 = self._import_boto3()
        session = self._make_session(boto3, profile, region)
        client = self._make_client(session, endpoint_url)

        logger.info(
            "Connecting to AWS IAM%s (profile=%s, region=%s)",
            f" via {endpoint_url}" if endpoint_url else "",
            profile or "default",
            region,
        )

        raw_data = self._fetch_authorization_details(client)
        logger.info(
            "Fetched: %d users, %d groups, %d roles, %d policies",
            len(raw_data.get("UserDetailList", [])),
            len(raw_data.get("GroupDetailList", [])),
            len(raw_data.get("RoleDetailList", [])),
            len(raw_data.get("Policies", [])),
        )

        # Optionally save the raw JSON
        if save_to:
            save_path = Path(save_to)
            save_path.write_text(
                json.dumps(raw_data, indent=2, default=str), encoding="utf-8"
            )
            logger.info("Raw IAM data saved to %s", save_path)

        # Write to a temp file and parse with AWSIAMParser
        # (reuses all validation and normalisation logic)
        return self._parse_raw(raw_data)

    # -- internal helpers ------------------------------------------------

    def _import_boto3(self) -> Any:
        try:
            import boto3
            return boto3
        except ImportError:
            raise AWSLiveScanError(
                "boto3 is not installed. Install it with:\n"
                "    pip install boto3\n"
                "Then re-run the live scan."
            )

    def _make_session(self, boto3: Any, profile: str | None, region: str) -> Any:
        try:
            if profile:
                session = boto3.Session(profile_name=profile, region_name=region)
            else:
                session = boto3.Session(region_name=region)
            return session
        except Exception as exc:
            raise AWSAuthError(
                f"Could not create AWS session: {exc}\n"
                "Make sure your AWS credentials are configured:\n"
                "  aws configure\n"
                "Or set environment variables:\n"
                "  AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY"
            ) from exc

    def _make_client(self, session: Any, endpoint_url: str | None) -> Any:
        try:
            kwargs: dict[str, Any] = {"service_name": "iam"}
            if endpoint_url:
                kwargs["endpoint_url"] = endpoint_url
            return session.client(**kwargs)
        except Exception as exc:
            raise AWSAuthError(f"Could not create IAM client: {exc}") from exc

    def _fetch_authorization_details(self, client: Any) -> dict:
        """
        Call iam:GetAccountAuthorizationDetails with pagination.
        Returns the merged result across all pages.
        """
        result: dict[str, list] = {
            "UserDetailList": [],
            "GroupDetailList": [],
            "RoleDetailList": [],
            "Policies": [],
        }

        paginator_kwargs = {
            "Filter": ["User", "Group", "Role", "LocalManagedPolicy", "AWSManagedPolicy"]
        }

        try:
            # Use paginator to handle accounts with many principals
            try:
                paginator = client.get_paginator("get_account_authorization_details")
                pages = paginator.paginate(**paginator_kwargs)
                for page in pages:
                    result["UserDetailList"].extend(page.get("UserDetailList", []))
                    result["GroupDetailList"].extend(page.get("GroupDetailList", []))
                    result["RoleDetailList"].extend(page.get("RoleDetailList", []))
                    result["Policies"].extend(page.get("Policies", []))
            except Exception:
                # Fallback: direct call (LocalStack sometimes doesn't support paginators)
                logger.warning("Paginator failed — falling back to direct API call.")
                response = client.get_account_authorization_details(**paginator_kwargs)
                result["UserDetailList"] = response.get("UserDetailList", [])
                result["GroupDetailList"] = response.get("GroupDetailList", [])
                result["RoleDetailList"] = response.get("RoleDetailList", [])
                result["Policies"] = response.get("Policies", [])

        except Exception as exc:
            error_str = str(exc).lower()
            if any(k in error_str for k in ("credentials", "token", "access key", "expire")):
                raise AWSAuthError(
                    f"AWS credentials error: {exc}\n"
                    "Run: aws configure   (or check your environment variables)"
                ) from exc
            if any(k in error_str for k in ("accessdenied", "not authorized", "forbidden")):
                raise AWSPermissionError(
                    f"Permission denied: {exc}\n"
                    "The caller needs: iam:GetAccountAuthorizationDetails"
                ) from exc
            raise AWSLiveScanError(f"Unexpected error fetching IAM data: {exc}") from exc

        # Serialize policy documents — boto3 returns them as dicts, parser expects JSON strings
        result = self._serialize_policy_documents(result)
        return result

    def _serialize_policy_documents(self, data: dict) -> dict:
        """
        boto3 returns inline PolicyDocument fields as Python dicts.
        AWSIAMParser expects them as JSON strings (matching the real API output).
        Serialize them so the parser handles both correctly.
        """
        for user in data.get("UserDetailList", []):
            for policy in user.get("UserPolicyList", []):
                if isinstance(policy.get("PolicyDocument"), dict):
                    policy["PolicyDocument"] = json.dumps(policy["PolicyDocument"])

        for group in data.get("GroupDetailList", []):
            for policy in group.get("GroupPolicyList", []):
                if isinstance(policy.get("PolicyDocument"), dict):
                    policy["PolicyDocument"] = json.dumps(policy["PolicyDocument"])

        for role in data.get("RoleDetailList", []):
            for policy in role.get("RolePolicyList", []):
                if isinstance(policy.get("PolicyDocument"), dict):
                    policy["PolicyDocument"] = json.dumps(policy["PolicyDocument"])
            if isinstance(role.get("AssumeRolePolicyDocument"), dict):
                role["AssumeRolePolicyDocument"] = json.dumps(role["AssumeRolePolicyDocument"])

        return data

    def _parse_raw(self, raw_data: dict) -> ParsedAWSPolicy:
        """Write raw data to a temp file and parse it with AWSIAMParser."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as tmp:
            json.dump(raw_data, tmp, default=str)
            tmp_path = Path(tmp.name)

        try:
            return AWSIAMParser().parse_file(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)   # clean up temp file


# ---------------------------------------------------------------------------
# LocalStack setup helper (printed when user runs this file directly)
# ---------------------------------------------------------------------------

LOCALSTACK_SETUP = """
╔══════════════════════════════════════════════════════════════════╗
║          Testing Without a Real AWS Account — LocalStack         ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  LocalStack simulates AWS services locally — free, no account.  ║
║                                                                  ║
║  Step 1 — Install LocalStack:                                    ║
║    pip install localstack                                        ║
║    pip install awscli-local                                      ║
║                                                                  ║
║  Step 2 — Start LocalStack:                                      ║
║    localstack start                                              ║
║                                                                  ║
║  Step 3 — Create test IAM resources:                             ║
║    awslocal iam create-user --user-name test-user                ║
║    awslocal iam attach-user-policy \\                             ║
║      --user-name test-user \\                                     ║
║      --policy-arn arn:aws:iam::aws:policy/AdministratorAccess    ║
║                                                                  ║
║  Step 4 — Run live scan against LocalStack:                      ║
║    cloudsentrix live-scan --cloud aws \\                          ║
║      --endpoint http://localhost:4566                            ║
║                                                                  ║
║  OR test this file directly:                                     ║
║    python src/aws_live_scanner.py                                ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""


# ---------------------------------------------------------------------------
# Manual smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    print(LOCALSTACK_SETUP)

    # Try LocalStack first — fall back to a helpful message
    scanner = AWSLiveScanner()
    try:
        policy = scanner.scan(
            endpoint_url="http://localhost:4566",
            region="us-east-1",
        )
        print(f"\n✅ Live scan successful!")
        print(f"Summary: {policy.summary()}")
        print(f"\nPrincipals found:")
        for binding in policy.bindings:
            p = binding.principal
            print(f"  [{p.principal_type.value}] {p.name}")

    except AWSLiveScanError as exc:
        print(f"\n⚠️  LocalStack not running: {exc}")
        print("\nTo test without LocalStack, use the JSON file instead:")
        print("  python src/aws_parser.py   (already tested ✅)")
