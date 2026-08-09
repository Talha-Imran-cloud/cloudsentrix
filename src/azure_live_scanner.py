"""
azure_live_scanner.py
---------------------
Fetches live Azure RBAC data using the 'az' CLI and returns an AzureIAMData object.

Requirements
  - Azure CLI installed  (https://docs.microsoft.com/cli/azure/install-azure-cli)
  - Authenticated        (az login  or  az login --service-principal …)
  - Subscription selected (az account set --subscription <id>)

Public API
  fetch_azure_live(subscription: str | None, save_path: str | None) -> AzureIAMData
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from azure_parser import AzureIAMData, parse_azure_dict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_az(args: list[str], description: str) -> list[dict]:
    """
    Run an 'az' CLI command and return parsed JSON.
    Prints a progress line and returns [] on failure (non-fatal).
    """
    cmd = ["az"] + args + ["--output", "json"]
    print(f"  [azure-live] {description} ...", flush=True)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        print(
            "\n[ERROR] 'az' CLI not found. "
            "Install from https://docs.microsoft.com/cli/azure/install-azure-cli",
            file=sys.stderr,
        )
        sys.exit(2)
    except subprocess.TimeoutExpired:
        print(f"\n[WARNING] Timed out: {' '.join(cmd)}", file=sys.stderr)
        return []

    if result.returncode != 0:
        print(
            f"\n[WARNING] az command failed (exit {result.returncode}): "
            f"{result.stderr.strip()[:200]}",
            file=sys.stderr,
        )
        return []

    try:
        data = json.loads(result.stdout)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        print(f"[WARNING] Could not parse JSON from: {' '.join(cmd)}", file=sys.stderr)
        return []


def _set_subscription(subscription: str) -> bool:
    """Switch to the requested subscription. Returns True on success."""
    result = subprocess.run(
        ["az", "account", "set", "--subscription", subscription],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(
            f"[ERROR] Could not set subscription '{subscription}': "
            f"{result.stderr.strip()}",
            file=sys.stderr,
        )
        return False
    return True


def _get_current_subscription() -> str:
    """Return the currently active subscription id."""
    try:
        result = subprocess.run(
            ["az", "account", "show", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        data = json.loads(result.stdout)
        return data.get("id") or data.get("name") or "unknown"
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def fetch_azure_live(
    subscription: str | None = None,
    save_path: str | None = None,
) -> AzureIAMData:
    """
    Fetch role assignments, role definitions, and service principals
    from a live Azure subscription and return an AzureIAMData object.

    Parameters
    ----------
    subscription : str | None
        Azure subscription ID or name. Uses currently active subscription if None.
    save_path : str | None
        If provided, saves the raw combined JSON to this path.
    """

    if subscription:
        print(f"[azure-live] Switching to subscription: {subscription}")
        if not _set_subscription(subscription):
            sys.exit(2)
    else:
        subscription = _get_current_subscription()
        print(f"[azure-live] Using active subscription: {subscription}")

    # ---- 1. Role Assignments -----------------------------------------------
    assignments_raw = _run_az(
        ["role", "assignment", "list", "--all", "--include-inherited"],
        "Fetching role assignments",
    )

    # ---- 2. Role Definitions (custom only — built-ins are huge) -------------
    definitions_raw = _run_az(
        ["role", "definition", "list", "--custom-role-only", "true"],
        "Fetching custom role definitions",
    )

    # ---- 3. Service Principals ----------------------------------------------
    sps_raw = _run_az(
        ["ad", "sp", "list", "--all"],
        "Fetching service principals",
    )

    print(
        f"[azure-live] Fetched: {len(assignments_raw)} assignments, "
        f"{len(definitions_raw)} custom roles, "
        f"{len(sps_raw)} service principals."
    )

    combined = {
        "assignments": assignments_raw,
        "definitions": definitions_raw,
        "service_principals": sps_raw,
    }

    # Optionally save raw data
    if save_path:
        out = Path(save_path)
        out.write_text(json.dumps(combined, indent=2), encoding="utf-8")
        print(f"[azure-live] Raw policy saved to: {save_path}")

    return parse_azure_dict(combined, source=f"live:{subscription}")
