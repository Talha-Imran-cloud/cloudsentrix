"""
Live Scanner
=============
Fetches a live GCP IAM policy directly from the GCP API using the
locally authenticated gcloud CLI — no SDK installation required.

Requirements:
    gcloud CLI installed and authenticated:
        gcloud auth application-default login
    OR service account key set:
        export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class LiveScanError(Exception):
    """Raised when live IAM policy fetch fails."""


def fetch_live_iam_policy(project_id: str) -> dict:
    """Fetches live IAM policy from GCP using gcloud CLI.

    Args:
        project_id: GCP project ID (e.g. 'my-project-123')

    Returns:
        IAM policy dict in the same format as a JSON export file.

    Raises:
        LiveScanError: If gcloud is not found or the fetch fails.
    """
    logger.info("Fetching live IAM policy for project: %s", project_id)

    try:
        result = subprocess.run(
            ["gcloud", "projects", "get-iam-policy", project_id, "--format=json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        raise LiveScanError(
            "gcloud CLI not found. Install it from https://cloud.google.com/sdk/install"
        )
    except subprocess.TimeoutExpired:
        raise LiveScanError("gcloud command timed out after 30 seconds.")

    if result.returncode != 0:
        raise LiveScanError(
            f"gcloud failed (exit {result.returncode}): {result.stderr.strip()}"
        )

    try:
        policy = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise LiveScanError(f"Could not parse gcloud output as JSON: {exc}") from exc

    if "bindings" not in policy:
        raise LiveScanError(
            "Unexpected response from gcloud — 'bindings' key missing. "
            "Are you authenticated? Run: gcloud auth application-default login"
        )

    logger.info(
        "Fetched %d binding(s) for project '%s'",
        len(policy.get("bindings", [])),
        project_id,
    )
    return policy


def save_policy_to_file(policy: dict, output_path: Path) -> None:
    """Saves a fetched policy dict to a JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    logger.info("Saved live policy to %s", output_path)
