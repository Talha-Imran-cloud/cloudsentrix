"""
AI Summary Generator
=======================
Turns a scan's findings + risk score into a short, plain-language summary
a non-technical stakeholder can read — using the Gemini API when a key is
configured, and a template-based fallback when it isn't (or when the API
call fails), so the `report` command always produces a usable summary.

The API key is NEVER hardcoded or accepted as a CLI argument — it is read
only from the GEMINI_API_KEY environment variable, so it never ends up in
shell history, a config file committed to git, or this source code.

Uses only the Python standard library (urllib) for the HTTP call, so no
extra pip dependency is needed just for this feature.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

GEMINI_API_KEY_ENV_VAR = "GEMINI_API_KEY"
GEMINI_MODEL = "gemini-2.0-flash"
GEMINI_ENDPOINT = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
REQUEST_TIMEOUT_SECONDS = 20


class AISummaryError(Exception):
    """Raised when the Gemini API call fails. Callers should catch this
    and fall back to build_fallback_summary() rather than let it crash
    the CLI — an AI summary is a nice-to-have, not a hard requirement."""


def _build_prompt(risk_score: int, rating: str, finding_counts: dict[str, int], top_findings: list[dict]) -> str:
    findings_lines = "\n".join(
        f"- [{f['severity']}] {f['title']} on '{f['principal_id']}': {f['description']}"
        for f in top_findings
    )
    return (
        "You are summarizing a cloud security scan for a non-technical stakeholder "
        "(e.g. a manager or client). Write 3-5 plain-language sentences: state the "
        "overall risk level, mention the most serious issue(s) in everyday terms, and "
        "note the general kind of action needed (no need to give exact commands). "
        "Do not use markdown formatting or bullet points in your answer — plain prose only.\n\n"
        f"Overall score: {risk_score}/100 ({rating})\n"
        f"Finding counts: {finding_counts}\n"
        f"Top findings:\n{findings_lines}\n"
    )


def generate_ai_summary(
    risk_score: int, rating: str, finding_counts: dict[str, int], top_findings: list[dict]
) -> str:
    """Calls the Gemini API to generate a plain-language summary.

    Raises:
        AISummaryError: If GEMINI_API_KEY isn't set, or the API call fails
            for any reason (network, auth, rate limit, unexpected response
            shape). Callers should catch this and use
            build_fallback_summary() instead.
    """
    api_key = os.environ.get(GEMINI_API_KEY_ENV_VAR)
    if not api_key:
        raise AISummaryError(
            f"{GEMINI_API_KEY_ENV_VAR} is not set. Set it in your environment to enable AI summaries."
        )

    prompt = _build_prompt(risk_score, rating, finding_counts, top_findings)
    payload = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode("utf-8")

    request = urllib.request.Request(
        f"{GEMINI_ENDPOINT}?key={api_key}",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise AISummaryError(f"Gemini API returned HTTP {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise AISummaryError(f"Could not reach the Gemini API: {exc.reason}") from exc
    except TimeoutError as exc:
        raise AISummaryError("Gemini API request timed out.") from exc

    try:
        text = body["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise AISummaryError(f"Unexpected response shape from Gemini API: {body}") from exc

    return text.strip()


def build_fallback_summary(risk_score: int, rating: str, finding_counts: dict[str, int]) -> str:
    """A deterministic, template-based summary used when no API key is
    configured or the Gemini call fails. Contains no external calls, so
    it always succeeds."""
    critical = finding_counts.get("CRITICAL", 0)
    high = finding_counts.get("HIGH", 0)

    if critical:
        headline = (
            f"This project's security posture is rated {rating.upper()} at {risk_score}/100. "
            f"There {'is' if critical == 1 else 'are'} {critical} critical finding"
            f"{'' if critical == 1 else 's'} that should be addressed immediately, as "
            "these represent direct paths for an attacker to gain broad control over the project."
        )
    elif high:
        headline = (
            f"This project's security posture is rated {rating.upper()} at {risk_score}/100. "
            f"There {'is' if high == 1 else 'are'} {high} high-severity finding"
            f"{'' if high == 1 else 's'} worth prioritizing soon."
        )
    else:
        headline = (
            f"This project's security posture is rated {rating.upper()} at {risk_score}/100, "
            "with no critical or high-severity findings at this time."
        )

    return (
        f"{headline} Overall, {finding_counts.get('CRITICAL', 0)} critical, "
        f"{finding_counts.get('HIGH', 0)} high, {finding_counts.get('MEDIUM', 0)} medium, "
        f"and {finding_counts.get('LOW', 0)} low-severity issues were identified. "
        "See the findings section below for full details and recommended remediation steps."
    )
