"""
Risk Scoring Engine
=====================
Converts a list of detection Findings into a single 0-100 project-wide
security score, plus a qualitative rating band. Powers the CLI's
one-line "Overall Security Score" summary and, later, trend tracking
across repeated scans.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

from detection import Finding, Severity

logger = logging.getLogger(__name__)


class RiskRating(str, Enum):
    EXCELLENT = "Excellent"
    GOOD = "Good"
    FAIR = "Fair"
    POOR = "Poor"
    CRITICAL = "Critical"


# Points deducted from a perfect 100 score for each finding of this severity.
SEVERITY_PENALTY: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
}

# (minimum score, rating) bands, checked from highest to lowest.
RATING_BANDS: tuple[tuple[int, RiskRating], ...] = (
    (90, RiskRating.EXCELLENT),
    (75, RiskRating.GOOD),
    (50, RiskRating.FAIR),
    (25, RiskRating.POOR),
    (0, RiskRating.CRITICAL),
)


@dataclass(frozen=True)
class RiskScore:
    score: int  # clamped to 0-100
    rating: RiskRating
    penalty_breakdown: dict[str, int]  # severity name -> total points deducted
    finding_counts: dict[str, int]  # severity name -> count of findings


class RiskScorer:
    """Computes a 0-100 project security score from a list of Findings."""

    def __init__(self, penalties: dict[Severity, int] | None = None) -> None:
        self.penalties = penalties if penalties is not None else SEVERITY_PENALTY

    def score(self, findings: list[Finding]) -> RiskScore:
        penalty_breakdown = {s.name: 0 for s in Severity}
        finding_counts = {s.name: 0 for s in Severity}

        total_penalty = 0
        for finding in findings:
            penalty = self.penalties.get(finding.severity, 0)
            penalty_breakdown[finding.severity.name] += penalty
            finding_counts[finding.severity.name] += 1
            total_penalty += penalty

        raw_score = 100 - total_penalty
        final_score = max(0, min(100, raw_score))
        rating = self._rate(final_score)

        logger.info(
            "Computed risk score: %d/100 (%s) from %d finding(s)",
            final_score, rating.value, len(findings),
        )

        return RiskScore(
            score=final_score,
            rating=rating,
            penalty_breakdown=penalty_breakdown,
            finding_counts=finding_counts,
        )

    @staticmethod
    def _rate(score: int) -> RiskRating:
        for threshold, rating in RATING_BANDS:
            if score >= threshold:
                return rating
        return RiskRating.CRITICAL  # unreachable (0 is the lowest band) — explicit fallback


# ---------------------------------------------------------------------------
# Manual smoke test — runs only when this file is executed directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    from parser import GCPIAMParser
    from graph import IAMGraph
    from detection import DetectionEngine

    policy = GCPIAMParser().parse_file("sample_data/sample_gcp_iam.json")
    graph = IAMGraph.from_policy(policy)
    findings = DetectionEngine().run(graph)

    result = RiskScorer().score(findings)

    print(f"\nOverall Security Score: {result.score}/100 ({result.rating.value})")
    print(f"Findings by severity : {result.finding_counts}")
    print(f"Penalty breakdown     : {result.penalty_breakdown}")