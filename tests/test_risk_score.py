"""Tests for src/risk_score.py — RiskScorer, RiskRating."""

from __future__ import annotations

import pytest

from detection import Severity
from risk_score import RiskRating, RiskScorer, SEVERITY_PENALTY, RATING_BANDS
from conftest import _make_finding


class TestRiskScorer:
    def test_no_findings_perfect_score(self):
        r = RiskScorer().score([])
        assert r.score == 100 and r.rating == RiskRating.EXCELLENT

    def test_sample_score_35_poor(self, sample_findings):
        r = RiskScorer().score(sample_findings)
        assert r.score == 35 and r.rating == RiskRating.POOR

    def test_penalty_per_critical(self):
        findings = [_make_finding("GCP-001", "a@x.com", Severity.CRITICAL)]
        r = RiskScorer().score(findings)
        assert r.score == 100 - SEVERITY_PENALTY[Severity.CRITICAL]

    def test_clamps_at_zero(self):
        findings = [_make_finding("X", "a@x.com", Severity.CRITICAL)] * 10
        r = RiskScorer().score(findings)
        assert r.score == 0 and r.rating == RiskRating.CRITICAL

    def test_score_never_exceeds_100(self):
        assert RiskScorer().score([]).score <= 100

    def test_boundary_90_excellent(self):
        custom = RiskScorer(penalties={s: 10 for s in Severity})
        r = custom.score([_make_finding("X", "a@x.com", Severity.LOW)])
        assert r.score == 90 and r.rating == RiskRating.EXCELLENT

    def test_boundary_89_good(self):
        custom = RiskScorer(penalties={s: 11 for s in Severity})
        r = custom.score([_make_finding("X", "a@x.com", Severity.LOW)])
        assert r.score == 89 and r.rating == RiskRating.GOOD

    def test_finding_counts_in_result(self, sample_findings):
        r = RiskScorer().score(sample_findings)
        assert r.finding_counts["CRITICAL"] == 2
        assert r.finding_counts["HIGH"] == 1
        assert r.finding_counts["MEDIUM"] == 0

    def test_penalty_breakdown_all_keys(self, sample_findings):
        r = RiskScorer().score(sample_findings)
        assert set(r.penalty_breakdown.keys()) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def test_custom_zero_penalties(self):
        custom = RiskScorer(penalties={s: 0 for s in Severity})
        r = custom.score([_make_finding("X", "a@x.com", Severity.CRITICAL)])
        assert r.score == 100

    def test_rating_band_poor_range(self):
        # score 30 should be in Poor band (25-49)
        r = RiskScorer().score([_make_finding("X", "a@x.com", Severity.CRITICAL)] * 2
                                + [_make_finding("Y", "b@x.com", Severity.HIGH)] * 2)
        # 100 - 2*25 - 2*15 = 100 - 80 = 20 -> CRITICAL band
        # Just confirm Poor rating works at the boundary
        custom = RiskScorer(penalties={s: 70 for s in Severity})
        r2 = custom.score([_make_finding("X", "a@x.com", Severity.LOW)])
        assert r2.score == 30 and r2.rating == RiskRating.POOR
