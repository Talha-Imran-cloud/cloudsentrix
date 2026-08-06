"""Tests for src/blast_radius.py — BlastRadiusCalculator."""

from __future__ import annotations
from pathlib import Path

import pytest

from blast_radius import BlastRadiusCalculator
from detection import Finding, Severity
from graph import IAMGraph
from parser import IAMBinding, Member, ParsedIAMPolicy
from conftest import (
    ADMIN, ANALYST, APP_BACKEND, INTERN,
    make_binding, make_policy, _make_finding,
)


def _g(*bindings) -> IAMGraph:
    return IAMGraph.from_policy(make_policy(Path("fake.json"), *bindings))


class TestBlastRadiusCalculate:
    def test_admin_100_percent(self, sample_blast):
        assert sample_blast.calculate(ADMIN).percentage == 100.0

    def test_intern_33_percent(self, sample_blast):
        assert sample_blast.calculate(INTERN).percentage == 33.3

    def test_analyst_zero(self, sample_blast):
        assert sample_blast.calculate(ANALYST).percentage == 0.0

    def test_app_backend_zero(self, sample_blast):
        assert sample_blast.calculate(APP_BACKEND).percentage == 0.0

    def test_intern_reaches_app_backend(self, sample_blast):
        assert APP_BACKEND in sample_blast.calculate(INTERN).reachable_principals

    def test_admin_reaches_all_others(self, sample_blast):
        r = sample_blast.calculate(ADMIN)
        for pid in [INTERN, APP_BACKEND, ANALYST]:
            assert pid in r.reachable_principals

    def test_empty_findings_zero_blast(self, sample_graph):
        calc = BlastRadiusCalculator(sample_graph, [])
        for pid in sample_graph.principal_ids():
            assert calc.calculate(pid).percentage == 0.0

    def test_unknown_principal_zero(self, sample_blast):
        assert sample_blast.calculate("ghost@x.com").percentage == 0.0

    def test_single_principal_no_zero_division(self):
        p = ParsedIAMPolicy(source_file=Path("f.json"), bindings=[
            IAMBinding(role="roles/owner",
                       members=(Member.from_raw("user:solo@x.com"),))
        ])
        g = IAMGraph.from_policy(p)
        calc = BlastRadiusCalculator(
            g, [_make_finding("GCP-004", "solo@x.com", Severity.CRITICAL)]
        )
        r = calc.calculate("solo@x.com")
        assert r.percentage == 0.0 and r.total_others == 0


class TestBlastRadiusCalculateAll:
    def test_sorted_descending(self, sample_blast):
        percs = [r.percentage for r in sample_blast.calculate_all()]
        assert percs == sorted(percs, reverse=True)

    def test_count_equals_principal_count(self, sample_blast, sample_graph):
        assert len(sample_blast.calculate_all()) == len(sample_graph.principal_ids())


class TestFindPath:
    def test_direct_path(self, sample_blast):
        assert sample_blast.find_path(INTERN, APP_BACKEND) == [INTERN, APP_BACKEND]

    def test_no_path_returns_none(self, sample_blast):
        assert sample_blast.find_path(ANALYST, INTERN) is None

    def test_unknown_source_returns_none(self, sample_blast):
        assert sample_blast.find_path("ghost@x.com", INTERN) is None

    def test_unknown_target_returns_none(self, sample_blast):
        assert sample_blast.find_path(INTERN, "ghost@x.com") is None

    def test_multi_hop_path_exists(self, sample_blast):
        path = sample_blast.find_path(ADMIN, ANALYST)
        assert path is not None and path[0] == ADMIN and path[-1] == ANALYST


class TestEscalationEdges:
    def test_count(self, sample_blast):
        assert len(sample_blast.escalation_edges()) == 4

    def test_are_triples(self, sample_blast):
        for item in sample_blast.escalation_edges():
            assert len(item) == 3

    def test_rule_ids_present(self, sample_blast):
        rule_ids = {e[2] for e in sample_blast.escalation_edges()}
        assert "GCP-004" in rule_ids and "GCP-005" in rule_ids

    def test_all_endpoints_valid_principals(self, sample_blast, sample_graph):
        principal_ids = set(sample_graph.principal_ids())
        for src, tgt, _ in sample_blast.escalation_edges():
            assert src in principal_ids and tgt in principal_ids
            