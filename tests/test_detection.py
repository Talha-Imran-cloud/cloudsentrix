"""Tests for src/detection.py — all 5 rules, DetectionEngine, summarize_findings."""

from __future__ import annotations
from pathlib import Path

import pytest

from detection import (
    DetectionEngine, DetectionRule, Finding, Severity, summarize_findings,
    IAMPolicyAdminRule, PublicAccessRule, ServiceAccountImpersonationRule,
    ServiceAccountKeyAdminRule, ServiceAccountTokenCreatorRule,
)
from graph import IAMGraph
from conftest import (
    ADMIN, ANALYST, APP_BACKEND, INTERN,
    make_binding, make_policy, _make_finding,
)


def _g(*bindings) -> IAMGraph:
    return IAMGraph.from_policy(make_policy(Path("fake.json"), *bindings))


class TestSeverity:
    def test_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW

    def test_str_names(self):
        for s in Severity:
            assert str(s) == s.name

    def test_int_critical_is_4(self):
        assert int(Severity.CRITICAL) == 4


class TestPublicAccessRule:
    def test_fires_for_all_users(self):
        g = _g(make_binding("roles/viewer", "allUsers"))
        fs = PublicAccessRule().evaluate(g)
        assert len(fs) == 1 and fs[0].severity == Severity.CRITICAL and fs[0].rule_id == "GCP-001"

    def test_fires_for_all_authenticated_users(self):
        g = _g(make_binding("roles/viewer", "allAuthenticatedUsers"))
        assert len(PublicAccessRule().evaluate(g)) == 1

    def test_no_finding_in_sample(self, sample_graph):
        assert PublicAccessRule().evaluate(sample_graph) == []

    def test_evidence_contains_role(self):
        g = _g(make_binding("roles/storage.objectViewer", "allUsers"))
        f = PublicAccessRule().evaluate(g)[0]
        assert "roles/storage.objectViewer" in f.evidence


class TestServiceAccountTokenCreatorRule:
    def test_fires_on_sample(self, sample_graph):
        fs = ServiceAccountTokenCreatorRule().evaluate(sample_graph)
        assert len(fs) == 1
        assert fs[0].principal_id == APP_BACKEND
        assert fs[0].severity == Severity.CRITICAL
        assert fs[0].rule_id == "GCP-002"

    def test_no_finding_without_role(self):
        g = _g(make_binding("roles/viewer", "user:safe@x.com"))
        assert ServiceAccountTokenCreatorRule().evaluate(g) == []


class TestServiceAccountKeyAdminRule:
    def test_fires_on_key_admin(self):
        g = _g(make_binding("roles/iam.serviceAccountKeyAdmin", "user:danger@x.com"))
        fs = ServiceAccountKeyAdminRule().evaluate(g)
        assert len(fs) == 1 and fs[0].rule_id == "GCP-003" and fs[0].severity == Severity.CRITICAL

    def test_no_finding_in_sample(self, sample_graph):
        assert ServiceAccountKeyAdminRule().evaluate(sample_graph) == []


class TestIAMPolicyAdminRule:
    def test_fires_for_owner(self, sample_graph):
        principals = [f.principal_id for f in IAMPolicyAdminRule().evaluate(sample_graph)]
        assert ADMIN in principals

    def test_fires_for_project_iam_admin(self):
        g = _g(make_binding("roles/resourcemanager.projectIamAdmin", "user:a@x.com"))
        fs = IAMPolicyAdminRule().evaluate(g)
        assert len(fs) == 1 and fs[0].principal_id == "a@x.com"

    def test_fires_for_security_admin(self):
        g = _g(make_binding("roles/iam.securityAdmin", "user:b@x.com"))
        fs = IAMPolicyAdminRule().evaluate(g)
        assert len(fs) == 1 and fs[0].principal_id == "b@x.com"

    def test_rule_id(self, sample_graph):
        for f in IAMPolicyAdminRule().evaluate(sample_graph):
            assert f.rule_id == "GCP-004"


class TestServiceAccountImpersonationRule:
    def test_fires_for_intern(self, sample_graph):
        fs = ServiceAccountImpersonationRule().evaluate(sample_graph)
        assert any(f.principal_id == INTERN for f in fs)

    def test_editor_alone_no_finding(self):
        g = _g(make_binding("roles/editor", "user:e@x.com"))
        assert ServiceAccountImpersonationRule().evaluate(g) == []

    def test_service_account_user_alone_no_finding(self):
        g = _g(make_binding("roles/iam.serviceAccountUser", "user:u@x.com"))
        assert ServiceAccountImpersonationRule().evaluate(g) == []

    def test_both_roles_in_evidence(self, sample_graph):
        fs = ServiceAccountImpersonationRule().evaluate(sample_graph)
        intern_f = next(f for f in fs if f.principal_id == INTERN)
        assert "roles/iam.serviceAccountUser" in intern_f.evidence
        assert "roles/editor" in intern_f.evidence

    def test_rule_id(self, sample_graph):
        for f in ServiceAccountImpersonationRule().evaluate(sample_graph):
            assert f.rule_id == "GCP-005"


class TestDetectionEngine:
    def test_total_findings(self, sample_findings):
        assert len(sample_findings) == 3

    def test_sorted_most_severe_first(self, sample_findings):
        sevs = [f.severity for f in sample_findings]
        assert sevs == sorted(sevs, reverse=True)

    def test_two_criticals_one_high(self, sample_findings):
        assert sum(1 for f in sample_findings if f.severity == Severity.CRITICAL) == 2
        assert sum(1 for f in sample_findings if f.severity == Severity.HIGH) == 1

    def test_all_findings_have_mitre_id(self, sample_findings):
        assert all(f.mitre_technique_id.startswith("T") for f in sample_findings)

    def test_empty_graph_no_findings(self):
        g = IAMGraph.from_policy(make_policy(Path("f.json")))
        assert DetectionEngine().run(g) == []

    def test_broken_rule_skipped_others_run(self):
        class BrokenRule(DetectionRule):
            rule_id = "TEST-BROKEN"; title = "Broken"; severity = Severity.LOW
            mitre_technique_id = "T0000"; mitre_technique_name = "Test"
            def evaluate(self, graph): raise RuntimeError("simulated bug")

        g = _g(make_binding("roles/viewer", "allUsers"))
        engine = DetectionEngine(rules=[BrokenRule()] + DetectionEngine._default_rules())
        findings = engine.run(g)
        assert any(f.rule_id == "GCP-001" for f in findings)

    def test_default_rules_count(self):
        assert len(DetectionEngine._default_rules()) == 5


class TestSummarizeFindings:
    def test_empty(self):
        assert summarize_findings([]) == {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "TOTAL": 0}

    def test_sample(self, sample_findings):
        s = summarize_findings(sample_findings)
        assert s["CRITICAL"] == 2 and s["HIGH"] == 1 and s["TOTAL"] == 3

    def test_total_equals_sum(self, sample_findings):
        s = summarize_findings(sample_findings)
        assert s["TOTAL"] == s["LOW"] + s["MEDIUM"] + s["HIGH"] + s["CRITICAL"]