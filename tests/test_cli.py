"""Tests for src/cli.py — pure business logic (no rich, no printing)."""

from __future__ import annotations
import json

import pytest

from detection import Finding, Severity
import cli
from conftest import ADMIN, ANALYST, APP_BACKEND, INTERN, _make_finding


class TestRunScan:
    def test_score_35(self, sample_json_file):
        assert cli.run_scan(str(sample_json_file)).risk.score == 35

    def test_findings_count(self, sample_json_file):
        assert len(cli.run_scan(str(sample_json_file)).findings) == 3

    def test_blast_radius_populated(self, sample_json_file):
        assert len(cli.run_scan(str(sample_json_file)).blast_radius) == 4

    def test_escalation_edges_populated(self, sample_json_file):
        assert len(cli.run_scan(str(sample_json_file)).escalation_edges) == 4

    def test_unsupported_cloud_raises(self, sample_json_file):
        with pytest.raises(ValueError, match="Unsupported cloud provider"):
            cli.run_scan(str(sample_json_file), cloud="aws")


class TestFilterBySeverity:
    def test_critical_only(self, sample_findings):
        filtered = cli.filter_by_severity(sample_findings, Severity.CRITICAL)
        assert all(f.severity == Severity.CRITICAL for f in filtered)
        assert len(filtered) == 2

    def test_low_keeps_all(self, sample_findings):
        assert len(cli.filter_by_severity(sample_findings, Severity.LOW)) == len(sample_findings)

    def test_high_keeps_high_and_critical(self, sample_findings):
        filtered = cli.filter_by_severity(sample_findings, Severity.HIGH)
        assert all(f.severity >= Severity.HIGH for f in filtered)


class TestDetermineExitCode:
    def test_exit_1_with_criticals(self, sample_findings):
        assert cli.determine_exit_code(sample_findings) == 1

    def test_exit_0_no_findings(self):
        assert cli.determine_exit_code([]) == 0

    def test_exit_0_only_high(self):
        assert cli.determine_exit_code([_make_finding("X", "a@x.com", Severity.HIGH)]) == 0


class TestFindBlastRadiusFor:
    def test_found(self, sample_json_file):
        result = cli.run_scan(str(sample_json_file))
        r = cli.find_blast_radius_for(result.blast_radius, INTERN)
        assert r is not None and r.percentage == 33.3

    def test_not_found_returns_none(self, sample_json_file):
        result = cli.run_scan(str(sample_json_file))
        assert cli.find_blast_radius_for(result.blast_radius, "ghost@x.com") is None


class TestMemberPrefix:
    def test_user(self):
        assert cli._member_prefix("alice@company.com") == "user"

    def test_service_account(self):
        assert cli._member_prefix("sa@proj.iam.gserviceaccount.com") == "serviceAccount"


class TestBuildRemediationCommand:
    def test_gcp002_contains_token_creator(self, sample_findings):
        f = next(f for f in sample_findings if f.rule_id == "GCP-002")
        cmd = cli.build_remediation_command(f)
        assert "serviceAccountTokenCreator" in cmd

    def test_unknown_rule_fallback(self):
        cmd = cli.build_remediation_command(_make_finding("UNKNOWN", "a@x.com", Severity.LOW))
        assert "manually" in cmd.lower() or "review" in cmd.lower()


class TestBuildJsonExport:
    def test_top_level_keys(self, sample_json_file):
        result = cli.run_scan(str(sample_json_file))
        export = cli.build_json_export(result)
        assert set(export.keys()) == {
            "cloudsentrix_version", "scanned_at", "source_file",
            "cloud", "summary", "findings", "blast_radius"
        }

    def test_score_in_summary(self, sample_json_file):
        assert cli.build_json_export(cli.run_scan(str(sample_json_file)))["summary"]["score"] == 35

    def test_remediation_in_every_finding(self, sample_json_file):
        export = cli.build_json_export(cli.run_scan(str(sample_json_file)))
        assert all("remediation" in f for f in export["findings"])

    def test_json_serializable(self, sample_json_file):
        export = cli.build_json_export(cli.run_scan(str(sample_json_file)))
        parsed = json.loads(json.dumps(export))
        assert parsed["summary"]["score"] == 35


class TestBuildHtmlExport:
    def test_has_interactive_graph_section(self, sample_json_file):
        html = cli.build_html_export(cli.run_scan(str(sample_json_file)))
        assert "Interactive Attack Graph" in html

    def test_no_unrendered_placeholder(self, sample_json_file):
        assert "__GRAPH_DATA_JSON__" not in cli.build_html_export(
            cli.run_scan(str(sample_json_file))
        )

    def test_finding_title_in_html(self, sample_json_file):
        html = cli.build_html_export(cli.run_scan(str(sample_json_file)))
        assert "Service Account Token Creator" in html

    def test_mitre_id_in_html(self, sample_json_file):
        html = cli.build_html_export(cli.run_scan(str(sample_json_file)))
        assert "T1098.001" in html

    def test_single_script_tag(self, sample_json_file):
        html = cli.build_html_export(cli.run_scan(str(sample_json_file)))
        assert html.count("<script>") == 1


class TestArgParser:
    def test_scan_defaults(self):
        args = cli.build_arg_parser().parse_args(["scan", "-f", "x.json"])
        assert args.command == "scan" and args.severity == "all" and args.top == 5

    def test_principal_path_source_target(self):
        args = cli.build_arg_parser().parse_args([
            "principal-path", "-f", "x.json",
            "--source", "a@x.com", "--target", "b@x.com"
        ])
        assert args.source == "a@x.com" and args.target == "b@x.com"

    def test_all_13_commands_parseable(self):
        p = cli.build_arg_parser()
        for cmd in [
            ["scan", "-f", "x.json"],
            ["blast-radius", "-f", "x.json", "-p", "a@x.com"],
            ["rules"],
            ["list-principals", "-f", "x.json"],
            ["validate", "-f", "x.json"],
            ["score", "-f", "x.json"],
            ["compare", "--old", "x.json", "--new", "y.json"],
            ["principal-path", "-f", "x.json", "--source", "a@x.com", "--target", "b@x.com"],
            ["mitre-map", "-f", "x.json"],
            ["remediate", "-f", "x.json"],
            ["export", "-f", "x.json", "-o", "out.json"],
            ["watch", "--path", "x.json"],
            ["report", "-f", "x.json"],
        ]:
            assert p.parse_args(cmd).command == cmd[0]

    def test_missing_file_raises(self):
        with pytest.raises(SystemExit):
            cli.build_arg_parser().parse_args(["scan"])

    def test_invalid_severity_raises(self):
        with pytest.raises(SystemExit):
            cli.build_arg_parser().parse_args(["scan", "-f", "x.json", "--severity", "nonsense"])
