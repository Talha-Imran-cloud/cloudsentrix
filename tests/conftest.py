"""conftest.py — Shared pytest fixtures for the CloudSentrix test suite."""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Make src/ importable from tests/
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest

from parser import GCPIAMParser, IAMBinding, Member, ParsedIAMPolicy
from graph import IAMGraph
from detection import DetectionEngine, Finding, Severity
from blast_radius import BlastRadiusCalculator
from risk_score import RiskScorer

ADMIN       = "admin@company.com"
INTERN      = "intern@company.com"
APP_BACKEND = "app-backend@my-project.iam.gserviceaccount.com"
ANALYST     = "analyst@company.com"

SAMPLE_JSON = {
    "bindings": [
        {"role": "roles/owner",
         "members": ["user:admin@company.com"]},
        {"role": "roles/editor",
         "members": ["user:intern@company.com",
                     "serviceAccount:app-backend@my-project.iam.gserviceaccount.com"]},
        {"role": "roles/iam.serviceAccountTokenCreator",
         "members": ["serviceAccount:app-backend@my-project.iam.gserviceaccount.com"]},
        {"role": "roles/iam.serviceAccountUser",
         "members": ["user:intern@company.com"]},
        {"role": "roles/viewer",
         "members": ["user:analyst@company.com"]},
    ]
}


def make_member(raw: str) -> Member:
    return Member.from_raw(raw)

def make_binding(role: str, *members: str) -> IAMBinding:
    return IAMBinding(role=role, members=tuple(Member.from_raw(m) for m in members))

def make_policy(path: Path, *bindings: IAMBinding) -> ParsedIAMPolicy:
    return ParsedIAMPolicy(source_file=path, bindings=list(bindings))

def _make_finding(rule_id: str, principal: str, sev: Severity) -> Finding:
    return Finding(
        rule_id=rule_id, title="Test", severity=sev, principal_id=principal,
        description="desc", mitre_technique_id="T0000",
        mitre_technique_name="Test Technique",
    )


@pytest.fixture(scope="session")
def sample_json_file(tmp_path_factory) -> Path:
    p = tmp_path_factory.mktemp("data") / "sample_gcp_iam.json"
    p.write_text(json.dumps(SAMPLE_JSON), encoding="utf-8")
    return p

@pytest.fixture(scope="session")
def sample_policy(sample_json_file) -> ParsedIAMPolicy:
    return GCPIAMParser().parse_file(sample_json_file)

@pytest.fixture(scope="session")
def sample_graph(sample_policy) -> IAMGraph:
    return IAMGraph.from_policy(sample_policy)

@pytest.fixture(scope="session")
def sample_findings(sample_graph) -> list[Finding]:
    return DetectionEngine().run(sample_graph)

@pytest.fixture(scope="session")
def sample_risk(sample_findings):
    return RiskScorer().score(sample_findings)

@pytest.fixture(scope="session")
def sample_blast(sample_graph, sample_findings) -> BlastRadiusCalculator:
    return BlastRadiusCalculator(sample_graph, sample_findings)
