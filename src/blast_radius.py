"""
Blast Radius Calculator
==========================
Answers the core question this whole tool exists to answer: "If this one
principal is compromised, how much of the project's identity surface
does an attacker ultimately control?"

It builds a derived "who can become whom" escalation graph from the
detection engine's Findings (Part 3), then computes multi-hop reachability
over it — so a principal that isn't Owner, but that can chain through one
or more impersonation paths to reach principals that ARE powerful, still
shows the full extent of what it can reach.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import networkx as nx

from graph import IAMGraph
from parser import MemberType
from detection import Finding

logger = logging.getLogger(__name__)


# Rule IDs whose findings mean "this principal can become/reach every
# SERVICE ACCOUNT in the project" (project-level impersonation grants).
SERVICE_ACCOUNT_IMPERSONATION_RULES = frozenset({"GCP-002", "GCP-003", "GCP-005"})

# Rule IDs whose findings mean "this principal can grant itself or anyone
# ANY role" — i.e. it can effectively become ANY principal in the project.
FULL_PROJECT_TAKEOVER_RULES = frozenset({"GCP-004"})


@dataclass(frozen=True)
class BlastRadiusResult:
    principal_id: str
    reachable_principals: tuple[str, ...]  # everyone this principal can ultimately become
    total_others: int  # size of the rest of the project's identity surface
    percentage: float  # 0.0 - 100.0


class BlastRadiusCalculator:
    """Builds a derived escalation graph from Findings and computes, for
    each principal, the share of the project's OTHER identities it could
    ultimately reach through direct or chained impersonation.
    """

    def __init__(self, graph: IAMGraph, findings: list[Finding]) -> None:
        self._iam_graph = graph
        self._escalation_graph = self._build_escalation_graph(graph, findings)

    def _build_escalation_graph(self, graph: IAMGraph, findings: list[Finding]) -> nx.DiGraph:
        escalation_graph: nx.DiGraph = nx.DiGraph()
        all_principals = graph.principal_ids()
        escalation_graph.add_nodes_from(all_principals)

        service_account_ids = [
            pid for pid in all_principals
            if (p := graph.get_principal(pid)) is not None and p.member_type == MemberType.SERVICE_ACCOUNT
        ]

        for finding in findings:
            source = finding.principal_id
            if source not in escalation_graph:
                # e.g. allUsers / allAuthenticatedUsers aren't identities we
                # escalate FROM in this model — skip findings sourced from them.
                continue

            if finding.rule_id in FULL_PROJECT_TAKEOVER_RULES:
                targets = [pid for pid in all_principals if pid != source]
            elif finding.rule_id in SERVICE_ACCOUNT_IMPERSONATION_RULES:
                targets = [pid for pid in service_account_ids if pid != source]
            else:
                targets = []

            for target in targets:
                escalation_graph.add_edge(source, target, via_rule=finding.rule_id)

        logger.info(
            "Built escalation graph: %d node(s), %d edge(s)",
            escalation_graph.number_of_nodes(), escalation_graph.number_of_edges(),
        )
        return escalation_graph

    def calculate(self, principal_id: str) -> BlastRadiusResult:
        """Blast radius for one principal: everyone transitively reachable
        (one hop or many), as a share of every OTHER principal in the project."""
        all_principals = self._iam_graph.principal_ids()
        total_others = len(all_principals) - (1 if principal_id in all_principals else 0)

        if principal_id not in self._escalation_graph or total_others <= 0:
            return BlastRadiusResult(
                principal_id=principal_id, reachable_principals=(), total_others=total_others, percentage=0.0,
            )

        reachable = nx.descendants(self._escalation_graph, principal_id)  # transitive, excludes self
        percentage = round((len(reachable) / total_others) * 100, 1)

        return BlastRadiusResult(
            principal_id=principal_id,
            reachable_principals=tuple(sorted(reachable)),
            total_others=total_others,
            percentage=percentage,
        )

    def calculate_all(self) -> list[BlastRadiusResult]:
        """Blast radius for every principal in the graph, worst (highest
        percentage) first."""
        results = [self.calculate(pid) for pid in self._iam_graph.principal_ids()]
        results.sort(key=lambda r: r.percentage, reverse=True)
        return results

    def escalation_edges(self) -> list[tuple[str, str, str]]:
        """Returns all edges in the escalation graph as (source, target, rule_id) triples.
        Useful for rendering attack-path visualizations and for testing."""
        return [
            (src, tgt, data.get("via_rule", ""))
            for src, tgt, data in self._escalation_graph.edges(data=True)
        ]

    def find_path(self, source_id: str, target_id: str) -> list[str] | None:
        """Shortest escalation path from source to target (inclusive of
        both endpoints), or None if either principal isn't in the graph
        or no escalation path exists between them. Complements
        calculate()/calculate_all(), which answer "how much" a principal
        can reach — this answers "via which specific steps"."""
        if source_id not in self._escalation_graph or target_id not in self._escalation_graph:
            return None
        try:
            return nx.shortest_path(self._escalation_graph, source_id, target_id)
        except nx.NetworkXNoPath:
            return None


# ---------------------------------------------------------------------------
# Manual smoke test — runs only when this file is executed directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    from parser import GCPIAMParser
    from detection import DetectionEngine

    policy = GCPIAMParser().parse_file("sample_data/sample_gcp_iam.json")
    graph = IAMGraph.from_policy(policy)
    findings = DetectionEngine().run(graph)

    calculator = BlastRadiusCalculator(graph, findings)
    results = calculator.calculate_all()

    print(f"\n{'Principal':<45} {'Blast Radius':>12}  Reaches")
    print("-" * 90)
    for r in results:
        reaches = ", ".join(r.reachable_principals) if r.reachable_principals else "(nothing further)"
        print(f"{r.principal_id:<45} {r.percentage:>10.1f}%  {reaches}")