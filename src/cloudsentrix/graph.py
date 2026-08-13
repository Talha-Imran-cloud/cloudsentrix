"""
IAM Permission Graph Engine
============================
Builds a directed graph from a ParsedIAMPolicy: principals (users, service
accounts, groups) as one node type, roles as another, connected by
HAS_ROLE edges.

This is a faithful, cloud-agnostic structural mirror of the parsed IAM
bindings — no security judgment is applied at this layer. Detecting
*dangerous* combinations (e.g. a role that allows impersonation) is the
job of the detection engine, built on top of this graph in a later part.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

import networkx as nx

from parser import GCPIAMParser, Member, MemberType, ParsedIAMPolicy

logger = logging.getLogger(__name__)


class NodeType(str, Enum):
    """Distinguishes principal nodes from role nodes in the graph."""
    PRINCIPAL = "principal"
    ROLE = "role"


class EdgeType(str, Enum):
    """The relationship an edge represents. Only HAS_ROLE exists at this
    layer; richer relationships (e.g. CAN_IMPERSONATE) get derived later,
    on top of this graph, by the detection engine."""
    HAS_ROLE = "HAS_ROLE"


class GraphBuildError(Exception):
    """Raised when a graph cannot be built from the given policy."""


@dataclass(frozen=True)
class PrincipalNode:
    """Convenience view of a principal node's identity and type."""
    node_id: str
    member_type: MemberType


class IAMGraph:
    """Wraps a networkx.DiGraph of an IAM policy with typed query helpers.

    Node IDs:
        - Principal nodes use the member's identifier (email), or the raw
          member string for identifier-less members (allUsers, allAuthenticatedUsers).
        - Role nodes use the GCP role name as-is (e.g. "roles/editor").

    Edges:
        - principal -> role, with edge attribute {"type": EdgeType.HAS_ROLE}.
    """

    def __init__(self) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()

    # -- construction ---------------------------------------------------

    @classmethod
    def from_policy(cls, policy: ParsedIAMPolicy) -> "IAMGraph":
        """Build an IAMGraph from a ParsedIAMPolicy.

        Raises:
            GraphBuildError: If the policy object is malformed in a way
                the parser should already have prevented (defensive check).
        """
        if policy is None:
            raise GraphBuildError("Cannot build a graph from a None policy.")

        graph = cls()
        if not policy.bindings:
            logger.warning(
                "Policy from %s has no bindings — resulting graph will be empty.",
                policy.source_file,
            )

        for binding in policy.bindings:
            graph._add_role_node(binding.role)
            for member in binding.members:
                graph._add_principal_node(member)
                graph._add_has_role_edge(member, binding.role)

        logger.info(
            "Built graph: %d principal(s), %d role(s), %d edge(s)",
            len(graph.principal_ids()), len(graph.role_ids()), graph.edge_count(),
        )
        return graph

    def _principal_node_id(self, member: Member) -> str:
        # allUsers / allAuthenticatedUsers have no identifier, so fall
        # back to the raw member string to keep the node id unique and readable.
        return member.identifier if member.identifier else member.raw

    def _add_principal_node(self, member: Member) -> None:
        node_id = self._principal_node_id(member)
        if node_id not in self._graph:
            self._graph.add_node(
                node_id,
                node_type=NodeType.PRINCIPAL,
                member_type=member.type,
                raw=member.raw,
            )

    def _add_role_node(self, role: str) -> None:
        if role not in self._graph:
            self._graph.add_node(role, node_type=NodeType.ROLE)

    def _add_has_role_edge(self, member: Member, role: str) -> None:
        node_id = self._principal_node_id(member)
        if not self._graph.has_edge(node_id, role):
            self._graph.add_edge(node_id, role, type=EdgeType.HAS_ROLE)

    # -- queries ----------------------------------------------------------

    def roles_of(self, principal_id: str) -> list[str]:
        """All roles a given principal (by node id, e.g. an email) directly holds."""
        if principal_id not in self._graph:
            return []
        return [
            target for target in self._graph.successors(principal_id)
            if self._graph.nodes[target].get("node_type") == NodeType.ROLE
        ]

    def principals_with_role(self, role: str) -> list[str]:
        """All principal ids directly holding a given role."""
        if role not in self._graph:
            return []
        return [
            source for source in self._graph.predecessors(role)
            if self._graph.nodes[source].get("node_type") == NodeType.PRINCIPAL
        ]

    def has_principal(self, principal_id: str) -> bool:
        return (
            principal_id in self._graph
            and self._graph.nodes[principal_id].get("node_type") == NodeType.PRINCIPAL
        )

    def get_principal(self, principal_id: str) -> PrincipalNode | None:
        """Typed view of a principal node (id + member type), or None if
        no such principal exists in the graph."""
        if not self.has_principal(principal_id):
            return None
        data = self._graph.nodes[principal_id]
        return PrincipalNode(node_id=principal_id, member_type=data["member_type"])

    def principal_ids(self) -> list[str]:
        return [n for n, d in self._graph.nodes(data=True) if d.get("node_type") == NodeType.PRINCIPAL]

    def role_ids(self) -> list[str]:
        return [n for n, d in self._graph.nodes(data=True) if d.get("node_type") == NodeType.ROLE]

    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    def underlying(self) -> nx.DiGraph:
        """Expose the raw networkx graph — later parts (detection engine,
        blast radius, visualization) build directly on top of this."""
        return self._graph

    def summary(self) -> dict[str, int]:
        return {
            "principals": len(self.principal_ids()),
            "roles": len(self.role_ids()),
            "edges": self.edge_count(),
        }


# ---------------------------------------------------------------------------
# Manual smoke test — runs only when this file is executed directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    policy = GCPIAMParser().parse_file("sample_data/sample_gcp_iam.json")
    graph = IAMGraph.from_policy(policy)

    print("\nGraph summary:", graph.summary())

    demo_principal = "intern@company.com"
    print(f"\nRoles held by {demo_principal}:")
    for role in graph.roles_of(demo_principal):
        print(f"  - {role}")

    demo_role = "roles/editor"
    print(f"\nPrincipals holding {demo_role}:")
    for principal in graph.principals_with_role(demo_role):
        print(f"  - {principal}")