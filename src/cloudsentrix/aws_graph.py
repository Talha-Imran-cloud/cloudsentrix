"""
AWS IAM Permission Graph Engine
=================================
Builds a directed graph from a ParsedAWSPolicy: principals (users, groups,
roles) as one node type, permissions (actions) as another, connected by
HAS_PERMISSION edges.

This mirrors the GCP graph engine's design — cloud-agnostic structural
representation. Security judgment (detecting dangerous combinations) is
the job of aws_detection.py, built on top of this graph.

Node types:
    - PRINCIPAL  — IAM user, group, or role
    - PERMISSION — An IAM action (e.g. "iam:passrole") or managed policy ARN

Edge types:
    - HAS_PERMISSION — principal -> permission
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

import networkx as nx

from aws_parser import (
    AWSIAMParser,
    AWSPrincipal,
    AWSPrincipalType,
    AWSPermission,
    AWSPermissionSource,
    ParsedAWSPolicy,
)

logger = logging.getLogger(__name__)


class AWSNodeType(str, Enum):
    PRINCIPAL = "principal"
    PERMISSION = "permission"


class AWSEdgeType(str, Enum):
    HAS_PERMISSION = "HAS_PERMISSION"


class AWSGraphBuildError(Exception):
    """Raised when a graph cannot be built from the given AWS policy."""


@dataclass(frozen=True)
class AWSPrincipalNode:
    """Convenience view of a principal node's identity and type."""
    node_id: str
    principal_type: AWSPrincipalType
    name: str
    arn: str


class AWSIAMGraph:
    """Wraps a networkx.DiGraph of an AWS IAM policy with typed query helpers.

    Node IDs:
        - Principal nodes use the ARN (globally unique).
        - Permission nodes use the action string (e.g. "iam:passrole").

    Edges:
        - principal -> permission, with {"type": AWSEdgeType.HAS_PERMISSION,
          "source": AWSPermissionSource, "policy_name": str}
    """

    def __init__(self) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()

    # -- construction ----------------------------------------------------

    @classmethod
    def from_policy(cls, policy: ParsedAWSPolicy) -> "AWSIAMGraph":
        """Build an AWSIAMGraph from a ParsedAWSPolicy.

        Raises:
            AWSGraphBuildError: If the policy object is None.
        """
        if policy is None:
            raise AWSGraphBuildError("Cannot build a graph from a None policy.")

        graph = cls()
        if not policy.bindings:
            logger.warning(
                "Policy from %s has no bindings — resulting graph will be empty.",
                policy.source_file,
            )

        for binding in policy.bindings:
            graph._add_principal_node(binding.principal)
            for permission in binding.permissions:
                graph._add_permission_node(permission.action)
                graph._add_has_permission_edge(binding.principal, permission)

        logger.info(
            "Built AWS graph: %d principal(s), %d unique permission(s), %d edge(s)",
            len(graph.principal_ids()),
            len(graph.permission_ids()),
            graph.edge_count(),
        )
        return graph

    def _add_principal_node(self, principal: AWSPrincipal) -> None:
        node_id = principal.principal_id
        if node_id not in self._graph:
            self._graph.add_node(
                node_id,
                node_type=AWSNodeType.PRINCIPAL,
                principal_type=principal.principal_type,
                name=principal.name,
                arn=principal.arn,
            )

    def _add_permission_node(self, action: str) -> None:
        if action not in self._graph:
            self._graph.add_node(action, node_type=AWSNodeType.PERMISSION)

    def _add_has_permission_edge(
        self, principal: AWSPrincipal, permission: AWSPermission
    ) -> None:
        node_id = principal.principal_id
        action = permission.action
        if not self._graph.has_edge(node_id, action):
            self._graph.add_edge(
                node_id,
                action,
                type=AWSEdgeType.HAS_PERMISSION,
                source=permission.source,
                resource=permission.resource,
                policy_name=permission.policy_name,
            )

    # -- queries ---------------------------------------------------------

    def permissions_of(self, principal_id: str) -> list[str]:
        """All permission (action) node ids a given principal directly holds."""
        if principal_id not in self._graph:
            return []
        return [
            target for target in self._graph.successors(principal_id)
            if self._graph.nodes[target].get("node_type") == AWSNodeType.PERMISSION
        ]

    def principals_with_permission(self, action: str) -> list[str]:
        """All principal ids that directly hold a given permission/action."""
        if action not in self._graph:
            return []
        return [
            source for source in self._graph.predecessors(action)
            if self._graph.nodes[source].get("node_type") == AWSNodeType.PRINCIPAL
        ]

    def has_permission(self, principal_id: str, action: str) -> bool:
        """Check if a principal directly holds a specific action."""
        return self._graph.has_edge(principal_id, action)

    def has_any_permission(self, principal_id: str, actions: frozenset[str]) -> list[str]:
        """Return which of the given actions the principal holds (empty = none)."""
        held = []
        for action in actions:
            if self._graph.has_edge(principal_id, action):
                held.append(action)
        return held

    def has_wildcard(self, principal_id: str) -> bool:
        """True if the principal holds '*' (full admin via AdministratorAccess or inline)."""
        return self._graph.has_edge(principal_id, "*")

    def has_managed_policy(self, principal_id: str, policy_arn: str) -> bool:
        """True if the principal has a managed-policy:<arn> permission node."""
        return self._graph.has_edge(principal_id, f"managed-policy:{policy_arn}")

    def has_principal(self, principal_id: str) -> bool:
        return (
            principal_id in self._graph
            and self._graph.nodes[principal_id].get("node_type") == AWSNodeType.PRINCIPAL
        )

    def get_principal(self, principal_id: str) -> AWSPrincipalNode | None:
        if not self.has_principal(principal_id):
            return None
        data = self._graph.nodes[principal_id]
        return AWSPrincipalNode(
            node_id=principal_id,
            principal_type=data["principal_type"],
            name=data["name"],
            arn=data["arn"],
        )

    def principals_by_type(self, principal_type: AWSPrincipalType) -> list[str]:
        """All principal ids of a given type (USER, GROUP, ROLE)."""
        return [
            n for n, d in self._graph.nodes(data=True)
            if d.get("node_type") == AWSNodeType.PRINCIPAL
            and d.get("principal_type") == principal_type
        ]

    def principal_ids(self) -> list[str]:
        return [
            n for n, d in self._graph.nodes(data=True)
            if d.get("node_type") == AWSNodeType.PRINCIPAL
        ]

    def permission_ids(self) -> list[str]:
        return [
            n for n, d in self._graph.nodes(data=True)
            if d.get("node_type") == AWSNodeType.PERMISSION
        ]

    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    def underlying(self) -> nx.DiGraph:
        """Expose the raw networkx graph for detection engine and visualization."""
        return self._graph

    def summary(self) -> dict[str, int]:
        users = len(self.principals_by_type(AWSPrincipalType.USER))
        groups = len(self.principals_by_type(AWSPrincipalType.GROUP))
        roles = len(self.principals_by_type(AWSPrincipalType.ROLE))
        return {
            "principals": len(self.principal_ids()),
            "users": users,
            "groups": groups,
            "roles": roles,
            "unique_permissions": len(self.permission_ids()),
            "edges": self.edge_count(),
        }


# ---------------------------------------------------------------------------
# Manual smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    policy = AWSIAMParser().parse_file("sample_data/sample_aws_iam.json")
    graph = AWSIAMGraph.from_policy(policy)

    print("\nGraph summary:", graph.summary())

    demo = "arn:aws:iam::123456789012:user/developer-bob"
    print(f"\nPermissions held by developer-bob:")
    for perm in graph.permissions_of(demo):
        print(f"  - {perm}")

    print(f"\nPrincipals with iam:passrole:")
    for p in graph.principals_with_permission("iam:passrole"):
        print(f"  - {p}")
