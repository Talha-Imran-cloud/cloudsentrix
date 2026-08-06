"""Tests for src/graph.py — IAMGraph."""

from __future__ import annotations
from pathlib import Path

import pytest

from graph import GraphBuildError, IAMGraph
from parser import MemberType
from conftest import (
    ADMIN, ANALYST, APP_BACKEND, INTERN,
    make_binding, make_policy,
)


def _g(*bindings) -> IAMGraph:
    return IAMGraph.from_policy(make_policy(Path("fake.json"), *bindings))


class TestIAMGraphHappyPath:
    def test_summary(self, sample_graph):
        assert sample_graph.summary() == {"principals": 4, "roles": 5, "edges": 6}

    def test_node_count(self, sample_graph):
        assert sample_graph.node_count() == 9

    def test_principals_present(self, sample_graph):
        for pid in [ADMIN, INTERN, APP_BACKEND, ANALYST]:
            assert sample_graph.has_principal(pid)

    def test_role_is_not_a_principal(self, sample_graph):
        assert not sample_graph.has_principal("roles/owner")

    def test_intern_roles(self, sample_graph):
        roles = sample_graph.roles_of(INTERN)
        assert "roles/editor" in roles
        assert "roles/iam.serviceAccountUser" in roles

    def test_analyst_single_role(self, sample_graph):
        assert sample_graph.roles_of(ANALYST) == ["roles/viewer"]

    def test_principals_with_editor_role(self, sample_graph):
        holders = sample_graph.principals_with_role("roles/editor")
        assert INTERN in holders
        assert APP_BACKEND in holders
        assert ADMIN not in holders

    def test_get_principal_user_type(self, sample_graph):
        p = sample_graph.get_principal(INTERN)
        assert p is not None and p.member_type == MemberType.USER

    def test_get_principal_service_account_type(self, sample_graph):
        p = sample_graph.get_principal(APP_BACKEND)
        assert p is not None and p.member_type == MemberType.SERVICE_ACCOUNT

    def test_get_principal_unknown_returns_none(self, sample_graph):
        assert sample_graph.get_principal("ghost@x.com") is None

    def test_roles_of_unknown_empty(self, sample_graph):
        assert sample_graph.roles_of("nobody@x.com") == []

    def test_principals_with_unknown_role_empty(self, sample_graph):
        assert sample_graph.principals_with_role("roles/doesNotExist") == []

    def test_duplicate_member_single_edge(self):
        g = _g(make_binding("roles/viewer", "user:dup@x.com", "user:dup@x.com"))
        assert g.edge_count() == 1

    def test_all_users_as_principal(self):
        g = _g(make_binding("roles/storage.objectViewer", "allUsers"))
        assert g.has_principal("allUsers")
        assert "roles/storage.objectViewer" in g.roles_of("allUsers")


class TestIAMGraphEdgeCases:
    def test_empty_policy_empty_graph(self):
        g = IAMGraph.from_policy(make_policy(Path("fake.json")))
        assert g.summary() == {"principals": 0, "roles": 0, "edges": 0}

    def test_none_policy_raises(self):
        with pytest.raises(GraphBuildError):
            IAMGraph.from_policy(None)  # type: ignore[arg-type]

    def test_underlying_is_digraph(self, sample_graph):
        import networkx as nx
        assert isinstance(sample_graph.underlying(), nx.DiGraph)
