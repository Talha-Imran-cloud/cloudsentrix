"""Tests for src/parser.py — GCPIAMParser, Member, ParsedIAMPolicy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from parser import (
    GCPIAMParser,
    IAMFileNotFoundError,
    InvalidIAMFormatError,
    Member,
    MemberType,
)
from conftest import ADMIN, ANALYST, APP_BACKEND, INTERN


class TestMember:
    def test_user_prefix(self):
        m = Member.from_raw("user:alice@example.com")
        assert m.type == MemberType.USER
        assert m.identifier == "alice@example.com"
        assert m.raw == "user:alice@example.com"

    def test_service_account_prefix(self):
        m = Member.from_raw("serviceAccount:sa@project.iam.gserviceaccount.com")
        assert m.type == MemberType.SERVICE_ACCOUNT

    def test_group_prefix(self):
        assert Member.from_raw("group:devs@company.com").type == MemberType.GROUP

    def test_all_users_no_identifier(self):
        m = Member.from_raw("allUsers")
        assert m.type == MemberType.ALL_USERS
        assert m.identifier == ""

    def test_all_authenticated_users(self):
        assert Member.from_raw("allAuthenticatedUsers").type == MemberType.ALL_AUTHENTICATED_USERS

    def test_unknown_prefix_falls_back(self):
        m = Member.from_raw("spooky:ghost@x.com")
        assert m.type == MemberType.UNKNOWN
        assert m.identifier == "ghost@x.com"

    def test_member_is_immutable(self):
        m = Member.from_raw("user:alice@example.com")
        with pytest.raises((AttributeError, TypeError)):
            m.identifier = "changed"  # type: ignore[misc]

    def test_two_same_raw_are_equal(self):
        assert Member.from_raw("user:a@b.com") == Member.from_raw("user:a@b.com")

    def test_colon_in_identifier_preserved(self):
        m = Member.from_raw("user:a:b@example.com")
        assert m.identifier == "a:b@example.com"


class TestGCPIAMParserHappyPath:
    def test_binding_count(self, sample_policy):
        assert len(sample_policy.bindings) == 5

    def test_unique_member_count(self, sample_policy):
        assert sample_policy.summary()["unique_members"] == 4

    def test_total_member_entries(self, sample_policy):
        assert sample_policy.summary()["total_member_entries"] == 6

    def test_intern_holds_two_roles(self, sample_policy):
        roles = sample_policy.roles_for_member(INTERN)
        assert "roles/editor" in roles
        assert "roles/iam.serviceAccountUser" in roles

    def test_analyst_holds_one_role(self, sample_policy):
        assert sample_policy.roles_for_member(ANALYST) == ["roles/viewer"]

    def test_unknown_member_returns_empty(self, sample_policy):
        assert sample_policy.roles_for_member("nobody@nowhere.com") == []

    def test_all_members_includes_duplicates(self, sample_policy):
        ids = [m.identifier for m in sample_policy.all_members()]
        assert ids.count(INTERN) == 2

    def test_empty_bindings_is_valid(self, tmp_path):
        f = tmp_path / "empty.json"
        f.write_text(json.dumps({"bindings": []}), encoding="utf-8")
        policy = GCPIAMParser().parse_file(f)
        assert policy.bindings == []

    def test_str_path_accepted(self, sample_json_file):
        policy = GCPIAMParser().parse_file(str(sample_json_file))
        assert len(policy.bindings) == 5

    def test_non_string_members_skipped(self, tmp_path):
        f = tmp_path / "mixed.json"
        f.write_text(json.dumps({
            "bindings": [{"role": "roles/viewer",
                          "members": ["user:a@b.com", 42, None]}]
        }), encoding="utf-8")
        policy = GCPIAMParser().parse_file(f)
        assert len(policy.bindings[0].members) == 1


class TestGCPIAMParserErrors:
    def test_file_not_found(self, tmp_path):
        with pytest.raises(IAMFileNotFoundError):
            GCPIAMParser().parse_file(tmp_path / "does_not_exist.json")

    def test_empty_file(self, tmp_path):
        f = tmp_path / "e.json"
        f.write_text("", encoding="utf-8")
        with pytest.raises(InvalidIAMFormatError, match="empty"):
            GCPIAMParser().parse_file(f)

    def test_invalid_json(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{ not valid json", encoding="utf-8")
        with pytest.raises(InvalidIAMFormatError, match="not valid JSON"):
            GCPIAMParser().parse_file(f)

    def test_missing_bindings_key(self, tmp_path):
        f = tmp_path / "nb.json"
        f.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
        with pytest.raises(InvalidIAMFormatError, match="bindings"):
            GCPIAMParser().parse_file(f)

    def test_bindings_not_a_list(self, tmp_path):
        f = tmp_path / "bl.json"
        f.write_text(json.dumps({"bindings": "string"}), encoding="utf-8")
        with pytest.raises(InvalidIAMFormatError):
            GCPIAMParser().parse_file(f)

    def test_top_level_not_object(self, tmp_path):
        f = tmp_path / "arr.json"
        f.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        with pytest.raises(InvalidIAMFormatError, match="JSON object"):
            GCPIAMParser().parse_file(f)

    def test_binding_missing_members(self, tmp_path):
        f = tmp_path / "bm.json"
        f.write_text(json.dumps({"bindings": [{"role": "roles/viewer"}]}), encoding="utf-8")
        with pytest.raises(InvalidIAMFormatError, match="members"):
            GCPIAMParser().parse_file(f)

    def test_binding_missing_role(self, tmp_path):
        f = tmp_path / "br.json"
        f.write_text(json.dumps({"bindings": [{"members": ["user:a@b.com"]}]}), encoding="utf-8")
        with pytest.raises(InvalidIAMFormatError, match="role"):
            GCPIAMParser().parse_file(f)
