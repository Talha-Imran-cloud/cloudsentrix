"""Tests for src/watch_handler.py — _snapshot, watch."""

from __future__ import annotations
import os
import time

import pytest

from watch_handler import _snapshot, watch


class TestSnapshot:
    def test_single_file(self, tmp_path):
        f = tmp_path / "policy.json"
        f.write_text("{}", encoding="utf-8")
        snap = _snapshot(f)
        assert f in snap and isinstance(snap[f], float)

    def test_directory_json_only(self, tmp_path):
        (tmp_path / "a.json").write_text("{}", encoding="utf-8")
        (tmp_path / "b.json").write_text("{}", encoding="utf-8")
        (tmp_path / "c.txt").write_text("ignore", encoding="utf-8")
        snap = _snapshot(tmp_path)
        assert len(snap) == 2
        assert tmp_path / "c.txt" not in snap

    def test_empty_directory(self, tmp_path):
        assert _snapshot(tmp_path) == {}

    def test_mtime_is_float(self, tmp_path):
        f = tmp_path / "p.json"
        f.write_text("{}", encoding="utf-8")
        assert isinstance(_snapshot(f)[f], float)


class TestWatch:
    def test_file_not_found_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            watch(tmp_path / "does_not_exist.json", on_change=lambda p: None)

    def test_change_detected_via_snapshot(self, tmp_path):
        """Verifies mtime-change detection without running the blocking watch() loop."""
        f = tmp_path / "policy.json"
        f.write_text("{}", encoding="utf-8")
        snap_before = _snapshot(f)
        time.sleep(0.05)
        os.utime(f, None)
        snap_after = _snapshot(f)
        changed = [fp for fp, mt in snap_after.items()
                   if fp not in snap_before or snap_before[fp] != mt]
        assert f in changed

    def test_no_change_when_unmodified(self, tmp_path):
        f = tmp_path / "stable.json"
        f.write_text("{}", encoding="utf-8")
        snap_before = _snapshot(f)
        snap_after = _snapshot(f)
        changed = [fp for fp, mt in snap_after.items()
                   if fp not in snap_before or snap_before[fp] != mt]
        assert changed == []

    def test_new_file_detected(self, tmp_path):
        snap_before = _snapshot(tmp_path)
        new_file = tmp_path / "new.json"
        new_file.write_text("{}", encoding="utf-8")
        snap_after = _snapshot(tmp_path)
        assert new_file in snap_after and new_file not in snap_before
