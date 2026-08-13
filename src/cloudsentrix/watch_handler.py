"""
File Watcher
==============
Polls a GCP IAM policy JSON file (or a directory of them) for changes and
triggers a callback whenever a change is detected.

Implemented with plain stdlib polling (mtime comparison) rather than a
filesystem-events library (e.g. watchdog), so this tool has zero extra
runtime dependencies to install — consistent with the project's
"free to develop" constraint.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)


def _snapshot(path: Path) -> dict[Path, float]:
    """Returns {file_path: mtime} for every file currently being watched."""
    if path.is_dir():
        candidates = sorted(p for p in path.glob("*.json") if p.is_file())
    else:
        candidates = [path]

    result: dict[Path, float] = {}
    for f in candidates:
        try:
            result[f] = f.stat().st_mtime
        except OSError:
            continue
    return result


def watch(path: Path, on_change: Callable[[Path], None], poll_interval: float = 2.0) -> None:
    """Polls `path` every `poll_interval` seconds. Whenever a watched file
    is new or its modification time has changed, calls on_change(file_path).

    Runs until interrupted with Ctrl+C (KeyboardInterrupt).

    Raises:
        FileNotFoundError: If `path` does not exist when watching starts.
    """
    if not path.exists():
        raise FileNotFoundError(f"Watch target does not exist: {path}")

    known = _snapshot(path)
    logger.info("Watching %s (%d file(s) tracked) every %.1fs", path, len(known), poll_interval)

    try:
        while True:
            time.sleep(poll_interval)
            current = _snapshot(path)

            changed = sorted(
                f for f, mtime in current.items()
                if f not in known or known[f] != mtime
            )
            for f in changed:
                on_change(f)

            known = current
    except KeyboardInterrupt:
        logger.info("Watch stopped by user.")