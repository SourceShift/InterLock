"""The host-side kill marker (C5, FR-067).

A kill document is signed by the plane and verified by the connector against
the pinned policy key, the host's org and its target.  The connector then
writes ``kill.json`` beside the active artifact pointer, because the hook
process never talks to the plane: its only input is the artifact path.

The marker is deliberately not part of the artifact.  A kill applies whatever
the artifact's freshness - a stale artifact is exactly when a kill matters -
and removing one is another signed publication, not a new compile, so it must
outlive any single artifact.

The hook reads the marker, never the network, and wraps the loaded policy so
that every event is blocked.  That wrapper is a decision, not an error: the
kill denies even when the hook runs with ``--on-error allow``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Optional

from ..enforce import Decision

#: The marker file name, in the same directory as ``active.json``.
KILL_MARKER = "kill.json"


def marker_path(artifact: Any) -> Path:
    """``kill.json`` beside the artifact: its directory, or a file's parent."""
    path = Path(artifact)
    directory = path if path.is_dir() else path.parent
    return directory / KILL_MARKER


def read_kill(artifact: Any) -> Optional[dict]:
    """The active kill document, or ``None``.

    A marker that exists but cannot be read is still a kill: the connector
    only writes one after verifying a signature, so an unreadable one means
    the state that demanded a block is unknown, and unknown is not allow.
    """
    path = marker_path(artifact)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError:
        return {"id": "unreadable", "reason": "kill marker is unreadable"}
    try:
        document = json.loads(raw)
    except ValueError:
        return {"id": "unreadable", "reason": "kill marker is not JSON"}
    if not isinstance(document, dict):
        return {"id": "unreadable", "reason": "kill marker is not an object"}
    kill = document.get("kill")
    if isinstance(kill, dict):
        return dict(kill)
    # A bare signed kill document is also a marker; it carries its own id.
    if isinstance(document.get("id"), str):
        return dict(document)
    return {"id": "unreadable", "reason": "kill marker names no kill"}


def apply_kill_marker(engine: Any, artifact: Any) -> Any:
    """Wrap ``engine`` in the kill switch when a marker is present."""
    kill = read_kill(artifact)
    if kill is None:
        return engine
    return KilledPolicy(engine, kill)


class KilledPolicy:
    """Every verdict is BLOCK, with the artifact identity still readable.

    Attribute access delegates to the wrapped policy so a receipt stamped by
    this engine still names the artifact sha256 and epoch that was killed -
    the kill is then on the receipt stream, not only in connector state.
    """

    def __init__(self, inner: Any, kill: Mapping[str, Any]) -> None:
        self.inner = inner
        self.kill = dict(kill)
        self.policy_id = "kill:" + str(self.kill.get("id") or "unknown")

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def reason(self) -> str:
        kill_id = self.kill.get("id") or "unknown"
        reason = self.kill.get("reason") or "policy killed"
        return "kill switch {}: {}".format(kill_id, reason)

    def evaluate(self, event: Any) -> Decision:
        return Decision.block(self.reason(), policy_id=self.policy_id)

    def evaluate_with_epoch(self, event: Any) -> tuple:
        epoch = getattr(self.inner, "epoch", "") or ""
        return self.evaluate(event), str(epoch)


__all__ = [
    "KILL_MARKER",
    "KilledPolicy",
    "apply_kill_marker",
    "marker_path",
    "read_kill",
]
