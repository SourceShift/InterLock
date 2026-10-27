"""The manifest version floor (C7).

A policy plane that is restored from a backup, or rolled back by an operator,
must never hand a host a manifest version older than one it has already been
issued. The floor is the highest version ever published for an org; every
publish advances it, and nothing on the publish path can lower it.

Lowering it is a deliberate, audited operator action (:func:`reset`), used
after a restore only when the operator is certain no host has seen the higher
version. :func:`advance` refuses a version below the floor rather than
silently keeping the old one, so a caller cannot mistake a refused write for
a successful one.

The floor lives in the store (``version_floor`` in Postgres, a dict in
``MemoryStore``) and is per-org and RLS-scoped. Both stores implement the same
four methods; this module holds the policy, not the storage.
"""
from __future__ import annotations

from typing import Any, Dict

__all__ = [
    "VersionFloorError",
    "advance",
    "bump_to",
    "current",
    "next_publish_version",
    "reset",
    "restore_check",
]


class VersionFloorError(ValueError):
    """A version would move the floor the wrong way."""

    code = "version_floor"


def current(store: Any, org_id: str) -> int:
    """The highest version ever published for ``org_id`` (0 when none)."""
    return int(store.version_floor_get(org_id) or 0)


def advance(store: Any, org_id: str, version: int, *,
            now: Any = None) -> int:
    """Advance the floor to ``version``; refuse to move it backwards."""
    value = int(version)
    floor = current(store, org_id)
    if value < floor:
        raise VersionFloorError(
            "manifest version {} is below the published floor {}; "
            "--reset-floor is the only way to lower it".format(value, floor))
    return int(store.version_floor_bump(org_id, value, now=now))


def bump_to(store: Any, org_id: str, version: int, *,
            now: Any = None) -> int:
    """Operator ``--bump-to``: raise the floor, never lower it silently."""
    return advance(store, org_id, version, now=now)


def next_publish_version(store: Any, org_id: str) -> int:
    """The version a new manifest must carry: above the manifest history and
    never below the floor."""
    return max(int(store.next_manifest_version(org_id)), current(store, org_id))


def reset(store: Any, org_id: str, version: int = 0, *,
          now: Any = None) -> int:
    """Operator ``--reset-floor``: deliberately lower the floor.

    This is the one path that can move the floor down. The CLI prints a
    warning and the caller is expected to audit it; the publish path never
    calls this.
    """
    return int(store.version_floor_reset(org_id, int(version), now=now))


def restore_check(store: Any, org_id: str) -> Dict[str, Any]:
    """Report whether the next publish would respect the floor.

    Used by ``interlock cloud admin version-floor --show`` after a restore:
    ``next_version`` below ``floor`` means the restored manifest history is
    behind what hosts were already issued and the operator must decide
    explicitly (bump, or reset with evidence).
    """
    floor = current(store, org_id)
    nxt = int(store.next_manifest_version(org_id))
    return {
        "org_id": org_id,
        "floor": floor,
        "next_version": nxt,
        "ok": nxt >= floor,
    }
