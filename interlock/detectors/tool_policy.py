"""Tool-call capability policy: allowlist (least privilege) and its inverse.

Two policy Rules that decide on the *action name* alone, before a tool runs.
They have opposite defaults, and that asymmetry is the whole point:

- An ALLOWLIST is fail-closed: only an explicitly permitted action passes, and
  every other action - an unknown tool, a renamed tool, a malformed event - is
  denied. This is the least-privilege posture. A new tool is off until it is
  added to the list, so the failure mode of a forgotten entry is a block, not
  an over-permission.
- A DENYLIST is fail-open: only a named action is denied and everything else
  falls through to the engine's default-allow. Use it to retire one specific
  dangerous tool without having to enumerate the whole safe set.

Both stay exact about the names an operator wrote: an action is recognised when
its string is one of them, or - for the Node client's shared namespaced names
only - when its canonical form (see :mod:`interlock.actions`) is one of them.
So a list naming ``child_process_exec_file`` also governs
``child_process.execFile``, while folding is not applied to arbitrary names: a
least-privilege allowlist naming ``read_file`` still denies ``READ_FILE`` and
``read.file``, spellings the operator never listed. Both stay silent (return
None) when they have no objection, leaving the engine's default-allow path
untouched for traffic the policy permits.
"""
from __future__ import annotations

from typing import Any, Iterable, Optional, Set

from ..actions import NODE_ACTION_NAMES, canonical_action, canonical_actions
from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

ALLOWLIST_POLICY_ID = "tool_allowlist"
DENYLIST_POLICY_ID = "tool_denylist"


def _materialise(names: Optional[Iterable[str]]) -> tuple:
    """Read the configured names once, so both views see the same entries.

    A generator allowlist would otherwise be drained by the first consumer and
    leave the second (the canonical Node folding) empty, making the same policy
    behave differently by container type.
    """
    if names is None:
        return ()
    if isinstance(names, str):
        return (names,)
    try:
        return tuple(names)
    except TypeError:
        return ()


def _as_name_set(names: Optional[Iterable[str]]) -> Set[str]:
    """Collect str action names into a set, exactly as written.

    A bare string is wrapped rather than iterated character-by-character, and
    non-str entries (None, int, nested containers) are skipped, so a malformed
    config narrows the policy instead of crashing or silently widening it.
    """
    if names is None:
        return set()
    if isinstance(names, str):
        items: Iterable[Any] = (names,)
    else:
        items = names
    return {name for name in items if isinstance(name, str)}


def _matches_listed(
    action: object, written: Set[str], canonical: frozenset
) -> bool:
    """Whether *action* is one the operator listed.

    An exact match against the written names always counts. Otherwise the
    action is admitted only when it is a shared Node action name and its
    canonical form is listed: the Node adapter's ``child_process.execFile``
    reaches a rule written with ``child_process_exec_file``. Arbitrary case or
    separator variants are *not* folded in - a least-privilege allowlist must
    not admit a spelling nobody approved.
    """
    if not isinstance(action, str) or not action:
        return False
    if action in written:
        return True
    name = canonical_action(action)
    return bool(name) and name in NODE_ACTION_NAMES and name in canonical


def tool_allowlist(
    allowed: Iterable[str], reason: str = "tool not on allowlist"
) -> Rule:
    """Rule: permit only actions in `allowed`; deny everything else.

    Fail-closed by construction: the permit branch is a membership test, so a
    non-str or missing action can never match and is denied like any other
    unknown tool. A list naming ``child_process_exec_file`` also permits the
    Node client's ``child_process.execFile`` (see :func:`_matches_listed`);
    other spellings are not folded, so it stays least-privilege. Returns None
    (no opinion) only for an explicitly permitted action.
    """
    names = _materialise(allowed)
    written = _as_name_set(names)
    canonical = canonical_actions(names)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if _matches_listed(event.action, written, canonical):
            return None
        return Decision.block(reason, policy_id=ALLOWLIST_POLICY_ID)

    return rule


def tool_denylist(denied: Iterable[str], reason: str = "tool denied by policy") -> Rule:
    """Rule: deny actions in `denied`; permit everything else.

    The inverse of the allowlist: an action is blocked only when it is named,
    and a denylist naming the Python ``child_process_exec`` also denies the
    Node client's ``child_process.exec`` (see :func:`_matches_listed`).
    Anything else returns None and falls through to the engine's default-allow.
    """
    names = _materialise(denied)
    written = _as_name_set(names)
    canonical = canonical_actions(names)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if _matches_listed(event.action, written, canonical):
            return Decision.block(reason, policy_id=DENYLIST_POLICY_ID)
        return None

    return rule
