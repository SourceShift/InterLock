"""Ordering-aware guard: refuse an action that follows a forbidden earlier one.

Every other detector here judges one event in isolation. Some of the most
damaging agent behaviours are only visible in *sequence*: reading a secret and
then opening a network connection, installing a dependency and then running its
postinstall, writing a plan and then editing far more files than the plan named.
Each step looks ordinary; the pair is the incident.

This Rule keeps a bounded journal of the last ``window`` canonical actions per
scope in this process and blocks a call that completes a configured
``(before, after)`` pair. Both sides are matched with
:func:`~.actions.canonical_action`, so ``http.post`` and ``http_post`` are the
same step, and a Node client is covered by a Python-shaped policy.

Scope is the event's ``span_id`` (one agent run), falling back to ``principal``
when no run is known, and to ``"<anon>"`` when neither is a non-empty string -
the same fail-closed identity rule the rate limiters use. Result-phase events
are ignored: a sequence is about what the agent *did*, not what tools returned.

State lives in the closure, so each factory call owns a fresh journal and two
rules cannot trip each other. It is process-local: a restart begins every scope
with an empty journal. Eviction bounds memory twice - each scope keeps at most
``window`` actions, and at most ``max_scopes`` scopes are tracked, oldest first.

Every call event is journalled, including one this rule blocks, so a blocked
``after`` step stays blocked while its ``before`` remains in the window instead
of being retried through. A block's reason names the two canonical actions and
the window only, never an argument value, so it is safe to put in a receipt.
"""
from __future__ import annotations

import threading
from collections import deque
from typing import Deque, Dict, List, Optional, Sequence, Tuple

from ..actions import canonical_action
from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "sequence"

# Identity used when an event carries neither a span id nor a principal. A
# subject we cannot name is still journalled, so it cannot escape by staying
# anonymous.
ANON = "<anon>"

DEFAULT_WINDOW = 50
DEFAULT_MAX_SCOPES = 1024


def _pairs(never: object) -> List[Tuple[str, str]]:
    """Validate ``never`` into canonical ``(before, after)`` pairs.

    Each entry must be a two-item sequence of non-empty strings. A bare string
    is rejected rather than silently split into characters. A malformed entry
    raises ``ValueError`` at construction, where the operator can still see it,
    instead of degrading to a rule that never fires.
    """
    if isinstance(never, str):
        raise ValueError(
            "never must be a sequence of [before, after] pairs, not a string")
    try:
        entries = list(never)  # type: ignore[arg-type]
    except TypeError:
        raise ValueError("never must be a sequence of [before, after] pairs")
    if not entries:
        raise ValueError("never must name at least one [before, after] pair")

    pairs: List[Tuple[str, str]] = []
    for entry in entries:
        if isinstance(entry, str):
            raise ValueError(
                "never entry must be a [before, after] pair, not a string")
        try:
            parts = list(entry)  # type: ignore[arg-type]
        except TypeError:
            raise ValueError("never entry must be a [before, after] pair")
        if len(parts) != 2:
            raise ValueError("never entry must hold exactly two actions")
        before, after = (canonical_action(part) for part in parts)
        if not before or not after:
            raise ValueError("never entry actions must be non-empty strings")
        pairs.append((before, after))
    return pairs


def _scope(event: SensorEvent) -> str:
    span_id = getattr(event, "span_id", None)
    if isinstance(span_id, str) and span_id:
        return span_id
    principal = getattr(event, "principal", None)
    if isinstance(principal, str) and principal:
        return principal
    return ANON


def sequence_guard(
    never: Sequence[Sequence[str]],
    window: int = DEFAULT_WINDOW,
    max_scopes: int = DEFAULT_MAX_SCOPES,
) -> Rule:
    """Rule: block a call that completes a forbidden ordered pair.

    *never* is a sequence of ``[before, after]`` pairs of action names. The rule
    recalls the last *window* canonical actions per scope and returns a BLOCK
    Decision when the current call's action is some pair's *after* and that
    pair's *before* is still in the journal. Otherwise it returns None.

    *window* must be a positive non-bool integer; *max_scopes* likewise. Any
    invalid argument raises ``ValueError`` at construction. The journal is
    updated under a per-rule lock and the rule never raises on odd input.
    """
    pairs = _pairs(never)
    if isinstance(window, bool) or not isinstance(window, int) or window <= 0:
        raise ValueError("window must be a positive integer")
    if (isinstance(max_scopes, bool) or not isinstance(max_scopes, int)
            or max_scopes <= 0):
        raise ValueError("max_scopes must be a positive integer")

    journals: Dict[str, Deque[str]] = {}
    lock = threading.Lock()

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "phase", "call") == "result":
            return None
        action = canonical_action(getattr(event, "action", None))
        if not action:
            return None

        scope = _scope(event)
        with lock:
            journal = journals.get(scope)
            if journal is None:
                if len(journals) >= max_scopes:
                    # Drop the oldest scope; a dict keeps insertion order.
                    journals.pop(next(iter(journals)))
                journal = journals[scope] = deque(maxlen=window)
            matched = None
            for before, after in pairs:
                if action == after and before in journal:
                    matched = (before, after)
                    break
            journal.append(action)
        if matched is not None:
            return Decision.block(
                reason="sequence: {} after {} within {} calls".format(
                    matched[1], matched[0], window),
                policy_id=POLICY_ID,
            )
        return None

    return rule
