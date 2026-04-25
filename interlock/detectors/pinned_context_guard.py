"""Pinned-context overwrite guard: memory writes must not clobber load-bearing keys.

Agent memory makes a context key a *promise*: the system role, the safety
policy, the operator's standing instructions. Those keys are read back as
trusted context on every later turn, so a write that overwrites one is not a
data edit - it is a persistent policy change. The write tool trusts its
arguments, which is exactly what makes ``{"key": "system_prompt", ...}`` from an
agent-driven memory call dangerous: the overwrite lands before anyone reads the
new value, and every subsequent turn inherits it.

This rule sits on the memory-write path, ahead of the effect. It has an opinion
only when both conditions hold:

- the action is a memory write (``memory_write``, ``context_set``,
  ``set_state``), and
- the target key names a protected entry.

The key is read from ``args["key"]``, falling back to ``args["name"]``, and
compared by exact membership - no case folding, because the key a guard must
protect is the literal one the reader will look up. A protected write blocks
with the key named in the reason; an ordinary write, a non-memory action, and
any event whose key cannot be read all return None (no opinion), leaving the
engine's default-allow path untouched.

A malformed ``protected`` config narrows the guard instead of crashing: None,
a non-iterable, or non-str entries yield fewer protected keys. Odd input never
raises - a non-dict args, a missing key, a non-str key, or a nested container
value is skipped rather than stringified.
"""
from __future__ import annotations

from typing import Any, FrozenSet, Iterable, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "pinned_context"

# Actions that write into agent memory / agent state. Anything else is out of
# scope, so the guard composes with the tool-level policies instead of
# shadowing them.
_MEMORY_ACTIONS = frozenset({"memory_write", "context_set", "set_state"})

# args keys carrying the target of the write, in priority order.
_KEY_FIELDS = ("key", "name")


def _as_key_frozenset(protected: Optional[Iterable[str]]) -> FrozenSet[str]:
    """Collect protected keys into a frozenset, skipping junk.

    A bare string is wrapped rather than iterated character-by-character, and
    non-str entries (None, int, nested containers) are skipped, so a malformed
    config narrows the protected set instead of admitting single characters.
    Keys are compared as-written: no lowercasing, because the value read back by
    the agent is the exact literal, not a normalised form.
    """
    if protected is None:
        return frozenset()
    if isinstance(protected, str):
        items: Iterable[Any] = (protected,)
    else:
        items = protected
    return frozenset(key for key in items if isinstance(key, str))


def pinned_context_guard(protected: Iterable[str]) -> Rule:
    """Build a Rule that blocks memory writes to any key in `protected`.

    Returns None (no opinion) for a write whose target key is not protected, for
    a non-memory action, and for any event whose key cannot be read as a string.
    Blocks a protected-key write with the key named in the reason.
    """
    pinned = _as_key_frozenset(protected)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "action", None) not in _MEMORY_ACTIONS:
            return None

        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None

        for field_name in _KEY_FIELDS:
            key = args.get(field_name)
            if isinstance(key, str):
                break
        else:
            return None

        if key in pinned:
            return Decision.block(
                reason="pinned_context_guard: protected key {}".format(key),
                policy_id=POLICY_ID,
            )
        return None

    return rule
