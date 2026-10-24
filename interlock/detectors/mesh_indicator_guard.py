"""Mesh indicator guard: block a call whose exact arguments other deployments
already blocked.

The mesh's consensus engine publishes *indicators*: the SHA-256 digests of
argument sets that at least a few independent organisations' guards refused
(see ``docs/guides/mesh.md``). This rule holds such a set and compares every
call's arguments, digested the same way receipts digest them
(:func:`interlock.receipt.digest_args`), against it. An exact match yields a
BLOCK (or an ESCALATE when the pack says so); anything else is no opinion.

Exact match is the point and the limit. It catches the identical payload, the
same injected page or the same command, arriving at a second deployment, and
it cannot catch a paraphrase: the mesh's fingerprint layer exists for that.
Because a digest reveals nothing about the payload, the indicator set itself
is safe to publish, and because a match needs the whole argument set to be
identical, this rule's false-positive rate is as close to zero as a rule
gets. The community publishes it with status ``test``, so on a subscriber's
canary and early rings its block is capped to an escalate until promoted.

Reads a dict ``args`` only; a non-dict never matches. Entries that are not
64 hex characters are dropped at build time. Call phase only. Never raises.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

from ..actions import action_matches, canonical_actions
from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule
from ..receipt import digest_args

POLICY_ID = "mesh_indicator"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def mesh_indicator_guard(indicators: Iterable[str], actions: Optional[Iterable[str]] = None,
                         verdict: str = "block") -> Rule:
    """Build a Rule that refuses a call whose argument digest is an indicator.

    *indicators* are SHA-256 hex digests as receipts record them; anything
    else is ignored. *actions*, when given, limits the rule to those tool
    names (canonicalised, so ``http.post`` matches ``http_post``). *verdict*
    is ``"block"`` (default) or ``"escalate"``.
    """
    digests = frozenset(d.lower() for d in _iter_strings(indicators) if _HEX64.match(d.lower()))
    scoped = canonical_actions(actions) if actions is not None else None
    escalate = verdict == "escalate"

    def rule(event: SensorEvent) -> Optional[Decision]:
        if not digests:
            return None
        if scoped is not None and not action_matches(getattr(event, "action", None), scoped):
            return None
        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None
        try:
            digest = digest_args(args)
        except Exception:
            return None
        if digest not in digests:
            return None
        reason = "mesh_indicator: arguments match an indicator other deployments blocked"
        if escalate:
            return Decision.escalate(reason, POLICY_ID)
        return Decision.block(reason, POLICY_ID)

    return rule


def _iter_strings(values: Optional[Iterable[str]]):
    if values is None:
        return
    try:
        iterator = iter(values)
    except TypeError:
        return
    for value in iterator:
        if isinstance(value, str):
            yield value
