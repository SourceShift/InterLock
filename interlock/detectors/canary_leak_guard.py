"""Canary-token leak guard: block egress that carries a planted canary.

A canary token is a secret string planted in the agent's context precisely so
that its later appearance somewhere else is proof the context leaked. Plant
``CANARY-<random>`` in a system prompt, a retrieved document, or a tool result;
if it ever shows up in an outbound payload, that payload did not originate from
the agent's own reasoning - it was copied out of the context and is being
exfiltrated.

This rule is that tripwire. It holds a set of canary strings and, for an egress
action, scans the str values under the content keys of ``args`` for any canary
as a substring. A hit yields a BLOCK; otherwise the rule has no opinion.

Unlike a shape-based secret scan (``secret_entropy_egress_guard``) or a
prefix-based one (``pii_redaction_guard``), detection here is exact identity:
the caller chooses a canary that is high-entropy and unique, so a substring hit
is essentially never a false positive and the rule needs no threshold tuning.

Reads only str values under the content keys of a dict ``args``; an int, None,
or nested container is skipped rather than stringified, and a non-dict ``args``
yields no opinion. Empty and non-str canaries are dropped at build time - an
empty canary would otherwise be a substring of everything and block all egress.
Non-egress actions return None. The rule never raises.
"""
from __future__ import annotations

from typing import Iterable, Optional, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "canary_leak"

# Egress action names this guard recognises. Kept to unambiguous transport
# verbs so a same-named in-house tool is not shadowed.
EGRESS_ACTIONS = frozenset({
    "http_post", "fetch", "request", "send", "upload", "log",
})

# Argument keys that may carry outbound content. Only a str value under one of
# these is scanned for a canary.
CONTENT_KEYS = ("data", "body", "payload", "content", "text", "message")


def canary_leak_guard(canaries: Iterable[str]) -> Rule:
    """Build a Rule that blocks egress whose payload contains a planted canary.

    *canaries* is the set of planted secret strings. Non-str entries, empty
    strings, and ``None`` are ignored, so a caller that accidentally passes an
    unfiltered collection cannot end up blocking all egress. For an action in
    :data:`EGRESS_ACTIONS`, each str value under a :data:`CONTENT_KEYS` key is
    checked for any canary as a substring; a hit yields a BLOCK carrying
    :data:`POLICY_ID`. Otherwise, including a non-egress action and a non-dict
    ``args``, the rule returns None (no opinion).
    """
    # Materialise once: filter to non-empty str and freeze the lookup for the
    # life of the returned rule.
    planted: Tuple[str, ...] = tuple(
        canary for canary in _iter_canaries(canaries) if canary
    )

    def rule(event: SensorEvent) -> Optional[Decision]:
        if not planted:
            return None
        if getattr(event, "action", None) not in EGRESS_ACTIONS:
            return None

        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None

        for key in CONTENT_KEYS:
            value = args.get(key)
            if not isinstance(value, str):
                continue
            for canary in planted:
                if canary in value:
                    return Decision.block(
                        reason="canary_leak_guard: canary token in egress",
                        policy_id=POLICY_ID,
                        attributed_to=key,
                    )
        return None

    return rule


def _iter_canaries(canaries: Optional[Iterable[str]]):
    """Yield *canaries* one by one, tolerating None and a non-str element.

    A detector must not raise on odd input, and the factory is a public entry
    point: ``None`` yields nothing, and an element that is not a str is skipped
    rather than stringified.
    """
    if canaries is None:
        return
    try:
        iterator = iter(canaries)
    except TypeError:
        return
    for canary in iterator:
        if isinstance(canary, str):
            yield canary
