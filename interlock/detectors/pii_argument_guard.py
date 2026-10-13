"""Argument guard: stop (or mask) personal data an agent puts into a call.

A query that carries a taxpayer id lands in the database's own logs; a search
URL with an email address lands in every proxy's. This rule looks for entities
from :mod:`interlock.masking` - validated, so a card must pass Luhn and a CPF its
check digits - in a call's string arguments, and then:

- ``verdict="block"`` (default): refuses the call, naming the entity and the
  argument, never the value;
- ``verdict="escalate"``: asks a human;
- ``verdict="mask"``: rewrites the arguments with the value masked by
  ``strategy`` and lets the call proceed - something a wire proxy, which must
  not change the statement a database runs, cannot offer.

::

    pii_argument_guard(entities=["BR_CPF", "US_SSN"], keys=["query"])
    pii_argument_guard(entities=["EMAIL_ADDRESS"], verdict="mask", strategy="hash")
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..masking import DEFAULT_THRESHOLD, ENTITIES, Masker, MaskRule, summary
from ..policy.engine import Rule

POLICY_ID = "pii_argument"
VERDICTS = ("block", "escalate", "mask")


def pii_argument_guard(
    entities: Iterable[str] = (),
    *,
    verdict: str = "block",
    strategy: str = "redact",
    keys: Optional[Iterable[str]] = None,
    actions: Optional[Iterable[str]] = None,
    threshold: float = DEFAULT_THRESHOLD,
    allow_list: Iterable[str] = (),
    hash_key: Optional[bytes] = None,
) -> Rule:
    """Build a call-phase Rule acting on entities found in arguments.

    entities: entity names (default all of :data:`interlock.masking.ENTITIES`).
    verdict:  ``block``, ``escalate`` or ``mask``.
    strategy: the masking strategy for ``verdict="mask"``.
    keys:     argument names to read; default every top-level str argument.
    actions:  tools the rule applies to; default every tool.
    """
    if verdict not in VERDICTS:
        raise ValueError("verdict must be one of {}".format(", ".join(VERDICTS)))
    wanted = tuple(e.upper() for e in entities) or tuple(sorted(ENTITIES))
    masker = Masker([MaskRule(entities=wanted, strategy=strategy)], threshold=threshold,
                    allow_list=allow_list, hash_key=hash_key)
    key_set = None if keys is None else frozenset(keys)
    action_set = None if actions is None else frozenset(actions)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if action_set is not None and event.action not in action_set:
            return None
        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None
        rewritten: Dict[str, Any] = {}
        counts: Dict[str, int] = {}
        for name, value in args.items():
            if not isinstance(value, str) or (key_set is not None and name not in key_set):
                continue
            found = masker.find(value, wanted)
            if not found:
                continue
            if verdict == "block":
                return Decision.block("pii_argument: {} in {}".format(found[0][0], name),
                                      POLICY_ID, attributed_to=name)
            if verdict == "escalate":
                return Decision.escalate(
                    "pii_argument: {} in {}".format(found[0][0], name), POLICY_ID,
                    attributed_to=name)
            masked, more = masker.mask_text(value)
            rewritten[name] = masked
            for entity, count in more.items():
                counts[entity] = counts.get(entity, 0) + count
        if not rewritten:
            return None
        decision = Decision.modify(rewritten, "masked {} in {}".format(
            summary(counts), ", ".join(sorted(rewritten))), POLICY_ID,
            attributed_to=sorted(rewritten)[0])
        decision.masked = counts
        return decision

    return rule
