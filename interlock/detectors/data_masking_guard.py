"""Result guard: mask sensitive data in what a tool returns, by entity, column or path.

A query tool returns rows; an HTTP tool returns JSON; a file tool returns text.
This rule runs the :mod:`interlock.masking` engine over the result before the
agent reads it: checksum-validated entities (cards pass Luhn, IBANs mod-97,
CPFs their mod-11 digits ...), column and dotted-path rules that mask a field
outright, and a strategy per rule - ``redact``, ``mask``, ``partial`` or a
keyed ``hash`` that keeps equal values equal::

    data_masking_guard(rules=[
        {"columns": ["password", "customer.ssn"], "strategy": "mask"},
        {"entities": ["CREDIT_CARD"], "strategy": "partial", "keep_last": 4},
        {"entities": ["EMAIL_ADDRESS"], "strategy": "hash"},
        {},                                   # every other entity: redact
    ], hash_key=key)

Rows may be dicts, or a ``{"columns": [...], "rows": [[...], ...]}`` table
(column names then apply per cell). The rewrite replaces the result; the
decision's ``masked`` field (and so the receipt) counts what was masked by
entity, never the values. Result phase only; the rule never raises.
"""
from __future__ import annotations

from typing import Any, Iterable, List, Mapping, Optional, Sequence, Union

from ..enforce import Decision
from ..event import SensorEvent
from ..masking import DEFAULT_THRESHOLD, Masker, MaskRule, summary
from ..policy.engine import Rule

POLICY_ID = "data_masking"


def _rules(rules: Optional[Sequence[Union[MaskRule, Mapping[str, Any]]]],
           entities: Optional[Iterable[str]]) -> List[MaskRule]:
    if rules is None:
        return [MaskRule(entities=tuple(entities or ()))]
    out = []
    for rule in rules:
        if isinstance(rule, MaskRule):
            out.append(rule)
        elif isinstance(rule, Mapping):
            spec = dict(rule)
            for key in ("entities", "columns"):
                if key in spec:
                    spec[key] = tuple(spec[key])
            out.append(MaskRule(**spec))
        else:
            raise TypeError("a masking rule is a MaskRule or a dict")
    return out


def data_masking_guard(
    rules: Optional[Sequence[Union[MaskRule, Mapping[str, Any]]]] = None,
    *,
    entities: Optional[Iterable[str]] = None,
    threshold: float = DEFAULT_THRESHOLD,
    allow_list: Iterable[str] = (),
    hash_key: Optional[Union[bytes, str]] = None,
    actions: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a result-phase Rule that masks sensitive data in tool results.

    rules:      MaskRules or dicts (``entities``, ``columns``, ``strategy``,
                ``keep_last``, ``mask_char``, ``name``); default one rule
                redacting ``entities`` (all entities when omitted).
    threshold:  minimum detection score; noisy entities need a context word.
    allow_list: exact values never masked (test fixtures, a public address).
    hash_key:   key for the ``hash`` strategy (bytes, or a hex/text string);
                default a per-process random key.
    actions:    tools the rule applies to; default every tool.
    """
    key = hash_key.encode("utf-8") if isinstance(hash_key, str) else hash_key
    masker = Masker(_rules(rules, entities), threshold=threshold,
                    allow_list=allow_list, hash_key=key)
    action_set = None if actions is None else frozenset(actions)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "phase", "call") != "result":
            return None
        if action_set is not None and event.action not in action_set:
            return None
        payload = getattr(event, "args", None)
        if not isinstance(payload, dict):
            return None
        try:
            masked, counts = masker.mask(payload)
        except Exception:
            return None
        if not counts:
            return None
        result = masked["result"] if set(masked) == {"result"} else masked
        decision = Decision.modify_result(
            result, reason="masked {}".format(summary(counts)), policy_id=POLICY_ID,
            attributed_to="result")
        decision.masked = counts
        return decision

    rule.phase = "result"  # type: ignore[attr-defined]
    return rule
