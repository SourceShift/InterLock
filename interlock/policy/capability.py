"""The scope template a derived capability document binds.

A scope document (``interlock.sidecar.rules.build_scoped_engine``) is pure
data: per-scope bindings of template ids to params. The templates are code and
live next to the rules module. This module ships the one template a *derived*
document needs, so ``interlock scope suggest`` can name a template id an
operator can actually serve without writing a factory first.

``action_envelope`` permits exactly the actions its ``allow`` list names, and
escalates every other one. Escalate, not block: the envelope is an *observation*
("these were allowed"), and an action it has not seen may be a new, legitimate
task - a human decides, and the decision is recorded. Bind ``on_unseen="block"``
when you have reviewed the envelope and want a refusal instead.

``allow`` is an **override** param, not a union one, and deliberately so. A
derived document states what each scope was *observed* doing; a union param
would let a leaf inherit its ancestor's actions and quietly report a wider
envelope than the scope ever used. Override means the deepest binding wins, so
a leaf bound to ``["ls"]`` stays ``ls`` even when its parent is bound to
``["ls", "pwd"]``.

Serve this module with a derived document::

    interlock scope suggest --from-receipts audit.jsonl --out scope.json --key-file k
    interlock sidecar --rules interlock.policy.capability:rules \\
        --scope-document scope.json --key-file k

The base ``rules`` list refuses everything, because an envelope with nothing
observed permits nothing: run this module *without* ``--scope-document`` and
every call escalates. That is the fail-closed reading of "no scope was derived".
"""
from __future__ import annotations

from typing import Iterable, Optional

from ..actions import action_matches, canonical_actions
from ..enforce import Decision
from ..event import SensorEvent
from .engine import Rule
from .scopes import Template

#: The template id a derived document binds. Fixed, so a document written by
#: ``interlock scope suggest`` names the same template this module exports.
TEMPLATE_ID = "action_envelope"

#: The ``policy_id`` receipts carry for a decision this template made.
POLICY_ID = "action_envelope"

#: Shown to the approver verbatim, so it says what happened, not what matched.
REASON_ESCALATE = (
    "outside the observed capability envelope: a human decides before this runs"
)
REASON_BLOCK = "outside the observed capability envelope (block)"


def action_envelope(
    allow: Iterable[str] = (), *, on_unseen: str = "escalate"
) -> Rule:
    """Rule: permit only the actions in ``allow``; anything else escalates.

    ``allow`` is canonicalised once at construction time, so a document naming
    ``http.post`` matches an event action spelled ``http_post``. An empty
    ``allow`` (or one holding nothing recognisable) permits nothing: every
    action is outside the envelope, which is the fail-closed direction.

    ``on_unseen`` is ``"escalate"`` (default) or ``"block"``. Any other value
    raises :class:`ValueError` at construction: a typo must not silently
    downgrade a refusal to an allow, and an unrecognised mode has no meaning to
    fall back to.
    """
    if on_unseen not in ("escalate", "block"):
        raise ValueError(
            "on_unseen must be 'escalate' or 'block', got {!r}".format(on_unseen)
        )
    allowed = canonical_actions(allow)
    escalate = on_unseen == "escalate"

    def rule(event: SensorEvent) -> Optional[Decision]:
        if action_matches(event.action, allowed):
            return None
        remediation = (
            "add the action to this scope's allow list after reviewing what it "
            "would do"
        )
        if escalate:
            return Decision.escalate(
                REASON_ESCALATE, policy_id=POLICY_ID, remediation=remediation
            )
        return Decision.block(
            REASON_BLOCK, policy_id=POLICY_ID, remediation=remediation
        )

    rule.policy_id = POLICY_ID  # type: ignore[attr-defined]
    return rule


#: Scope templates, keyed by the id a derived scope document binds.
templates = {TEMPLATE_ID: Template(TEMPLATE_ID, action_envelope)}

#: The base rule set for the non-scoped path. An envelope with nothing observed
#: permits nothing, so serving this without a scope document escalates every
#: call rather than pretending something was derived.
rules = [action_envelope(allow=())]

__all__ = [
    "TEMPLATE_ID",
    "POLICY_ID",
    "REASON_ESCALATE",
    "REASON_BLOCK",
    "action_envelope",
    "templates",
    "rules",
]
