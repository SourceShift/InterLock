"""Turn a combined decision into enforcement, in one place.

Every enforcement site - the ``@guard`` decorator, ``enforce_tool_call`` and
``enforce_tool_result``, and the coding-agent hook adapters - hands its
decision to :func:`settle`. Keeping the dispatch here is what makes it
exhaustive: each verdict has one branch, and a verdict without a branch (a
newer enum member, or a rule that built ``Decision(verdict=7)``) is blocked
rather than falling through to "run it", which is how a new verdict used to
silently allow.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from .._runtime import get_engine
from ..approval import settle_escalation
from ..enforce import Blocked, Decision, Verdict
from ..event import SensorEvent
from ..policy.engine import epoch_of
from ..receipt import emit_receipt

_log = logging.getLogger("interlock")

#: The policy id on a block caused by a verdict no enforcement site knows.
UNHANDLED_POLICY_ID = "unhandled_verdict"


def settle(
    event: SensorEvent,
    decision: Decision,
    *,
    engine: Any,
    enforcement: str = "blocking",
    elapsed_us: Optional[int] = None,
    site: str = "",
) -> Decision:
    """Enforce ``decision`` for ``event``; return what the action proceeds with.

    The return value is an ALLOW (proceed unchanged) or a MODIFY (proceed with
    ``modified_args`` / ``modified_result``). BLOCK raises :class:`Blocked`; an
    ESCALATE asks the approver and raises :class:`NotApproved` unless approved;
    monitor mode records and returns ALLOW. Exactly one receipt is written.
    """
    epoch = epoch_of(engine, event)
    verdict = decision.verdict
    monitor = enforcement == "monitor"
    observed = monitor and verdict != Verdict.ALLOW
    _log.debug(
        "%saction=%s verdict=%s reason=%s span=%s observed=%s attributed_to=%s",
        site, event.action, getattr(verdict, "name", verdict), decision.reason,
        event.span_id, observed, decision.attributed_to,
    )

    if verdict == Verdict.ALLOW:
        emit_receipt(event, decision, policy_epoch=epoch, elapsed_us=elapsed_us)
        return decision
    if monitor:
        # Observe-only: record what would have happened, never intervene.
        if isinstance(verdict, Verdict):
            emit_receipt(event, decision, observed=True, policy_epoch=epoch,
                         elapsed_us=elapsed_us)
        return Decision.allow()
    if verdict == Verdict.BLOCK:
        emit_receipt(event, decision, policy_epoch=epoch, elapsed_us=elapsed_us)
        raise Blocked(decision, event.action)
    if verdict == Verdict.MODIFY:
        emit_receipt(event, decision, policy_epoch=epoch, elapsed_us=elapsed_us)
        return decision
    if verdict == Verdict.ESCALATE:
        # The policy in force when the approver answers: the process engine
        # may have been reinstalled meanwhile, which mutates nothing on the
        # engine object that decided - so re-resolve it, don't re-read it.
        is_global = engine is get_engine()

        def current_epoch() -> Optional[str]:
            return epoch_of(get_engine() if is_global else engine, event)

        # A declarative engine records what a capped mesh rule would have
        # done when no approver is installed; any other engine has no
        # recorder, and the escalation is refused as usual.
        shadow = getattr(engine, "record_shadow", None)
        return settle_escalation(
            event, decision, epoch=epoch, current_epoch=current_epoch,
            elapsed_us=elapsed_us, shadow=shadow if callable(shadow) else None,
        )
    refused = Decision.block(
        "unhandled verdict {!r}, denied fail-closed".format(verdict),
        policy_id=decision.policy_id or UNHANDLED_POLICY_ID,
        attributed_to=decision.attributed_to,
    )
    emit_receipt(event, refused, policy_epoch=epoch, elapsed_us=elapsed_us,
                 policy_verdict=str(verdict))
    raise Blocked(refused, event.action)


def record_failure(event: SensorEvent, exc: BaseException, *, engine: Any) -> None:
    """Write the ``phase="outcome"`` receipt for an allowed tool that failed.

    ``enforcer`` is ``os`` for a permission error raised by the operating
    system - under the BRACE sandbox, that is the sandbox refusing - else
    ``tool``. Best effort: a sink failure here must not mask the tool's own
    exception, so it is swallowed (and counted by the sink's drop counter).
    """
    enforcer = getattr(exc, "enforcer", None)
    if not isinstance(enforcer, str):
        if isinstance(exc, Blocked):
            enforcer = "policy"  # a guard nested inside the tool refused
        elif isinstance(exc, PermissionError):
            enforcer = "os"
        else:
            enforcer = "tool"
    try:
        emit_receipt(
            event,
            Decision(Verdict.ALLOW, type(exc).__name__),
            policy_epoch=epoch_of(engine, event),
            outcome="failed",
            enforcer=enforcer,
            phase="outcome",
        )
    except Blocked:
        pass
