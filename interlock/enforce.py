"""Verdicts, decisions, and the exception a block raises."""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Dict, Optional


class Verdict(IntEnum):
    """What the guard does with an action. The integer values are the wire
    encoding (see ``interlock.wire``) and must never be renumbered.

    ALLOW    run it.
    BLOCK    never run it.
    MODIFY   run it with rewritten arguments (or deliver a rewritten result).
    ESCALATE the action is legal but a human must decide: it runs only if an
             approver approves this exact call. With no approver installed it
             is blocked - never allowed - so a deployment that ignores
             escalation keeps today's behaviour.
    """

    ALLOW = 0
    BLOCK = 1
    MODIFY = 2
    ESCALATE = 3


@dataclass
class Decision:
    verdict: Verdict = Verdict.ALLOW
    reason: str = ""
    policy_id: Optional[str] = None
    modified_args: Optional[Dict[str, Any]] = None  # populated only for MODIFY
    # The NAME of the argument that tripped the policy ("command", "path",
    # "url") - never the argument's value, which would turn a diagnostic
    # field into a data-exfiltration surface.
    attributed_to: Optional[str] = None
    # Replacement for a tool RESULT under a MODIFY verdict on a result-phase
    # event. Unlike modified_args (merged into the outgoing request), this
    # replaces the whole return value the caller receives.
    modified_result: Optional[Any] = None
    # What a masking rewrite masked: entity name -> count. Names and counts
    # only, never values; copied into the receipt and summed by reports.
    masked: Optional[Dict[str, int]] = None

    @classmethod
    def allow(cls, reason: str = "", policy_id: Optional[str] = None) -> "Decision":
        return cls(Verdict.ALLOW, reason, policy_id)

    @classmethod
    def block(
        cls,
        reason: str,
        policy_id: Optional[str] = None,
        attributed_to: Optional[str] = None,
    ) -> "Decision":
        return cls(Verdict.BLOCK, reason, policy_id, attributed_to=attributed_to)

    @classmethod
    def modify(
        cls,
        modified_args: Dict[str, Any],
        reason: str = "",
        policy_id: Optional[str] = None,
        attributed_to: Optional[str] = None,
    ) -> "Decision":
        return cls(
            Verdict.MODIFY, reason, policy_id, modified_args,
            attributed_to=attributed_to,
        )

    @classmethod
    def escalate(
        cls,
        reason: str,
        policy_id: Optional[str] = None,
        attributed_to: Optional[str] = None,
    ) -> "Decision":
        """Build an ESCALATE: pause the call until an approver decides.

        ``reason`` is shown to the approver verbatim and bound into the
        approval, so write it for a human: what the call does and why it needs
        a decision. ``attributed_to`` names the argument that triggered it.
        """
        return cls(Verdict.ESCALATE, reason, policy_id, attributed_to=attributed_to)

    @classmethod
    def modify_result(
        cls,
        result: Any,
        reason: str = "",
        policy_id: Optional[str] = None,
        attributed_to: Optional[str] = None,
    ) -> "Decision":
        """Build a MODIFY that replaces a tool result instead of its args."""
        return cls(
            Verdict.MODIFY, reason, policy_id, None,
            attributed_to=attributed_to, modified_result=result,
        )


class Blocked(Exception):
    """Raised when an enforcing guard denies an action. On the call side the
    action never runs. On the result side the tool has already run - its side
    effects stand - and this is raised in place of delivering the payload, so
    the caller never sees what the tool said."""

    def __init__(self, decision: Decision, action: str):
        self.decision = decision
        self.action = action
        super().__init__("blocked action '{}': {}".format(action, decision.reason))


class NotApproved(Blocked):
    """An ESCALATE that was not approved: no approver was installed, the
    approver declined, or the approval did not match this exact call.

    A subclass of :class:`Blocked`, so code that handles blocks handles this
    too; catch it on its own to tell "needs a human" apart from "refused".
    """
