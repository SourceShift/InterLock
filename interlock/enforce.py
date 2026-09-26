"""Verdicts, decisions, and the exception a block raises."""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Dict, Optional


class Verdict(IntEnum):
    """Tri-state verdict. The integer values match the native engine's out-param
    contract (0/1/2), so a Rust engine can drop in behind the same enum later.
    """

    ALLOW = 0
    BLOCK = 1
    MODIFY = 2


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


class Blocked(Exception):
    """Raised when an enforcing guard denies an action before it runs."""

    def __init__(self, decision: Decision, action: str):
        self.decision = decision
        self.action = action
        super().__init__("blocked action '{}': {}".format(action, decision.reason))
