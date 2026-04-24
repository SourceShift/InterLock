"""Dangerous-execution interceptor.

A policy Rule that gates *execution* actions - shell, subprocess, dynamic code
evaluation - before the effect happens, blocking commands that carry
destructive or exfiltration patterns.

This is a dangerous-pattern gate, NOT a total execution ban. The rule is only
armed when the event's action looks like execution; a safe command through an
execution action is allowed (returns None), and a scary string flowing through
a non-execution action (a search query, a fetched document) is ignored. The
action name - not the text alone - decides whether this rule has jurisdiction,
so an unrelated tool that happens to carry hostile-looking text is left alone.

Stays silent (returns None) when nothing matches, leaving the engine's
default-allow path untouched for benign traffic.
"""
from __future__ import annotations

from typing import Any, Iterable, List, Optional, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

# Matched as case-insensitive substrings of the action name, so 'run_shell',
# 'exec', 'subprocess_call' and 'code_eval' are all execution-type.
DEFAULT_EXECUTION_ACTIONS: Tuple[str, ...] = (
    "shell",
    "exec",
    "subprocess",
    "run_code",
    "system",
    "eval",
    "spawn",
    "bash",
)

# Ordered so the first matching pattern is deterministic and stable.
BUILTIN_PATTERNS: Tuple[str, ...] = (
    "rm -rf",
    "mkfs",
    ":(){",
    "curl",
    "wget",
    "| sh",
    "|sh",
    "chmod 777",
    "dd if=",
    "sudo ",
    "os.system",
    "__import__",
    "base64 -d",
)

POLICY_ID = "execution_guard"


def _resolve_actions(execution_actions: Optional[Iterable[str]]) -> Tuple[str, ...]:
    """Lowercased action substrings, defaulting to the built-in set.

    A caller-supplied set fully replaces the default. A bare string is wrapped
    rather than iterated character-by-character.
    """
    if execution_actions is None:
        return DEFAULT_EXECUTION_ACTIONS
    if isinstance(execution_actions, str):
        items: Iterable[Any] = (execution_actions,)
    else:
        items = execution_actions
    return tuple(
        action.lower() for action in items if isinstance(action, str) and action
    )


def _scan_text(event: SensorEvent) -> str:
    """Lowercased scan text built from str arg values only.

    Non-str values (None, int, nested containers) are skipped rather than
    coerced, so structural data never produces a spurious match.
    """
    args = event.args
    if not isinstance(args, dict):
        return ""
    parts: List[str] = [value for value in args.values() if isinstance(value, str)]
    return " ".join(parts).lower()


def execution_guard(
    execution_actions: Optional[Iterable[str]] = None,
    extra_patterns: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks dangerous commands before they execute.

    execution_actions, if given, replaces the default set of action substrings
    that mark an event as execution-type; extra_patterns extends the built-in
    dangerous-command set. Both are matched case-insensitively.
    """
    actions = _resolve_actions(execution_actions)

    patterns: List[str] = list(BUILTIN_PATTERNS)
    if extra_patterns is not None:
        for pattern in extra_patterns:
            if isinstance(pattern, str) and pattern:
                patterns.append(pattern.lower())
    # Deduplicate while preserving first-seen order (built-ins take priority).
    patterns = list(dict.fromkeys(patterns))

    def rule(event: SensorEvent) -> Optional[Decision]:
        action = event.action
        if not isinstance(action, str):
            return None
        lowered = action.lower()
        # Not an execution action: out of scope, whatever the args say.
        if not any(sub in lowered for sub in actions):
            return None
        text = _scan_text(event)
        if not text:
            return None
        for pattern in patterns:
            if pattern in text:
                return Decision.block(
                    reason="dangerous execution: {}".format(pattern),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
