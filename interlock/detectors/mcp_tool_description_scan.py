"""MCP tool-description injection detector.

An MCP server's tool metadata - the tool name, its description, parameter docs -
is attacker-controlled text that reaches the model *before* the tool is ever
called. A malicious server can bury instructions in a tool description so the
model treats them as if the user wrote them ("ignore previous...",
"always include...", "do not tell the user...").

This rule scans the action name and every top-level string argument value for
signatures of that smuggling and blocks the registration/call before the
metadata is handed to the model.

Note the action name is in scope here, unlike the indirect prompt-injection
detector which scans data channels only: an MCP tool name is itself part of the
metadata being smuggled, so it must not be trusted.

Silent (returns None) when nothing matches, leaving the engine's default-allow
path untouched for benign traffic.
"""
from __future__ import annotations

from typing import Iterable, List, Optional, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

# Ordered so the first matching signature is deterministic and stable.
BUILTIN_PATTERNS: Tuple[str, ...] = (
    "ignore previous",
    "ignore all instructions",
    "you must",
    "do not tell",
    "exfiltrate",
    "send to",
    "before using this tool",
    "system:",
    "<important>",
    "always include",
    "forward the",
)

POLICY_ID = "mcp_tool_description_scan"


def _scan_text(event: SensorEvent) -> str:
    """Lowercased scan text: the action name plus every top-level str arg value.

    Non-str values (None, int, nested dict, list) are skipped rather than
    coerced: a signature buried inside a nested schema is out of scope, and
    repr()-ing structural data would invent matches that are not there.
    """
    parts: List[str] = []
    action = event.action
    if isinstance(action, str):
        parts.append(action)
    args = event.args
    if isinstance(args, dict):
        parts.extend(value for value in args.values() if isinstance(value, str))
    return " ".join(parts).lower()


def mcp_tool_description_scan(
    extra_patterns: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule that blocks hidden instructions in MCP tool metadata.

    extra_patterns, if given, extends the built-in signature set; each entry is
    matched case-insensitively. Duplicates are dropped while keeping the
    built-ins first.
    """
    patterns: List[str] = list(BUILTIN_PATTERNS)
    if isinstance(extra_patterns, str):
        # A bare string would otherwise iterate character-by-character, turning
        # every one-letter pattern into a match-everything rule.
        extra_patterns = (extra_patterns,)
    if extra_patterns is not None:
        for pattern in extra_patterns:
            # An empty pattern is a substring of every text, so it would block
            # unconditionally; it is malformed input, not a signature.
            if isinstance(pattern, str) and pattern:
                patterns.append(pattern.lower())
    # Deduplicate, preserving first-seen order so built-ins keep priority.
    patterns = list(dict.fromkeys(patterns))

    def rule(event: SensorEvent) -> Optional[Decision]:
        text = _scan_text(event)
        if not text:
            return None
        for pattern in patterns:
            if pattern in text:
                return Decision.block(
                    reason="{}: {}".format(POLICY_ID, pattern),
                    policy_id=POLICY_ID,
                )
        return None

    return rule
