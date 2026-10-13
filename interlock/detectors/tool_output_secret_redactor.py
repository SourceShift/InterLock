"""Result guard: mask credentials in what a tool returns, before the agent reads it.

A coding agent that runs ``cat .env`` or ``kubectl config view`` gets the secret
in its context window, and from there it can end up in a summary, a commit, or
a request to a third party. Blocking the read is one answer; this rule is the
other: let the read happen and replace each credential-shaped value in the
result with ``[REDACTED <KIND>]``, so the agent sees the structure it needed
and never the secret.

It recognises values that are self-evidently credentials, whatever the key
around them: PEM private keys, AWS access key ids and secret assignments,
GitHub tokens, OpenAI-style ``sk-`` keys, npm and Slack tokens, Google API keys,
JWTs, the password in ``scheme://user:pass@host``, ``Authorization:`` header
values, bearer tokens, and ``NAME=value`` assignments whose name says secret
(``*_TOKEN``, ``*_SECRET``, ``*_PASSWORD``, ``*_API_KEY``, ``*_PRIVATE_KEY``).

Result phase only. Every string in the payload is scanned, nested dicts and
lists included (to a fixed depth). The rewrite replaces the tool's return
value: a string result comes back as the redacted string, a dict result as the
redacted dict. Under the Claude Code hook adapter the redacted value reaches
the model through ``updatedToolOutput``. The rule never raises.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any, List, Optional, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "tool_output_secret_redact"

_MAX_DEPTH = 6

#: (kind, pattern, group to mask - 0 for the whole match)
PATTERNS: List[Tuple[str, "re.Pattern[str]", int]] = [
    ("PRIVATE_KEY", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), 0),
    ("AWS_ACCESS_KEY_ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("AWS_SECRET", re.compile(
        r"(?i)\b(?:aws_secret_access_key|aws_session_token)\b\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{16,})"), 1),
    ("GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"), 0),
    ("API_KEY", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}\b"), 0),
    ("NPM_TOKEN", re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"), 0),
    ("SLACK_TOKEN", re.compile(r"\bxox[bpcsa]-[A-Za-z0-9-]{10,}\b"), 0),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0),
    ("URL_PASSWORD", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/]+)@"), 1),
    ("AUTH_HEADER", re.compile(r"(?i)\bauthorization\s*[:=]\s*(?:[A-Za-z]+\s+)?([^\s\"',;]{8,})"), 1),
    ("BEARER_TOKEN", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,})"), 1),
    ("SECRET", re.compile(
        r"(?im)^\s*(?:export\s+)?[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY)"
        r"[A-Z0-9_]*\s*[:=]\s*[\"']?([^\s\"'#]{6,})"), 1),
]


#: Values of a secret-named assignment that are not secrets: a type in
#: source code (``link_token: string;``) or a reference to where the secret
#: lives (``API_KEY = os.environ[...]``, ``token: ${TOKEN}``).
_NOT_A_VALUE = re.compile(
    r"^(?:string|number|boolean|bigint|any|unknown|never|void|object|null|undefined|none|"
    r"str|int|float|bool|bytes|optional|list|dict|true|false)\b[\[\]<>|?;,)]*$"
    r"|^(?:process\.env|os\.environ|os\.getenv|env\.|getenv|config\.|settings\.|self\.|this\.)"
    r"|^\$|^%\(|[(){};]$",
    re.IGNORECASE)


def redact_text(text: str) -> Tuple[str, List[str]]:
    """Mask every credential-shaped value in ``text``; return (text, kinds)."""
    kinds: List[str] = []
    for kind, pattern, group in PATTERNS:
        def mask(match: "re.Match[str]", kind: str = kind, group: int = group) -> str:
            if match.group(group).startswith("[REDACTED"):
                return match.group(0)  # an earlier pattern already masked it
            if kind == "SECRET" and _NOT_A_VALUE.search(match.group(group)):
                return match.group(0)  # a type or a reference, not a credential
            kinds.append(kind)
            marker = "[REDACTED {}]".format(kind)
            if group == 0:
                return marker
            start, end = match.span(group)
            base = match.start(0)
            whole = match.group(0)
            return whole[: start - base] + marker + whole[end - base:]
        text = pattern.sub(mask, text)
    return text, kinds


def _redact(value: Any, depth: int, kinds: List[str]) -> Any:
    if isinstance(value, str):
        redacted, found = redact_text(value)
        kinds.extend(found)
        return redacted
    if depth >= _MAX_DEPTH:
        return value
    if isinstance(value, dict):
        return {k: _redact(v, depth + 1, kinds) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v, depth + 1, kinds) for v in value]
    return value


def tool_output_secret_redactor() -> Rule:
    """Build a result-phase Rule that masks credentials in tool output.

    Returns a MODIFY carrying the redacted result when anything was masked,
    else None. The reason names the kinds masked, never the values.
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "phase", "call") != "result":
            return None
        payload = getattr(event, "args", None)
        if not isinstance(payload, dict):
            return None
        try:
            kinds: List[str] = []
            redacted = _redact(payload, 0, kinds)
        except Exception:
            return None
        if not kinds:
            return None
        result = redacted["result"] if set(redacted) == {"result"} else redacted
        decision = Decision.modify_result(
            result,
            reason="masked {} in tool output".format(", ".join(sorted(set(kinds)))),
            policy_id=POLICY_ID,
            attributed_to="result",
        )
        # Counts per kind, never values: the receipt's ``masked`` field and the
        # metrics read this, as they do for the masking engine's rewrites.
        decision.masked = dict(Counter(kinds))
        return decision

    rule.phase = "result"  # type: ignore[attr-defined]
    return rule
