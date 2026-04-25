"""IBAN redaction guard: mask bank account numbers out of egress payloads.

An IBAN is a bank account identifier, and unlike a password it is not secret by
nature - it is printed on invoices and shared with anyone who pays you. What
makes it dangerous to leak is what it *enables*: a complete IBAN plus a name is
enough to originate a direct debit in much of the SEPA area, so an IBAN that
rides out in an ``http_post`` body or a log line is a payment-fraud primitive,
not just a privacy annoyance. Copying one into an outbound payload is almost
always an accident of context - a model echoing an invoice it was asked to
summarise - so failing the transport would punish the legitimate work.

This rule therefore sits at the MODIFY point of the allow/modify/block
spectrum: it rewrites the IBAN to a marker in place and lets the (now-clean)
send proceed. The exfiltration is neutralised without breaking the request.

Two design points carry the weight.

First, a candidate is masked only if it survives the ISO 7064 MOD-97-10 check.
That is what separates an IBAN from a string that merely looks like one
(``AB12 CD34 ...``, a German postal code with a country prefix, a part number).
Validation is cheap arithmetic - rearrange, map letters to ``ord - 55``, and
require ``int(digits) % 97 == 1`` - and it means a false positive costs
nothing, because an unvalidated candidate is left exactly as it was. A rule
that masked on shape alone would corrupt legitimate payloads.

Second, the scan is bounded to the *content* keys of an egress action.
Destination keys (``url``, ``endpoint``, ``uri``, ``host``) are never touched:
rewriting where a request goes would break the send the redaction exists to
preserve, and the destination is the egress allowlist's concern, not this
rule's.

One wrinkle worth naming. The detection pattern is deliberately permissive
about spaces because real IBANs are written in groups of four, and the
``[ ]?`` inside its repeated group means a greedy match will also swallow
ordinary words that follow (``...00 by friday`` matches whole, and the
concatenation is not a valid IBAN). Masking the raw match would therefore
redact nothing. So a match that fails validation is retried as its
space-delimited prefixes, longest first, and the longest prefix that passes
MOD-97 is the span that gets masked - the trailing prose is returned
untouched. The rewrite stays a ``re.sub`` over :data:`PATTERN`; only the span
that is actually a bank account is replaced.

Reads only str values under the content keys of a dict ``args``; an int, None,
or nested container is skipped rather than stringified, and a non-dict ``args``
yields no opinion. Non-egress actions return None. The rule never raises.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "iban_redact"

# The mask a redacted account number is replaced with.
MARKER = "[REDACTED IBAN]"

# Country code + two check digits, then 11-30 further alphanumerics, each
# optionally preceded by a single space so the grouped "DE89 3704 0044 ..."
# form matches as one candidate. The shape gate is intentionally loose: the
# MOD-97 check, not this pattern, decides what is really an IBAN.
PATTERN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b")

# ISO 13616 bounds. The pattern's lower bound already guarantees MIN_LENGTH for
# a whole match, but the same bound is enforced on trimmed prefixes so a short
# fragment cannot be rescued by a lucky checksum.
MIN_LENGTH = 15
MAX_LENGTH = 34

# Egress action names this guard recognises. Kept to verbs that unambiguously
# leave the process, so a same-named in-house tool is not shadowed.
EGRESS_ACTIONS = frozenset({
    "http_post", "http_get", "fetch", "request", "send", "upload",
    "log", "write",
})

# Argument keys that may carry outbound content. Destination keys are absent by
# design; only a str under one of these is scanned.
CONTENT_KEYS = (
    "data", "body", "payload", "content", "text", "message", "msg", "value",
)


def _mod97_ok(compact: str) -> bool:
    """Return True if ``compact`` (spaces already removed) is a valid IBAN.

    Implements ISO 7064 MOD-97-10: drop the four leading chars to the end, map
    every letter to its two-digit value (``A`` -> 10, ..., ``Z`` -> 35), then
    require the resulting integer to be congruent to 1 modulo 97. Anything that
    is neither a digit nor an upper-case letter fails outright, as does a
    length outside the ISO bounds.
    """
    if not (MIN_LENGTH <= len(compact) <= MAX_LENGTH):
        return False

    rearranged = compact[4:] + compact[:4]
    digits: List[str] = []
    for ch in rearranged:
        if "0" <= ch <= "9":
            digits.append(ch)
        elif "A" <= ch <= "Z":
            digits.append(str(ord(ch) - 55))
        else:
            return False

    return int("".join(digits)) % 97 == 1


def _validated_prefix(candidate: str) -> Optional[str]:
    """Longest space-delimited prefix of ``candidate`` that passes MOD-97.

    ``candidate`` is a raw :data:`PATTERN` match, which may have swallowed
    trailing prose because the pattern permits a space before each group. Each
    prefix is tried longest first so the widest genuine account number wins;
    None means no prefix is a valid IBAN and the match is left intact.
    """
    tokens = candidate.split(" ")
    for end in range(len(tokens), 0, -1):
        prefix = " ".join(tokens[:end])
        if _mod97_ok(prefix.replace(" ", "")):
            return prefix
    return None


def _redact_match(match: "re.Match[str]") -> str:
    """Replace a validated IBAN span with the marker, else echo it unchanged."""
    candidate = match.group(0)
    valid = _validated_prefix(candidate)
    if valid is None:
        return candidate
    return MARKER + candidate[len(valid):]


def iban_redactor() -> Rule:
    """Build a Rule that masks IBANs out of an outbound action's payload.

    For an action in :data:`EGRESS_ACTIONS`, every str value under a
    :data:`CONTENT_KEYS` key has each :data:`PATTERN` match that passes the
    MOD-97 checksum replaced with :data:`MARKER`. When at least one key
    changed, the rule returns a MODIFY carrying only the rewritten keys, so the
    send proceeds with the account number stripped and the destination
    untouched. Otherwise - a clean payload, a non-egress action, or a non-dict
    ``args`` - it returns None (no opinion).
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "action", None) not in EGRESS_ACTIONS:
            return None

        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None

        changed: Dict[str, str] = {}
        for key in CONTENT_KEYS:
            value = args.get(key)
            if not isinstance(value, str):
                continue
            cleaned, hits = PATTERN.subn(_redact_match, value)
            # ``subn`` counts a match even when _redact_match echoes it back
            # unchanged (a candidate that failed MOD-97), so a no-op rewrite
            # must not be reported as a change.
            if hits and cleaned != value:
                changed[key] = cleaned

        if not changed:
            return None
        return Decision.modify(changed, reason="iban_redact", policy_id=POLICY_ID)

    return rule
