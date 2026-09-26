"""Base64 / hex encoded-injection detector.

Encoding is a channel transform, not new content: an attacker who knows a
plain-text filter matches "ignore previous instructions" can ship the exact
same instruction as a base64 or hex blob and the filter never sees it. This
rule takes the inverse view — instead of enumerating obfuscations, it finds
long base64-ish and hex-ish tokens, decodes each candidate back to text, and
re-runs the *same* marker set over the decoded bytes. One matcher, several
channels.

Only top-level *string* arg values are inspected; non-str values (None, ints,
nested dicts/lists) are skipped rather than stringified, so structural data
cannot trip the check and odd input never raises. Decoding failures are
swallowed: a token that is not valid base64/hex is simply not a match. With
nothing decoded to a marker the rule stays silent (returns None), leaving the
engine's default-allow path untouched for benign traffic.
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Iterator, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "base64_payload_scan"

# A base64-ish token: the standard alphabet for 24+ chars, with up to two
# trailing pad chars. 24 chars is 18 decoded bytes — long enough that
# incidental runs of identifier-ish text rarely reach it.
_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

# A hex-ish token: 16+ byte-pairs, i.e. 32+ hex chars. The pair grouping
# keeps an odd-length run from being treated as a token.
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")

# Substring markers, matched case-insensitively against decoded text. Kept
# deliberately blunt: the decode step already narrowed the candidate space.
_MARKERS = (
    "ignore previous instructions",
    "you are now",
    "system prompt",
    "exfiltrate",
)


def _decoded_candidates(value: str) -> Iterator[str]:
    """Yield lowercased utf-8 decodings of every encoded token in *value*.

    Each decode is attempted independently and a failure is skipped: an
    invalid base64/hex token is not a match, it is not an error.
    """
    for token in _B64_RE.findall(value):
        try:
            raw = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        yield raw.decode("utf-8", errors="ignore").lower()

    for token in _HEX_RE.findall(value):
        try:
            raw = bytes.fromhex(token)
        except ValueError:
            continue
        yield raw.decode("utf-8", errors="ignore").lower()


def _first_marker(value: str) -> Optional[str]:
    """Return the first injection marker found in any decoding, else None."""
    for decoded in _decoded_candidates(value):
        for marker in _MARKERS:
            if marker in decoded:
                return marker
    return None


def base64_payload_scan() -> Rule:
    """Build a Rule that blocks injections smuggled as base64/hex blobs.

    Scans each top-level string arg value, decodes every long base64-ish and
    hex-ish token, and blocks on the first marker found in a decoding. Returns
    None when no string value decodes to a marker, when every token fails to
    decode, or when args is not a mapping.
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        args: Any = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None
        for name, value in args.items():
            if not isinstance(value, str):
                continue
            if _first_marker(value) is not None:
                return Decision.block(
                    reason="base64_payload_scan: decoded injection",
                    policy_id=POLICY_ID,
                    attributed_to=name,
                )
        return None

    return rule
