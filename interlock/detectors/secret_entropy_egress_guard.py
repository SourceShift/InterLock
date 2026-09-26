"""High-entropy token egress guard: block outbound payloads carrying likely secrets.

Pattern-based secret scans (see ``pii_redaction_guard``) only catch the key
formats someone thought to write down - ``sk-...``, ``AKIA...``, a PEM block.
A secret that matches no known prefix, or a random session token minted by an
in-house service, sails straight past them. What such a secret cannot hide is
its *randomness*: a 32-character API key is drawn from a large alphabet, so its
per-character Shannon entropy is far above that of ordinary language.

This rule is that statistical backstop. For an egress action it tokenises the
string values under the content keys - splitting on whitespace and any
non-alphanumeric separator - and, for every token at least ``min_len``
characters long, computes the Shannon entropy of the token's own character
distribution. A token at or above ``threshold`` bits per character is random
enough to be a credential, so the egress is blocked. Words, prose, and long but
low-entropy strings (a run of the same character, a dotted identifier) sit well
below the line and pass.

Deliberately coarse: it flags *shape*, not identity, so it is a companion to a
precise secret scan, not a replacement. Callers tune ``threshold`` for their
own content - a lower value catches hex-encoded secrets (max 4.0 bits/char) at
the cost of more false positives on unusual identifiers.

Reads only str values under the content keys of a dict ``args``; an int, None,
or nested container is skipped rather than stringified, and a non-dict ``args``
yields no opinion. Non-egress actions return None. The rule never raises.
"""
from __future__ import annotations

import math
import re
from typing import Dict, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "secret_entropy"

# Egress action names this guard recognises. Kept to unambiguous transport
# verbs so a same-named in-house tool is not shadowed.
EGRESS_ACTIONS = frozenset({
    "http_post", "fetch", "request", "send", "upload",
})

# Argument keys that may carry outbound content. Only a str value under one of
# these is tokenised.
CONTENT_KEYS = ("data", "body", "payload", "content", "text")

# A token is a maximal run of alphanumerics; everything else (whitespace,
# punctuation, URL separators) is a boundary. This lifts a bare key out of
# "token=<key>&x=1" or "Bearer <key>".
_TOKEN_BOUNDARY = re.compile(r"[^0-9A-Za-z]+")

DEFAULT_MIN_LEN = 20
DEFAULT_THRESHOLD = 4.0


def token_entropy(token: str) -> float:
    """Shannon entropy of *token* in bits per character.

    Uses the token's own character distribution: ``-sum(p * log2(p))`` over the
    characters present. Zero for a uniform run ("aaaa"), ``log2(n)`` for ``n``
    distinct characters, so the score is already normalised per character and
    comparable across token lengths.
    """
    length = len(token)
    if length == 0:
        return 0.0
    counts: Dict[str, int] = {}
    for char in token:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def secret_entropy_egress_guard(
    min_len: int = DEFAULT_MIN_LEN,
    threshold: float = DEFAULT_THRESHOLD,
) -> Rule:
    """Build a Rule that blocks egress whose payload holds a high-entropy token.

    For an action in :data:`EGRESS_ACTIONS`, each str value under a
    :data:`CONTENT_KEYS` key is split into tokens; any token of at least
    *min_len* characters whose Shannon entropy is at or above *threshold*
    (bits/char) yields a BLOCK. Otherwise, including a non-egress action and a
    non-dict ``args``, the rule returns None (no opinion).
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "action", None) not in EGRESS_ACTIONS:
            return None

        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None

        for key in CONTENT_KEYS:
            value = args.get(key)
            if not isinstance(value, str):
                continue
            for token in _TOKEN_BOUNDARY.split(value):
                if len(token) < min_len:
                    continue
                if token_entropy(token) >= threshold:
                    return Decision.block(
                        reason="secret_entropy_egress_guard: high-entropy token",
                        policy_id=POLICY_ID,
                        attributed_to=key,
                    )
        return None

    return rule
