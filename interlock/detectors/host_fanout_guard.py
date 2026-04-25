"""Egress host fan-out guard: block an agent that contacts too many distinct hosts.

An allowlist asks "is this destination legitimate?" and a rate limiter asks "how
*many* calls is this principal making?". Neither notices the shape of the
traffic: one request each to fifty different hosts is a scan (or a slow,
low-and-slow exfiltration), yet every single call is to some host and every
per-host budget is untouched. Breadth is the signal here, not depth.

This Rule watches egress actions and remembers the *set of distinct hosts* they
have addressed in this process. The host is read from ``args["url"]`` with
``urllib.parse.urlparse`` - only the hostname, so ``https://a.example:443/x`` and
``http://A.example/y`` collapse to the single host ``a.example`` and a caller
cannot inflate the count by shuffling ports, case, or paths. A destination the
rule has already seen is always allowed through: revisiting a host is normal
retry behaviour and must never trip the guard.

The boundary is what makes the rule useful rather than noisy: with ``limit=2``
the first two *distinct* hosts pass and the third distinct host is blocked. The
check runs before the new host is recorded, so ``len(seen) >= limit`` reads as
"adding this host would exceed the limit" - and the blocked host is never
recorded, because it was never contacted. Repeated attempts at it stay blocked.

State lives in the closure, so two rules built from separate factory calls never
share a set and cannot trip each other. Anything the rule cannot interpret is
skipped rather than guessed at: a non-egress action, a non-dict ``args``, a
missing/non-string ``url``, a URL with no hostname, or a ``urlparse`` that
rejects the input all return None (no opinion) and never raise.

Out of scope, left to other rules: which hosts are legitimate (an allowlist) and
what the right limit is. This rule counts distinct destinations and nothing else.
"""
from __future__ import annotations

from typing import Optional, Set
from urllib.parse import urlparse

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "host_fanout"

DEFAULT_LIMIT = 5

# Egress action names this guard recognises. Kept to verbs that unambiguously
# leave the process, so a same-named in-house tool is not shadowed.
EGRESS_ACTIONS = frozenset({
    "http_post", "http_get", "fetch", "request", "send",
})


def _host_of(args: object) -> Optional[str]:
    """Return the lowercased hostname of ``args["url"]``, or None.

    None means "no host this rule can name" - a non-dict ``args``, a missing or
    non-string ``url``, a URL with no authority (``/relative/path``), or input
    ``urlparse`` refuses. The caller treats that as "skip", never as a host.
    """
    if not isinstance(args, dict):
        return None
    url = args.get("url")
    if not isinstance(url, str):
        return None
    try:
        host = urlparse(url).hostname
    except (ValueError, TypeError):
        return None
    if not host:
        return None
    return host


def host_fanout_guard(limit: int = DEFAULT_LIMIT) -> Rule:
    """Rule: block the first egress event that would reach beyond `limit` hosts.

    Each call to the factory owns a fresh set of seen hosts, so limits are
    independent across rules. A repeat of an already-seen host returns None
    regardless of the limit; the event that introduces the (``limit``+1)th
    distinct host returns a BLOCK Decision. Non-egress actions, and egress
    events whose ``args`` carry no usable host, return None and are not counted.
    """
    seen: Set[str] = set()

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "action", None) not in EGRESS_ACTIONS:
            return None

        host = _host_of(getattr(event, "args", None))
        if host is None:
            return None
        if host in seen:
            return None
        if len(seen) >= limit:
            # Recording this host would push the distinct count past `limit`.
            # It is not added: the event is refused, so the host is never
            # contacted and cannot count as seen. Further tries stay blocked.
            return Decision.block(
                reason="host_fanout_guard: too many distinct hosts",
                policy_id=POLICY_ID,
            )
        seen.add(host)
        return None

    return rule
