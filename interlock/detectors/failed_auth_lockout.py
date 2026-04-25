"""Failed-authentication lockout: stop a principal that keeps failing to authenticate.

A single failed authentication is noise - a typo, an expired token, a race on a
refresh. A *run* of them from one principal is a signal: credential stuffing, a
brute-forced secret, or an agent wedged retrying a login it will never win.
No single event is worth blocking, so like the other rate limiters here this rule
judges a principal only in aggregate.

This Rule keeps one running count of failed authentications per principal and
refuses further events once that count exceeds ``limit``. Only events that are
themselves failed authentications - ``action == "auth"`` with a falsey
``args["ok"]`` - are counted; every other event returns None (no opinion) and is
left untouched, so ordinary traffic neither trips the lockout nor is blocked by
it. The boundary is inclusive at the limit: with ``limit=2`` the second failure
still passes and the third is blocked.

The counter lives in the closure, so each factory call owns fresh state - two
rules built from separate ``failed_auth_lockout()`` calls cannot trip each other.
The key is the event's principal, falling back to ``"<anon>"`` when it is absent
or not a string, so a caller with no identity is still locked out rather than
escaping unnamed. The rule never raises on odd input: missing fields, non-dict
args, and non-string principals are all handled without crashing.
"""
from __future__ import annotations

from typing import Dict, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "failed_auth_lockout"

# Identity used when an event carries no usable principal. A subject we cannot
# name is still counted, so it cannot escape the limit by staying anonymous.
ANON = "<anon>"

DEFAULT_LIMIT = 5

# The action name whose failures are counted. Any other action is ignored.
AUTH_ACTION = "auth"


def failed_auth_lockout(limit: int = DEFAULT_LIMIT) -> Rule:
    """Rule: block once one principal's failed-auth count exceeds *limit*.

    Only events with ``action == "auth"`` and a falsey ``args["ok"]`` are
    counted, keyed by ``event.principal`` (falling back to ``"<anon>"`` when it
    is None or not a string). While a key's running count is <= *limit* the rule
    returns None; once it is strictly greater it returns a BLOCK Decision. Every
    non-failing event returns None without affecting any counter. Each call to
    this factory returns a Rule with its own fresh counter.
    """
    counts: Dict[str, int] = {}

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "action", None) != AUTH_ACTION:
            return None

        # A non-dict args (None, int, list, ...) cannot prove success, so it is
        # treated the same as a missing "ok" - a failed authentication.
        args = getattr(event, "args", None)
        ok = args.get("ok") if isinstance(args, dict) else None
        if ok:
            return None

        principal = getattr(event, "principal", None)
        if not isinstance(principal, str):
            principal = ANON

        counts[principal] = counts.get(principal, 0) + 1
        if counts[principal] > limit:
            return Decision.block(
                reason="failed_auth_lockout: limit {} exceeded".format(limit),
                policy_id=POLICY_ID,
            )
        return None

    return rule
