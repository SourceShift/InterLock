"""Per-principal token budget: cap tokens estimated by a dependency-free
chars-per-token heuristic, documented to stay within 0.5x-2.0x of a real
tokenizer's count, accumulated per principal over a rolling window.

Rate limiters here count *calls*; a cost guard sums a number the caller hands
it. Neither bounds the one resource a model-driven agent actually spends -
tokens - so an agent that sends a few enormous prompts, or a caller that streams
a long conversation back in, can burn a context window or a bill in a handful of
individually ordinary-looking calls. The volume of *text* is the signal, and a
call counter is blind to it.

This Rule estimates the tokens each event carries - a dependency-free
chars-per-token heuristic (:mod:`interlock.tokens`, no tokenizer dependency) -
and accumulates them per principal over a rolling window of ``window_s``
seconds. Once a principal's estimated spend in the window goes over ``limit``
the rule blocks the event. The window is a real rolling window: each charge carries
the event's timestamp and ages out once it is older than ``window_s``, so a
principal that slows down earns allowance back without any explicit reset.

The boundary is inclusive at the limit, matching the other budget rules: with
``limit=200`` a window may hold exactly 200 tokens, and the call that takes it
past 200 is the one refused. The
tally lives in the closure, so each factory call owns fresh state - two rules
built from separate ``token_budget_guard()`` calls never share a window and
cannot trip each other. The key is the event's principal, falling back to
``"<anon>"`` when it is absent or not a string, so a caller with no identity is
still budgeted rather than escaping unnamed.

Only the text an event carries is counted - every string found in its args, at
any nesting depth (up to a small depth cap) - so a call that sends no text
spends nothing. A missing, non-dict, or text-free args is skipped without
crashing, and the rule never raises on odd input. It counts whichever side of a
call it is shown: a call-phase event carries the input text, and a payload that
also embeds an expected or observed output under any key is counted too.

Receipts. The per-event estimate is stamped onto the event as the plain
attribute ``event.tokens`` (best-effort), which :func:`interlock.receipt.emit_receipt`
records in the ``tokens`` field of the receipt, so ``interlock report`` can
surface estimated token spend. The stamp never changes the verdict.

Refill. ``refill`` is an optional callable ``refill(principal, elapsed_s) ->
tokens``. When given, that many tokens are credited back before the new event is
charged, letting a deployment top the budget up over time (a leaky bucket)
instead of waiting for old charges to age out of the window. A negative,
non-numeric, or raising refill is ignored rather than trusted - a broken
callback must not silently disable the cap.
"""
from __future__ import annotations

import math
import time
from typing import Callable, Dict, List, Optional, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule
from ..tokens import estimate_tokens

POLICY_ID = "token_budget"

# Defaults chosen for a long-ish agent session: a generous per-principal budget
# over an hour, so only a genuine runaway trips it. Deployments set their own.
DEFAULT_LIMIT = 100_000
DEFAULT_WINDOW_S = 3600.0

# Identity used when an event carries no usable principal. A subject we cannot
# name is still budgeted, so it cannot escape the cap by staying anonymous.
ANON = "<anon>"

# How deep to walk nested args looking for text. Caps the work a hostile,
# deeply-nested argument value can force, and keeps a cyclic container (which
# cannot survive JSON but can be built in-process) from recursing forever.
MAX_DEPTH = 6


def _tokens_in(value: object, depth: int) -> int:
    """Estimated tokens in *value*: strings directly, containers one level in."""
    if isinstance(value, str):
        return estimate_tokens(value)
    if depth >= MAX_DEPTH:
        return 0
    if isinstance(value, dict):
        return sum(_tokens_in(item, depth + 1) for item in value.values())
    if isinstance(value, (list, tuple, set, frozenset)):
        return sum(_tokens_in(item, depth + 1) for item in value)
    return 0


def estimate_event_tokens(args: object) -> int:
    """Estimated tokens across every string an event's ``args`` carries.

    A non-dict ``args`` (``None``, a string, a number) has no keyed text to
    count and returns ``0``. Otherwise every value is walked - strings counted
    directly, dicts and sequences walked to a fixed depth - so a prompt, a list
    of messages, or a nested content dict are all seen. Never raises.
    """
    if not isinstance(args, dict):
        return 0
    return sum(_tokens_in(value, 0) for value in args.values())


def _event_time(event: SensorEvent) -> float:
    """The event's timestamp when it is a usable finite number, else now."""
    ts = getattr(event, "ts", None)
    if isinstance(ts, (int, float)) and not isinstance(ts, bool):
        if math.isfinite(ts):
            return float(ts)
    return time.time()


def _stamp(event: SensorEvent, tokens: int) -> None:
    """Attach the per-event estimate to the event for the receipt to pick up.

    Best-effort: an event-like object that refuses the attribute just does not
    feed the receipt, and the verdict is unaffected either way.
    """
    try:
        event.tokens = tokens
    except Exception:
        pass


def _credit(refill: Callable[[str, float], float], principal: str, elapsed: float) -> float:
    """Tokens to give back, or 0.0 when the refill is unusable."""
    try:
        value = refill(principal, elapsed)
    except Exception:
        return 0.0
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    if not math.isfinite(value):
        return 0.0
    return max(0.0, float(value))


def token_budget_guard(
    limit: float = DEFAULT_LIMIT,
    window_s: float = DEFAULT_WINDOW_S,
    refill: Optional[Callable[[str, float], float]] = None,
) -> Rule:
    """Rule: block once a principal's estimated tokens reach *limit* in *window_s*.

    Each event's estimated token cost (see :func:`estimate_event_tokens`) is
    charged to its principal's rolling window and the window is trimmed of
    charges older than ``window_s``. While the trimmed total is below *limit*
    the rule returns None (no opinion); once it reaches *limit* it returns a
    BLOCK Decision. Each call to this factory returns a Rule with its own fresh
    per-principal window, so separate budgets are independent.

    ``refill``, when given, is called as ``refill(principal, elapsed_s)`` and
    the value it returns is credited back before this event is charged; a
    negative, non-numeric, or raising refill is ignored.
    """
    spent: Dict[str, List[Tuple[float, int]]] = {}
    window = float(window_s) if isinstance(window_s, (int, float)) else 0.0

    def rule(event: SensorEvent) -> Optional[Decision]:
        principal = getattr(event, "principal", None)
        if not isinstance(principal, str):
            principal = ANON
        now = _event_time(event)
        charged = estimate_event_tokens(getattr(event, "args", None))
        _stamp(event, charged)

        entries = spent.setdefault(principal, [])
        # A charge exactly window_s old has left the window; drop it too, so the
        # window is the half-open (now - window_s, now].
        cutoff = now - window
        while entries and entries[0][0] <= cutoff:
            entries.pop(0)

        used = sum(count for _, count in entries)
        if refill is not None and entries:
            used -= _credit(refill, principal, now - entries[-1][0])
        used = max(0.0, used) + charged
        entries.append((now, charged))

        if used > limit:
            return Decision.block(
                reason="token_budget: limit {} tokens per {}s exceeded".format(
                    limit, window_s
                ),
                policy_id=POLICY_ID,
            )
        return None

    return rule
