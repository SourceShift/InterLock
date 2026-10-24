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
callback must not silently disable the cap. It is invoked while the rule holds
its lock, so a charge and its credit are one atomic step; a refill callback must
therefore not call back into this same rule, or it will deadlock.
"""
from __future__ import annotations

import math
import threading
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
    """The event's timestamp, clamped so it can never run ahead of the clock.

    A usable finite number is kept as-is when it is in the past - an old event
    may be a legitimate replay - and clamped to ``time.time()`` when it is in
    the future. Without that clamp a caller could stamp one event a day ahead,
    trimming every real charge out of the window. A missing, non-numeric,
    boolean, or non-finite timestamp falls back to now.
    """
    ts = getattr(event, "ts", None)
    if isinstance(ts, (int, float)) and not isinstance(ts, bool):
        try:
            usable = math.isfinite(ts)
        except OverflowError:
            usable = False
        if usable:
            now = time.time()
            value = float(ts)
            return min(value, now)
    return time.time()


def _positive_limit(name: str, value: object) -> float:
    """*value* as a positive finite float, or ``ValueError`` naming *name*."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("{} must be a finite number greater than 0".format(name))
    try:
        ok = math.isfinite(value) and value > 0
    except OverflowError:
        ok = False
    if not ok:
        raise ValueError("{} must be a finite number greater than 0".format(name))
    return float(value)


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
    negative, non-numeric, or raising refill is ignored. Both *limit* and
    *window_s* must be finite numbers greater than 0; anything else raises
    ``ValueError`` at construction. The per-principal map and every window are
    updated under one per-rule lock, and a future event timestamp is clamped to
    now so it cannot rewind a principal's window.
    """
    _positive_limit("limit", limit)
    window = _positive_limit("window_s", window_s)
    spent: Dict[str, List[Tuple[float, int]]] = {}
    lock = threading.Lock()

    def rule(event: SensorEvent) -> Optional[Decision]:
        principal = getattr(event, "principal", None)
        if not isinstance(principal, str):
            principal = ANON
        now = _event_time(event)
        charged = estimate_event_tokens(getattr(event, "args", None))
        _stamp(event, charged)

        with lock:
            entries = spent.get(principal)
            # A charge exactly window_s old has left the window; drop it too, so
            # the window is the half-open (now - window_s, now]. Filter rather
            # than pop from the front: forward-only clamping still lets an older
            # replay event be appended after a newer one.
            if entries is not None:
                cutoff = now - window
                entries[:] = [entry for entry in entries if entry[0] > cutoff]
                if not entries:
                    del spent[principal]
                    entries = None
            if entries is None:
                entries = []

            used = sum(count for _, count in entries)
            if refill is not None and entries:
                # Elapsed comes from the newest charge, which need not be last.
                newest = max(entry[0] for entry in entries)
                used -= _credit(refill, principal, now - newest)
            used = max(0.0, used) + charged
            # Keep the map bounded: a principal with no live charges and no new
            # text spends nothing, so there is no window worth remembering.
            if entries or charged:
                entries.append((now, charged))
                spent[principal] = entries
            over_limit = used > limit

        if over_limit:
            return Decision.block(
                reason="token_budget: limit {} tokens per {}s exceeded".format(
                    limit, window_s
                ),
                policy_id=POLICY_ID,
            )
        return None

    return rule
