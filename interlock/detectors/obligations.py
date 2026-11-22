"""Live obligation guard: refuse a run that ignored a deadline it opened.

:mod:`interlock.obligations` judges a receipt log after the fact. This rule
brings the same model forward to the call stream: when a call matches an
obligation's ``when`` action, the rule opens it against the run's scope, and
when the matching ``then`` arrives inside the deadline the rule closes it. An
obligation still open past its deadline makes the run's **next** call meet a
refusal - escalate by default, so a human decides whether the deficient run may
continue, or block outright.

A breach fires once. The obligation is dropped when it is refused, so a run is
corrected, not bricked: every later call sees an empty ledger rather than the
same breach again. The receipt log remains the authority - ``interlock
obligations check`` replays the whole history and reports every opening,
including the late ones this detector deliberately does not refuse.

Why a late discharge is not refused: the ``then`` action is the compensating
step. Blocking the approval or the cleanup that arrives late makes the run
worse and teaches nothing, so the rule lets it through, drops the obligation,
and leaves the "breached - discharged late" verdict to the log check.

``approvals_only`` is refused at construction. Whether a call carried an
approval is stamped on the **receipt** by the adapter after the rule runs, so
the live event cannot answer it; a rule that guessed would be silently weaker
than the log check. Use the log check for that obligation shape.

State lives in the closure, so each factory call owns a fresh ledger and two
rules cannot discharge each other. It is process-local, like the sequence
guard: a restart forgets every open obligation, and the log check still knows
better. Scope is ``span_id`` -> ``principal`` -> ``"<anon>"``, evicted oldest
first beyond ``max_scopes``; one scope holds at most ``max_open`` openings,
evicting its own oldest. Every reason names actions and the deadline only, so
it is safe to put in a receipt.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from ..actions import canonical_action
from ..enforce import Decision
from ..event import SensorEvent
from ..obligations import Obligation, parse, subject_of
from ..policy.engine import Rule

POLICY_ID = "obligation"

DEFAULT_MAX_SCOPES = 1024
DEFAULT_MAX_OPEN = 64
ON_BREACH = ("escalate", "block")

#: One open obligation: which entry of ``wanted`` it is, when it opened, and
#: its deadline. Kept as a plain tuple so the ledger stays cheap.
_Open = Tuple[int, float, float]  # (index into wanted, opened_at, required_by)


def _deadline(seconds: float) -> str:
    return ("{}s".format(int(seconds)) if float(seconds).is_integer()
            else "{}s".format(seconds))


def obligations(
    require: Sequence[object],
    *,
    on_breach: str = "escalate",
    max_scopes: int = DEFAULT_MAX_SCOPES,
    max_open: int = DEFAULT_MAX_OPEN,
    clock: Optional[Callable[[], float]] = None,
) -> Rule:
    """Rule: refuse a call once an obligation the run opened has lapsed.

    *require* is an obligation list in the JSON shape :func:`~interlock.
    obligations.parse` validates - ``[{"when": ..., "then": ...,
    "within": ...}]`` - so the declarative form compiles to the same rule.

    *on_breach* is ``"escalate"`` (ask a human whether the deficient run may
    continue; the default) or ``"block"``. *max_scopes* and *max_open* bound
    memory and must be positive non-bool integers. *clock* returns the current
    time as a float and defaults to :func:`time.time`; tests pass a fake.

    Any invalid argument raises ``ValueError`` at construction, where the
    operator can still see it. The ledger is mutated under a per-rule lock and
    the rule never raises on a malformed event.
    """
    if not isinstance(on_breach, str) or on_breach not in ON_BREACH:
        raise ValueError("on_breach must be one of {}".format(", ".join(ON_BREACH)))
    if (isinstance(max_scopes, bool) or not isinstance(max_scopes, int)
            or max_scopes <= 0):
        raise ValueError("max_scopes must be a positive integer")
    if (isinstance(max_open, bool) or not isinstance(max_open, int) or max_open <= 0):
        raise ValueError("max_open must be a positive integer")
    now_fn = time.time if clock is None else clock
    if not callable(now_fn):
        raise ValueError("clock must be a callable returning a float")

    wanted: List[Obligation] = parse(require)
    if any(item.approvals_only for item in wanted):
        raise ValueError(
            "approvals_only is checked from receipts only: the live event does "
            "not carry an approval. Use `interlock obligations check` for that "
            "obligation, or drop approvals_only.")

    ledgers: Dict[str, List[_Open]] = {}
    lock = threading.Lock()

    def _refuse(obligation: Obligation, opened_at: float, now: float) -> Decision:
        reason = "obligation: {} not followed by {} within {} (open {:.0f}s)".format(
            obligation.when, obligation.then, _deadline(obligation.within),
            now - opened_at)
        if on_breach == "block":
            return Decision.block(reason=reason, policy_id=POLICY_ID)
        return Decision.escalate(reason=reason, policy_id=POLICY_ID)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "phase", "call") != "call":
            return None
        action = canonical_action(getattr(event, "action", None))
        if not action:
            return None
        scope = subject_of(event)
        now = float(now_fn())

        with lock:
            ledger = ledgers.get(scope)
            if ledger is None:
                if len(ledgers) >= max_scopes:
                    # Drop the oldest scope; a dict keeps insertion order.
                    ledgers.pop(next(iter(ledgers)))
                ledger = ledgers[scope] = []

            # 1. Discharge: the compensating action, on time or late, closes
            #    the oldest opening it matches. Late is still dropped here -
            #    the log check reports it as a breach, and refusing the
            #    compensating call would make the run worse.
            for position, (index, _opened, _by) in enumerate(ledger):
                if action == wanted[index].then:
                    del ledger[position]
                    break

            # 2. Expire: the oldest lapsed obligation refuses this call, once.
            lapsed: Optional[_Open] = None
            for position, entry in enumerate(ledger):
                index, _opened, required_by = entry
                if now > required_by:
                    lapsed = ledger.pop(position)
                    break
            if lapsed is not None:
                obligation = wanted[lapsed[0]]
                return _refuse(obligation, lapsed[1], now)

            # 3. Open: a trigger action starts its clock.
            for index, obligation in enumerate(wanted):
                if action != obligation.when:
                    continue
                if len(ledger) >= max_open:
                    # Bounded memory beats completeness: the log still holds it.
                    ledger.pop(0)
                ledger.append((index, now, now + obligation.within))
            return None

    return rule


__all__ = ["DEFAULT_MAX_OPEN", "DEFAULT_MAX_SCOPES", "ON_BREACH", "POLICY_ID",
           "obligations"]
