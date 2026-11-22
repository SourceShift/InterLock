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

State lives in the closure by default, so each factory call owns a fresh
ledger and two rules cannot discharge each other. That is process-local, which
a daemon can live with but a hook host cannot: it runs one process per tool
call, so the ``when`` in one process is forgotten before the ``then`` arrives.
Point ``state=`` at an absolute path and the openings move to
:class:`~interlock.obligation_ledger.FileLedger` (a small SQLite file holding
scope, action names and timestamps - never an argument), so the next hook
invocation enforces the deadline the previous one opened. The file is created
on the first event, not at construction, so ``interlock policy check`` does not
write anything. If it cannot be read or written the rule falls back to the
in-process ledger for that call and logs once: a storage fault is the same
failure as a restart, which the log check still reports from the receipts, and
refusing every call would make the guard worse than the incident.

Scope is ``span_id`` -> ``principal`` -> ``"<anon>"``, evicted oldest first
beyond ``max_scopes``; one scope holds at most ``max_open`` openings, evicting
its own oldest. Every reason names actions and the deadline only, so it is safe
to put in a receipt.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from ..actions import canonical_action
from ..enforce import Decision
from ..event import SensorEvent
from ..obligation_ledger import FileLedger
from ..obligations import Obligation, parse, subject_of
from ..policy.engine import Rule

_log = logging.getLogger(__name__)

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
    state: Optional[str] = None,
) -> Rule:
    """Rule: refuse a call once an obligation the run opened has lapsed.

    *require* is an obligation list in the JSON shape :func:`~interlock.
    obligations.parse` validates - ``[{"when": ..., "then": ...,
    "within": ...}]`` - so the declarative form compiles to the same rule.

    *on_breach* is ``"escalate"`` (ask a human whether the deficient run may
    continue; the default) or ``"block"``. *max_scopes* and *max_open* bound
    memory and must be positive non-bool integers. *clock* returns the current
    time as a float and defaults to :func:`time.time`; tests pass a fake.

    *state* is an absolute path to a SQLite file that makes the ledger survive
    the process - required for a hook host, which runs one process per call.
    A relative path is refused: a hook's working directory is the agent's, and
    the ledger must not be writable by the thing it is guarding.

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
    if state is not None:
        if not isinstance(state, str) or not state.strip():
            raise ValueError("state must be a non-empty path or None")
        if not os.path.isabs(os.path.expanduser(state)):
            raise ValueError(
                "state must be an absolute path: a hook's working directory is "
                "the agent's, and the ledger must not sit where the guarded "
                "process can move it")

    wanted: List[Obligation] = parse(require)
    if any(item.approvals_only for item in wanted):
        raise ValueError(
            "approvals_only is checked from receipts only: the live event does "
            "not carry an approval. Use `interlock obligations check` for that "
            "obligation, or drop approvals_only.")

    ledgers: Dict[str, List[_Open]] = {}
    lock = threading.Lock()
    durable: Optional[FileLedger] = None
    durable_failed = False

    def _refuse(obligation: Obligation, opened_at: float, now: float) -> Decision:
        reason = "obligation: {} not followed by {} within {} (open {:.0f}s)".format(
            obligation.when, obligation.then, _deadline(obligation.within),
            now - opened_at)
        if on_breach == "block":
            return Decision.block(reason=reason, policy_id=POLICY_ID)
        return Decision.escalate(reason=reason, policy_id=POLICY_ID)

    def _memory_apply(scope: str, action: str, now: float) -> Optional[Tuple[Obligation, float]]:
        """The in-process ledger; returns the breached obligation, if any."""
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
            for position, entry in enumerate(ledger):
                if action == wanted[entry[0]].then:
                    del ledger[position]
                    break

            # 2. Expire: the oldest lapsed obligation refuses this call, once.
            for position, entry in enumerate(ledger):
                if now > entry[2]:
                    lapsed = ledger.pop(position)
                    return wanted[lapsed[0]], lapsed[1]

            # 3. Open: a trigger action starts its clock.
            for index, obligation in enumerate(wanted):
                if action != obligation.when:
                    continue
                if len(ledger) >= max_open:
                    # Bounded memory beats completeness: the log still holds it.
                    ledger.pop(0)
                ledger.append((index, now, now + obligation.within))
            return None

    def _apply(scope: str, action: str, now: float) -> Optional[Tuple[Obligation, float]]:
        """Apply one call to the durable ledger, falling back on a storage fault."""
        nonlocal durable, durable_failed
        if state is None:
            return _memory_apply(scope, action, now)
        if durable is None and not durable_failed:
            try:
                durable = FileLedger(state)
            except Exception as exc:  # a state file that cannot be opened
                durable_failed = True
                _log.warning(
                    "interlock: obligation ledger %s unavailable (%s); the rule "
                    "falls back to a process-local ledger", state, exc)
        if durable is not None:
            try:
                return durable.apply(scope, action, wanted, now,
                                     max_scopes=max_scopes, max_open=max_open)
            except Exception as exc:  # locked, full disk, a corrupted file
                durable, durable_failed = None, True
                _log.warning(
                    "interlock: obligation ledger %s failed (%s); the rule falls "
                    "back to a process-local ledger", state, exc)
        return _memory_apply(scope, action, now)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "phase", "call") != "call":
            return None
        action = canonical_action(getattr(event, "action", None))
        if not action:
            return None
        scope = subject_of(event)
        now = float(now_fn())

        breach = _apply(scope, action, now)
        if breach is None:
            return None
        return _refuse(breach[0], breach[1], now)

    return rule


__all__ = ["DEFAULT_MAX_OPEN", "DEFAULT_MAX_SCOPES", "ON_BREACH", "POLICY_ID",
           "obligations"]
