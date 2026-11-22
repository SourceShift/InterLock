"""Obligations: what must happen *after* something did, inside a deadline.

Every other rule in interlock forbids an action. An obligation binds the other
way: "after a deploy, an approval must be referenced within ten minutes" is not
a prohibition - the deploy is fine, and only the missing follow-up makes the run
deficient. Two things are needed to judge that, and neither is visible in a
single event: a clock, and the evidence that the follow-up happened.

Both live here. :func:`evaluate` reads a receipt log and reports, per opening,
whether the discharge arrived inside the deadline, arrived late, or never
arrived; :func:`interlock.detectors.obligations.obligations` applies the same
model to a live call stream, so a run that ignored an obligation meets a
refusal on its next call instead of only in an audit.

An obligation names *actions*, never arguments: receipts store
``args_digest``, and a rule that has to look inside an argument to decide
whether a promise was kept cannot be answered from a log. ``approvals_only``
asks the discharge receipt to carry an ``approval`` (an escalation a human or a
grant settled), which is the one follow-up the receipt already records.

Scope is the same identity ``sequence_guard`` uses - the event's ``span_id``
(one agent run), falling back to ``principal``, then to ``"<anon>"`` - so a
sequence and an obligation over the same run agree about what "the same agent"
means.
"""
from __future__ import annotations

import dataclasses
import math
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from .actions import canonical_action

POLICY_ID = "obligation"

#: Identity used when an event carries neither a span id nor a principal. Kept
#: equal to ``sequence_guard.ANON`` on purpose: one run, one name.
ANON = "<anon>"

#: Obligation states. ``breached`` covers both "never discharged" and
#: "discharged late": the deadline passed while the obligation was open.
PENDING = "pending"
DISCHARGED = "discharged"
BREACHED = "breached"
STATES = (PENDING, DISCHARGED, BREACHED)

#: The keys an obligation entry may carry. An unknown key is refused rather
#: than ignored: a misspelled ``within`` that quietly defaulted would produce
#: an obligation that never fires, which is the worst kind.
_KEYS = frozenset({"when", "then", "within", "policy_id", "approvals_only"})

#: Verdicts that mean the action ran. A BLOCK did not, so it opens nothing and
#: discharges nothing - the trigger never happened.
_RAN = ("ALLOW", "MODIFY")


@dataclasses.dataclass(frozen=True)
class Obligation:
    """``when`` must be followed by ``then`` within ``within`` seconds."""

    when: str
    then: str
    within: float
    policy_id: str = POLICY_ID
    approvals_only: bool = False

    def describe(self) -> str:
        tail = " with an approval" if self.approvals_only else ""
        return "{} -> {}{} within {}s".format(
            self.when, self.then, tail, _seconds(self.within))


@dataclasses.dataclass(frozen=True)
class Status:
    """One opening of an obligation and how it was (or was not) kept."""

    obligation: Obligation
    scope: str
    opened_at: float
    required_by: float
    state: str
    opened_at_index: int = 0
    discharged_at: Optional[float] = None
    discharged_at_index: Optional[int] = None

    @property
    def late(self) -> bool:
        return self.state == BREACHED and self.discharged_at is not None

    def describe(self) -> str:
        if self.state == DISCHARGED:
            return "{}: {} discharged after {:.0f}s".format(
                self.scope, self.obligation.describe(),
                self.discharged_at - self.opened_at if self.discharged_at is not None else 0)
        if self.state == PENDING:
            return "{}: {} still open ({}s left)".format(
                self.scope, self.obligation.describe(), max(0, round(self.required_by - self.opened_at)))
        if self.late:
            return "{}: {} breached - discharged late".format(
                self.scope, self.obligation.describe())
        return "{}: {} breached - never discharged".format(
            self.scope, self.obligation.describe())


def _seconds(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else str(value)


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def parse(spec: Any) -> List[Obligation]:
    """Validate a JSON-shaped obligation list into :class:`Obligation` objects.

    Accepts a bare list or ``{"obligations": [...]}``. Every entry must be an
    object with ``when``, ``then`` and a positive ``within``; ``policy_id`` and
    ``approvals_only`` are optional. Action names are canonicalised, so
    ``http.post`` and ``http_post`` are one action. Anything malformed raises
    ``ValueError`` naming the entry - an obligation that silently never fires is
    worse than one that refuses to load.
    """
    if isinstance(spec, Mapping):
        unknown = set(spec) - {"obligations"}
        if unknown:
            raise ValueError("unknown key(s) {} beside 'obligations'".format(
                ", ".join(sorted(repr(key) for key in unknown))))
        entries = spec.get("obligations")
        if not isinstance(entries, (list, tuple)):
            raise ValueError("'obligations' must be a list")
    elif isinstance(spec, (list, tuple)):
        entries = spec
    elif isinstance(spec, str):
        raise ValueError("obligations must be a list of objects, not a string")
    else:
        raise ValueError("obligations must be a list of objects")
    if not entries:
        raise ValueError("an obligation list names at least one obligation")

    out: List[Obligation] = []
    for index, entry in enumerate(entries):
        where = "obligation {}".format(index)
        if not isinstance(entry, Mapping):
            raise ValueError("{} must be an object".format(where))
        extra = set(entry) - _KEYS
        if extra:
            raise ValueError("{}: unknown key(s) {} (valid: {})".format(
                where, ", ".join(sorted(repr(key) for key in extra)),
                ", ".join(sorted(_KEYS))))
        when = canonical_action(entry.get("when"))
        then = canonical_action(entry.get("then"))
        if not when or not then:
            raise ValueError("{}: 'when' and 'then' must be non-empty action names".format(
                where))
        if when == then:
            raise ValueError(
                "{}: 'then' must differ from 'when' - a call that opens its own "
                "obligation can never fail it".format(where))
        within = _number(entry.get("within"))
        if within is None or within <= 0:
            raise ValueError("{}: 'within' must be a positive number of seconds".format(where))
        policy_id = entry.get("policy_id", POLICY_ID)
        if not isinstance(policy_id, str) or not policy_id:
            raise ValueError("{}: 'policy_id' must be a non-empty string".format(where))
        approvals_only = entry.get("approvals_only", False)
        if not isinstance(approvals_only, bool):
            raise ValueError("{}: 'approvals_only' must be true or false".format(where))
        out.append(Obligation(when=when, then=then, within=within,
                              policy_id=policy_id, approvals_only=approvals_only))
    return out


def subject_of(event_or_receipt: Any) -> str:
    """The scope an event or receipt belongs to (span id, principal, ``<anon>``)."""
    span_id = getattr(event_or_receipt, "span_id", None)
    if isinstance(span_id, str) and span_id:
        return span_id
    principal = getattr(event_or_receipt, "principal", None)
    if isinstance(principal, str) and principal:
        return principal
    return ANON


def evaluate(receipts: Iterable[Any], obligations: Sequence[Obligation], *,
             now: Optional[float] = None,
             scope_of: Optional[Any] = None) -> List[Status]:
    """Report every opening of every obligation found in a receipt log.

    *receipts* is read in the order it is given (a log is append-ordered). Only
    ``phase="call"`` receipts whose verdict means the call ran open or
    discharge an obligation: a ``BLOCK`` receipt records an action that never
    happened, and a ``pending:``/``declined:`` escalation was not an approval.
    Receipts are grouped by :func:`subject_of`, so one agent run's deploy cannot
    be discharged by another run's write.

    *now* is the clock the still-open obligations are judged against. It
    defaults to the newest receipt's ``ts``, which makes two runs over the same
    log agree; pass ``time.time()`` when "has it lapsed yet" is what you asked.
    *scope_of* overrides the grouping function (both a SensorEvent and a Receipt
    work out of the box).
    """
    if not obligations:
        return []
    subject = scope_of or subject_of
    open_by: Dict[int, List[Status]] = {}
    found: List[Status] = []
    newest: Optional[float] = None

    def _settle(index: int, opened: Status, **changes: Any) -> None:
        # `status` is a frozen dataclass, so equality is by value: remove the
        # open entry by identity, then record the settled copy.
        open_by[index][:] = [entry for entry in open_by[index] if entry is not opened]
        found.append(dataclasses.replace(opened, **changes))

    for index, receipt in enumerate(receipts):
        ts = _number(getattr(receipt, "ts", None))
        if ts is None:
            continue
        newest = ts if newest is None else max(newest, ts)
        if getattr(receipt, "phase", "call") != "call":
            continue
        if getattr(receipt, "verdict", None) not in _RAN:
            continue
        action = canonical_action(getattr(receipt, "action", None))
        if not action:
            continue
        scope = subject(receipt)

        # Discharge first: one call can close an earlier opening and, when its
        # action is a trigger for something else, open its own.
        for ob_index, obligation in enumerate(obligations):
            pending = [status for status in open_by.get(ob_index, [])
                       if status.scope == scope and status.state == PENDING]
            if not pending:
                continue
            if action != obligation.then:
                continue
            if obligation.approvals_only and not getattr(receipt, "approval", None):
                continue
            status = pending[0]
            state = BREACHED if ts > status.required_by else DISCHARGED
            _settle(ob_index, status, state=state, discharged_at=ts,
                    discharged_at_index=index)

        for ob_index, obligation in enumerate(obligations):
            if action == obligation.when:
                open_by.setdefault(ob_index, []).append(Status(
                    obligation=obligation, scope=scope, opened_at=ts,
                    required_by=ts + obligation.within, state=PENDING,
                    opened_at_index=index))

    clock = newest if now is None else now
    if clock is not None:
        for ob_index, statuses in open_by.items():
            for status in list(statuses):
                if clock > status.required_by:
                    _settle(ob_index, status, state=BREACHED)
    # Whatever is still open is pending as of `clock`.
    for statuses in open_by.values():
        found.extend(statuses)
    found.sort(key=lambda status: (status.opened_at_index, status.scope))
    return found


def counts(statuses: Iterable[Status]) -> Dict[str, int]:
    """How many openings are in each state, every state present."""
    out = {state: 0 for state in STATES}
    for status in statuses:
        out[status.state] = out.get(status.state, 0) + 1
    return out


__all__ = [
    "ANON",
    "BREACHED",
    "DISCHARGED",
    "Obligation",
    "PENDING",
    "POLICY_ID",
    "STATES",
    "Status",
    "counts",
    "evaluate",
    "parse",
    "subject_of",
]
