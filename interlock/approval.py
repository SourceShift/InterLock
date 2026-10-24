"""Human approval for ESCALATE verdicts, bound to the exact call.

An ESCALATE says "this call is legal, but a person must decide". Approval is
where hand-rolled guards usually go wrong, so this module fixes the rules:

- **An approval covers one exact request.** The request is bound to the action,
  the phase, a digest of the arguments that will run, the principal, the
  working directory, the policy that decided (its epoch) and the reason shown
  to the approver. Approving ``rm -rf build`` does not approve ``rm -rf src``,
  nor the same call from another directory; a reload of the policy invalidates
  every grant issued under the old one.
- **One use by default.** A plain ``True`` from the approver runs this call
  once. Wider scopes are explicit and closed: :func:`approve_for_session`
  (the rest of this span) or :func:`approve_for` (a number of seconds). Either
  still only matches the same bound request.
- **The reason is frozen.** It is cut to one line of at most
  :data:`MAX_REASON_BYTES` bytes before the approver sees it, and that exact
  text is part of the binding, so it cannot change after review.
- **A block always wins.** The engine only returns ESCALATE when no rule
  blocked, so an approval can never override a BLOCK.
- **No approver means blocked.** With no approver installed, a declining
  approver, an approver that raises, or a policy that changed while the
  approver was deciding, the call raises :class:`~interlock.enforce.NotApproved`.

Every outcome is a receipt: ``policy_verdict="ESCALATE"`` with ``verdict``
ALLOW, MODIFY or BLOCK and an ``approval`` field saying how it was settled.

Same-process limit: the approver runs in the agent's process, so code that is
already malicious there can install an approver of its own. That is the same
trust boundary as every in-process rule (see the security model). For a
boundary the agent cannot reach, approve outside its process - the coding-agent
hook adapters hand ESCALATE to the agent's native approval prompt.
"""
from __future__ import annotations

import copy
import secrets
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Callable, List, Optional, Tuple, Union

from .enforce import Decision, NotApproved, Verdict
from .event import SensorEvent
from .receipt import digest_args, emit_receipt

#: Longest escalation reason, in UTF-8 bytes, an approver is shown.
MAX_REASON_BYTES = 512

#: Grant scopes.
ONCE, SESSION, TTL = "once", "session", "ttl"

#: Most grants a :class:`GrantStore` keeps; beyond this the oldest go first.
MAX_GRANTS = 1024


def bound_reason(reason: str) -> str:
    """One printable line of at most :data:`MAX_REASON_BYTES` UTF-8 bytes."""
    line = " ".join(str(reason or "").split())
    line = "".join(ch for ch in line if ch.isprintable())
    encoded = line.encode("utf-8")
    if len(encoded) <= MAX_REASON_BYTES:
        return line
    return encoded[:MAX_REASON_BYTES].decode("utf-8", "ignore")


@dataclass(frozen=True)
class ApprovalRequest:
    """What an approver is asked to decide. Frozen: it cannot be edited after
    the approver has seen it.

    ``event`` is the full call, so an approver can show a human what they are
    approving. It never reaches a receipt; receipts carry ``args_digest``.
    """

    request_id: str
    action: str
    phase: str
    args_digest: str
    reason: str
    principal: Optional[str] = None
    span_id: Optional[str] = None
    call_id: Optional[str] = None
    policy_id: Optional[str] = None
    attributed_to: Optional[str] = None
    policy_epoch: Optional[str] = None
    cwd: Optional[str] = None
    created: float = 0.0
    event: Optional[SensorEvent] = field(default=None, repr=False, compare=False)

    @property
    def binding(self) -> Tuple[object, ...]:
        """The fields an approval is bound to.

        ``cwd`` is last so a grant approved for "publish in this directory"
        cannot be reused for the identical call made from another one.
        """
        return (self.action, self.phase, self.args_digest, self.principal,
                self.policy_epoch, self.policy_id, self.reason, self.cwd)


@dataclass(frozen=True)
class Approval:
    """An approver's yes, with its scope. Build one with the helpers below."""

    scope: str = ONCE
    ttl: Optional[float] = None


@dataclass(frozen=True)
class Declined:
    """An approver's no, with what the caller should be told (a review id and
    the next step, say). ``pending`` marks "not yet decided" rather than "no"."""

    reason: str = ""
    pending: bool = False


def approve_once() -> Approval:
    """Approve this call, once."""
    return Approval(ONCE)


def approve_for_session() -> Approval:
    """Approve this exact request for the rest of the current span."""
    return Approval(SESSION)


def approve_for(seconds: float) -> Approval:
    """Approve this exact request for ``seconds`` from now."""
    if not seconds or seconds <= 0:
        raise ValueError("approve_for needs a positive number of seconds")
    return Approval(TTL, float(seconds))


#: An approver gets a request and returns True / an Approval to approve, or
#: False / None / a Declined to decline.
Approver = Callable[[ApprovalRequest], Union[bool, Approval, "Declined", None]]


@dataclass
class Grant:
    """A stored approval wider than one use."""

    grant_id: str
    binding: Tuple[object, ...]
    scope: str
    action: str
    principal: Optional[str]
    session: Optional[str]
    created: float
    expires: Optional[float] = None
    state: str = "active"  # active | expired | revoked
    uses: int = 0


class GrantStore:
    """The process's active session and TTL grants. Thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._grants: List[Grant] = []

    def match(self, request: ApprovalRequest, now: Optional[float] = None) -> Optional[Grant]:
        now = time.time() if now is None else now
        with self._lock:
            self._prune_locked(now)
            for grant in self._grants:
                if grant.state != "active":
                    continue
                if grant.binding != request.binding:
                    continue
                if grant.scope == SESSION and (
                    request.span_id is None or grant.session != request.span_id
                ):
                    continue
                grant.uses += 1
                return grant
        return None

    def add(self, grant: Grant) -> None:
        with self._lock:
            self._grants.append(grant)
            self._prune_locked(time.time())

    def prune(self, now: Optional[float] = None) -> None:
        """Drop expired and revoked grants, then the oldest above :data:`MAX_GRANTS`."""
        now = time.time() if now is None else now
        with self._lock:
            self._prune_locked(now)

    def _prune_locked(self, now: float) -> None:
        """The body of :meth:`prune`; the caller holds ``self._lock``."""
        live: List[Grant] = []
        for grant in self._grants:
            if grant.state in ("expired", "revoked"):
                continue
            if grant.expires is not None and now >= grant.expires:
                grant.state = "expired"
                continue
            live.append(grant)
        if len(live) > MAX_GRANTS:
            live.sort(key=lambda grant: grant.created)
            live = live[-MAX_GRANTS:]
        self._grants = live

    def revoke(self, *, action: Optional[str] = None,
               principal: Optional[str] = None,
               session: Optional[str] = None) -> int:
        """Revoke active grants matching every filter given; return how many."""
        count = 0
        with self._lock:
            for grant in self._grants:
                if grant.state != "active":
                    continue
                if action is not None and grant.action != action:
                    continue
                if principal is not None and grant.principal != principal:
                    continue
                if session is not None and grant.session != session:
                    continue
                grant.state = "revoked"
                count += 1
        return count

    def active(self) -> List[Grant]:
        now = time.time()
        with self._lock:
            self._prune_locked(now)
            return [replace(g) for g in self._grants if g.state == "active"]

    def clear(self) -> None:
        with self._lock:
            self._grants.clear()


_approver: Optional[Approver] = None
_store = GrantStore()


def set_approver(approver: Optional[Approver]) -> None:
    """Install (or with None, remove) the process approver for ESCALATE."""
    global _approver
    _approver = approver


def get_approver() -> Optional[Approver]:
    return _approver


def grants() -> GrantStore:
    """The process grant store (list, revoke or clear session/TTL grants)."""
    return _store


def merged_args(event: SensorEvent, decision: Decision) -> dict:
    """The arguments the call will run with: the event's args with the
    decision's rewrites applied (a ``modified_args`` key wins)."""
    args = dict(getattr(event, "args", None) or {})
    if decision.modified_args:
        args.update(decision.modified_args)
    return args


def make_request(event: SensorEvent, decision: Decision, epoch: Optional[str],
                 *, effective_args: Optional[dict] = None) -> ApprovalRequest:
    """Bind an approval to the arguments the call will actually run.

    With ``effective_args`` omitted the event's args and the decision's
    rewrites are merged here, so an approver shown this request sees the
    rewritten call rather than the pre-rewrite one.
    """
    args = dict(effective_args) if effective_args is not None else merged_args(event, decision)
    if args == getattr(event, "args", None):
        shown = event
    else:
        # A shallow copy keeps attributes a rule stamped on the event (the
        # token estimate, say) that ``dataclasses.replace`` would drop.
        shown = copy.copy(event)
        shown.args = args
    return ApprovalRequest(
        request_id=secrets.token_hex(8),
        action=event.action,
        phase=getattr(event, "phase", "call"),
        args_digest=digest_args(args),
        reason=bound_reason(decision.reason),
        principal=event.principal,
        span_id=event.span_id,
        call_id=getattr(event, "call_id", None),
        policy_id=decision.policy_id,
        attributed_to=decision.attributed_to,
        policy_epoch=epoch,
        cwd=getattr(event, "cwd", None),
        created=time.time(),
        event=shown,
    )


def settle_escalation(
    event: SensorEvent,
    decision: Decision,
    *,
    epoch: Optional[str],
    current_epoch: Callable[[], Optional[str]],
    elapsed_us: Optional[int] = None,
    approver: Optional[Approver] = None,
) -> Decision:
    """Ask for (or reuse) an approval; return what the call proceeds with.

    Returns an ALLOW, or a MODIFY carrying the escalation's rewrites, when
    approved. Raises :class:`NotApproved` otherwise. Writes one receipt either
    way.
    """
    request = make_request(event, decision, epoch)
    proceed = _proceed(decision)
    effective_event = request.event or event

    def record(verdict_decision: Decision, how: str) -> None:
        emit_receipt(
            effective_event, verdict_decision, policy_epoch=epoch, policy_verdict="ESCALATE",
            approval=how, elapsed_us=elapsed_us,
        )

    def refuse(how: str, why: str) -> None:
        refused = Decision(
            Verdict.BLOCK, "not approved ({}): {}".format(why, request.reason),
            decision.policy_id, attributed_to=decision.attributed_to,
        )
        record(refused, how)
        raise NotApproved(refused, event.action)

    grant = _store.match(request)
    if grant is not None:
        record(proceed, "reused:" + grant.scope)
        return proceed

    chosen = approver if approver is not None else get_approver()
    if chosen is None:
        refuse("no-approver", "no approver is installed")
        raise AssertionError("unreachable")
    try:
        answer = chosen(request)
    except Exception as exc:  # an approver that fails has not approved
        refuse("approver-error", "approver raised {}".format(type(exc).__name__))
        raise  # refuse() always raises; this keeps the type checker honest
    if isinstance(answer, Declined):
        refuse("pending" if answer.pending else "declined",
               bound_reason(answer.reason) or "declined by the approver")
        raise AssertionError("unreachable")
    approval = _normalise(answer)
    if approval is None:
        refuse("declined", "declined by the approver")
        raise AssertionError("unreachable")
    if current_epoch() != epoch:
        refuse("declined", "the policy changed while the approval was pending")

    scope = approval.scope
    if scope == SESSION and event.span_id is None:
        scope = ONCE  # a session grant needs a span to bind to
    if scope in (SESSION, TTL):
        now = time.time()
        _store.add(Grant(
            grant_id=secrets.token_hex(8),
            binding=request.binding,
            scope=scope,
            action=request.action,
            principal=request.principal,
            session=request.span_id if scope == SESSION else None,
            created=now,
            expires=now + approval.ttl if scope == TTL and approval.ttl else None,
        ))
    record(proceed, "approved:" + scope)
    return proceed


def _proceed(decision: Decision) -> Decision:
    """The decision an approved escalation runs under: its rewrites, if any."""
    if decision.modified_args or decision.modified_result is not None:
        return Decision(
            Verdict.MODIFY, decision.reason, decision.policy_id,
            decision.modified_args, attributed_to=decision.attributed_to,
            modified_result=decision.modified_result,
        )
    return Decision(Verdict.ALLOW, decision.reason, decision.policy_id,
                    attributed_to=decision.attributed_to)


def _normalise(answer: object) -> Optional[Approval]:
    if answer is True:
        return Approval(ONCE)
    if isinstance(answer, Approval):
        if answer.scope not in (ONCE, SESSION, TTL):
            return None
        if answer.scope == TTL and not answer.ttl:
            return None
        return answer
    return None


def tty_approver(*, show_args: bool = True, max_chars: int = 2000) -> Approver:
    """An approver that asks the human at the controlling terminal.

    It reads ``/dev/tty`` directly, never stdin, so piped input (or an agent
    writing to the process's stdin) cannot answer for the human. With no
    terminal it declines. Answers: ``y`` once, ``s`` for the session, anything
    else declines.
    """

    def approver(request: ApprovalRequest) -> Union[Approval, None]:
        try:
            tty = open("/dev/tty", "r+", encoding="utf-8")
        except OSError:
            return None
        with tty:
            lines = [
                "",
                "interlock: approval needed",
                "  action : {}{}".format(request.action,
                                         "" if request.phase == "call" else " (result)"),
                "  reason : {}".format(request.reason),
            ]
            if request.attributed_to:
                lines.append("  field  : {}".format(request.attributed_to))
            if request.principal:
                lines.append("  agent  : {}".format(request.principal))
            if show_args and request.event is not None:
                lines.append("  args   : {}".format(_printable(request.event.args, max_chars)))
            lines.append("Approve? [y] once, [s] this session, [N]o: ")
            tty.write("\n".join(lines))
            tty.flush()
            answer = tty.readline().strip().lower()
        if answer in ("y", "yes"):
            return approve_once()
        if answer in ("s", "session"):
            return approve_for_session()
        return None

    return approver


def _printable(value: object, limit: int) -> str:
    text = repr(value)
    text = "".join(ch if ch.isprintable() else "\\x{:02x}".format(ord(ch)) for ch in text)
    return text if len(text) <= limit else text[:limit] + "..."


def is_interactive() -> bool:
    """Whether a controlling terminal exists for :func:`tty_approver`."""
    try:
        with open("/dev/tty", "r"):
            return True
    except OSError:
        return False
