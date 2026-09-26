"""MCP capability lease: a grant that expires, enforced at call time.

Every other MCP policy in this package is a standing licence. The allowlist
admits a host forever once it is listed, the trust registry and tool pinning
never ask when the review happened, and the consent budget counts *uses* -
none of them can answer "was this grant still valid when the call happened?".
An operator's yes from a review three months ago is enforced identically
today, with no way to make it lapse short of editing policy and restarting.
That is the gap this Rule closes: a capability grant becomes a :class:`Lease`
- an immutable (subject, capability, issued_at, expires_at) value - and the
rule denies the next call whose grant has lapsed, with a reason that says
*expired* rather than merely *denied*, because the operator's next action
(renew, or review from scratch) depends on which.

Order is load-bearing, in both directions. Install this rule ahead of the
``mcp_*`` rules so its denial is the one the caller sees - a later allowlist
or pinning rule would otherwise block first and mask the expiry with its own
reason. And while a lease holds the rule returns None, never
``Decision.allow()``: the engine returns the first non-ALLOW decision, and a
rule that stayed silent only because the grant holds must not silence the
rest of the MCP suite. A live lease means "judge the call on its merits",
not "let it through".

Semantics:

- subject: resolved the way ``mcp_trust_registry`` resolves an origin - an
  explicit ``args["__origin__"]`` label first (per-call, and not chosen by
  the untrusted server), else the prefix of a dotted action name
  (``"github.create_issue"`` -> ``"github"``). An event that names no
  subject at all is out of scope: this rule leases servers, and a call that
  cannot name one is left to the rules that police that failure.
- capability: the event's full action name. A lease covers an event when the
  subjects are equal and the lease's capability is that action name, or
  :data:`ANY_CAPABILITY` - a grant over every capability on the subject.
- boundary: a lease is live on the half-open interval
  ``issued_at <= ts < expires_at``. Exactly at ``expires_at`` it is DEAD -
  the last tick before expiry passes, the tick at or after denies. The
  deadline is the first refused instant, which is how an operator reads it.
- time: checked against ``event.ts`` - when the action happened - never a
  wall clock. This module imports no clock at all, which is what makes the
  boundary testable without sleeping.

State lives in a :class:`LeaseRegistry` the caller constructs and passes in,
unlike the closure state of ``mcp_consent_budget`` and ``host_fanout_guard``:
a registry must outlive a single event and be shareable by several rules, and
closure state cannot be shared on purpose. Two registries never share
grants; two rules built around one registry see one grant store. Every read
and write takes a lock, so concurrent calls on a shared registry are safe.
The rule itself never mutates the registry - state changes only through
:meth:`LeaseRegistry.issue` and :meth:`LeaseRegistry.renew`.

Renewing: renewal is an explicit re-issue, not a silent slide. When a lease
lapses, call ``registry.renew(subject, capability, issued_at, expires_at)``
with the new window (typically now and now + ttl) and the next call is
covered again. Without a renewal path, the first expiry that breaks a
healthy deployment gets the lease turned off - renewal is what keeps
time-boxed trust usable at all.

Trust boundary: ``SensorEvent.ts`` is set by the sensor, never by the tool
or its caller. A caller-supplied future ``ts`` would extend every lease at
once, so an adapter must not forward caller-controlled timestamps into
events - the lease clock is exactly as trustworthy as the event clock.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "mcp_capability_lease"

# The args key an adapter uses to label a call with its server origin.
_ORIGIN_KEY = "__origin__"

# The action-name separator that introduces a dotted origin prefix.
_ORIGIN_SEPARATOR = "."

# A lease capability that covers every action on the leased subject.
ANY_CAPABILITY = "*"

# Registry keys are (subject, capability) pairs.
_LeaseKey = Tuple[str, str]


@dataclass(frozen=True)
class Lease:
    """One capability grant: who, what, and the window it is valid for.

    An immutable value. Issuing or renewing replaces the stored lease, it
    never edits one in place, so a lease observed by a concurrent reader can
    never change under it. ``expires_at`` must be strictly after
    ``issued_at``: a lease dead on arrival is an operator error, refused at
    construction rather than silently never covering anything.
    """

    subject: str
    capability: str
    issued_at: float
    expires_at: float

    def __post_init__(self) -> None:
        if not self.expires_at > self.issued_at:
            raise ValueError(
                "expires_at must be after issued_at: {!r} <= {!r}".format(
                    self.expires_at, self.issued_at
                )
            )

    def covers(self, at: float) -> bool:
        """Is the lease live at `at`? Half-open: issued_at <= at < expires_at."""
        return self.issued_at <= at < self.expires_at


class LeaseRegistry:
    """The grant store: issue, renew, and look up leases per (subject,
    capability).

    Construct one, pass the same object to every rule that must agree on the
    same grants (the four ``mcp_*`` detectors and this rule should all sit
    behind one registry), and renew through it when a lease lapses. All
    access takes a lock, so sharing one registry across rules and threads is
    safe.
    """

    def __init__(self) -> None:
        self._leases: Dict[_LeaseKey, Lease] = {}
        self._lock = threading.Lock()

    def issue(
        self, subject: str, capability: str, issued_at: float, expires_at: float
    ) -> Lease:
        """Grant a fresh lease, replacing any previous one for the same key."""
        lease = Lease(subject, capability, issued_at, expires_at)
        with self._lock:
            self._leases[(subject, capability)] = lease
        return lease

    def renew(
        self, subject: str, capability: str, issued_at: float, expires_at: float
    ) -> Lease:
        """Re-issue a lapsed (or still-live) lease with a new window.

        Renewal is how a lapsed grant is re-armed without touching the
        rules: the stored lease is replaced by a fresh one covering
        ``[issued_at, expires_at)``. Refused with KeyError when no lease was
        ever issued for the key - there is nothing to renew, and silently
        manufacturing a first grant under the name of a renewal would hide
        that this registry never approved the capability at all.
        """
        with self._lock:
            if (subject, capability) not in self._leases:
                raise KeyError(
                    "no lease to renew for {}/{}".format(subject, capability)
                )
            lease = Lease(subject, capability, issued_at, expires_at)
            self._leases[(subject, capability)] = lease
        return lease

    def inspect(
        self, subject: str, capability: str, at: float
    ) -> Tuple[Optional[Lease], Optional[Lease]]:
        """Return (live lease covering `at`, latest issued lease), or Nones.

        The two reads happen under one lock so a renewal between them cannot
        be observed half-applied. An exact-capability lease is preferred over
        an :data:`ANY_CAPABILITY` one for both slots: the rule uses the
        second element to tell an *expired* grant from a *never issued* one,
        because the operator's next action differs - renew, versus review
        and issue. Read-only: the rule consults, it never mutates.
        """
        covering: Optional[Lease] = None
        latest: Optional[Lease] = None
        with self._lock:
            for key in ((subject, capability), (subject, ANY_CAPABILITY)):
                lease = self._leases.get(key)
                if lease is None:
                    continue
                if latest is None:
                    latest = lease
                if covering is None and lease.covers(at):
                    covering = lease
        return covering, latest


def _origin_from_args(args: Any) -> Optional[str]:
    """Resolve an explicit ``args["__origin__"]`` label, if it is usable.

    Args are attacker-influenced and may be anything - None, an int, a list.
    A non-mapping args, a missing key, a non-str or blank label all mean "no
    label here", so the caller falls through to the dotted-name source.
    """
    if not isinstance(args, dict):
        return None
    origin = args.get(_ORIGIN_KEY)
    if isinstance(origin, str) and origin.strip():
        return origin
    return None


def _origin_from_action(action: Any) -> Optional[str]:
    """Resolve the origin prefix of a dotted action name, if there is one.

    ``"github.create_issue"`` -> ``"github"``. Splitting on the first
    separator keeps the origin a single segment, so ``"github.repo.delete"``
    is still the ``github`` server. A non-str action, or one with no
    separator or an empty prefix (``".evil"``), yields None.
    """
    if not isinstance(action, str):
        return None
    origin, separator, _ = action.partition(_ORIGIN_SEPARATOR)
    if separator and origin:
        return origin
    return None


def _resolve_subject(event: SensorEvent) -> Tuple[Optional[str], Optional[str]]:
    """Resolve the server this event belongs to; return (subject, arg key).

    The arg key is ``__origin__`` when the subject was read from an explicit
    label, else None when it was inferred from the dotted action name - an
    inferred subject names no argument, so a denial cannot attribute one.
    Both None means the event names no subject this rule leases.
    """
    labelled = _origin_from_args(event.args)
    if labelled is not None:
        return labelled, _ORIGIN_KEY
    return _origin_from_action(event.action), None


def mcp_capability_lease(registry: LeaseRegistry) -> Rule:
    """Rule: deny a call whose lease has lapsed; stay silent while it holds.

    Returns None when a lease covering the event's subject and action is
    live at ``event.ts`` - silence, not ``Decision.allow()``, so the rules
    after this one still judge the call. Blocks when no lease covers the
    event: because the grant expired (the reason names the instant it
    lapsed), because it has not come into force yet (the reason names the
    instant it starts), or because none was ever issued (the reason says
    so). Install this rule ahead of the other ``mcp_*`` rules so the expiry,
    not a downstream policy's reason, is what the operator sees.
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        subject, attributed = _resolve_subject(event)
        if subject is None:
            return None
        action = event.action
        covering, latest = registry.inspect(subject, action, event.ts)
        if covering is not None:
            return None
        if latest is None:
            reason = "{}: no lease issued for {}/{}".format(
                POLICY_ID, subject, action
            )
        elif event.ts < latest.issued_at:
            reason = "{}: lease for {}/{} not in force until {}".format(
                POLICY_ID, subject, action, latest.issued_at
            )
        else:
            reason = "{}: lease for {}/{} expired at {}".format(
                POLICY_ID, subject, action, latest.expires_at
            )
        return Decision.block(reason, policy_id=POLICY_ID, attributed_to=attributed)

    return rule
