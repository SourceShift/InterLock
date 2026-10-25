"""Protection attestation: is this process actually guarded, and how well?

interlock's most dangerous state is silent. Never call ``install()`` and the
default engine allows everything; wrap tools with ``@monitor()`` and nothing is
enforced; install a ``FileSink`` without a key and nobody can verify the log
after a restart. None of these look wrong from the outside.

:func:`attest` reads the live runtime and reports one :class:`Check` per
setting that weakens protection - every row of the security model's
"Settings that weaken protection" table maps to a check id in
:data:`WEAKENING_SETTINGS`, and a test keeps the two in step - plus a few
health signals. :func:`require` turns the report into a startup assertion::

    interlock.install(rules=[...], sink=FileSink(path, key=key))
    interlock.posture.require()          # raises ProtectionError if unprotected

``attest`` is read-only: no side effects, no network. The sidecar probe (only
when asked for) opens the local unix socket and nothing else.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

OK, INFO, WARN, FAIL = "ok", "info", "warn", "fail"

#: Posture levels, weakest first.
LEVELS = ("unprotected", "degraded", "enforced")

#: Security-model "Settings that weaken protection" row -> check id.
WEAKENING_SETTINGS: Dict[str, str] = {
    "Never calling `install()`": "engine.installed",
    '`enforcement="monitor"` / `@monitor()`': "enforcement.monitor",
    "`ScopedEngine(..., allow_unscoped=True)`": "scopes.allow_unscoped",
    "A hand-written rule that can raise": "rules.hand_written",
    "`Sandbox(..., backend=\"soft\")`, or a host where only `soft` is available": "sandbox.backend",
    "Granting hosts to a sandbox profile": "sandbox.hosts",
    "`FileSink(path)` without `key=`": "audit.key",
    "Several processes appending to one audit file at once": "audit.single_writer",
    "`RemoteEngine(..., timeout=None)` (Python or Node.js)": "sidecar.timeout",
    "`RemoteEngine(..., unreachable=\"allow\")` (Python or Node.js)": "sidecar.unreachable",
    "`RemoteEngine(..., unreachable=\"degraded\")` (Python or Node.js)": "sidecar.unreachable",
}


@dataclass(frozen=True)
class Check:
    """One finding. ``status`` is ok, info, warn or fail; ``fix`` is one line."""

    id: str
    status: str
    summary: str
    fix: str = ""


@dataclass(frozen=True)
class Posture:
    checks: Tuple[Check, ...] = field(default_factory=tuple)

    @property
    def level(self) -> str:
        """``unprotected`` if any check fails, ``degraded`` if any warns,
        else ``enforced``."""
        statuses = {c.status for c in self.checks}
        if FAIL in statuses:
            return "unprotected"
        if WARN in statuses:
            return "degraded"
        return "enforced"

    def check(self, check_id: str) -> Optional[Check]:
        return next((c for c in self.checks if c.id == check_id), None)

    def to_dict(self) -> Dict[str, Any]:
        return {"level": self.level, "checks": [asdict(c) for c in self.checks]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def render(self, *, color: bool = False) -> str:
        glyph = {OK: "✓", INFO: "·", WARN: "!", FAIL: "✗"}
        paint = {OK: "32", INFO: "2", WARN: "33", FAIL: "31"}
        lines = ["interlock protection: {}".format(self.level.upper()), ""]
        for c in self.checks:
            mark = glyph.get(c.status, "?")
            if color:
                mark = "\x1b[{}m{}\x1b[0m".format(paint.get(c.status, "0"), mark)
            lines.append("{} {:<24} {}".format(mark, c.id, c.summary))
            if c.fix and c.status in (WARN, FAIL):
                lines.append("  {:<24} fix: {}".format("", c.fix))
        return "\n".join(lines)


class ProtectionError(RuntimeError):
    """Raised by :func:`require` when the posture is below the required level."""

    def __init__(self, posture: Posture, required: str) -> None:
        self.posture = posture
        failing = [c for c in posture.checks if c.status in (WARN, FAIL)]
        detail = "; ".join("{}: {}".format(c.id, c.summary) for c in failing)
        super().__init__(
            "interlock protection is {}, {} required: {}".format(
                posture.level, required, detail)
        )


def attest(
    *,
    engine: Any = None,
    sink: Any = None,
    probe_sidecar: bool = False,
) -> Posture:
    """Report the protection in force. Read-only.

    ``engine`` and ``sink`` default to the process engine and sink. Set
    ``probe_sidecar`` to also check that a ``RemoteEngine``'s daemon answers.
    """
    from . import _runtime
    from .approval import get_approver
    from .receipt import dropped_receipts, get_sink

    checks: List[Check] = []
    installed = _runtime._engine is not None
    active = engine if engine is not None else (_runtime._engine if installed else None)
    checks.append(_engine_check(active, installed or engine is not None))
    checks.append(_epoch_check(active))
    checks.append(_monitor_check())
    checks.append(_unscoped_check(active))
    checks.append(_hand_written_check(active))
    checks.extend(_sandbox_checks())
    the_sink = sink if sink is not None else get_sink()
    checks.extend(_audit_checks(the_sink, dropped_receipts()))
    checks.extend(_sidecar_checks(active, probe_sidecar))
    checks.append(_approver_check(get_approver()))
    return Posture(tuple(checks))


def require(min_level: str = "enforced", **kwargs: Any) -> Posture:
    """Raise :class:`ProtectionError` unless the posture is at ``min_level``.

    ``"enforced"`` (the default) accepts no warnings; ``"degraded"`` accepts
    warnings but no failures. Returns the posture otherwise.
    """
    if min_level not in LEVELS:
        raise ValueError("min_level must be one of {}".format(", ".join(LEVELS)))
    posture = attest(**kwargs)
    if LEVELS.index(posture.level) < LEVELS.index(min_level):
        raise ProtectionError(posture, min_level)
    return posture


# --- individual checks --------------------------------------------------------


def _engine_check(engine: Any, installed: bool) -> Check:
    if not installed or engine is None:
        return Check("engine.installed", FAIL,
                     "install() was never called: every guarded call is allowed",
                     "call interlock.install(rules=[...]) at startup")
    size = _rule_count(engine)
    if size == 0:
        return Check("engine.installed", FAIL,
                     "the installed engine has no rules: every guarded call is allowed",
                     "pass rules=[...] to interlock.install()")
    kind = type(engine).__name__
    if size is None:
        return Check("engine.installed", OK, "{} installed".format(kind))
    return Check("engine.installed", OK, "{} with {} rule(s)".format(kind, size))


def _rule_count(engine: Any) -> Optional[int]:
    if type(engine).__name__ == "PolicyEngine":
        try:
            return len(engine)
        except TypeError:
            return None
    return None


def _epoch_check(engine: Any) -> Check:
    epoch = getattr(engine, "epoch", None)
    if isinstance(epoch, str):
        return Check("engine.epoch", INFO, "policy epoch {}".format(epoch))
    return Check("engine.epoch", INFO, "policy epoch decided per event or by a sidecar")


def _monitor_check() -> Check:
    from .interceptors.decorator import registered_modes

    modes = registered_modes()
    observing = sorted(name for name, mode in modes.items() if mode == "monitor")
    if observing:
        shown = ", ".join(observing[:5]) + (" (+{} more)".format(len(observing) - 5)
                                            if len(observing) > 5 else "")
        return Check("enforcement.monitor", WARN,
                     "{} guarded tool(s) only observe: {}".format(len(observing), shown),
                     "switch @monitor() / enforcement=\"monitor\" to blocking once trialled")
    return Check("enforcement.monitor", OK,
                 "{} guarded tool(s), all enforcing".format(len(modes)))


def _unscoped_check(engine: Any) -> Check:
    if getattr(engine, "allow_unscoped", False):
        return Check("scopes.allow_unscoped", WARN,
                     "calls with no principal are allowed without running any rule",
                     "drop allow_unscoped=True or set a default_scope")
    return Check("scopes.allow_unscoped", OK, "unscoped calls are blocked or scoped")


def _hand_written_check(engine: Any) -> Check:
    rules = getattr(engine, "_rules", None)
    if not isinstance(rules, list):
        return Check("rules.hand_written", INFO, "rule set not inspectable here")
    own = [r for r in rules
           if not str(getattr(r, "__module__", "")).startswith("interlock.")]
    if not own:
        return Check("rules.hand_written", OK, "only built-in rules")
    return Check("rules.hand_written", INFO,
                 "{} hand-written rule(s): one that raises surfaces its own exception, "
                 "not Blocked".format(len(own)),
                 "wrap risky tests in deny_when(), which fails closed")


def _sandbox_checks() -> List[Check]:
    from .brace.backends import available_backends

    backends = available_backends()
    best = backends[0] if backends else "soft"
    if best == "soft":
        backend = Check("sandbox.backend", WARN,
                        "only the soft BRACE backend is available: not a security boundary",
                        "install bubblewrap (Linux) or use macOS sandbox-exec; pass require=")
    else:
        backend = Check("sandbox.backend", OK, "BRACE backend available: {}".format(best))
    hosts = Check("sandbox.hosts", INFO,
                  "a profile that grants hosts gives the child all network on "
                  "bubblewrap/Seatbelt; check each Sandbox's enforced set")
    return [backend, hosts]


def _audit_checks(sink: Any, dropped: int) -> List[Check]:
    checks: List[Check] = []
    if sink is None:
        checks.append(Check("audit.sink", WARN, "no receipt sink: decisions are not recorded",
                            "install(sink=FileSink(path, key=...))"))
        checks.append(Check("audit.key", INFO, "no sink installed"))
    else:
        checks.append(Check("audit.sink", OK, "{} installed".format(type(sink).__name__)))
        if getattr(sink, "ephemeral_key", False):
            checks.append(Check("audit.key", WARN,
                                "sink key is per-process: receipts can't be verified after a restart",
                                "pass key= (or a public-key signer) to the sink"))
        else:
            checks.append(Check("audit.key", OK, "sink has a persistent key"))
    checks.append(Check("audit.single_writer", INFO,
                        "one writer per audit file; verify the file with "
                        "`python -m interlock report FILE --key-file K`"))
    if dropped:
        checks.append(Check("audit.dropped", WARN,
                            "{} receipt(s) failed to write and are not yet reported".format(dropped),
                            "check the sink's storage; the next write records the gap"))
    else:
        checks.append(Check("audit.dropped", OK, "no dropped receipts"))
    return checks


def _sidecar_checks(engine: Any, probe: bool) -> List[Check]:
    if type(engine).__name__ != "RemoteEngine":
        return [Check("sidecar.timeout", OK, "in-process engine (no sidecar)"),
                Check("sidecar.unreachable", OK, "in-process engine (no sidecar)")]
    checks: List[Check] = []
    mode = getattr(engine, "unreachable", "deny")
    if mode == "allow":
        checks.append(Check("sidecar.unreachable", WARN,
                            "a dead sidecar lets every call through unchecked",
                            "use unreachable=\"deny\" (default) or \"degraded\""))
    elif mode == "degraded":
        checks.append(Check("sidecar.unreachable", INFO,
                            "a dead sidecar falls back to its signed offline policy only"))
    else:
        checks.append(Check("sidecar.unreachable", OK, "a dead sidecar blocks every call"))
    timeout = getattr(engine, "timeout", None)
    if timeout is None:
        checks.append(Check("sidecar.timeout", WARN,
                            "RemoteEngine has no timeout: a hung sidecar hangs every call",
                            "pass timeout= (default 5 seconds)"))
    else:
        checks.append(Check("sidecar.timeout", OK, "sidecar timeout {}s".format(timeout)))
    if probe:
        checks.append(probe_sidecar(getattr(engine, "path", "")))
    return checks


def probe_sidecar(path: str, timeout: float = 2.0) -> Check:
    """Ask a sidecar to decide a harmless probe event."""
    from .event import SensorEvent
    from .sidecar.client import RemoteEngine

    try:
        engine = RemoteEngine(path, timeout=timeout)
        try:
            engine.evaluate(SensorEvent(action="interlock.doctor.probe", args={}))
        finally:
            close = getattr(engine, "close", None)
            if callable(close):
                close()
    except Exception as exc:
        reason = getattr(getattr(exc, "decision", None), "reason", None) or str(exc)
        return Check("sidecar.reachable", FAIL, "sidecar at {} did not answer: {}".format(
            path, reason), "start it: interlock-sidecar --socket {} ...".format(path))
    return Check("sidecar.reachable", OK, "sidecar at {} answers".format(path))


def _approver_check(approver: Any) -> Check:
    if approver is None:
        return Check("approval.approver", INFO,
                     "no approver: every ESCALATE verdict is blocked, except a capped mesh "
                     "rule's, which is recorded as a shadow finding")
    return Check("approval.approver", OK, "approver installed")
