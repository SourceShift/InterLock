"""Talk to the daemon: a stand-in for PolicyEngine that lives in another process.

:class:`RemoteEngine` duck-types the one method every call site uses,
``evaluate(event) -> Decision``, so it drops in wherever an engine is accepted -
``interlock.set_engine(remote)`` for the ``@guard`` decorator, or
``enforce_tool_call(..., engine=remote)``. Nothing above it changes, and no
interface has to be invented for it to fit.

**Every transport failure raises ``Blocked``.** Not a warning, not an allow, not
a special exception a caller has to know about: a caller that already handles
``except Blocked`` gets the fail-closed behaviour for free. This is deliberate
and it is the whole availability story - the daemon is not optional, and an
agent that cannot reach it does not act. A caller running in ``monitor`` mode
is not exempt: an unreachable daemon is an infrastructure failure, not a policy
verdict, so it must not be downgraded into a silent pass-through.
"""
from __future__ import annotations

import itertools
import logging
import os
import socket
import threading
from dataclasses import replace
from typing import Any, Optional

from ..enforce import Blocked, Decision, Verdict
from ..event import SensorEvent
from .fallback import FallbackError, fallback_path, read_fallback_metadata
from ..wire import (
    MAX_LINE,
    WireError,
    decode_line,
    encode_frame,
    error_frame,
    parse_response,
    read_scope_envelope,
    request_frame,
)


#: Seconds :class:`RemoteEngine` waits for a connect, a send, or a reply when
#: no ``timeout`` is given. A hung daemon then blocks the call after this long
#: instead of hanging it forever.
DEFAULT_TIMEOUT = 5.0

#: What a client does when its daemon cannot be reached (see sidecar.fallback).
UNREACHABLE_LEVELS = ("deny", "degraded", "allow")
#: The policy id on decisions made without the daemon.
UNREACHABLE_POLICY_ID = "sidecar_unreachable"

_log = logging.getLogger("interlock")


def _is_unreachable(exc: Exception) -> bool:
    """No daemon to ask: no socket, refused, timed out, or it hung up. An error
    frame from a live daemon is not unreachable - it is a refusal."""
    if isinstance(exc, WireError):
        return str(exc) == "daemon closed the connection"
    return isinstance(exc, (OSError, socket.timeout))


class RemoteEngine:
    """An engine that decides by asking the daemon over a unix socket.

    One connection is reused across calls, and a lock serializes them: a
    request/response exchange on a stream socket cannot be interleaved, so
    concurrent callers share the connection in turn rather than racing on it.

    ``scope`` pins the scope set this client expects to be judged under. It is
    the path of the signed scope document the daemon published (its
    ``--scope-document`` file), verified at construction under ``scope_key``,
    and presented on every request. The daemon refuses a request whose scope
    document is not the one it serves (``scope_mismatch``), so a scoped client
    that reaches a daemon serving a *different* scope set blocks instead of
    being quietly decided under it. The envelope is read once: after the
    operator republishes a scope document, restart the daemon and its clients
    together (the old envelope would be refused, not silently accepted).

    ``timeout`` bounds each socket operation (connect, send, and waiting for a
    reply), in seconds. It defaults to :data:`DEFAULT_TIMEOUT`; pass ``None`` to
    wait forever. A timeout raises ``Blocked``, like any other transport
    failure. A single call may bound itself with ``evaluate(event,
    timeout=...)``; the previous value is restored afterwards, including on the
    already-open socket, so a short tier deadline cannot leak into a later
    direct call.

    ``artifact_sha256`` pins the artifact the daemon must be serving. Every
    response frame in artifact mode carries the daemon's sha; a mismatch (or a
    daemon that reports none) is a refusal, not an outage, so a fallback can
    never silently substitute a different policy. ``artifact_epoch``, when
    given, is checked the same way.
    """

    #: Tells a caller (``TieredEvaluator``) that a per-call ``timeout`` keyword
    #: is honoured, including on a warm socket.
    supports_timeout = True

    def __init__(
        self,
        path: str,
        *,
        timeout: Optional[float] = DEFAULT_TIMEOUT,
        unreachable: str = "deny",
        fallback: Optional[str] = None,
        fallback_key: Optional[bytes] = None,
        fallback_max_age: float = 7 * 86400,
        scope: Optional[str] = None,
        scope_key: Optional[bytes] = None,
        artifact_sha256: Optional[str] = None,
        artifact_epoch: Optional[str] = None,
    ) -> None:
        if unreachable not in UNREACHABLE_LEVELS:
            raise ValueError("unreachable must be one of {}".format(", ".join(UNREACHABLE_LEVELS)))
        if unreachable == "degraded" and fallback_key is None:
            raise ValueError("unreachable='degraded' needs fallback_key to verify the fallback file")
        if artifact_sha256 is not None and (
            not isinstance(artifact_sha256, str) or not artifact_sha256
        ):
            raise ValueError("artifact_sha256 must be a non-empty string")
        if artifact_epoch is not None and not isinstance(artifact_epoch, str):
            raise ValueError("artifact_epoch must be a string")
        if scope is None:
            if scope_key is not None:
                raise ValueError("scope_key was given without scope: pass the daemon's "
                                 "published scope document with scope=PATH")
            self.scope_envelope = None
        else:
            if scope_key is None:
                raise ValueError("scope=PATH needs scope_key to verify the published document")
            # Read eagerly: an operator learns at construction that the file is
            # missing or foreign-signed, not on the first guarded call.
            self.scope_envelope = read_scope_envelope(scope, scope_key)
        self.path = str(path)
        self.timeout = timeout
        self.artifact_sha256 = artifact_sha256
        self.artifact_epoch = artifact_epoch
        self.unreachable = unreachable
        self.fallback = fallback or fallback_path(self.path)
        self._fallback_key = fallback_key
        self.fallback_max_age = fallback_max_age
        self.fallbacks = 0  # how many calls were decided without the daemon
        self._fallback_engine: Any = None
        self._fallback_stamp: Any = None
        self._lock = threading.Lock()
        self._sock: Optional[socket.socket] = None
        self._reader = None
        self._ids = itertools.count(1)

    def evaluate(self, event: SensorEvent, *, timeout: Optional[float] = None) -> Decision:
        """Ask the daemon for the verdict, or raise ``Blocked``.

        When the daemon is *unreachable* (no socket, refused, timed out, hung
        up) and ``unreachable`` is ``degraded`` or ``allow``, the call is
        decided without it, and a warning is logged every time. A daemon that
        answers with an error frame is reachable and refusing: always blocked.

        ``timeout`` bounds this call only. It is applied to a live socket too,
        because ``_connect`` caches the socket and its original timeout would
        otherwise keep governing every later call.
        """
        with self._lock:
            previous = self.timeout
            if timeout is not None:
                self.timeout = float(timeout)
                self._apply_timeout(self.timeout)
            try:
                try:
                    return self._exchange(event)
                except Exception as exc:
                    self._drop()
                    if self.unreachable != "deny" and _is_unreachable(exc):
                        return self._without_daemon(event, exc)
                    raise Blocked(
                        Decision.block(self._reason_for(exc)), event.action
                    )
            finally:
                if timeout is not None:
                    self.timeout = previous
                    self._apply_timeout(previous)

    def _apply_timeout(self, value: Optional[float]) -> None:
        """Re-apply a timeout to an already-open socket, if there is one."""
        sock = self._sock
        if sock is None:
            return
        try:
            sock.settimeout(value)
        except OSError:
            pass

    def _without_daemon(self, event: SensorEvent, exc: Exception) -> Decision:
        self.fallbacks += 1
        why = "{}: {}".format(type(exc).__name__, exc)
        if self.unreachable == "allow":
            _log.warning("interlock: guard daemon unreachable at %s (%s); ALLOWING %r "
                         "unchecked (unreachable='allow')", self.path, why, event.action)
            return Decision.allow(
                "guard daemon unreachable ({}); allowed unchecked".format(why),
                policy_id=UNREACHABLE_POLICY_ID)
        try:
            engine = self._load_fallback()
        except FallbackError as problem:
            raise Blocked(Decision.block(
                "guard daemon unreachable at {} ({}) and the fallback policy is "
                "unusable: {}; denied fail-closed".format(self.path, why, problem),
                policy_id=UNREACHABLE_POLICY_ID), event.action)
        _log.warning("interlock: guard daemon unreachable at %s (%s); deciding %r with "
                     "the offline fallback policy", self.path, why, event.action)
        decision = engine.evaluate(event)
        if decision.verdict == Verdict.ALLOW:
            return Decision.allow("decided by the offline fallback policy",
                                  policy_id=UNREACHABLE_POLICY_ID)
        return replace(decision, policy_id="fallback/{}".format(decision.policy_id),
                       reason="[guard daemon unreachable: fallback policy] {}".format(
                           decision.reason))

    def _load_fallback(self) -> Any:
        try:
            st = os.stat(self.fallback)
            stamp = (st.st_mtime, st.st_size)
        except OSError:
            stamp = None
        if self._fallback_engine is not None and stamp == self._fallback_stamp:
            return self._fallback_engine
        from ..policy.declarative import load_policy
        assert self._fallback_key is not None
        metadata = read_fallback_metadata(
            self.fallback, self._fallback_key, max_age=self.fallback_max_age
        )
        if self.artifact_sha256 is not None:
            if metadata["artifact_sha256"] is None:
                raise FallbackError(
                    "fallback policy is not pinned to an artifact, but the "
                    "client pinned {}".format(self.artifact_sha256)
                )
            if metadata["artifact_sha256"] != self.artifact_sha256:
                raise FallbackError(
                    "fallback policy belongs to artifact {}, not the pinned "
                    "{}".format(metadata["artifact_sha256"], self.artifact_sha256)
                )
            if self.artifact_epoch is not None and metadata["epoch"] != self.artifact_epoch:
                raise FallbackError(
                    "fallback policy belongs to epoch {!r}, not the pinned "
                    "{!r}".format(metadata["epoch"], self.artifact_epoch)
                )
        self._fallback_engine = load_policy(metadata["policy"], source=self.fallback)
        self._fallback_stamp = stamp
        return self._fallback_engine

    def close(self) -> None:
        with self._lock:
            self._drop()

    def __enter__(self) -> "RemoteEngine":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- internals -----------------------------------------------------------

    def _exchange(self, event: SensorEvent) -> Decision:
        op_id = "op-{}-{}".format(os.getpid(), next(self._ids))
        # Encode before touching the socket. A request the daemon cannot accept
        # is a refusal this client can establish on its own, so it must never be
        # mistaken for an outage: opening the connection first would let the
        # daemon's close race the reply and surface as EOF, which is classified
        # unreachable. Nothing below sends a byte for a request refused here.
        try:
            payload = encode_frame(
                request_frame(op_id, event, scope=self.scope_envelope)
            )
        except Exception as exc:
            raise WireError(
                "bad_request",
                "request could not be encoded: {}: {}".format(
                    type(exc).__name__, exc
                ),
            )
        if len(payload) > MAX_LINE:
            raise WireError("too_large", "request exceeded the frame limit")

        sock = self._connect()
        reader = self._reader
        if reader is None:  # _connect installs it; unreachable in practice
            raise WireError("internal", "connection has no reader")
        sock.sendall(payload)
        line = reader.readline(MAX_LINE + 1)
        if not line:
            raise WireError("bad_response", "daemon closed the connection")
        if len(line) > MAX_LINE:
            raise WireError("too_large", "response exceeded the frame limit")
        frame = decode_line(line)
        self._check_artifact_pin(frame)
        return parse_response(frame, op_id)

    def _check_artifact_pin(self, frame: dict) -> None:
        """Refuse a reply from a daemon serving a different artifact.

        Only a pinned client checks, so a non-artifact client's frames are
        unchanged. A live daemon that cannot prove its artifact is a refusal:
        accepting the decision would let a rollback or a wrong-environment
        daemon decide under a policy the caller never pinned.
        """
        if self.artifact_sha256 is None:
            return
        got = frame.get("policy_artifact")
        if not isinstance(got, str) or not got:
            raise WireError(
                "artifact_mismatch",
                "daemon reported no policy artifact to match the pin",
            )
        if got != self.artifact_sha256:
            raise WireError(
                "artifact_mismatch",
                "daemon serves artifact {} but the client pinned {}".format(
                    got, self.artifact_sha256
                ),
            )
        if self.artifact_epoch is not None:
            epoch = frame.get("policy_epoch")
            if epoch != self.artifact_epoch:
                raise WireError(
                    "artifact_mismatch",
                    "daemon serves epoch {!r} but the client pinned {!r}".format(
                        epoch, self.artifact_epoch
                    ),
                )

    def _connect(self) -> socket.socket:
        if self._sock is not None:
            return self._sock
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.path)
        self._sock = sock
        # A buffered reader is what bounds readline; keeping it across calls is
        # why the lock above is about more than tidiness.
        self._reader = sock.makefile("rb")
        return sock

    def _drop(self) -> None:
        reader, self._reader = self._reader, None
        sock, self._sock = self._sock, None
        for closeable in (reader, sock):
            if closeable is not None:
                try:
                    closeable.close()
                except OSError:
                    pass

    def _reason_for(self, exc: Exception) -> str:
        if isinstance(exc, WireError):
            return "guard daemon refused the request ({}) at {}: {}".format(
                exc.code, self.path, exc
            )
        return "guard daemon unreachable at {}: {}: {}".format(
            self.path, type(exc).__name__, exc
        )


def probe(path: str, *, timeout: float = 0.25) -> bool:
    """True if something is accepting connections at ``path``.

    Used to tell a live daemon from a socket file left behind by a crash, so
    the second daemon refuses to start instead of unlinking a live socket.
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(path)
        return True
    except OSError:
        return False
    finally:
        sock.close()


__all__ = ["DEFAULT_TIMEOUT", "RemoteEngine", "probe", "error_frame"]
