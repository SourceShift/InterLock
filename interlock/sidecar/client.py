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
import os
import socket
import threading
from typing import Optional

from ..enforce import Blocked, Decision
from ..event import SensorEvent
from ..wire import (
    MAX_LINE,
    WireError,
    decode_line,
    encode_frame,
    error_frame,
    parse_response,
    request_frame,
)


class RemoteEngine:
    """An engine that decides by asking the daemon over a unix socket.

    One connection is reused across calls, and a lock serializes them: a
    request/response exchange on a stream socket cannot be interleaved, so
    concurrent callers share the connection in turn rather than racing on it.
    """

    def __init__(self, path: str, *, timeout: Optional[float] = None) -> None:
        self.path = str(path)
        self.timeout = timeout
        self._lock = threading.Lock()
        self._sock: Optional[socket.socket] = None
        self._reader = None
        self._ids = itertools.count(1)

    def evaluate(self, event: SensorEvent) -> Decision:
        """Ask the daemon for the verdict, or raise ``Blocked``."""
        with self._lock:
            try:
                return self._exchange(event)
            except Exception as exc:
                self._drop()
                raise Blocked(
                    Decision.block(self._reason_for(exc)), event.action
                )

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
        sock = self._connect()
        reader = self._reader
        if reader is None:  # _connect installs it; unreachable in practice
            raise WireError("internal", "connection has no reader")
        sock.sendall(encode_frame(request_frame(op_id, event)))
        line = reader.readline(MAX_LINE + 1)
        if not line:
            raise WireError("bad_response", "daemon closed the connection")
        if len(line) > MAX_LINE:
            raise WireError("too_large", "response exceeded the frame limit")
        return parse_response(decode_line(line), op_id)

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


__all__ = ["RemoteEngine", "probe", "error_frame"]
