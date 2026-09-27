"""The daemon: one engine, one receipt chain, one process.

Threaded, not forked. :mod:`interlock.sink` is explicit that the read-prev /
sign / append step is only serialized *within* a process - "two processes
writing one file each start their own chain at GENESIS, and verify() reports the
junction as a break. One sink instance, one process, one chain." A forking
server would shatter the receipt chain on every connection; threads share the
one sink under its own lock and keep the chain unbroken.

A rule that raises is denied, not allowed. ``PolicyEngine.evaluate`` does not
catch, so this layer does, and it answers with a BLOCK - the same fail-closed
contract :func:`interlock.policy.engine.deny_when` already implements for a
predicate that raises. The exception's *message* goes to stderr and never into
the decision: a rule's message can quote the argument it choked on, and a
decision's reason is the durable field that lands in a receipt.
"""
from __future__ import annotations

import logging
import os
import socket
import socketserver
import struct
from typing import Any, Optional

from ..enforce import Decision
from ..policy.engine import PolicyEngine
from ..receipt import emit_receipt, set_sink
from ..wire import (
    MAX_LINE,
    WireError,
    decode_line,
    encode_frame,
    error_frame,
    parse_request,
    response_frame,
)

_log = logging.getLogger("interlock")

# SO_PEERCRED (Linux) and LOCAL_PEERCRED (BSD/macOS) are not both present in
# every platform's socket module nor in every stub, hence the getattr reads.
_SO_PEERCRED = getattr(socket, "SO_PEERCRED", None)
_LOCAL_PEERCRED = getattr(socket, "LOCAL_PEERCRED", None)
_SOL_LOCAL = getattr(socket, "SOL_LOCAL", 0)
_UID_AT = {"linux": 1, "bsd": 1}  # offset of cr_uid within the returned struct


def peer_uid(connection: Any) -> Optional[int]:
    """The uid at the other end of a unix socket, or None if unknowable.

    Best-effort by design: the socket's file mode (0600) is the real boundary,
    and this is a second check that uses the kernel's own answer where the
    platform offers one. Returning None means "could not ask", never "allowed" -
    the caller treats None as no extra information rather than as a pass.
    """
    try:
        if _SO_PEERCRED is not None:  # Linux: struct ucred {pid, uid, gid}
            raw = connection.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, 12)
            return struct.unpack("3i", raw)[_UID_AT["linux"]]
        if _LOCAL_PEERCRED is not None:  # macOS: struct xucred, cr_uid second
            raw = connection.getsockopt(_SOL_LOCAL, _LOCAL_PEERCRED, 8)
            return struct.unpack("II", raw[:8])[_UID_AT["bsd"]]
    except Exception:
        return None
    return None


class _Handler(socketserver.StreamRequestHandler):
    """One connection: read frames, decide, answer. Never reads argument values
    into a log line."""

    def handle(self) -> None:  # noqa: C901 - a protocol loop reads as a loop
        uid = peer_uid(self.connection)
        if uid is not None and uid != os.getuid():
            _log.error(
                "sidecar: refusing connection from uid %s (socket owner is %s)",
                uid, os.getuid(),
            )
            return
        while True:
            try:
                line = self.rfile.readline(MAX_LINE + 1)
            except OSError:
                return
            if not line:
                return
            if len(line) > MAX_LINE or not line.endswith(b"\n"):
                # Oversized and unterminated are the same answer, and the
                # connection ends: the rest of a runaway line is not a frame.
                self._reply(error_frame("", "too_large", "frame exceeded limit"))
                return

            op_id = ""
            try:
                frame = decode_line(line)
                if isinstance(frame.get("id"), str):
                    op_id = frame["id"]
                op_id, event = parse_request(frame)
            except WireError as exc:
                self._reply(error_frame(op_id, exc.code, str(exc)))
                continue

            decision = self._decide(event)
            # Recorded before it is transmitted: the decision happened whether
            # or not the answer could be encoded.
            emit_receipt(event, decision)
            try:
                self._reply(response_frame(op_id, decision))
            except WireError as exc:
                self._reply(error_frame(op_id, exc.code, str(exc)))

    def _decide(self, event: Any) -> Decision:
        engine: PolicyEngine = self.server.engine  # type: ignore[attr-defined]
        try:
            return engine.evaluate(event)
        except Exception as exc:
            _log.exception("sidecar: rule raised; denying fail-closed")
            return Decision.block(
                "rule error, denied fail-closed: {}".format(type(exc).__name__)
            )

    def _reply(self, frame: dict) -> None:
        try:
            self.wfile.write(encode_frame(frame))
        except OSError:
            pass


def _assert_private_dir(address: str) -> None:
    """Refuse a socket directory another user could replace the socket in.

    The file mode alone is not enough: in a directory anyone can write, anyone
    can unlink the socket and bind their own in its place. The sticky bit is
    what makes a shared directory safe (only the owner may unlink), so a
    group/world-writable directory *without* it is a refusal.
    """
    directory = os.path.dirname(address) or "."
    if not os.path.isdir(directory):
        raise OSError("socket directory {} does not exist".format(directory))
    mode = os.stat(directory).st_mode
    if mode & 0o022 and not mode & 0o1000:
        raise OSError(
            "socket directory {} is group/world-writable without the sticky "
            "bit; another user could replace the socket".format(directory)
        )


class SidecarServer(socketserver.ThreadingUnixStreamServer):
    """A threaded unix-socket server over one engine.

    ``daemon_threads`` so a handler cannot keep the process alive after the
    serve loop stops. An in-flight request aborted at shutdown surfaces to the
    client as a closed connection, which :class:`~interlock.sidecar.client.RemoteEngine`
    turns into a block - the safe direction.

    Installing a sink here is a process-global act by design: one daemon per
    process, one sink, one chain.

    The socket is restricted to its owner here, not in the CLI, because binding
    honours the umask: a default umask lands the file at 0755 - group and world
    connectable - while every comment promises 0600. A class that binds an
    enforcement socket has to be the thing that seals it, or the boundary is
    only documentation.
    """

    daemon_threads = True
    allow_reuse_address = False
    # socketserver defaults to a backlog of 5, which REFUSES (not queues) the
    # sixth simultaneous connect. A guard several workers connect to at once
    # would drop legitimate clients, so the backlog is sized for a burst.
    request_queue_size = 128

    def __init__(
        self,
        address: str,
        engine: PolicyEngine,
        *,
        sink: Optional[Any] = None,
    ) -> None:
        self.engine = engine
        if sink is not None:
            set_sink(sink)
        _assert_private_dir(address)
        super().__init__(address, _Handler)
        try:
            os.chmod(address, 0o600)
        except OSError:
            super().server_close()
            try:
                os.unlink(address)
            except OSError:
                pass
            raise
