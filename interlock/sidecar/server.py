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
import threading
from typing import Any, Optional, Set

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
    scope_identity,
    verify_scope_envelope,
)

_log = logging.getLogger("interlock")

# SO_PEERCRED (Linux) and LOCAL_PEERCRED (BSD/macOS) are not both present in
# every platform's socket module nor in every stub, hence the getattr reads.
_SO_PEERCRED = getattr(socket, "SO_PEERCRED", None)
_LOCAL_PEERCRED = getattr(socket, "LOCAL_PEERCRED", None)
_SOL_LOCAL = getattr(socket, "SOL_LOCAL", 0)
_UID_AT = {"linux": 1, "bsd": 1}  # offset of cr_uid within the returned struct

# Returned by ``_Handler._scope_for`` when the frame's overlay was refused: the
# error frame has been sent, and the caller must not decide the event. A unique
# sentinel, not None, because None legitimately means "no scope document".
_REFUSED = object()


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

    def setup(self) -> None:
        super().setup()
        self.server._track(self.connection)  # type: ignore[attr-defined]

    def finish(self) -> None:
        try:
            super().finish()
        finally:
            self.server._untrack(self.connection)  # type: ignore[attr-defined]

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
            self._serve_frame(line)

    def _serve_frame(self, line: bytes) -> None:
        """Serve one line, answering every failure and returning to the loop.

        A wire refusal keeps its own code. Anything else a per-frame step
        raises - a ``RecursionError`` from a deeply nested document, an
        unexpected error in a scope or decision step - is logged and answered
        as ``internal`` rather than allowed to kill the connection. The frame
        after a bad one must still be served: a connection that dies with no
        reply looks like an outage to the client and can be downgraded by
        ``unreachable="allow"``.
        """
        op_id = ""
        try:
            frame = decode_line(line)
        except WireError as exc:
            self._reply(error_frame(op_id, exc.code, str(exc)))
            return
        except Exception as exc:  # e.g. RecursionError from json.loads
            self._internal(op_id, exc)
            return
        if isinstance(frame.get("id"), str):
            op_id = frame["id"]
        try:
            op_id, event = parse_request(frame)
        except WireError as exc:
            self._reply(error_frame(op_id, exc.code, str(exc)))
            return
        except Exception as exc:
            self._internal(op_id, exc)
            return

        try:
            # A scope overlay rides the request and must verify before the
            # engine sees the event: an unverified overlay has no decision, so
            # the far end is told to block rather than served a verdict under a
            # scope set this daemon did not agree to.
            scope_document = self._scope_for(frame, op_id)
            if scope_document is _REFUSED:
                return

            decision = self._decide(event)

            # Recorded before it is transmitted: the decision happened whether
            # or not the answer could be encoded. A sink that cannot record it
            # is a refusal, not an outage: the decision must not be made again
            # without an audit trail by a caller's fallback path. Answer with no
            # verdict and serve the next frame; the write is not retried.
            try:
                emit_receipt(
                    event, decision,
                    scope_document=scope_document,
                    policy_epoch=self.server.policy_epoch,  # type: ignore[attr-defined]
                    policy_artifact=self.server.artifact_sha256,  # type: ignore[attr-defined]
                )
            except Exception as exc:
                _log.exception("sidecar: receipt sink failed; refusing the call")
                self._reply(error_frame(
                    op_id, "receipt_failed",
                    "receipt write failed: {}".format(type(exc).__name__),
                ))
                return

            try:
                self._reply(response_frame(
                    op_id, decision,
                    policy_epoch=self.server.policy_epoch,  # type: ignore[attr-defined]
                    policy_artifact=self.server.artifact_sha256,  # type: ignore[attr-defined]
                ))
            except WireError as exc:
                self._reply(error_frame(op_id, exc.code, str(exc)))
        except WireError as exc:
            self._reply(error_frame(op_id, exc.code, str(exc)))
        except Exception as exc:
            self._internal(op_id, exc)

    def _internal(self, op_id: str, exc: BaseException) -> None:
        _log.error(
            "sidecar: unhandled error serving a frame; replying internal",
            exc_info=exc,
        )
        self._reply(error_frame(
            op_id, "internal", "internal error: {}".format(type(exc).__name__)
        ))

    def _scope_for(self, frame: dict, op_id: str) -> Any:
        """Resolve this frame's scope-document identity, or :data:`_REFUSED`.

        A frame with no overlay is governed by the daemon's own scope document,
        if it has one. An overlay must verify under the daemon's key - and, when
        the daemon serves a document of its own, must be *that* document. Any
        shortfall (no key to verify with, no signature, a signature that does
        not verify, a different document) is answered with an error frame, so
        the far end has no verdict and blocks, and :data:`_REFUSED` keeps the
        decision from being made.
        """
        overlay = frame.get("scope")
        configured = self.server.scope_document  # type: ignore[attr-defined]
        if overlay is None:
            return scope_identity(configured) if configured is not None else None
        key = self.server.scope_key  # type: ignore[attr-defined]
        if key is None:
            self._reply(error_frame(
                op_id, "unauthenticated_scope",
                "this daemon has no scope key to verify the overlay",
            ))
            return _REFUSED
        try:
            verify_scope_envelope(overlay, key)
        except WireError as exc:
            self._reply(error_frame(op_id, exc.code, str(exc)))
            return _REFUSED
        if configured is not None and scope_identity(overlay) != scope_identity(configured):
            self._reply(error_frame(
                op_id, "scope_mismatch",
                "the presented scope document is not the one this daemon serves",
            ))
            return _REFUSED
        return scope_identity(overlay)

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
        scope_key: Optional[bytes] = None,
        scope_document: Optional[Any] = None,
    ) -> None:
        self.engine = engine
        # The key a request's signed scope overlay must verify under, and the
        # signed scope document this daemon serves (its envelope). Both optional:
        # a daemon with neither behaves exactly as before and refuses any overlay
        # it is handed (there is no key to prove one with).
        self.scope_key = scope_key
        self.scope_document = scope_document
        # Artifact mode (C6): when the engine was materialised from artifact
        # bytes, every receipt and every response frame carries the artifact's
        # sha256 and epoch. A plain rule set leaves both None, so its receipts
        # and frames are byte-identical to the R19 shape.
        artifact_bytes = getattr(engine, "artifact_bytes", None)
        sha = getattr(engine, "sha256", None)
        epoch = getattr(engine, "epoch", None)
        self.artifact_sha256 = (
            sha if artifact_bytes is not None and isinstance(sha, str) and sha else None
        )
        self.policy_epoch = (
            epoch if artifact_bytes is not None and isinstance(epoch, str) and epoch else None
        )
        # Connections whose handler thread is still running. ``server_close``
        # shuts them down: a daemon thread would otherwise keep answering on an
        # open connection long after the server stopped accepting new ones.
        self._live: Set[socket.socket] = set()
        self._live_lock = threading.Lock()
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

    def _track(self, connection: socket.socket) -> None:
        with self._live_lock:
            self._live.add(connection)

    def _untrack(self, connection: socket.socket) -> None:
        with self._live_lock:
            self._live.discard(connection)

    def server_close(self) -> None:
        """Stop listening and end every open connection.

        ``shutdown(SHUT_RDWR)`` wakes a handler blocked in ``readline`` with an
        EOF, so it returns and its thread ends; the handler's own ``finish``
        closes the file descriptor. Closing it here instead could hand a reused
        descriptor number to a thread still using the old one. A request caught
        mid-flight sees a closed connection, which the client turns into a
        block.
        """
        super().server_close()
        with self._live_lock:
            live = list(self._live)
            self._live.clear()
        for connection in live:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
