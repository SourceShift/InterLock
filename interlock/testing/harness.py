"""Run a sidecar daemon inside the test process, and speak to it raw.

The daemon is threaded, so a test can host one in-process and drive it over a
real unix socket. Two things make that safe to do repeatedly:

- the receipt sink is process-global, so the harness restores whatever sink was
  installed before it started. Without that, one test's daemon would quietly
  become the next test's sink.
- the socket file is removed on the way out, so a later daemon on the same path
  is exercising the fresh-socket path rather than the stale-file path.

``send_raw`` exists for the frames a client would never build: the negatives. A
malformed line has to reach the socket as bytes, which
:class:`~interlock.sidecar.client.RemoteEngine` deliberately will not do.
"""
from __future__ import annotations

import contextlib
import os
import socket
import threading
import time
from typing import Any, Dict, Optional

from .. import receipt
from ..policy.engine import PolicyEngine
from ..sidecar.client import probe
from ..sidecar.server import SidecarServer
from ..wire import MAX_LINE, decode_line


@contextlib.contextmanager
def serve(
    engine: PolicyEngine,
    path: Any,
    *,
    sink: Optional[Any] = None,
    timeout: float = 5.0,
):
    """Serve ``engine`` at ``path`` for the duration of the block."""
    path = str(path)
    previous_sink = receipt.get_sink()
    server = SidecarServer(path, engine, sink=sink)
    thread = threading.Thread(
        target=server.serve_forever, daemon=True, name="interlock-sidecar"
    )
    thread.start()
    try:
        deadline = time.time() + timeout
        while not probe(path) and time.time() < deadline:
            time.sleep(0.01)
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=timeout)
        receipt.set_sink(previous_sink)
        try:
            os.unlink(path)
        except OSError:
            pass


def send_raw(path: Any, line: Any, *, timeout: float = 5.0) -> Dict[str, Any]:
    """Send one line to the daemon and read one frame back. ``{}`` on EOF."""
    if isinstance(line, str):
        line = line.encode("utf-8")
    if not line.endswith(b"\n"):
        line += b"\n"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(str(path))
        sock.sendall(line)
        with sock.makefile("rb") as reader:
            raw = reader.readline(MAX_LINE + 1)
    finally:
        sock.close()
    if not raw:
        return {}
    return decode_line(raw)
