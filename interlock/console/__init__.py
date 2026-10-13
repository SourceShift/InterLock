"""The interlock console: a local web UI over this process's policy engine.

interlock has no network surface of its own; this package is the one place
that opens a socket. It serves a JSON API under ``/api/`` and the built web
app from a static directory, both bound to loopback only (see
:class:`~interlock.console.server.ConsoleServer`).
"""
from __future__ import annotations

from .server import ConsoleServer, ConsoleRequestHandler, LOOPBACK_HOSTS
from . import catalog  # noqa: F401 - registers the /api/detectors routes
from . import audit  # noqa: F401 - registers the /api/receipts routes
from . import playground  # noqa: F401 - registers the /api/evaluate, /api/presets routes
from . import inspector  # noqa: F401 - registers the /api/scopes/*, /api/sandbox routes

__all__ = ["ConsoleServer", "ConsoleRequestHandler", "LOOPBACK_HOSTS"]
