"""Serve the one policy engine to agents running in another language.

An agent written in JavaScript (R13) does not get a second policy engine. It
gets a unix socket to this daemon, which owns the one engine, the one rule set,
and the one receipt chain. The JS side enforces what it is told; it never
evaluates. Nothing about a policy crosses the language boundary, so there is
nothing to keep in sync.

The daemon must never call ``interlock._runtime.get_engine()``. That function
lazily *creates* an empty :class:`~interlock.policy.engine.PolicyEngine` when
none is installed, and an empty engine allows everything - a fail-open guard
that looks healthy. The daemon builds its own engine and refuses to start when
that engine has no rules (see :func:`interlock.sidecar.rules.load_rules`).
"""
from __future__ import annotations

from .client import RemoteEngine
from .rules import EmptyRules, RulesError, load_rules
from .server import SidecarServer, peer_uid

__all__ = [
    "RemoteEngine",
    "SidecarServer",
    "load_rules",
    "RulesError",
    "EmptyRules",
    "peer_uid",
]
