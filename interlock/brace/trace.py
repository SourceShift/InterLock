"""Putting sandbox launches on the same policy seam as every other action.

A production environment traces the events inside a sandbox and feeds them back to
its control plane. interlock already has that plane: ``evaluate(event) ->
Decision``. So a sandbox launch is not a special case, it is one more action. This
module turns a launch into a ``process_spawn`` :class:`SensorEvent` and runs it
through the very same :func:`enforce_tool_call` the MCP interceptor uses, before
the process is started. A policy can therefore block a spawn, or rewrite its argv
via a MODIFY verdict, using the same rules that govern tool calls.

The payoff of reusing the seam rather than inventing a second one: a rule like
``deny_tool("process_spawn")`` or a scope binding that denies network already
covers the sandbox, and every launch shows up in the same audit path as every
MCP call.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..interceptors.mcp import enforce_tool_call
from ..policy.engine import PolicyEngine
from .profile import SandboxProfile

_log = logging.getLogger("interlock.brace")

SPAWN_ACTION = "process_spawn"


def check_spawn(
    argv: List[str],
    profile: SandboxProfile,
    *,
    engine: Optional[PolicyEngine] = None,
    enforcement: str = "blocking",
    principal: Optional[str] = None,
) -> List[str]:
    """Run the launch through the policy engine before it happens.

    Returns the argv to actually execute: unchanged on ALLOW, or replaced when a
    rule returns MODIFY with a new ``argv``. Raises :class:`~interlock.enforce.Blocked`
    on a BLOCK verdict under blocking enforcement. Under ``enforcement="monitor"``
    the would-be decision is recorded and the original argv is returned.
    """
    args: Dict[str, Any] = {
        "path": argv[0] if argv else "",
        "argv": list(argv),
        "allow_network": profile.allow_network,
        "allowed_hosts": list(profile.allowed_hosts),
        "write_paths": list(profile.write_paths),
    }
    safe = enforce_tool_call(
        SPAWN_ACTION,
        args,
        engine=engine,
        enforcement=enforcement,
        principal=principal,
    )
    # Honor an argv rewrite if a MODIFY rule supplied one; otherwise keep ours.
    new_argv = safe.get("argv")
    if isinstance(new_argv, list) and new_argv:
        return [str(x) for x in new_argv]
    return list(argv)


def record_exit(backend: str, argv: List[str], returncode: Optional[int]) -> None:
    """Emit the completion trace for a finished sandbox run."""
    _log.debug(
        "brace backend=%s exit=%s argv=%s",
        backend,
        returncode,
        " ".join(argv[:4]) + (" ..." if len(argv) > 4 else ""),
    )
