"""A rules module the sidecar can import, for the R29 scope-over-the-wire smoke.

``interlock.sidecar --rules tests.fixtures.rules:rules`` imports this module by
dotted path. It exports the three things the scoped daemon needs, all built from
one source so the daemon and an in-process oracle cannot drift:

- ``rules`` - a non-empty rule list, so the daemon's empty-engine refusal is
  satisfied (the base policy served when no scope document is given).
- ``templates`` - the scope templates a scope document binds, keyed by template
  id. A scope document is pure data; the factories are code and live here.
- ``scope_document()`` - the declared scope document: which template each scope
  binds, and with which params.

``shell_allowlist`` is deliberately tiny: one per-command allowlist, so a scope
resolves to "this principal may run these commands" and the per-principal
difference (``acme/agent1`` may run ``ls`` but not ``rm``) is a single,
checkable fact.
"""
from __future__ import annotations

from typing import Iterable, Optional

from interlock.enforce import Decision
from interlock.event import SensorEvent
from interlock.policy.engine import Rule
from interlock.policy.scopes import Template

POLICY_ID = "shell_allowlist"
SHELL_ACTION = "run_shell"


def shell_allowlist(allow: Iterable[str] = ()) -> Rule:
    """Rule: permit ``run_shell`` only for a command whose first word is allowed."""
    allowed = frozenset(allow)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if event.action != SHELL_ACTION:
            return None
        args = event.args if isinstance(event.args, dict) else {}
        cmd = args.get("cmd")
        first = str(cmd).split()[0] if isinstance(cmd, str) and cmd.strip() else ""
        if first and first in allowed:
            return None
        return Decision.block(
            "{}: command not allowed".format(POLICY_ID),
            policy_id=POLICY_ID,
            attributed_to="cmd",
        )

    return rule


#: Scope templates, keyed by the id a scope document binds. ``allow`` unions up
#: the scope chain, so a deeper scope can only widen the allowlist.
templates = {
    "shell_allowlist": Template("shell_allowlist", shell_allowlist, frozenset({"allow"})),
}

#: The base rule set for the non-scoped path (no ``--scope-document``).
rules = [shell_allowlist(allow=["ls"])]


def scope_document() -> dict:
    """The scope document this module declares.

    ``acme`` may run ``ls`` and ``pwd``; ``acme/agent1`` inherits that and may
    run ``ls`` - a principal scope with no binding at all (``beta/agent2``)
    resolves to an empty engine and is allowed, which is the per-principal
    difference the smoke compares.
    """
    return {
        "version": 1,
        "default_scope": [],
        "allow_unscoped": False,
        "bindings": {
            "acme": [
                {"template": "shell_allowlist", "params": {"allow": ["ls", "pwd"]}},
            ],
            "acme/agent1": [
                {"template": "shell_allowlist", "params": {"allow": ["ls"]}},
            ],
        },
    }
