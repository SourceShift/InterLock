"""The rules module the C5 compiler and connector import, for tests.

Templates are code and never travel in an artifact.  This module is the
``module:attr`` spec every C5 test names (``tests.fixtures.cloud.rules_module:
templates``), and it deliberately covers all four verdicts so the compile
round-trip corpus exercises allow, block, modify and escalate:

* ``shell_allowlist`` - a per-scope command allowlist (block outside it).
* ``egress_denylist`` - a per-scope host denylist (block listed hosts).
* ``file_guard`` - escalate paths under a prefix, redact paths naming a
  secret, block key material, allow the rest.

Every factory is deterministic and reads no clock, environment or network, so
an artifact compiled from these templates evaluates identically on every host.
"""
from __future__ import annotations

from typing import Iterable, Optional

from interlock.enforce import Decision
from interlock.event import SensorEvent
from interlock.policy.engine import Rule
from interlock.policy.scopes import Template

SHELL_ACTION = "run_shell"
EGRESS_ACTION = "net_fetch"
READ_ACTION = "read_file"
WRITE_ACTION = "write_file"

SHELL_POLICY_ID = "shell_allowlist"
EGRESS_POLICY_ID = "egress_denylist"
FILE_POLICY_ID = "file_guard"


def _args(event: SensorEvent) -> dict:
    return event.args if isinstance(event.args, dict) else {}


def shell_allowlist(allow: Iterable[str] = ()) -> Rule:
    """Permit a shell command only when its first word is in the allowlist.

    Covers both the sensor's ``run_shell`` event (``args.cmd``) and a coding
    agent's raw ``Bash`` hook event (``args.command``), so the same compiled
    artifact can be exercised through an installed hook.
    """
    allowed = frozenset(str(item) for item in allow)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if event.action == SHELL_ACTION:
            cmd = _args(event).get("cmd")
        elif event.action == "Bash":
            cmd = _args(event).get("command")
        else:
            return None
        first = str(cmd).split()[0] if isinstance(cmd, str) and cmd.strip() else ""
        if first and first in allowed:
            return None
        return Decision.block(
            "shell_allowlist: command not allowed",
            policy_id=SHELL_POLICY_ID,
            attributed_to="cmd",
        )

    return rule


def egress_denylist(deny_hosts: Iterable[str] = ()) -> Rule:
    """Block ``net_fetch`` to any host the scope denies."""
    denied = frozenset(str(item).lower() for item in deny_hosts)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if event.action != EGRESS_ACTION:
            return None
        host = _args(event).get("host")
        if isinstance(host, str) and host.lower() in denied:
            return Decision.block(
                "egress_denylist: host not allowed",
                policy_id=EGRESS_POLICY_ID,
                attributed_to="host",
            )
        return None

    return rule


def file_guard(escalate_prefixes: Iterable[str] = ()) -> Rule:
    """Escalate, redact or block file access; allow everything else."""
    prefixes = tuple(str(item) for item in escalate_prefixes)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if event.action not in (READ_ACTION, WRITE_ACTION):
            return None
        path = _args(event).get("path")
        if not isinstance(path, str) or not path:
            return None
        if any(path.startswith(prefix) for prefix in prefixes):
            return Decision.escalate(
                "file_guard: path needs approval",
                policy_id=FILE_POLICY_ID,
                attributed_to="path",
            )
        if "secret" in path:
            return Decision.modify(
                {"path": "/redacted"},
                reason="file_guard: secret path redacted",
                policy_id=FILE_POLICY_ID,
                attributed_to="path",
            )
        if path.endswith((".pem", ".key")):
            return Decision.block(
                "file_guard: key material is not readable",
                policy_id=FILE_POLICY_ID,
                attributed_to="path",
            )
        return None

    return rule


#: Scope templates, keyed by the id a scope document binds. Allowlists and
#: deny-lists union up the scope chain; escalate prefixes do too.
templates = {
    "shell_allowlist": Template(
        "shell_allowlist", shell_allowlist, union_params=frozenset({"allow"})
    ),
    "egress_denylist": Template(
        "egress_denylist", egress_denylist, deny_params=frozenset({"deny_hosts"})
    ),
    "file_guard": Template(
        "file_guard", file_guard, union_params=frozenset({"escalate_prefixes"})
    ),
}


def scope_document() -> dict:
    """Two tenants with different bindings, so the corpus covers two scopes."""
    return {
        "version": 1,
        "default_scope": [],
        "allow_unscoped": False,
        "bindings": {
            "acme": [
                {"template": "shell_allowlist", "params": {"allow": ["ls", "pwd"]}},
                {
                    "template": "egress_denylist",
                    "params": {"deny_hosts": ["evil.example", "tracker.example"]},
                },
                {"template": "file_guard", "params": {"escalate_prefixes": ["/etc"]}},
            ],
            "acme/agent1": [
                {"template": "shell_allowlist", "params": {"allow": ["ls"]}},
            ],
            "beta": [
                {"template": "shell_allowlist", "params": {"allow": ["cat", "ls"]}},
                {
                    "template": "egress_denylist",
                    "params": {"deny_hosts": ["evil.example"]},
                },
                {
                    "template": "file_guard",
                    "params": {"escalate_prefixes": ["/etc", "/var"]},
                },
            ],
        },
    }


__all__ = [
    "EGRESS_ACTION",
    "EGRESS_POLICY_ID",
    "FILE_POLICY_ID",
    "READ_ACTION",
    "SHELL_ACTION",
    "SHELL_POLICY_ID",
    "WRITE_ACTION",
    "egress_denylist",
    "file_guard",
    "scope_document",
    "shell_allowlist",
    "templates",
]
