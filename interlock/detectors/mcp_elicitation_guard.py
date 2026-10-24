"""MCP guard: refuse servers' elicitation requests.

MCP elicitation lets a *server* ask the user a question through the client
(``elicitation/create``). A compromised or malicious server can use it to
phish - "re-enter your API token to continue" - in the client's own UI. This
rule blocks elicitation events (action ``mcp.elicitation``, or the raw method
name ``elicitation/create``) unless the server is listed in ``allow_servers``
(matched against the ``__origin__`` label your adapter sets).
"""
from __future__ import annotations

from typing import Iterable, Optional

from ..actions import action_matches, canonical_actions
from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "mcp_elicitation"
ELICITATION_ACTIONS = frozenset({"mcp.elicitation", "elicitation/create"})
_elicitation_actions = canonical_actions(ELICITATION_ACTIONS)


def mcp_elicitation_guard(allow_servers: Iterable[str] = ()) -> Rule:
    """Build a Rule blocking elicitation from every server not allowed."""
    allowed = frozenset(allow_servers)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if not action_matches(event.action, _elicitation_actions):
            return None
        args = event.args if isinstance(event.args, dict) else {}
        origin = args.get("__origin__")
        if isinstance(origin, str) and origin in allowed:
            return None
        return Decision.block("mcp_elicitation: server {} may not ask the user for input".format(
            origin if isinstance(origin, str) else "(unlabelled)"), POLICY_ID,
            attributed_to="__origin__")

    return rule
