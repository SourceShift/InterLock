"""Result guard: withhold an HTTP response by its status code.

An upstream 500 often carries a stack trace, a connection string or a query; a
403 body can describe the permission model. This rule reads the status of a
tool's HTTP result and withholds the result when it matches::

    http_status_guard(statuses=["5xx", 403])

Statuses are codes (``403``) or classes (``"5xx"``). The status is read from a
``status``/``status_code``/``statusCode`` field of the result. The tool has
already run - withholding keeps its output from the agent, it doesn't undo it.
"""
from __future__ import annotations

from typing import Iterable, Optional, Union

from ..actions import action_matches, canonical_actions
from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "http_status"
_STATUS_KEYS = ("status", "status_code", "statusCode")


def http_status_guard(statuses: Iterable[Union[int, str]], *, verdict: str = "block",
                      actions: Optional[Iterable[str]] = None) -> Rule:
    """Build a result-phase Rule withholding results with matching statuses."""
    if verdict not in ("block", "escalate"):
        raise ValueError("verdict must be block or escalate")
    exact, classes = set(), set()
    for status in statuses:
        text = str(status).lower()
        if len(text) == 3 and text.endswith("xx") and text[0].isdigit():
            classes.add(text[0])
        elif text.isdigit():
            exact.add(int(text))
        else:
            raise ValueError("a status is a code (403) or a class ('5xx'), got {!r}".format(status))
    action_set = None if actions is None else canonical_actions(actions)
    make = Decision.block if verdict == "block" else Decision.escalate

    def rule(event: SensorEvent) -> Optional[Decision]:
        if getattr(event, "phase", "call") != "result":
            return None
        if action_set is not None and not action_matches(event.action, action_set):
            return None
        payload = getattr(event, "args", None)
        if not isinstance(payload, dict):
            return None
        status = next((payload[k] for k in _STATUS_KEYS if k in payload), None)
        if isinstance(status, str) and status.isdigit():
            status = int(status)
        if not isinstance(status, int) or isinstance(status, bool):
            return None
        if status in exact or str(status)[0] in classes:
            return make("http_status: upstream answered {}".format(status), POLICY_ID,
                        attributed_to="status")
        return None

    rule.phase = "result"  # type: ignore[attr-defined]
    return rule
