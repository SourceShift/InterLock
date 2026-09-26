"""MCP trust registry: gate tool calls on the trustworthiness of their origin.

An MCP server is a supply-chain edge: the tools it advertises run in-process
against the agent's capabilities. Trusting a tool therefore means trusting the
*server* that published it, so this Rule resolves each event to a single origin
and checks that origin against a fixed registry of trusted servers.

An origin is resolved from two sources, most explicit first:

1. ``args["__origin__"]`` - the sensor or adapter labelled the call with the
   server it came from. An explicit label wins because it is per-call and cannot
   be inferred from a name the untrusted server itself chose.
2. the prefix of a dotted action name - ``"github.create_issue"`` resolves to
   ``"github"``. This is the fallback for transports that encode the origin in
   the tool name (the common MCP spelling) and did not attach a label.

Both sources can be absent or malformed, and the rule is fail-closed: an
unresolvable origin is *untrusted*, not unknown-but-permitted. A tool that
cannot prove which server it belongs to is exactly the case the registry exists
to refuse, so a bare ``"bareword"`` action is blocked rather than waved through.

Only an origin that resolves *and* is a member of the trusted set returns None
(no opinion), leaving the engine's default-allow path untouched. Every other
event - untrusted origin, unresolvable origin, non-dict args - is blocked.
"""
from __future__ import annotations

from typing import Any, FrozenSet, Iterable, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "mcp_trust_registry"

# The action-name separator that introduces a dotted origin prefix.
_ORIGIN_SEPARATOR = "."

# The args key an adapter uses to label a call with its server origin.
_ORIGIN_KEY = "__origin__"

# Rendered in the block reason when no origin could be resolved at all.
_UNRESOLVED = "<unknown>"


def _as_origin_frozenset(trusted: Optional[Iterable[str]]) -> FrozenSet[str]:
    """Collect trusted origin names into a frozenset.

    A bare string is wrapped rather than iterated character-by-character, and
    non-str entries (None, int, nested containers) are skipped, so a malformed
    config narrows the registry instead of crashing - or, worse, silently
    trusting single characters. A frozenset is used because the registry is
    fixed at construction time and is only ever read.
    """
    if trusted is None:
        return frozenset()
    if isinstance(trusted, str):
        items: Iterable[Any] = (trusted,)
    else:
        items = trusted
    return frozenset(name for name in items if isinstance(name, str))


def _origin_from_args(args: Any) -> Optional[str]:
    """Resolve an explicit ``args["__origin__"]`` label, if it is usable.

    Args are attacker-influenced and may be anything - None, an int, a list.
    A non-mapping args, a missing key, or a blank/non-str label all mean "no
    label here", so the caller falls through to the dotted-name source rather
    than treating a malformed label as a refusal on its own.
    """
    if not isinstance(args, dict):
        return None
    origin = args.get(_ORIGIN_KEY)
    if isinstance(origin, str) and origin.strip():
        return origin
    return None


def _origin_from_action(action: Any) -> Optional[str]:
    """Resolve the origin prefix of a dotted action name, if there is one.

    ``"github.create_issue"`` -> ``"github"``. Splitting on the first separator
    keeps the origin a single segment, so ``"github.repo.delete"`` is still the
    ``github`` server. A non-str action, or one with no separator or an empty
    prefix (``".evil"``), yields None and is left for the fail-closed default.
    """
    if not isinstance(action, str):
        return None
    origin, separator, _ = action.partition(_ORIGIN_SEPARATOR)
    if separator and origin:
        return origin
    return None


def _resolve_origin(event: SensorEvent) -> Optional[str]:
    """Resolve an event's origin, explicit label first, dotted name second."""
    return _origin_from_args(event.args) or _origin_from_action(event.action)


def mcp_trust_registry(trusted: Iterable[str]) -> Rule:
    """Rule: permit calls only from origins in `trusted`; deny all others.

    Fail-closed by construction: the permit branch is a strict membership test,
    so an unresolvable or non-str origin can never match and is denied like any
    other untrusted server. Returns None (no opinion) only for a call whose
    origin resolves *and* appears in the registry.
    """
    registry = _as_origin_frozenset(trusted)

    def rule(event: SensorEvent) -> Optional[Decision]:
        origin = _resolve_origin(event)
        if origin is not None and origin in registry:
            return None
        # Only an explicit origin label names a triggering argument; an
        # origin inferred from the dotted action name has none to attribute.
        return Decision.block(
            "mcp_trust_registry: untrusted origin {}".format(
                origin if origin is not None else _UNRESOLVED
            ),
            policy_id=POLICY_ID,
            attributed_to=(
                _ORIGIN_KEY if _origin_from_args(event.args) is not None else None
            ),
        )

    return rule
