"""MCP tool schema pinning: freeze a tool's declared schema, block later drift.

An MCP server is a supply-chain edge, and the schema it advertises for a tool is
part of that server's interface. The rug-pull attack exploits the moment after
review: a server ships a tool with an innocuous description, an operator approves
it, and the *next* handshake declares the same tool name with a different
description or input schema - one that steers the model into a harmful call.

Name-based policy cannot see this, because the tool name never changes. This Rule
closes the gap by binding a tool name to the sha256 of the exact schema string
that was reviewed. Every later call must present that same string in
``args["__schema__"]``; the moment the hash differs, the interface changed under
the approval and the call is blocked.

The rule has an opinion only about pinned tools:

- a pinned tool whose declared schema hashes to its pin -> None (no opinion)
- a pinned tool whose schema hashes to anything else   -> BLOCK (drift)
- a tool that is not pinned                            -> None (out of scope)

Fail-closed where it counts: a pinned tool that presents *no* usable schema - a
missing key, a non-dict args, a non-str value - is drift like any other. The pin
was set against a concrete string, and a call that cannot produce that string has
not proven itself; refusing it is the point of pinning. Unpinned traffic is left
alone, so this guard composes with a name or capability policy rather than
replacing it.

A malformed pin map (None, a non-dict, or non-str entries) yields an empty pin
set, which makes the rule inert: it pins nothing and passes everything. That is
deliberate. The contract is "unpinned tools pass", and a pin map that failed to
load is indistinguishable from one that names nothing; silently fabricating
coverage the operator never supplied would be worse than being inert. Supply real
pins to enforce.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "mcp_tool_pinning"

# The args key an adapter uses to carry a tool's current declared schema.
_SCHEMA_KEY = "__schema__"


def pin_of(schema: str) -> str:
    """Return the sha256 hex digest that `schema` pins to.

    A config-time helper, not a detector path: it is called on a known-good
    schema string to build a pin map, so it stays strict rather than silently
    hashing the repr of a non-string.
    """
    return hashlib.sha256(schema.encode("utf-8")).hexdigest()


def _as_pin_map(pins: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Collect tool-name -> digest pins into a plain dict, skipping junk.

    A non-mapping config yields no pins. A non-str name can never equal an
    action name and a non-str digest can never equal a hex digest, so both are
    skipped: a malformed entry narrows the pin set instead of crashing the rule.
    """
    if not isinstance(pins, dict):
        return {}
    return {
        name: digest
        for name, digest in pins.items()
        if isinstance(name, str) and isinstance(digest, str)
    }


def _declared_schema(args: Any) -> Optional[str]:
    """Return the schema string an event declares, or None if it declares none.

    Args are attacker-influenced and may be anything - None, an int, a list. A
    non-mapping args, a missing key, or a non-str value all mean "no usable
    schema here", which the caller treats as drift for a pinned tool.
    """
    if not isinstance(args, dict):
        return None
    schema = args.get(_SCHEMA_KEY)
    if isinstance(schema, str):
        return schema
    return None


def mcp_tool_pinning(pins: Dict[str, str]) -> Rule:
    """Rule: block any pinned tool whose declared schema no longer matches its pin.

    Returns None (no opinion) for a call whose schema hashes to its pin, and for
    any tool that is not pinned. Blocks a pinned tool whose schema is absent or
    unusable, and any whose hash differs from the pin - a tampered description,
    a changed input schema, or a swapped tool behind the same name.
    """
    expected = _as_pin_map(pins)

    def rule(event: SensorEvent) -> Optional[Decision]:
        action = event.action
        if not isinstance(action, str):
            return None
        pin = expected.get(action)
        if pin is None:
            return None
        schema = _declared_schema(event.args)
        if schema is not None and pin_of(schema) == pin:
            return None
        return Decision.block(
            "mcp_tool_pinning: schema drift for {}".format(action),
            policy_id=POLICY_ID,
            attributed_to=_SCHEMA_KEY,
        )

    return rule
