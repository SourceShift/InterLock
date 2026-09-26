"""Retrieval guard: only retrieve documents from allowlisted sources.

Retrieval is an injection vector in its own right. A RAG pipeline that pulls
from the open web hands the model whatever an attacker planted there, and the
model treats retrieved text with far more trust than it treats user input - so
the poisoning never has to pass the prompt filter. The defence that survives
that framing is provenance: a retrieval may only draw from sources the operator
has vetted. This rule encodes that decision at the argument detector, before
any document is fetched.

The rule is fail-closed. A retrieval whose source is absent, non-string, or
simply not on the list is blocked rather than waved through, because the only
safe reading of "I cannot tell where this came from" is "assume hostile". The
one source of slack is the ordinary non-retrieval action, which is not this
rule's business and so yields no opinion.

The source is read from ``args["source"]``, falling back to
``args["collection"]`` (the name several vector stores use). Values that cannot
be a source - None, an int, a nested dict or list - are never stringified into a
match; they simply fail the allowlist test and block. A detector must never
raise on odd input, so a non-dict ``args`` also fails closed here.
"""
from __future__ import annotations

from typing import Iterable, Optional, Set

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "rag_source_allowlist"

# The action names that denote a retrieval. Only these are this rule's concern;
# anything else is not a retrieval and gets no opinion.
RETRIEVAL_ACTIONS: Set[str] = {"retrieve", "rag_query", "search_docs"}


def _render(source: object) -> str:
    """Render a source for the reason string without ever raising.

    A usable source is echoed verbatim so the operator can see which value was
    rejected; an unusable one (None, an int, a container) is named as
    ``<missing>`` rather than coerced, since its real content is not a source.
    """
    if isinstance(source, str):
        return source
    return "<missing>"


def rag_source_allowlist(allowed: Iterable[str]) -> Rule:
    """Build a Rule that blocks retrieval from a source outside ``allowed``.

    ``allowed`` is snapshotted into a set at build time, so a later mutation of
    the caller's iterable cannot widen the policy. The returned rule:

    * returns None for a non-retrieval action, or a retrieval whose source is a
      member of the allowlist;
    * returns a BLOCK naming the source otherwise - including the fail-closed
      case where no source can be read at all.

    It never raises.
    """
    permitted: Set[str] = {s for s in allowed if isinstance(s, str)}

    def rule(event: SensorEvent) -> Optional[Decision]:
        action = getattr(event, "action", None)
        if action not in RETRIEVAL_ACTIONS:
            return None

        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            # A retrieval we cannot inspect is a retrieval we cannot vet.
            return Decision.block(
                reason="rag_source_allowlist: source {} not allowed".format(
                    _render(None)
                ),
                policy_id=POLICY_ID,
            )

        source = args.get("source")
        src_key = "source"
        if source is None:
            source = args.get("collection")
            src_key = "collection"

        if isinstance(source, str) and source in permitted:
            return None

        return Decision.block(
            reason="rag_source_allowlist: source {} not allowed".format(
                _render(source)
            ),
            policy_id=POLICY_ID,
            attributed_to=src_key,
        )

    return rule
