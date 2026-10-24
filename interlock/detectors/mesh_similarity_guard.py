"""Mesh similarity guard: escalate a call that looks like an attack other
deployments blocked, even when it is not word for word the same.

The mesh publishes *fingerprints* of blocked payloads: 768-bit sketches made
inside the reporting node by redacting, embedding, quantising and then
randomising every bit with a calibrated probability (local differential
privacy; see ``interlock.mesh.fingerprint`` and ``docs/guides/mesh.md``). A
fingerprint cannot be turned back into text, and two fingerprints of similar
text land close in Hamming distance.

This rule fingerprints the string content of a call's arguments the same way,
without the noise, and compares it with every published fingerprint. A
distance under the threshold for the pack's privacy budget ``alpha`` yields an
ESCALATE by default: similarity is evidence, not proof, and the right response
to "this looks like what hit three other companies" is to ask a human. A pack
may ask for a BLOCK instead.

Scope it to the tool classes the fingerprints came from (``actions=``) to keep
unrelated traffic out of the comparison. Reads a dict ``args`` only. Call phase
only. Never raises.
"""
from __future__ import annotations

from typing import Iterable, List, Optional

from ..actions import action_matches, canonical_actions
from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "mesh_similarity"


def mesh_similarity_guard(fingerprints: Iterable[str], alpha: float = 1.5,
                          actions: Optional[Iterable[str]] = None, verdict: str = "escalate",
                          max_distance: Optional[int] = None) -> Rule:
    """Build a Rule that escalates (or blocks) a call whose arguments are
    similar to a published fingerprint.

    *fingerprints* are hex-encoded 96-byte sketches; anything else is dropped.
    *alpha* is the privacy budget they were made with, which sets the match
    threshold unless *max_distance* overrides it. *actions* scopes the rule to
    those tool names. *verdict* is ``"escalate"`` (default) or ``"block"``.
    """
    from ..mesh import fingerprint as fp

    published: List[bytes] = []
    for value in _iter_strings(fingerprints):
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            continue
        if len(raw) == fp.BYTES:
            published.append(raw)
    try:
        limit = int(max_distance) if max_distance is not None else fp.threshold(float(alpha))
    except (TypeError, ValueError):
        limit = fp.threshold(fp.DEFAULT_ALPHA)
    scoped = canonical_actions(actions) if actions is not None else None
    block = verdict == "block"

    def rule(event: SensorEvent) -> Optional[Decision]:
        if not published:
            return None
        if scoped is not None and not action_matches(getattr(event, "action", None), scoped):
            return None
        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None
        try:
            text = fp.text_of_args(args)
            if not text:
                return None
            live = fp.fingerprint(text, None)
            best = min(fp.hamming(live, candidate) for candidate in published)
        except Exception:
            return None
        if best > limit:
            return None
        reason = "mesh_similarity: arguments resemble an attack other deployments blocked (distance {})".format(best)
        if block:
            return Decision.block(reason, POLICY_ID)
        return Decision.escalate(reason, POLICY_ID)

    return rule


def _iter_strings(values: Optional[Iterable[str]]):
    if values is None:
        return
    try:
        iterator = iter(values)
    except TypeError:
        return
    for value in iterator:
        if isinstance(value, str):
            yield value
