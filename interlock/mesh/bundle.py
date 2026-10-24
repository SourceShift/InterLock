"""Policy packs as the mesh publishes them, and how a ring applies one.

A pack is an ordinary declarative policy document (see
``docs/guides/policies.md``) with one extra fact per rule: a ``status`` that
says how much the community trusts it yet.

=================  ====================================================================
``experimental``   just merged; passed the forge's gates and a maintainer's review
``test``           ran at least a week in monitor mode on the canary ring without noise
``stable``         clean on the early ring; the rule the pack means to ship
``deprecated``     superseded or withdrawn; subscribers drop it
=================  ====================================================================

A subscriber is on a **ring** and the ring decides two things: which statuses
it installs at all, and the strongest verdict a rule of each status may carry
(its **ceiling**). A decision above the ceiling becomes an ``escalate``, which
asks a human instead of acting. The defaults follow the design document:

=========  ===========================  =========================================
ring       installs                     default ceiling by status
=========  ===========================  =========================================
canary     experimental, test, stable   experimental → escalate · test → modify
early      test, stable                 test → modify
stable     stable                       none: the pack's own verdict
=========  ===========================  =========================================

On top of the ceiling, every rule that is new to this node (or whose logic
changed) spends a **monitor window** in shadow mode: it is evaluated and its
would-be verdict is recorded, but it decides nothing. The window restarts when
the rule's condition changes and not when only its status is promoted, so a
rule does not go dark again just because the community trusts it more.

Mesh packs may not lock rules: ``locked`` is stripped, because a subscriber
must always be able to disable a community rule in its own policy file.
"""
from __future__ import annotations

import copy
import hashlib
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Tuple

from ._util import canonical

__all__ = [
    "STATUSES", "RINGS", "DEFAULT_CEILINGS", "VERDICT_RANK", "DEFAULT_MONITOR_SECONDS",
    "PackError", "normalize_pack", "rule_digest", "pack_summary", "apply_ring", "RingResult",
]

STATUSES = ("experimental", "test", "stable", "deprecated")
RINGS: Dict[str, Tuple[str, ...]] = {
    "canary": ("experimental", "test", "stable"),
    "early": ("test", "stable"),
    "stable": ("stable",),
}
DEFAULT_CEILINGS: Dict[str, Optional[str]] = {
    "experimental": "escalate",
    "test": "modify",
    "stable": None,
}
VERDICT_RANK = {"escalate": 1, "modify": 2, "block": 3}
DEFAULT_MONITOR_SECONDS = 7 * 86400

#: Keys the subscriber sets on a rule when applying a ring; a pack author may
#: not set them, so a pack cannot pre-empt the node's own safety settings.
_SUBSCRIBER_KEYS = ("mode", "ceiling")
_IGNORED_FOR_DIGEST = ("status", "mode", "ceiling", "description", "locked")


class PackError(ValueError):
    """A pack that cannot be published or installed."""


def normalize_pack(doc: Any, *, name: str = "<pack>") -> Dict[str, Any]:
    """Validate the pack-level shape and fill in defaults.

    Every rule gets an explicit ``status`` (``experimental`` when missing), may
    not carry subscriber-only keys, and may not be locked. Rule validity itself
    (conditions, detectors, verdicts) is the policy loader's job and is checked
    when the pack is published and again when it is installed.
    """
    if not isinstance(doc, dict):
        raise PackError("{}: a pack must be a JSON object".format(name))
    if doc.get("extends") is not None:
        raise PackError("{}: a pack cannot extend another document".format(name))
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        raise PackError("{}: a pack needs a non-empty 'rules' list".format(name))
    out = copy.deepcopy(dict(doc))
    out["rules"] = []
    seen = set()
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise PackError("{}: rules[{}] is not an object".format(name, index))
        rule = dict(rule)
        for key in _SUBSCRIBER_KEYS:
            if key in rule:
                raise PackError("{}: rules[{}] sets {!r}, which only a subscriber may".format(
                    name, index, key))
        status = rule.get("status", "experimental")
        if status not in STATUSES:
            raise PackError("{}: rules[{}] has status {!r}; use one of {}".format(
                name, index, status, ", ".join(STATUSES)))
        rule["status"] = status
        rule.pop("locked", None)
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise PackError("{}: rules[{}] has no id".format(name, index))
        if rule_id in seen:
            raise PackError("{}: duplicate rule id {!r}".format(name, rule_id))
        seen.add(rule_id)
        out["rules"].append(rule)
    return out


def rule_digest(rule: Mapping[str, Any]) -> str:
    """Identity of a rule's *logic*: everything but its status and prose.

    Used to decide whether a rule is new to a node (monitor window) and to
    report which exact rule fired.
    """
    body = {k: v for k, v in rule.items() if k not in _IGNORED_FOR_DIGEST}
    return hashlib.sha256(canonical(body)).hexdigest()[:16]


def pack_summary(doc: Mapping[str, Any]) -> Dict[str, Any]:
    """The facts the targets metadata publishes about a pack (``custom``)."""
    counts: Dict[str, int] = {}
    for rule in doc.get("rules", []):
        counts[rule.get("status", "experimental")] = counts.get(rule.get("status", "experimental"), 0) + 1
    return {
        "name": doc.get("name"),
        "description": doc.get("description"),
        "channel": doc.get("channel"),
        "rule_count": len(doc.get("rules", [])),
        "statuses": dict(sorted(counts.items())),
    }


class RingResult:
    """What :func:`apply_ring` produced: the installable document, the rules it
    dropped and why, and when the next shadow rule leaves its window."""

    def __init__(self, document: Dict[str, Any], dropped: List[Tuple[str, str]],
                 shadowed: List[str], ceilings: Dict[str, str],
                 next_transition: Optional[float]) -> None:
        self.document = document
        self.dropped = dropped
        self.shadowed = shadowed
        self.ceilings = ceilings
        self.next_transition = next_transition


def apply_ring(doc: Mapping[str, Any], ring: str, *, now: float,
               first_seen: MutableMapping[str, Any],
               monitor_seconds: float = DEFAULT_MONITOR_SECONDS,
               ceilings: Optional[Mapping[str, Optional[str]]] = None,
               source: str = "mesh") -> RingResult:
    """Turn a published pack into the document this node installs.

    ``first_seen`` maps a rule id to ``{"digest": ..., "since": ts}`` and is
    updated in place: it is the node's memory of when it first saw each rule's
    current logic, and it must persist between loads for the monitor window to
    mean anything.
    """
    if ring not in RINGS:
        raise PackError("unknown ring {!r}; use one of {}".format(ring, ", ".join(RINGS)))
    allowed = RINGS[ring]
    ceiling_by_status: Dict[str, Optional[str]] = dict(DEFAULT_CEILINGS)
    if ceilings:
        for status, ceiling in ceilings.items():
            if status not in STATUSES:
                raise PackError("ceiling for unknown status {!r}".format(status))
            if ceiling is not None and ceiling not in VERDICT_RANK:
                raise PackError("ceiling {!r} is not a verdict".format(ceiling))
            ceiling_by_status[status] = ceiling
    out = copy.deepcopy(dict(doc))
    out.pop("extends", None)
    out["rules"] = []
    dropped: List[Tuple[str, str]] = []
    shadowed: List[str] = []
    applied_ceilings: Dict[str, str] = {}
    next_transition: Optional[float] = None
    for rule in doc.get("rules", []):
        rule = dict(rule)
        rule_id = str(rule.get("id"))
        status = rule.get("status", "experimental")
        if status == "deprecated":
            dropped.append((rule_id, "deprecated"))
            continue
        if status not in allowed:
            dropped.append((rule_id, "status {} is below the {} ring".format(status, ring)))
            continue
        rule.pop("locked", None)
        rule.pop("mode", None)
        rule.pop("ceiling", None)
        ceiling = ceiling_by_status.get(status)
        if ceiling is not None:
            rule["ceiling"] = ceiling
            applied_ceilings[rule_id] = ceiling
        digest = rule_digest(rule)
        memory = first_seen.get(rule_id)
        if not isinstance(memory, dict) or memory.get("digest") != digest:
            memory = {"digest": digest, "since": now}
            first_seen[rule_id] = memory
        since = float(memory.get("since", now))
        until = since + monitor_seconds
        if monitor_seconds > 0 and now < until:
            rule["mode"] = "shadow"
            shadowed.append(rule_id)
            next_transition = until if next_transition is None else min(next_transition, until)
        out["rules"].append(rule)
    out.setdefault("name", source)
    return RingResult(out, dropped, shadowed, applied_ceilings, next_transition)
