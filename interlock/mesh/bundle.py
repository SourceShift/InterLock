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
asks a human instead of acting. The defaults follow decision R5 in
``internal-docs/research/mesh-decisions.md``: no community rule blocks on its own.

=========  ===========================  ==================================================
ring       installs                     default ceiling by status
=========  ===========================  ==================================================
canary     experimental, test, stable   experimental → escalate · test, stable → modify
early      test, stable                 test, stable → modify
stable     stable                       stable → modify
=========  ===========================  ==================================================

A ``modify`` ceiling leaves a pack's rewrites alone and turns its blocks into
escalations. A **grant** from the operator (``config.json``, ``interlock mesh
grant``) lifts the ceiling to the pack's own verdict, for one rule or for a pack
at and above a status.

On top of the ceiling, every rule that is new to this node (or whose logic
changed) spends a **monitor window** in shadow mode: it is evaluated and its
would-be verdict is recorded, but it decides nothing. The window restarts when
the rule's condition changes and not when only its status is promoted, so a
rule does not go dark again just because the community trusts it more.

Mesh packs may not lock rules: ``locked`` is stripped, because a subscriber
must always be able to disable a community rule in its own policy file.

A pack names its licence as an SPDX id in ``license`` (decision R4): packs are
``Apache-2.0`` unless they say otherwise, and the targets metadata publishes
it. A rule may carry its own ``license`` (one taken from a project with another
licence); like ``description`` it is metadata and not part of the rule's logic.
"""
from __future__ import annotations

import copy
import hashlib
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Tuple

from ._util import canonical

__all__ = [
    "STATUSES", "RINGS", "DEFAULT_CEILINGS", "VERDICT_RANK", "DEFAULT_MONITOR_SECONDS",
    "PackError", "normalize_pack", "rule_digest", "pack_summary", "apply_ring", "RingResult",
    "GRANT_STATUSES", "check_grants", "grant_matches", "DEFAULT_PACK_LICENSE",
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
    "stable": "modify",
}
VERDICT_RANK = {"escalate": 1, "modify": 2, "block": 3}
DEFAULT_MONITOR_SECONDS = 7 * 86400
#: A pack is code: Apache-2.0, the project's own licence, unless it says otherwise.
DEFAULT_PACK_LICENSE = "Apache-2.0"

#: How far a grant for a status reaches: a grant for ``test`` covers ``test``
#: and ``stable`` rules. ``deprecated`` rules are never installed, so never granted.
GRANT_STATUSES: Dict[str, int] = {"experimental": 0, "test": 1, "stable": 2}

#: Keys the subscriber sets on a rule when applying a ring; a pack author may
#: not set them, so a pack cannot pre-empt the node's own safety settings.
_SUBSCRIBER_KEYS = ("mode", "ceiling", "origin")
_IGNORED_FOR_DIGEST = ("status", "mode", "ceiling", "origin", "description", "locked", "license")


class PackError(ValueError):
    """A pack that cannot be published or installed."""


def normalize_pack(doc: Any, *, name: str = "<pack>") -> Dict[str, Any]:
    """Validate the pack-level shape and fill in defaults.

    Every rule gets an explicit ``status`` (``experimental`` when missing), may
    not carry subscriber-only keys, and may not be locked. The pack gets an
    explicit ``license`` (``Apache-2.0`` when missing). Rule validity itself
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
    licence = doc.get("license", DEFAULT_PACK_LICENSE)
    if not isinstance(licence, str) or not licence.strip():
        raise PackError("{}: 'license' must be an SPDX licence identifier".format(name))
    out = copy.deepcopy(dict(doc))
    out["license"] = licence
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
    """Identity of a rule's *logic*: everything but its status, prose and licence.

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
        "license": doc.get("license", DEFAULT_PACK_LICENSE),
    }


def check_grants(grants: Any) -> Dict[str, List[Dict[str, str]]]:
    """Validate an operator's grants and return a normalised copy.

    The shape is ``{"block": [entry, ...]}`` where an entry is either
    ``{"pack": NAME, "status": STATUS}`` (that pack's rules at or above
    ``STATUS``) or ``{"rule": ID}``, optionally with ``"pack"`` to keep the
    grant to one pack's rule of that id. Anything else is refused rather than
    read as "no grant", so a typo is seen.
    """
    if grants is None:
        return {"block": []}
    if not isinstance(grants, Mapping):
        raise PackError("grants must be an object like {\"block\": [...]}")
    unknown = sorted(set(grants) - {"block"})
    if unknown:
        raise PackError("unknown grant kind(s) {}; only 'block' is granted".format(", ".join(unknown)))
    entries = grants.get("block", [])
    if not isinstance(entries, list):
        raise PackError("grants.block must be a list")
    out: List[Dict[str, str]] = []
    for index, entry in enumerate(entries):
        where = "grants.block[{}]".format(index)
        if not isinstance(entry, Mapping) or set(entry) - {"pack", "status", "rule"}:
            raise PackError("{} must be {{pack, status}} or {{rule[, pack]}}".format(where))
        for key in ("pack", "rule"):
            if key in entry and (not isinstance(entry[key], str) or not entry[key]):
                raise PackError("{}.{} must be a non-empty string".format(where, key))
        if "rule" in entry:
            if "status" in entry:
                raise PackError("{} grants one rule; it takes no status".format(where))
        elif "pack" not in entry or entry.get("status") not in GRANT_STATUSES:
            raise PackError("{} needs a pack and a status ({})".format(where, ", ".join(GRANT_STATUSES)))
        out.append({k: str(v) for k, v in sorted(entry.items())})
    return {"block": out}


def grant_matches(grants: Mapping[str, Any], *, pack: Optional[str], rule_id: str, status: str) -> bool:
    """Whether a (checked) grant lifts the ceiling of this rule.

    ``pack`` is the name the node subscribed to (``mesh:<pack>``), not the
    pack document's own ``name``, which its author chose.
    """
    rank = GRANT_STATUSES.get(status)
    for entry in grants.get("block", ()):
        if "rule" in entry:
            if entry["rule"] == rule_id and entry.get("pack") in (None, pack):
                return True
        elif entry["pack"] == pack and rank is not None and rank >= GRANT_STATUSES[entry["status"]]:
            return True
    return False


class RingResult:
    """What :func:`apply_ring` produced: the installable document, the rules it
    dropped and why, when the next shadow rule leaves its window, the rules a
    grant lifted, and the rules whose verdict the ceiling caps to an escalate."""

    def __init__(self, document: Dict[str, Any], dropped: List[Tuple[str, str]],
                 shadowed: List[str], ceilings: Dict[str, str],
                 next_transition: Optional[float], *, granted: Optional[List[str]] = None,
                 capped: Optional[List[str]] = None) -> None:
        self.document = document
        self.dropped = dropped
        self.shadowed = shadowed
        self.ceilings = ceilings
        self.next_transition = next_transition
        self.granted = list(granted or [])
        self.capped = list(capped or [])


def apply_ring(doc: Mapping[str, Any], ring: str, *, now: float,
               first_seen: MutableMapping[str, Any],
               monitor_seconds: float = DEFAULT_MONITOR_SECONDS,
               ceilings: Optional[Mapping[str, Optional[str]]] = None,
               source: str = "mesh", grants: Optional[Mapping[str, Any]] = None,
               pack: Optional[str] = None) -> RingResult:
    """Turn a published pack into the document this node installs.

    ``first_seen`` maps a rule id to ``{"digest": ..., "since": ts}`` and is
    updated in place: it is the node's memory of when it first saw each rule's
    current logic, and it must persist between loads for the monitor window to
    mean anything.

    ``grants`` (see :func:`check_grants`) lifts the ceiling of the rules it
    matches to the pack's own verdict. Pack grants match ``pack``, the name the
    node subscribed to; without one they match the document's ``name``. Every
    installed rule is marked ``"origin": "mesh"``.
    """
    if ring not in RINGS:
        raise PackError("unknown ring {!r}; use one of {}".format(ring, ", ".join(RINGS)))
    allowed = RINGS[ring]
    granting = check_grants(grants)
    pack_name = pack if pack is not None else doc.get("name")
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
    granted: List[str] = []
    capped: List[str] = []
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
        for key in _SUBSCRIBER_KEYS:
            rule.pop(key, None)
        ceiling = ceiling_by_status.get(status)
        if grant_matches(granting, pack=pack_name, rule_id=rule_id, status=status):
            granted.append(rule_id)
            ceiling = None
        if ceiling is not None:
            rule["ceiling"] = ceiling
            applied_ceilings[rule_id] = ceiling
            limit = VERDICT_RANK[ceiling]
            # A detector may return any verdict, so any ceiling below block can bite it.
            if VERDICT_RANK.get(rule.get("verdict"), 0) > limit or (
                    "detector" in rule and limit < VERDICT_RANK["block"]):
                capped.append(rule_id)
        rule["origin"] = "mesh"
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
    return RingResult(out, dropped, shadowed, applied_ceilings, next_transition,
                      granted=granted, capped=capped)
