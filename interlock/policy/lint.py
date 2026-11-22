"""Static checks *across* a declarative policy's rules.

Loading a policy answers "is each rule well formed". It cannot answer "can
these rules ever do what they say" - and a rule set that cannot is worse than a
permissive one, because it reads as a guarantee. NOMOS (arXiv 2610.11030) makes
the same point about compiled tool-call gates: the failure modes are structural,
not syntactic, so they need a pass over the whole rule set.

Three shapes are decidable from the document alone, and each is reported with
the reason a reader could verify by hand:

``unsatisfiable``
    The rule's condition can never match. It is ``all``-ed with two action
    constraints on different actions - an event cannot be both ``deploy`` and
    ``approve`` - or with an empty ``any``.

``shadowed``
    An earlier plain ``block`` rule has the identical condition (and phase), so
    the later rule is never evaluated: the engine returns the first block. This
    is not necessarily a bug, but a rule that can never fire should be a known
    one - it is usually a policy written in the wrong order.

``contradicts-requirement``
    The rule set requires an action and blocks it. An obligation whose ``then``
    action an unconditional ``block`` rule refuses for every call can never be
    discharged, so every run that opens the obligation is eventually refused.

What this pass deliberately does not do: it does not reason about arguments,
provenance selectors, detector semantics, or ``extends``/``disable``/
``overlay`` (the rules written in the file being linted are the rules it sees -
lint an overlay on its own to check it). Detectors are opaque - their verdicts
are decided at run time - so a detector can only be the *subject* of a finding,
never the shadowing or blocking rule.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set

from ..actions import canonical_action

#: The two action constraints of one ``all`` disagree, so it never matches.
UNSATISFIABLE = "unsatisfiable"
#: An earlier block rule with the same condition decides every event first.
SHADOWED = "shadowed"
#: A required action is blocked for every call, so the requirement is dead.
CONTRADICTS = "contradicts-requirement"

__all__ = ["CONTRADICTS", "Finding", "SHADOWED", "UNSATISFIABLE", "lint_document",
           "lint_file"]


@dataclass(frozen=True)
class Finding:
    """One structural problem, located by rule id so a reader can find it."""

    code: str
    rule: str
    message: str
    path: str = ""

    def as_dict(self) -> Dict[str, str]:
        return asdict(self)


def _canonical(action: Any) -> Optional[str]:
    if not isinstance(action, str) or not action:
        return None
    try:
        return canonical_action(action)
    except (TypeError, ValueError):
        return action


def _action_set(value: Any) -> Optional[FrozenSet[str]]:
    """The actions an ``{"action": ...}`` value admits; None when unknown.

    A glob cannot be expanded without the action catalogue, so it is unknown -
    the caller must not treat unknown as "nothing".
    """
    if isinstance(value, str):
        name = _canonical(value)
        return frozenset({name}) if name else None
    if isinstance(value, (list, tuple)):
        names = [_canonical(item) for item in value]
        if not names or any(name is None for name in names):
            return None
        return frozenset(names)  # type: ignore[arg-type]
    return None


def _actions(cond: Any) -> Optional[FrozenSet[str]]:
    """Every action an event must be among for *cond* to match.

    None means "not derivable" - a condition that never mentions an action, or
    one that uses a glob or a disjunction. An empty set means the condition
    contradicts itself and can never match.
    """
    if not isinstance(cond, Mapping):
        return None
    if "action" in cond:
        return _action_set(cond["action"])
    if cond.get("field") == "action":
        for operator in ("eq", "in"):
            if operator in cond:
                return _action_set(cond[operator])
        return None
    if "all" in cond and isinstance(cond["all"], list):
        known = [part for part in (_actions(item) for item in cond["all"])
                 if part is not None]
        if not known:
            return None
        narrowed = set(known[0])
        for part in known[1:]:
            narrowed.intersection_update(part)
        return frozenset(narrowed)
    if "any" in cond and isinstance(cond["any"], list):
        union: Set[str] = set()
        for item in cond["any"]:
            part = _actions(item)
            if part is None:
                return None
            union.update(part)
        return frozenset(union)
    return None


def _action_only(cond: Any) -> bool:
    """Whether *cond* constrains nothing but the action (an unconditional block)."""
    if not isinstance(cond, Mapping):
        return False
    if set(cond) == {"action"}:
        return True
    if set(cond) == {"all"} and isinstance(cond["all"], list) and cond["all"]:
        return all(_action_only(part) for part in cond["all"])
    return False


def _fingerprint(rule: Mapping[str, Any]) -> str:
    """The rule's (phase, condition) as a canonical string, for equality."""
    return json.dumps([rule.get("phase", "call"), rule.get("when")],
                      sort_keys=True, separators=(",", ":"), default=str)


def _plain_block(rule: Mapping[str, Any]) -> bool:
    return (rule.get("verdict") == "block" and "detector" not in rule
            and rule.get("mode", "enforce") == "enforce"
            and rule.get("phase", "call") == "call")


def _quarantined_ids(quarantined: Iterable[str]) -> Set[str]:
    """Rule ids from ``engine.quarantined`` entries (``"id: why"`` strings)."""
    return {entry.split(":", 1)[0].strip() for entry in quarantined}


def _required_actions(rule: Mapping[str, Any]) -> List[str]:
    """The ``then`` actions of an obligations rule, or nothing for any other."""
    detector = rule.get("detector")
    if not isinstance(detector, str):
        return []
    name = detector.rsplit(":", 1)[-1].rsplit(".", 1)[-1]
    if name != "obligations":
        return []
    spec = rule.get("with")
    require = spec.get("require") if isinstance(spec, Mapping) else None
    if not isinstance(require, list):
        return []
    return [then for then in (_canonical(item.get("then"))
                              for item in require if isinstance(item, Mapping))
            if then]


def lint_document(doc: Mapping[str, Any], *, quarantined: Sequence[str] = (),
                  path: str = "") -> List[Finding]:
    """Every structural finding in *doc*, in rule order.

    *quarantined* is ``engine.quarantined`` from the load: those rules are not
    in the engine, so they neither shadow nor are shadowed. :class:`Findings
    <Finding>` named a rule id the loader rejected would be noise.
    """
    rules = [rule for rule in doc.get("rules", [])
             if isinstance(rule, Mapping)]
    skipped = _quarantined_ids(quarantined)
    rules = [rule for rule in rules if rule.get("id") not in skipped]
    findings: List[Finding] = []

    # 1. A condition that cannot match.
    for rule in rules:
        actions = _actions(rule.get("when")) if "when" in rule else None
        if actions is not None and not actions:
            findings.append(Finding(
                UNSATISFIABLE, str(rule.get("id", "")),
                "its condition requires an event to be two different actions at "
                "once, so it never matches", path))

    # 2. A rule an earlier block rule decides before it.
    seen: Dict[str, str] = {}
    for rule in rules:
        when = rule.get("when")
        if not isinstance(when, Mapping):
            continue
        rule_id = str(rule.get("id", ""))
        key = _fingerprint(rule)
        earlier = seen.get(key)
        if earlier is not None:
            findings.append(Finding(
                SHADOWED, rule_id,
                "rule {!r} has the same condition and phase and blocks first, so "
                "this rule is never evaluated".format(earlier), path))
        if _plain_block(rule):
            seen.setdefault(key, rule_id)

    # 3. A required action that is refused for every call.
    blocked: Dict[str, str] = {}
    for rule in rules:
        if not _plain_block(rule):
            continue
        cond = rule.get("when")
        if not _action_only(cond):
            continue
        for action in _actions(cond) or ():
            blocked.setdefault(action, str(rule.get("id", "")))
    if blocked:
        for rule in rules:
            if "detector" not in rule:
                continue
            for action in _required_actions(rule):
                blocker = blocked.get(action)
                if blocker is None:
                    continue
                findings.append(Finding(
                    CONTRADICTS, str(rule.get("id", "")),
                    "it requires {!r}, but rule {!r} blocks every {!r} call - the "
                    "requirement can never be met".format(action, blocker, action),
                    path))
    return findings


def lint_file(path: str) -> List[Finding]:
    """Every finding in one policy file, located by *path*.

    Raises :class:`~interlock.policy.declarative.PolicyError` when the file does
    not parse or does not load; an invalid policy has no structure to lint.
    """
    from .declarative import check_policy_file, read_policy_file

    report = check_policy_file(path)
    doc, _ = read_policy_file(path)
    return lint_document(doc, quarantined=report.get("quarantined", ()), path=path)
