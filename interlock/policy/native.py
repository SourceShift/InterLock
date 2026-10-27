"""Native policy evaluation (R31): a Rust fast path over a compiled plan.

The Python engine is the policy source of truth. This module translates a
declarative policy into a plan the native evaluator can run, but **only when
it can translate everything**: the planner returns ``None`` the moment it
meets a detector, a rewrite, an overlay, a disabled or quarantined rule, a
shadow rule, or a mesh ceiling. A policy is therefore either fully native or
fully Python, which is what makes the two paths impossible to disagree by
construction rather than by test only.

The plan format mirrors the condition language in
:mod:`interlock.policy.declarative` exactly; :mod:`interlock_engine` is the
Rust side and documents the semantics it copies. Detector rules are native
only when the detector itself has a Rust port (see :data:`NATIVE_DETECTORS`);
every other detector keeps the whole policy on Python, because a detector can
choose a verdict and a half-ported one could choose differently.

The evaluator is opt-in (``INTERLOCK_NATIVE=1``) until the parity suite has
run for a release, and a failure at any point falls back to the Python engine
for that event.

Two front ends sit on the same Rust engine: a PyO3 class (used here) and a C
ABI (``il_eval_plan``) for processes that do not embed CPython. Both are in
``rust/``; neither is required - without the wheel, this module reports no
native path and everything runs as before.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, List, Mapping, Optional

from ..enforce import Decision, Verdict

_log = logging.getLogger(__name__)

#: Set to a truthy value to let an eligible policy use the native evaluator.
ENV_FLAG = "INTERLOCK_NATIVE"

#: Below this many rules the JSON boundary costs more than the evaluation it
#: saves; the planner declines and the Python engine runs. Override for
#: benchmarking with INTERLOCK_NATIVE_MIN_RULES.
DEFAULT_MIN_RULES = 8

#: Event fields the Rust side accepts in a ``{"field": ...}`` test.
FIELDS = frozenset(
    {"action", "principal", "phase", "span_id", "parent_principal", "call_id"}
)

OPS = frozenset(
    {"eq", "ne", "in", "not_in", "gt", "ge", "lt", "le", "contains",
     "startswith", "endswith", "exists", "glob", "matches"}
)

#: Longest regex the native evaluator accepts (mirrors MAX_PATTERN).
MAX_PATTERN = 512

#: Detectors with a Rust port in ``rust/engine/src/detectors.rs``, keyed by
#: every spelling the Python loader accepts and valued by the canonical plan
#: name. A detector not listed here - or listed but used with ``with``
#: parameters - keeps the policy on the Python engine.
NATIVE_DETECTORS = {
    name: name
    for name in (
        "ansi_escape_output_guard",
        "crlf_header_injection_guard",
        "download_extension_guard",
        "code_eval_exec_guard",
    )
}
NATIVE_DETECTORS.update({"{0}.{0}".format(name): name for name in list(NATIVE_DETECTORS)})


def enabled() -> bool:
    """Whether the operator asked for the native path."""
    return os.environ.get(ENV_FLAG, "").strip().lower() in {"1", "true", "yes", "on"}


def _plan_class() -> Optional[Any]:
    """The compiled-plan class from the optional accelerator, or None."""
    try:
        import interlock_scopes  # type: ignore[import-not-found]
    except Exception:  # pragma: no cover - the accelerator is optional
        return None
    return getattr(interlock_scopes, "NativePlan", None)


def min_rules() -> int:
    raw = os.environ.get("INTERLOCK_NATIVE_MIN_RULES")
    if raw is None:
        return DEFAULT_MIN_RULES
    try:
        return max(0, int(raw))
    except ValueError:
        return DEFAULT_MIN_RULES


def plan_for(engine: Any, *, minimum: Optional[int] = None) -> Optional[str]:
    """A compiled plan for ``engine``, or None if any part is unsupported.

    Reads ``engine.documents`` - the effective policy documents, in the order
    their rules were compiled - rather than the compiled callables, because a
    callable no longer carries the condition it was built from.

    ``minimum`` overrides the size gate for this call. The default (``None``)
    reads :func:`min_rules`; an artifact-backed policy passes ``0`` because it
    was explicitly compiled for the native fast path, and a one-rule artifact
    should not silently fall back to Python just because the JSON boundary
    would cost more than the rule.
    """
    text, _ = plan_for_with_reason(engine, minimum=minimum)
    return text


def plan_for_with_reason(
    engine: Any, *, minimum: Optional[int] = None
) -> tuple:
    """``(plan_json, reason)``; exactly one is None.

    ``reason`` is a short human string for ``CompiledPolicy.status()`` and the
    policy CLI. It never contains an event or an argument value: it is written
    to a terminal and a quote of a rule id is deliberate, but nothing else is
    carried out of the policy.
    """
    if getattr(engine, "quarantined", None):
        return None, "engine has quarantined rules"
    if getattr(engine, "overlays", None):
        return None, "engine has overlays"
    if getattr(engine, "_shadow", None):
        return None, "engine has shadow rules"
    if getattr(engine, "_code_rules", None):
        return None, "engine has code rules"
    documents = getattr(engine, "documents", None)
    if not documents:
        return None, "engine has no documents to plan"
    rules: List[Mapping[str, Any]] = []
    for document in documents:
        if not isinstance(document, Mapping):
            return None, "engine document is not an object"
        # An overlay document is applied by prepending its widened rules, which
        # documents do not record; a mesh parent carries ceilings; a `disable`
        # list removes rules that the documents still contain.
        if document.get("overlay") or document.get("extends") or document.get("disable"):
            return None, "engine document uses overlay, extends or disable"
        raw_rules = document.get("rules", [])
        if not isinstance(raw_rules, list):
            return None, "engine document rules are not a list"
        for raw in raw_rules:
            rule = _rule(raw)
            if rule is None:
                rule_id = raw.get("id") if isinstance(raw, Mapping) else None
                if isinstance(rule_id, str) and rule_id:
                    return None, "rule {!r} is not expressible natively".format(rule_id)
                return None, "a rule is not expressible natively"
            rules.append(rule)
    floor = min_rules() if minimum is None else max(0, int(minimum))
    if len(rules) < floor:
        return None, "rule count {} is below the native minimum {}".format(
            len(rules), floor
        )
    return json.dumps({"version": 1, "rules": rules}, sort_keys=True), None


def available() -> bool:
    """Whether the optional accelerator is importable in this process."""
    return _plan_class() is not None


def abi_version() -> Optional[int]:
    """The accelerator's ``ENGINE_ABI``, or None when it is not installed."""
    try:
        import interlock_scopes  # type: ignore[import-not-found]
    except Exception:  # pragma: no cover - the accelerator is optional
        return None
    value = getattr(interlock_scopes, "ENGINE_ABI", None)
    return value if isinstance(value, int) else None


def _rule(raw: Any) -> Optional[Mapping[str, Any]]:
    if not isinstance(raw, Mapping):
        return None
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not rule_id:
        return None
    if "detector" in raw:
        return _detector(raw, rule_id)
    # Rewrites change the event the remaining rules judge, shadow rules never
    # decide, and a ceiling can turn a block into an escalation: none of that
    # is in the plan.
    if "set" in raw:
        return None
    if raw.get("mode", "enforce") != "enforce":
        return None
    if raw.get("ceiling") is not None or raw.get("origin") is not None:
        return None
    verdict = raw.get("verdict")
    if verdict not in ("block", "escalate"):
        return None
    phase = raw.get("phase", "call")
    if phase not in ("call", "result"):
        return None
    reason = raw.get("reason", rule_id)
    if not isinstance(reason, str):
        return None
    if "when" not in raw:
        return None
    when = _condition(raw["when"])
    if when is None:
        return None
    if "on" in raw:
        scope = _action(raw["on"])
        if scope is None:
            return None
        when = {"all": [scope, when]}
    return {
        "id": rule_id,
        "verdict": 1 if verdict == "block" else 3,
        "reason": reason,
        "phase": phase,
        "when": when,
    }


def _detector(raw: Mapping[str, Any], rule_id: str) -> Optional[Mapping[str, Any]]:
    """A native detector rule, or None when the detector has no Rust port.

    Only the four stateless scanners are here. A ``with`` payload, a shadow
    mode, a ceiling or an origin on a detector rule all decline: the Rust port
    has no parameters and no verdict transform, so accepting one would be a
    different rule. Detector rules run in the call phase in Python as well;
    ``phase`` is not a property they honour.
    """
    name = raw.get("detector")
    canonical = NATIVE_DETECTORS.get(name) if isinstance(name, str) else None
    if canonical is None:
        return None
    if raw.get("with") not in (None, {}):
        return None
    if raw.get("mode", "enforce") != "enforce":
        return None
    if raw.get("ceiling") is not None or raw.get("origin") is not None:
        return None
    if raw.get("phase", "call") != "call":
        return None
    rule: Mapping[str, Any] = {"id": rule_id, "detector": canonical}
    if "on" in raw:
        scope = _action(raw["on"])
        if scope is None:
            return None
        rule = {"id": rule_id, "detector": canonical, "when": scope}
    return rule


def _action(raw: Any) -> Optional[Mapping[str, Any]]:
    if isinstance(raw, str):
        return {"action": raw} if raw else None
    if isinstance(raw, list) and raw and all(isinstance(v, str) and v for v in raw):
        return {"action": list(raw)}
    if (
        isinstance(raw, Mapping)
        and set(raw) == {"glob"}
        and isinstance(raw["glob"], str)
        and raw["glob"]
    ):
        return {"action": {"glob": raw["glob"]}}
    return None


def _condition(raw: Any) -> Optional[Mapping[str, Any]]:
    if not isinstance(raw, Mapping) or not raw:
        return None
    if "all" in raw or "any" in raw:
        key = "all" if "all" in raw else "any"
        if set(raw) != {key}:
            return None
        parts = raw[key]
        if not isinstance(parts, list) or not parts:
            return None
        subs = [_condition(part) for part in parts]
        if any(sub is None for sub in subs):
            return None
        return {key: subs}
    if "not" in raw:
        if set(raw) != {"not"}:
            return None
        inner = _condition(raw["not"])
        return None if inner is None else {"not": inner}
    if "action" in raw and "field" not in raw and "arg" not in raw:
        if set(raw) != {"action"}:
            return None
        action = _action(raw["action"])
        return None if action is None else action
    if "field" in raw and "arg" not in raw:
        return _test(raw, "field", raw["field"])
    if "arg" in raw and "field" not in raw:
        return _test(raw, "arg", raw["arg"])
    return None


def _test(raw: Mapping[str, Any], subject: str, name: Any) -> Optional[Mapping[str, Any]]:
    if not isinstance(name, str) or not name:
        return None
    if subject == "field" and name not in FIELDS:
        return None
    operators = [key for key in raw if key != subject]
    if len(operators) != 1 or operators[0] not in OPS:
        return None
    op = operators[0]
    value = raw[op]
    if op == "exists" and not isinstance(value, bool):
        return None
    if op in ("gt", "ge", "lt", "le") and (
        isinstance(value, bool) or not isinstance(value, (int, float))
    ):
        return None
    if op in ("contains", "startswith", "endswith", "glob", "matches") and not isinstance(
        value, str
    ):
        return None
    if op == "matches" and isinstance(value, str) and len(value) > MAX_PATTERN:
        return None
    if op in ("in", "not_in") and not isinstance(value, list):
        return None
    # The plan keeps the condition language's own shape: the operator is the
    # key, exactly as in a policy document. A separate {"op", "value"} pair
    # would be a second schema to keep in sync.
    return {subject: name, op: value}


def build(engine: Any, *, minimum: Optional[int] = None) -> Optional[Any]:
    """Compile ``engine``'s policy into a native plan, or None.

    A plan the Rust side rejects (a regex it cannot compile, a malformed
    document) is treated as ineligible, never as an error: the Python engine
    is always the fallback. ``minimum`` is forwarded to :func:`plan_for`.
    """
    plan_class = _plan_class()
    if plan_class is None:
        return None
    text = plan_for(engine, minimum=minimum)
    if text is None:
        return None
    try:
        return plan_class(text)
    except Exception as exc:  # pragma: no cover - depends on the wheel
        _log.info("interlock: policy not eligible for the native engine: %s", exc)
        return None


def payload(event: Any) -> str:
    """The event as the native side reads it.

    ``allow_nan=False`` matters: serde_json has no NaN literal, and silently
    turning NaN into a string would change what a ``gt`` test sees. Raising
    instead hands the event to the Python engine, which compares the value the
    caller actually passed.
    """
    return json.dumps(
        {
            "action": getattr(event, "action", ""),
            "args": getattr(event, "args", {}) or {},
            "principal": getattr(event, "principal", None),
            "span_id": getattr(event, "span_id", None),
            "parent_principal": getattr(event, "parent_principal", None),
            "call_id": getattr(event, "call_id", None),
            "phase": getattr(event, "phase", "call") or "call",
        },
        allow_nan=False,
    )


def decide(plan: Any, event: Any) -> Decision:
    """Evaluate one event natively. Raises on anything the native side rejects."""
    verdict, policy_id, reason, attributed = plan.evaluate(payload(event))
    if verdict == int(Verdict.ALLOW):
        return Decision.allow()
    if verdict == int(Verdict.BLOCK):
        return Decision.block(reason, policy_id, attributed_to=attributed)
    if verdict == int(Verdict.ESCALATE):
        return Decision.escalate(reason, policy_id, attributed_to=attributed)
    # A verdict the planner does not emit: treat it as a block, like every
    # other unknown verdict in the package.
    return Decision.block(reason or "unknown native verdict", policy_id,
                          attributed_to=attributed)


#: The policy ``interlock policy doctor`` replays through both backends. It is
#: deliberately small but exercises every comparison operator, nested
#: all/any/not, an action glob, a unicode value, a long value and a missing
#: argument - the cases where a hand-ported evaluator most often drifts.
PARITY_RULES = [
    {"id": "parity-eq", "verdict": "block", "reason": "eq",
     "when": {"all": [{"action": "read_file"},
                      {"arg": "path", "eq": "/etc/passwd"}]}},
    {"id": "parity-ne", "verdict": "block", "reason": "ne",
     "when": {"all": [{"action": "read_file"},
                      {"arg": "path", "ne": "/tmp/ok"}]}},
    {"id": "parity-in", "verdict": "block", "reason": "in",
     "when": {"all": [{"action": "net_fetch"},
                      {"arg": "host", "in": ["evil.example", "tracker.example"]}]}},
    {"id": "parity-not-in", "verdict": "block", "reason": "not_in",
     "when": {"all": [{"action": "net_fetch"},
                      {"arg": "host", "not_in": ["docs.example", "api.acme.com"]}]}},
    {"id": "parity-gt", "verdict": "block", "reason": "gt",
     "when": {"all": [{"action": "write_file"},
                      {"arg": "size", "gt": 1000}]}},
    {"id": "parity-ge", "verdict": "block", "reason": "ge",
     "when": {"all": [{"action": "write_file"},
                      {"arg": "size", "ge": 1000}]}},
    {"id": "parity-lt", "verdict": "block", "reason": "lt",
     "when": {"all": [{"action": "write_file"},
                      {"arg": "size", "lt": 10}]}},
    {"id": "parity-le", "verdict": "block", "reason": "le",
     "when": {"all": [{"action": "write_file"},
                      {"arg": "size", "le": 10}]}},
    {"id": "parity-contains", "verdict": "block", "reason": "contains",
     "when": {"all": [{"action": "run_shell"},
                      {"arg": "cmd", "contains": "rm -rf"}]}},
    {"id": "parity-startswith", "verdict": "block", "reason": "startswith",
     "when": {"all": [{"action": "run_shell"},
                      {"arg": "cmd", "startswith": "curl "}]}},
    {"id": "parity-endswith", "verdict": "block", "reason": "endswith",
     "when": {"all": [{"action": "read_file"},
                      {"arg": "path", "endswith": ".pem"}]}},
    {"id": "parity-exists", "verdict": "block", "reason": "exists",
     "when": {"all": [{"action": "read_file"},
                      {"arg": "path", "exists": True}]}},
    {"id": "parity-glob", "verdict": "block", "reason": "glob",
     "when": {"all": [{"action": "net_fetch"},
                      {"arg": "host", "glob": "*.internal"}]}},
    {"id": "parity-matches", "verdict": "block", "reason": "matches",
     "when": {"all": [{"action": "read_file"},
                      {"arg": "path", "matches": "^/etc/"}]}},
    {"id": "parity-nested", "verdict": "block", "reason": "nested",
     "when": {"all": [
         {"action": "run_shell"},
         {"any": [
             {"arg": "cmd", "contains": "sudo"},
             {"not": {"arg": "cmd", "startswith": "echo"}},
         ]},
     ]}},
    {"id": "parity-action-glob", "verdict": "block", "reason": "action glob",
     "when": {"all": [
         {"action": {"glob": "net_*"}},
         {"arg": "host", "eq": "blocked.example"},
     ]}},
]

#: Events for :data:`PARITY_RULES`: matches, non-matches, unicode, a value
#: longer than 4 KiB, missing arguments, non-string numbers and case variants.
PARITY_EVENTS = [
    {"action": "read_file", "args": {"path": "/etc/passwd"}},
    {"action": "read_file", "args": {"path": "/tmp/ok"}},
    {"action": "read_file", "args": {"path": "/etc/ssl/key.pem"}},
    {"action": "read_file", "args": {}},
    {"action": "READ_FILE", "args": {"path": "/etc/passwd"}},
    {"action": "net_fetch", "args": {"host": "evil.example"}},
    {"action": "net_fetch", "args": {"host": "docs.example"}},
    {"action": "net_fetch", "args": {"host": "svc.internal"}},
    {"action": "net_fetch", "args": {"host": "blocked.example"}},
    {"action": "net_fetch", "args": {"host": "héllo.example"}},
    {"action": "write_file", "args": {"size": 5000}},
    {"action": "write_file", "args": {"size": 5}},
    {"action": "write_file", "args": {"size": "5000"}},
    {"action": "run_shell", "args": {"cmd": "rm -rf /"}},
    {"action": "run_shell", "args": {"cmd": "curl http://x"}},
    {"action": "run_shell", "args": {"cmd": "echo héllo €"}},
    {"action": "run_shell", "args": {"cmd": "x" * 5000}},
    {"action": "run_shell", "args": {"cmd": "echo hi"}},
    {"action": "python", "args": {}},
    {"action": "", "args": {}},
]


def _shape(decision: Any) -> tuple:
    return (
        decision.verdict,
        decision.policy_id,
        decision.reason,
        decision.attributed_to,
        decision.modified_args,
    )


def parity_report() -> dict:
    """Replay the embedded corpus through both backends and compare.

    ``interlock policy doctor`` prints this so an operator can see that the
    installed accelerator agrees with the Python engine on the exact cases
    the planner translates. The check is self-contained (no test fixtures),
    so it works from an installed wheel. A missing accelerator, an
    inexpressible corpus or an import failure is reported, never raised: a
    diagnostic must not crash.
    """
    if not available():
        return {
            "ran": False, "ok": None, "cases": 0, "mismatches": 0,
            "detail": "the native accelerator is not installed",
        }
    from ..event import SensorEvent
    from .declarative import load_policy

    try:
        engine = load_policy({"version": 1, "rules": PARITY_RULES})
        plan = build(engine, minimum=0)
    except Exception as exc:  # pragma: no cover - depends on the wheel
        return {
            "ran": False, "ok": False, "cases": 0, "mismatches": 0,
            "detail": "could not build the parity policy: {}".format(exc),
        }
    if plan is None:
        return {
            "ran": True, "ok": False, "cases": 0, "mismatches": 0,
            "detail": "the embedded parity policy is not expressible natively",
        }
    mismatches = []
    for item in PARITY_EVENTS:
        event = SensorEvent(action=item["action"], args=item.get("args") or {})
        try:
            native_decision = decide(plan, event)
        except Exception as exc:  # pragma: no cover - depends on the wheel
            mismatches.append("{}: native raised {}".format(item["action"], exc))
            continue
        try:
            python_decision = engine.evaluate(event)
        except Exception as exc:  # pragma: no cover - depends on the wheel
            mismatches.append("{}: python raised {}".format(item["action"], exc))
            continue
        if _shape(native_decision) != _shape(python_decision):
            mismatches.append("{}: native {} != python {}".format(
                item["action"], _shape(native_decision), _shape(python_decision)))
    return {
        "ran": True,
        "ok": not mismatches,
        "cases": len(PARITY_EVENTS),
        "mismatches": len(mismatches),
        "detail": mismatches[0] if mismatches else None,
    }
