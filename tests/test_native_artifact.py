"""Artifact-backed native evaluation (C6): per-scope plans, parity, the switch.

`CompiledPolicy` plans the artifact's declarative **documents** once, at load,
and then plans every bound scope's compiled engine for itself. Today's shipped
scope templates are Python factories with no declarative document, so they
stay on Python - but the per-scope machinery is real: an eligible scope is
planned, reported in ``native_scopes`` and evaluated through its own plan.

The parity assertion compares native on/off over the shipped cloud corpus and
all five decision fields, because R31's whole claim is that the two backends
cannot disagree by construction. The corpus covers every operator, unicode,
>4 KiB arguments, non-string numbers, missing arguments and more than one
scope. A detector or a rewrite has no native translation, so that artifact
must decline the plan rather than serve a partial one.

The artifact path is native-on by default; ``INTERLOCK_NATIVE=0`` still forces
Python, because the operator's documented escape hatch must win.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from interlock.enforce import Decision, Verdict
from interlock.event import SensorEvent
from interlock.policy.artifact import (
    ARTIFACT_FORMAT,
    FAILURE_POLICY_DEFAULTS,
    canonical_bytes,
    load_artifact,
    seal_artifact,
)
from interlock.policy import native

pytest.importorskip("interlock_scopes")

CORPUS = Path(__file__).resolve().parent / "fixtures" / "cloud" / "policy_corpus.jsonl"

RULES = [
    {"id": "no-rm", "verdict": "block", "reason": "destructive",
     "when": {"all": [{"action": "run_shell"},
                      {"arg": "cmd", "contains": "rm -rf"}]}},
    {"id": "no-evil-egress", "verdict": "block", "reason": "egress denied",
     "when": {"all": [{"action": "net_fetch"},
                      {"arg": "host", "in": ["evil.example", "tracker.example"]}]}},
    {"id": "ask-etc", "verdict": "escalate", "reason": "needs approval",
     "when": {"all": [{"action": "read_file"},
                      {"arg": "path", "startswith": "/etc"}]}},
    {"id": "no-key-material", "verdict": "block", "reason": "key material",
     "when": {"all": [{"action": ["read_file", "write_file"]},
                      {"arg": "path", "endswith": ".pem"}]}},
    {"id": "no-secret-write", "verdict": "block", "reason": "secret write",
     "when": {"all": [{"action": "write_file"},
                      {"arg": "path", "contains": "secret"}]}},
    {"id": "no-curl", "verdict": "block", "reason": "curl",
     "when": {"all": [{"action": "run_shell"},
                      {"arg": "cmd", "startswith": "curl "}]}},
    {"id": "no-dotdot", "verdict": "block", "reason": "traversal",
     "when": {"arg": "path", "contains": ".."}},
    {"id": "no-force-push", "verdict": "block", "reason": "force push",
     "when": {"all": [{"action": "run_shell"},
                      {"arg": "cmd", "contains": "push --force"}]}},
    {"id": "no-prod", "verdict": "escalate", "reason": "production",
     "when": {"arg": "host", "eq": "prod.example"}},
    # The rest of the operator table, so parity covers the translator rather
    # than a handful of shapes. Every operator the native planner accepts has
    # at least one rule, and the corpus carries an event that reaches it.
    {"id": "non-prod-egress", "verdict": "escalate", "reason": "non-prod",
     "when": {"all": [{"action": "net_fetch"},
                      {"arg": "host", "ne": "prod.example"}]}},
    {"id": "unlisted-host", "verdict": "escalate", "reason": "unlisted host",
     "when": {"all": [{"action": "net_fetch"},
                      {"arg": "host", "not_in": ["api.acme.com", "prod.example"]}]}},
    {"id": "large-upload", "verdict": "block", "reason": "large upload",
     "when": {"all": [{"action": "net_fetch"}, {"arg": "size", "gt": 4096}]}},
    {"id": "boundary-upload", "verdict": "escalate", "reason": "boundary",
     "when": {"all": [{"action": "net_fetch"}, {"arg": "size", "ge": 4096}]}},
    {"id": "negative-size", "verdict": "block", "reason": "negative",
     "when": {"all": [{"action": "net_fetch"}, {"arg": "size", "lt": 0}]}},
    {"id": "zero-size", "verdict": "escalate", "reason": "empty upload",
     "when": {"all": [{"action": "net_fetch"}, {"arg": "size", "le": 0}]}},
    {"id": "missing-payload", "verdict": "block", "reason": "missing payload",
     "when": {"all": [{"action": "write_file"}, {"arg": "data", "exists": False}]}},
    {"id": "pem-glob", "verdict": "block", "reason": "key glob",
     "when": {"arg": "path", "glob": "**/*.pem"}},
    {"id": "curl-regex", "verdict": "block", "reason": "curl regex",
     "when": {"all": [{"action": "run_shell"},
                      {"arg": "cmd", "matches": r"^\s*curl\s"}]}},
    {"id": "internal-only", "verdict": "escalate", "reason": "external egress",
     "when": {"all": [
         {"action": "net_fetch"},
         {"not": {"any": [
             {"arg": "host", "endswith": ".acme.com"},
             {"arg": "host", "eq": "localhost"},
         ]}},
     ]}},
    # An action glob, and the corpus's ``list_dir`` event is what reaches it.
    {"id": "list-by-glob", "verdict": "escalate", "reason": "listing by glob",
     "when": {"action": {"glob": "list_*"}}},
]


def _body(rules, **overrides):
    body = {
        "format": ARTIFACT_FORMAT,
        "documents": [{"version": 1, "rules": rules}],
        "scope": {"version": 1, "bindings": {}, "default_scope": [],
                  "allow_unscoped": True},
        "rules_module": None,
        "template_ids": [],
        "catalog": "",
        "failure_policy": dict(FAILURE_POLICY_DEFAULTS),
    }
    body.update(overrides)
    return seal_artifact(body)


def _load(rules=None, **overrides):
    raw = canonical_bytes(_body(RULES if rules is None else rules, **overrides))
    return raw, load_artifact(raw)


def _corpus():
    events = []
    for line in CORPUS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        item = json.loads(line)
        events.append(SensorEvent(
            action=item["action"], args=item.get("args") or {},
            principal=item.get("principal"),
        ))
    return events


def _shape(decision):
    return (
        decision.verdict,
        decision.policy_id,
        decision.reason,
        decision.attributed_to,
        decision.modified_args,
    )


def test_native_base_is_planned_and_reported():
    _, policy = _load()
    status = policy.status()
    assert status["enabled"] is True
    assert status["native_base"] is True
    assert status["native_scopes"] == []
    assert status["python_scopes"] == []
    assert status["native_unavailable_reason"] is None
    assert status["epoch"] == policy.epoch
    assert status["sha256"] == policy.sha256


def test_native_on_and_off_agree_over_the_corpus():
    raw, armed = _load()
    plain = load_artifact(raw, native_enabled=False)
    events = _corpus()
    assert len(events) == 84
    for event in events:
        assert _shape(armed.evaluate(event)) == _shape(plain.evaluate(event)), event


def test_native_off_reports_the_reason():
    raw, _ = _load()
    status = load_artifact(raw, native_enabled=False).status()
    assert status["native_base"] is False
    assert "disabled" in (status["native_unavailable_reason"] or "")


def test_a_detector_policy_is_declined_whole():
    rules = RULES + [
        {"id": "egress", "detector": "data_egress.network_egress_guard",
         "with": {"allowed_hosts": ["api.acme.com"]}},
    ]
    _, policy = _load(rules)
    status = policy.status()
    assert status["native_base"] is False
    assert "egress" in (status["native_unavailable_reason"] or "")
    # The Python engine still answers: declining a plan is not an error.
    decision = policy.evaluate(SensorEvent(
        "net_fetch", {"host": "evil.example"}, principal="acme"))
    assert decision.verdict is Verdict.BLOCK


def test_a_modify_policy_is_declined_whole():
    rules = RULES + [
        {"id": "redact", "verdict": "modify", "set": {"path": "/redacted"},
         "reason": "redacted", "when": {"arg": "path", "endswith": ".conf"}},
    ]
    _, policy = _load(rules)
    status = policy.status()
    assert status["native_base"] is False
    assert "redact" in (status["native_unavailable_reason"] or "")
    decision = policy.evaluate(SensorEvent(
        "write_file", {"path": "app.conf", "data": "x"}))
    assert decision.verdict is Verdict.MODIFY
    assert decision.modified_args == {"path": "/redacted"}


def _scoped_artifact():
    from tests.fixtures.cloud.rules_module import scope_document

    body = _body(RULES)
    body["scope"] = scope_document()
    body["rules_module"] = "tests.fixtures.cloud.rules_module:templates"
    body["template_ids"] = ["egress_denylist", "file_guard", "shell_allowlist"]
    return seal_artifact(body)


def test_scoped_artifact_reports_python_scopes_and_still_evaluates():
    body = _scoped_artifact()
    policy = load_artifact(canonical_bytes(body))
    status = policy.status()
    assert status["native_base"] is True
    assert status["native_scopes"] == []
    assert status["python_scopes"] == ["acme", "acme/agent1", "beta"]
    assert "Python callables" in (status["native_unavailable_reason"] or "")
    decision = policy.evaluate(SensorEvent(
        "run_shell", {"cmd": "ls"}, principal="acme/agent1"))
    assert decision.verdict is Verdict.ALLOW


def test_an_eligible_scope_is_planned_and_evaluated_natively(monkeypatch):
    # The shipped templates carry no declarative document, so the real planner
    # declines them. Make one eligible here: the point under test is that each
    # bound scope is planned independently and its plan is what decides.
    real_build = native.build
    real_decide = native.decide
    scope_engines = []

    def fake_build(engine, *, minimum=None):
        if getattr(engine, "documents", None):
            return real_build(engine, minimum=minimum)
        scope_engines.append(engine)
        return ("scope-plan", len(scope_engines))

    def fake_decide(plan, event):
        if isinstance(plan, tuple) and plan[0] == "scope-plan":
            return Decision.block("native scope plan", policy_id="native-scope")
        return real_decide(plan, event)

    monkeypatch.setattr(native, "build", fake_build)
    monkeypatch.setattr(native, "decide", fake_decide)

    policy = load_artifact(canonical_bytes(_scoped_artifact()))

    status = policy.status()
    assert status["native_base"] is True
    assert sorted(status["native_scopes"]) == ["acme", "acme/agent1", "beta"]
    assert status["python_scopes"] == []
    assert len(scope_engines) == 3
    # The base floor allows this read; the scope's plan blocks it, so a BLOCK
    # from "native-scope" can only have come through the per-scope plan.
    decision = policy.evaluate(SensorEvent(
        "read_file", {"path": "/tmp/x"}, principal="acme/agent1"))
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "native-scope"


def test_a_two_scope_artifact_plans_only_the_eligible_scope(monkeypatch):
    # Kickoff item 3's mixed case: two scopes, one planned and one left on
    # Python. The scope engines are sorted, so "acme" is planned first and
    # "acme/agent1"/"beta" are declined. The shim plan delegates to the same
    # Python engine, so a difference in any decision field would mean the
    # mixed routing changed the answer.
    real_build = native.build
    real_decide = native.decide
    scope_engines = []
    planned_calls = []

    def fake_build(engine, *, minimum=None):
        if getattr(engine, "documents", None):
            return real_build(engine, minimum=minimum)
        scope_engines.append(engine)
        if len(scope_engines) == 1:
            return ("scope-plan", engine)
        return None

    def fake_decide(plan, event):
        if isinstance(plan, tuple) and plan[0] == "scope-plan":
            planned_calls.append(event)
            return plan[1].evaluate(event)
        return real_decide(plan, event)

    monkeypatch.setattr(native, "build", fake_build)
    monkeypatch.setattr(native, "decide", fake_decide)

    raw = canonical_bytes(_scoped_artifact())
    armed = load_artifact(raw)
    plain = load_artifact(raw, native_enabled=False)

    status = armed.status()
    assert status["native_base"] is True
    assert status["native_scopes"] == ["acme"]
    assert status["python_scopes"] == ["acme/agent1", "beta"]
    assert len(scope_engines) == 3

    for event in _corpus():
        assert _shape(armed.evaluate(event)) == _shape(plain.evaluate(event)), event

    # At least one corpus event sits exactly on the planned scope, so the
    # eligible scope's plan (not just the base) decided it.
    assert planned_calls


def test_interlock_native_zero_forces_python_for_artifacts(monkeypatch):
    raw, _ = _load()
    monkeypatch.setenv("INTERLOCK_NATIVE", "0")

    policy = load_artifact(raw)
    status = policy.status()

    assert status["enabled"] is False
    assert status["native_base"] is False
    assert status["native_scopes"] == []
    assert status["rule"] == "INTERLOCK_NATIVE=0 forces Python"
    assert "INTERLOCK_NATIVE=0" in (status["native_unavailable_reason"] or "")
    # The Python engine is the definition of the semantics, so the decision
    # is unchanged.
    assert policy.evaluate(
        SensorEvent("run_shell", {"cmd": "rm -rf /"})).verdict is Verdict.BLOCK


def test_a_native_failure_falls_back_and_is_counted(monkeypatch):
    raw, armed = _load()
    plain = load_artifact(raw, native_enabled=False)
    event = SensorEvent("run_shell", {"cmd": "rm -rf /"})

    def boom(plan, event):
        raise RuntimeError("native blew up")

    monkeypatch.setattr(native, "decide", boom)
    assert armed.native_fallbacks == 0
    decision = armed.evaluate(event)
    assert _shape(decision) == _shape(plain.evaluate(event))
    assert armed.native_fallbacks == 1
    assert armed.status()["native_fallbacks"] == 1


def test_the_size_gate_does_not_hide_a_small_artifact():
    # One rule is below R31's default minimum of eight, but an artifact was
    # explicitly compiled for this path, so the plan must still be built.
    _, policy = _load([RULES[0]])
    assert native.min_rules() >= 1
    assert policy.status()["native_base"] is True
