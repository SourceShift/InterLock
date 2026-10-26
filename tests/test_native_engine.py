"""Parity between the Python policy engine and the native plan evaluator (R31).

The two paths are only allowed to disagree if they are different policies,
which the planner prevents by refusing anything it cannot translate whole.
These tests are the belt to that suspenders: the same events go through both
engines and the decisions must match field for field.

Skipped when the optional ``interlock_scopes`` wheel is not installed; the
Rust CI job installs it and runs this file, the Python jobs skip it.
"""
from __future__ import annotations

import ctypes
import json
from pathlib import Path

import pytest

from interlock.actions import canonical_action
from interlock.event import SensorEvent
from interlock.policy import native
from interlock.policy.declarative import load_policy

interlock_scopes = pytest.importorskip("interlock_scopes")
pytest.importorskip("interlock_scopes", reason="optional native accelerator")

if not hasattr(interlock_scopes, "NativePlan"):  # pragma: no cover - old wheel
    pytest.skip("installed interlock_scopes predates the native engine",
                allow_module_level=True)


POLICY = {
    "version": 1,
    "name": "native-parity",
    "tools": {"custom_tool": ["path", "command", "limit"]},
    "rules": [
        {"id": "no-recursive-delete", "verdict": "block",
         "reason": "recursive delete",
         "when": {"all": [{"action": "Bash"},
                          {"arg": "command", "matches": r"rm\s+-[a-z]*r"}]}},
        {"id": "ask-force-push", "verdict": "escalate",
         "reason": "force push needs a human",
         "when": {"all": [{"action": "Bash"},
                          {"arg": "command", "contains": "push --force"}]}},
        {"id": "no-pem-read", "verdict": "block", "reason": "key material",
         "when": {"arg": "path", "glob": "*.pem"}},
        {"id": "cap-rows", "verdict": "block", "reason": "row limit",
         "when": {"all": [{"action": ["query_db"]}, {"arg": "limit", "gt": 1000}]}},
        {"id": "no-egress", "verdict": "block", "reason": "egress host",
         "when": {"arg": "host", "in": ["evil.example", "bad.example"]}},
        {"id": "no-ssh", "verdict": "block", "reason": "ssh",
         "when": {"arg": "command", "startswith": "ssh "}},
        {"id": "no-shell-out", "verdict": "block", "reason": "result leak",
         "phase": "result",
         "when": {"arg": "result", "contains": "BEGIN PRIVATE KEY"}},
        {"id": "restricted-principal", "verdict": "escalate",
         "reason": "restricted principal",
         "when": {"field": "principal", "eq": "intern"}},
        {"id": "no-dotdot", "verdict": "block", "reason": "path traversal",
         "when": {"arg": "path", "contains": ".."}},
        {"id": "missing-owner", "verdict": "escalate",
         "reason": "owner required",
         "when": {"arg": "owner", "exists": False}},
        {"id": "no-tmp-binary", "verdict": "block", "reason": "tmp binary",
         "when": {"all": [{"arg": "path", "startswith": "/tmp/"},
                          {"not": {"arg": "path", "endswith": ".txt"}}]}},
        {"id": "either-host", "verdict": "block", "reason": "either",
         "when": {"any": [{"arg": "host", "eq": "x.example"},
                          {"field": "principal", "eq": "bad"}]}},
        {"id": "owner-not-dev", "verdict": "escalate", "reason": "owner not dev",
         "when": {"all": [{"arg": "owner", "exists": True},
                          {"arg": "owner", "ne": "dev"}]}},
        {"id": "no-hundred", "verdict": "block", "reason": "hundred",
         "when": {"arg": "limit", "eq": 100}},
    ],
}

EVENTS = [
    SensorEvent(action="Bash", args={"command": "rm -rf /"}),
    SensorEvent(action="bash", args={"command": "rm -rf build/"}),
    SensorEvent(action="Bash", args={"command": "git push --force origin main"}),
    SensorEvent(action="Bash", args={"command": "ssh root@host"}),
    SensorEvent(action="Bash", args={"command": "ls"}),
    SensorEvent(action="read_file", args={"path": "certs/server.pem"}),
    SensorEvent(action="read_file", args={"path": "../../etc/passwd"}),
    SensorEvent(action="query_db", args={"limit": 5000}),
    SensorEvent(action="query_db", args={"limit": 10}),
    SensorEvent(action="http_post", args={"host": "evil.example"}),
    SensorEvent(action="http_post", args={"host": "api.acme.com"}),
    SensorEvent(action="custom_tool", args={"path": "ok.txt"}),
    SensorEvent(action="custom_tool", args={"path": "ok.txt", "owner": "team"}),
    SensorEvent(action="read_file", args={"result": "-----BEGIN PRIVATE KEY-----"},
                phase="result"),
    SensorEvent(action="read_file", args={"result": "hello"}, phase="result"),
    SensorEvent(action="Bash", args={"command": "ls"}, principal="intern"),
    SensorEvent(action="Bash", args={"command": "git push --force && rm -rf /"}),
    SensorEvent(action="custom_tool", args={"path": "/tmp/scratch.bin"}),
    SensorEvent(action="custom_tool", args={"path": "/tmp/notes.txt"}),
    SensorEvent(action="custom_tool", args={"path": "ok.txt", "owner": "dev"}),
    SensorEvent(action="http_post", args={"host": "x.example"}),
    SensorEvent(action="query_db", args={"limit": 100.0}),
]


def _plan(engine) -> object:
    text = native.plan_for(engine)
    assert text is not None
    return native._plan_class()(text)


def test_policy_is_eligible():
    engine = load_policy(POLICY)
    text = native.plan_for(engine)
    assert text is not None, "a plain declarative policy should compile"


@pytest.mark.parametrize("event", EVENTS, ids=lambda e: f"{e.action}-{e.phase}")
def test_native_matches_python(event):
    engine = load_policy(POLICY)
    plan = _plan(engine)
    expected = engine.evaluate(event)
    got = native.decide(plan, event)
    assert got.verdict == expected.verdict, (event, expected, got)
    if expected.verdict.name != "ALLOW":
        assert got.policy_id == expected.policy_id
        assert got.reason == expected.reason
        assert got.attributed_to == expected.attributed_to


def test_enabled_engine_answers_identically(monkeypatch):
    plain = load_policy(POLICY)
    monkeypatch.setenv(native.ENV_FLAG, "1")
    armed = load_policy(POLICY)
    monkeypatch.delenv(native.ENV_FLAG)
    assert armed._native_plan is not None
    assert plain._native_plan is None
    for event in EVENTS:
        assert armed.evaluate(event) == plain.evaluate(event), event


@pytest.mark.parametrize(
    "extra",
    [
        {"rules": POLICY["rules"] + [
            {"id": "detector", "detector": "data_egress.network_egress_guard",
             "with": {"allowed_hosts": ["api.acme.com"]}}]},
        {"rules": POLICY["rules"] + [
            {"id": "rewrite", "verdict": "modify", "set": {"limit": 100},
             "reason": "cap", "when": {"arg": "limit", "gt": 100}}]},
        {"rules": POLICY["rules"], "disable": ["no-ssh"]},
    ],
)
def test_planner_refuses_unsupported(extra):
    doc = {"version": 1, **{k: v for k, v in POLICY.items() if k != "version"}, **extra}
    engine = load_policy(doc)
    assert native.plan_for(engine) is None


def test_planner_refuses_shadow_rule():
    doc = {"version": 1, "rules": POLICY["rules"] + [
        {"id": "shadow", "verdict": "block", "mode": "shadow",
         "reason": "observe", "when": {"action": "Bash"}}]}
    engine = load_policy(doc)
    assert native.plan_for(engine) is None


def test_planner_refuses_small_policy():
    doc = {"version": 1, "rules": POLICY["rules"][:2]}
    engine = load_policy(doc)
    assert native.plan_for(engine) is None


def test_canonical_action_parity():
    """The Rust canonicaliser must agree with Python's, name form for form."""
    rule_names = [
        "Bash", "http.fetch", "fs.readFile", "child_process.execFile",
        "HTTPServer", "read_file", "a.b/c:readFile",
    ]
    rules = [
        {"id": f"m{i}", "verdict": 1, "reason": name, "when": {"action": name}}
        for i, name in enumerate(rule_names)
    ]
    plan = native._plan_class()(json.dumps({"version": 1, "rules": rules}))
    spellings = rule_names + [
        "bash", "BASH", "HTTP.server", "fs.read_file", "child_process.exec_file",
        "readFile", "unrelated_tool",
    ]
    for spelling in spellings:
        got = native.decide(plan, SensorEvent(action=spelling))
        expected = [n for n in rule_names
                    if canonical_action(n) == canonical_action(spelling)]
        if not expected:
            assert got.verdict.name == "ALLOW", spelling
        else:
            assert got.verdict.name == "BLOCK", spelling
            assert got.reason == expected[0], spelling


def _library() -> ctypes.CDLL:
    directory = Path(interlock_scopes.__file__).parent
    candidates = [p for p in directory.iterdir() if p.suffix in (".so", ".dylib", ".pyd")]
    assert candidates, "no extension module beside interlock_scopes/__init__.py"
    return ctypes.CDLL(str(candidates[0]))


def test_c_abi_evaluates_and_reports_errors():
    lib = _library()
    lib.il_abi_version.restype = ctypes.c_uint32
    assert lib.il_abi_version() == 1
    lib.il_eval_plan.restype = ctypes.c_int
    lib.il_eval_plan.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
    ]

    plan = native.plan_for(load_policy(POLICY)).encode()
    event = native.payload(SensorEvent(action="Bash", args={"command": "rm -rf /"})).encode()
    verdict = ctypes.c_int(9)
    policy = ctypes.create_string_buffer(128)
    reason = ctypes.create_string_buffer(256)
    rc = lib.il_eval_plan(
        event, len(event), plan, len(plan),
        ctypes.byref(verdict), policy, 128, reason, 256,
    )
    assert rc == 0
    assert verdict.value == 1
    assert policy.value == b"no-recursive-delete"
    assert reason.value == b"recursive delete"

    bad = b"{not json"
    rc = lib.il_eval_plan(
        bad, len(bad), plan, len(plan),
        ctypes.byref(verdict), policy, 128, reason, 256,
    )
    assert rc == -1
