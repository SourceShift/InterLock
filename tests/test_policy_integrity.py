"""A14: an overlay cannot weaken the base.

An overlay may only tighten. It cannot redefine a tool schema (which would make
the base's own argument check reject, and silently quarantine, a locked rule),
leave a schema behind for the next load, or add a rule that rewrites arguments
before the locked rule judges them. A rule added in code survives a reload.
"""
import threading

import pytest

from interlock import SensorEvent, Verdict, deny_tool
from interlock.policy.declarative import (
    TOOL_SCHEMAS,
    PolicyError,
    load_policy,
    register_tool_schema,
)
from interlock.policy.engine import _rule_label


def ev(action="run", phase="call", **args):
    return SensorEvent(action=action, args=args, phase=phase, principal="p1")


def verdict(engine, event):
    return engine.evaluate(event).verdict


@pytest.fixture(autouse=True)
def _isolate_tool_schemas():
    """TOOL_SCHEMAS is process-global and conftest does not reset it."""
    saved = dict(TOOL_SCHEMAS)
    try:
        yield
    finally:
        TOOL_SCHEMAS.clear()
        TOOL_SCHEMAS.update(saved)


BASE = {
    "version": 1,
    "name": "base",
    "tools": {"Bash": ["command"]},
    "rules": [
        {"id": "no-curl", "locked": True, "verdict": "block", "on": "Bash",
         "when": {"arg": "command", "contains": "curl"}},
    ],
}


def curl_call():
    return ev("Bash", command="curl https://evil.example")


# --- overlay tool schemas -------------------------------------------------------


def test_overlay_cannot_redefine_a_tool_schema():
    register_tool_schema("Bash", ["command"])
    before = dict(TOOL_SCHEMAS)
    overlay = {
        "version": 1,
        "name": "bad",
        "tools": {"Bash": ["cmd"]},
        "rules": [{"id": "sneak", "verdict": "block", "on": "Bash",
                   "when": {"arg": "cmd", "exists": True}}],
    }
    engine = load_policy(BASE, overlays=[("bad", overlay)])

    status = engine.overlays[0][1]
    assert engine.overlays[0][0] == "bad"
    assert status.startswith("ignored")
    assert "overlay tools may not redefine action 'Bash'" in status
    # The base rule is neither quarantined nor weakened.
    assert engine.locked == ["no-curl"]
    assert engine.quarantined == []
    assert verdict(engine, curl_call()) is Verdict.BLOCK
    # Neither the overlay's schema nor the base's shorthand survives the load.
    assert TOOL_SCHEMAS == before


def test_a_later_base_load_sees_no_overlay_schema():
    overlay = {"version": 1, "name": "bad", "tools": {"Bash": ["cmd"]}}
    load_policy(BASE, overlays=[("bad", overlay)])
    again = load_policy(BASE)
    assert again.locked == ["no-curl"]
    assert again.quarantined == []
    assert verdict(again, curl_call()) is Verdict.BLOCK


def test_overlay_same_schema_is_a_noop_and_a_new_action_is_scoped():
    before = dict(TOOL_SCHEMAS)
    overlay = {
        "version": 1,
        "name": "schema",
        "tools": {"Bash": ["command"], "NewTool": ["cmd"]},
        "rules": [{"id": "newtool-block", "verdict": "block", "on": "NewTool",
                   "when": {"arg": "cmd", "contains": "danger"}}],
    }
    engine = load_policy(BASE, overlays=[("schema", overlay)])
    assert engine.overlays[0][1] == "applied"
    assert verdict(engine, ev("NewTool", cmd="danger")) is Verdict.BLOCK
    # The action existed for this overlay's compile only.
    assert "NewTool" not in TOOL_SCHEMAS
    assert TOOL_SCHEMAS == before


def test_concurrent_loads_do_not_leak_an_overlay_tool():
    before = dict(TOOL_SCHEMAS)
    overlay = {
        "version": 1,
        "name": "race",
        "tools": {"RaceTool": ["x"]},
        "rules": [{"id": "race-block", "verdict": "block", "on": "RaceTool",
                   "when": {"arg": "x", "eq": 1}}],
    }
    errors = []

    def worker():
        for _ in range(40):
            try:
                engine = load_policy(BASE, overlays=[("race", overlay)])
                if verdict(engine, ev("RaceTool", x=1)) is not Verdict.BLOCK:
                    errors.append("overlay rule missing")
                if verdict(engine, curl_call()) is not Verdict.BLOCK:
                    errors.append("base rule missing")
            except Exception as exc:  # a deadlock or race surfaces as a failure
                errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert TOOL_SCHEMAS == before


# --- overlay rewrite rules ------------------------------------------------------


@pytest.mark.parametrize("raw", [
    {"id": "sneak", "verdict": "modify", "on": "Bash",
     "when": {"arg": "command", "contains": "curl"},
     "set": {"command": "echo harmless"}},
    {"id": "sneak-set", "verdict": "block", "when": {"arg": "x", "eq": 1},
     "set": {"x": 2}},
])
def test_an_overlay_cannot_add_a_rewriting_rule(raw):
    overlay = {"version": 1, "name": "rewrite", "rules": [raw]}
    engine = load_policy(BASE, overlays=[("rewrite", overlay)])
    status = engine.overlays[0][1]
    assert status.startswith("ignored")
    assert raw["id"] in status
    assert "overlays may only add blocking or escalating rules" in status
    # The rewrite never ran, so the locked rule still sees the original command.
    assert verdict(engine, curl_call()) is Verdict.BLOCK


def test_an_overlay_cannot_add_a_detector_rule():
    overlay = {
        "version": 1,
        "name": "detector",
        "rules": [{"id": "redact", "detector": "tool_output_secret_redactor"}],
    }
    engine = load_policy(BASE, overlays=[("detector", overlay)])
    status = engine.overlays[0][1]
    assert status.startswith("ignored")
    assert "redact" in status
    assert "overlays may only add blocking or escalating rules" in status
    assert verdict(engine, curl_call()) is Verdict.BLOCK


def test_an_overlay_may_still_add_a_plain_block_rule():
    overlay = {
        "version": 1,
        "name": "tighten",
        "rules": [{"id": "no-danger", "verdict": "block",
                   "when": {"action": "danger"}}],
    }
    engine = load_policy(BASE, overlays=[("tighten", overlay)])
    assert engine.overlays[0][1] == "applied"
    assert verdict(engine, ev("danger")) is Verdict.BLOCK
    # It did not replace or loosen the base.
    assert verdict(engine, curl_call()) is Verdict.BLOCK


def test_an_overlay_may_still_widen_a_widenable_list():
    base = {
        "version": 1,
        "name": "egress-base",
        "rules": [{"id": "egress", "detector": "data_egress.network_egress_guard",
                   "with": {"allowed_hosts": ["api.acme.com"]},
                   "widenable": ["allowed_hosts"]}],
    }
    overlay = {"version": 1, "name": "widen",
               "widen": {"egress": {"allowed_hosts": ["staging.acme.com"]}}}
    engine = load_policy(base, overlays=[("widen", overlay)])
    assert engine.overlays[0][1] == "applied"
    assert verdict(engine, ev("http_post", url="https://staging.acme.com/x")) is Verdict.ALLOW
    assert verdict(engine, ev("http_post", url="https://evil.example")) is Verdict.BLOCK


# --- code-added rules across reload ---------------------------------------------


def _loader_from(doc):
    return lambda: load_policy(doc)


def test_a_code_added_rule_survives_a_successful_reload_exactly_once():
    engine = load_policy(BASE)
    code_rule = deny_tool("danger")
    code_label = _rule_label(code_rule)
    engine.add_rule(code_rule)
    engine._loader = _loader_from(BASE)

    assert verdict(engine, ev("danger")) is Verdict.BLOCK
    assert engine.reload() is True
    assert verdict(engine, ev("danger")) is Verdict.BLOCK
    assert engine.policy_ids.count(code_label) == 1
    # A second reload must not accumulate another copy.
    assert engine.reload() is True
    assert engine.policy_ids.count(code_label) == 1
    assert verdict(engine, curl_call()) is Verdict.BLOCK


def test_a_failed_reload_keeps_the_rules_and_the_code_rule():
    engine = load_policy(BASE)
    code_rule = deny_tool("danger")
    code_label = _rule_label(code_rule)
    engine.add_rule(code_rule)
    before = list(engine.policy_ids)

    def fail():
        raise PolicyError("loader broke")

    engine._loader = fail
    assert engine.reload() is False
    assert engine.policy_ids == before
    assert engine.policy_ids.count(code_label) == 1
    assert engine.last_error and "loader broke" in engine.last_error
    assert verdict(engine, ev("danger")) is Verdict.BLOCK
    assert verdict(engine, curl_call()) is Verdict.BLOCK

    # A later successful reload still carries exactly one copy.
    engine._loader = _loader_from(BASE)
    assert engine.reload() is True
    assert engine.policy_ids.count(code_label) == 1
    assert verdict(engine, ev("danger")) is Verdict.BLOCK
