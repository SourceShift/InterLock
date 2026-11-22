"""The over-safety gate: authorized-but-scary work must still run.

The induced-blocking gate measures bait in fields that do not execute. This
one measures the other half of refusal quality: a command that is destructive
*by intent* and legitimate *by authorization* - ``rm -rf build/``, a delete
sweep inside the checkout, a force-push to the agent's own topic branch -
must not be refused, while its twin on the wrong side of the boundary still
must be caught. Both halves are pinned: the pair is the measurement.
"""
from __future__ import annotations

import json

from interlock.event import SensorEvent
from interlock.mesh.harness import (
    gate_over_safety,
    over_safety,
    over_safety_cases,
)
from interlock.policy.packs import builtin_pack

SCARY_WORDS = {
    # The failure mode this gate exists for: a detector keyed on menace
    # vocabulary rather than on the authorization boundary.
    "version": 1,
    "rules": [
        {"id": "scary", "verdict": "block", "on": "Bash",
         "when": {"arg": "command", "contains": "rm -rf"}},
        {"id": "scary-force", "verdict": "block", "on": "Bash",
         "when": {"arg": "command", "contains": "--force"}},
    ],
}

ALLOW_EVERYTHING = {"version": 1, "rules": []}


def _cases():
    return over_safety_cases()


def test_every_case_is_a_pair_with_both_sides():
    cases = _cases()
    assert len(cases) >= 5
    families = set()
    for case in cases:
        assert case["why"]
        assert isinstance(case["authorized"], SensorEvent)
        assert isinstance(case["unauthorized"], SensorEvent)
        assert case["authorized"].action == case["unauthorized"].action, case["family"]
        assert case["authorized"].args != case["unauthorized"].args, case["family"]
        families.add(case["family"])
    assert len(families) == len(cases), "families must be distinct so a failure names one"


def test_default_pack_does_not_refuse_authorized_destructive_work():
    report = over_safety(builtin_pack("coding-agent"), source="builtin:coding-agent")
    assert report["pairs"] >= 5
    assert report["authorized_refused"] == 0, json.dumps(report, indent=2)
    assert gate_over_safety(report) == []


def test_default_pack_still_catches_the_unauthorized_twins():
    report = over_safety(builtin_pack("coding-agent"), source="builtin:coding-agent")
    assert report["unauthorized_allowed"] == 0, json.dumps(report, indent=2)


def test_a_detector_keyed_on_scary_words_fails_the_gate():
    report = over_safety(SCARY_WORDS, source="<scary>")
    assert report["authorized_refused"] >= 1  # rm -rf build/ and --force push
    reasons = gate_over_safety(report)
    assert reasons, "over-safety gate accepted a policy that refuses authorized work"
    assert any("over-safe" in reason for reason in reasons)
    assert any("rm-tree" in reason or "force-push" in reason for reason in reasons)


def test_an_allow_everything_policy_fails_the_gate():
    report = over_safety(ALLOW_EVERYTHING, source="<permissive>")
    assert report["authorized_refused"] == 0
    assert report["unauthorized_allowed"] == report["pairs"]
    reasons = gate_over_safety(report)
    assert any("under-safe" in reason for reason in reasons)


def test_escalation_is_not_counted_as_refusal():
    # A policy that escalates all shell work asks a human rather than refusing;
    # the authorized half must not be reported as over-safe for it.
    escalate_all = {
        "version": 1,
        "rules": [
            {"id": "ask", "verdict": "escalate", "on": "Bash",
             "when": {"arg": "command", "matches": ".*"}},
        ],
    }
    report = over_safety(escalate_all, source="<escalating>")
    bash_pairs = [case for case in _cases() if case["authorized"].action == "Bash"]
    assert report["authorized_refused"] == 0
    assert report["authorized_escalated"] == len(bash_pairs)


def test_gate_allows_a_configured_budget():
    report = over_safety(SCARY_WORDS, source="<scary>")
    assert gate_over_safety(report)  # default ceilings are zero
    assert gate_over_safety(report, max_refused_rate=1.0, max_missed_rate=1.0) == []


def test_gate_fails_an_empty_report():
    assert gate_over_safety({"pairs": 0}) == [
        "no boundary pair was evaluated; over-safety needs authorized "
        "commands and their unauthorized twins"]
