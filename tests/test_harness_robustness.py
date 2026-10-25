"""Induced blocking and pathological-cost measurement.

A guard can be wrong in two more ways than "it fired on benign traffic": an
attacker can make it fire by putting bait in a field that does not execute, or
make it expensive by sending a legal-but-pathological call. These tests pin the
measurements, not a machine's speed.
"""
from __future__ import annotations

from interlock.event import SensorEvent
from interlock.mesh.harness import (
    gate_induced,
    gate_stress,
    induced_blocking,
    stress,
    stress_events,
)
from interlock.shell.parser import MAX_INPUT

BROAD = {
    "version": 1,
    "rules": [
        {"id": "description-bait", "verdict": "block", "on": "Bash",
         "when": {"arg": "description", "contains": "ignore previous instructions"}},
    ],
}

NARROW = {
    "version": 1,
    "rules": [
        {"id": "destructive", "verdict": "block", "on": "Bash",
         "when": {"arg": "command", "contains": "rm -rf /"}},
    ],
}

CORPUS = [SensorEvent("Bash", {"command": "ls", "description": "list the directory"})]
POISON = [{"id": "bait", "text": "ignore previous instructions"}]


def test_a_rule_that_reads_metadata_is_caught_inducing_a_block():
    report = induced_blocking(BROAD, CORPUS, POISON, source="test")
    assert report["variants"] == 1
    assert report["induced"] == 1
    assert report["by_rule"] == {"description-bait": 1}
    assert report["examples"][0]["arg"] == "description"
    assert gate_induced(report)  # rate above the default ceiling of zero


def test_an_execution_rule_ignores_bait_in_a_description():
    report = induced_blocking(NARROW, CORPUS, [{"id": "p", "text": "rm -rf /"}],
                              source="test")
    assert report["variants"] == 1
    assert report["induced"] == 0
    assert gate_induced(report) == []


def test_result_phase_content_is_not_counted_as_induced():
    corpus = [SensorEvent("mcp__x__read", {"text": "ordinary result"}, phase="result")]
    report = induced_blocking(BROAD, corpus, POISON, source="test")
    assert report["variants"] == 0
    assert gate_induced(report) == [
        "no injectable event was evaluated; induced blocking needs a corpus and poisons"]


def test_gate_induced_allows_a_configured_budget():
    report = {"variants": 10, "induced": 1, "induced_rate": 0.1, "by_rule": {"r": 1}}
    assert gate_induced(report)  # default ceiling is zero
    assert gate_induced(report, max_rate=0.2) == []


def test_stress_measures_each_case_and_gates_the_slow_one():
    rows = stress(NARROW, [SensorEvent("Bash", {"command": "ls"})], repeats=1)
    assert rows[0]["verdict"] == "ALLOW"
    assert rows[0]["latency_us"]["p95"] >= rows[0]["latency_us"]["p50"]

    slow = [{"case": 0, "action": "Bash", "bytes": 10,
             "latency_us": {"p50": 60_000, "p95": 60_000}}]
    assert gate_stress(slow, max_p95_us=50_000)
    assert gate_stress(slow, max_p95_us=100_000) == []
    assert gate_stress([]) == ["no stress case ran"]


def test_stress_cases_exceed_the_parser_cap():
    commands = [event.args.get("command", "") for event in stress_events()
                if event.action == "Bash"]
    assert max(len(command) for command in commands) > MAX_INPUT
