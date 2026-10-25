"""Per-rule false-positive measurement: every rule gets a number, even a quiet one."""
from __future__ import annotations

from interlock.event import SensorEvent
from interlock.mesh.harness import measure, measure_each_detector, measure_each_rule

POLICY = {
    "version": 1,
    "name": "per-rule",
    "rules": [
        {"id": "blocks-secret", "verdict": "block", "on": "Read",
         "when": {"arg": "file_path", "endswith": ".secret"}},
        {"id": "never-matches", "verdict": "block", "on": "Grep",
         "when": {"arg": "pattern", "eq": "never-this"}},
    ],
}

CORPUS = [
    SensorEvent("Read", {"file_path": "/tmp/a.secret"}),
    SensorEvent("Read", {"file_path": "/tmp/a.txt"}),
    SensorEvent("Grep", {"pattern": "ordinary"}),
]


def test_each_rule_is_measured_on_its_own():
    rows = measure_each_rule(POLICY, CORPUS, repeats=2)
    assert [row["rule"] for row in rows] == ["blocks-secret", "never-matches"]

    firing, quiet = rows
    assert firing["false_positives"] == 2  # one event x two passes
    assert firing["evaluated"] == 6
    assert firing["verdicts"] == {"BLOCK": 2}
    assert firing["fp_rate"] == 2 / 6

    # A rule that never fires is exactly the case measure() cannot report.
    assert quiet["false_positives"] == 0
    assert quiet["verdicts"] == {}
    assert quiet["fp_rate"] == 0.0
    for row in rows:
        assert row["latency_us"]["p99"] >= row["latency_us"]["p95"]
        assert row["latency_us"]["p95"] >= row["latency_us"]["p50"]


def test_rule_latency_is_that_rule_not_the_pack():
    """Isolated rules run in one-rule engines, so the number is not the pack total."""
    rows = measure_each_rule(POLICY, CORPUS, repeats=1)
    pack = measure(POLICY, CORPUS, repeats=1)
    # Both rules together must decide in at least the median time of one alone.
    assert pack["latency_us"]["p50"] > 0
    assert max(row["latency_us"]["p50"] for row in rows) <= pack["latency_us"]["p50"] * 3


def test_a_malformed_rule_is_reported_and_the_sweep_continues():
    policy = {"version": 1, "rules": [POLICY["rules"][0], "not-an-object"]}
    rows = measure_each_rule(policy, CORPUS)
    assert rows[0]["rule"] == "blocks-secret"
    assert "error" in rows[1]
    assert rows[1]["rule"] == "#1"


def test_measure_carries_p99():
    result = measure(POLICY, CORPUS, repeats=2)
    assert result["latency_us"]["p99"] >= result["latency_us"]["p95"]


DETECTOR_POLICY = {
    "version": 1,
    "rules": [
        {"id": "bash-destructive", "on": "Bash",
         "detector": "destructive_command_guard", "with": {"keys": ["command"]}},
        {"id": "write-destructive", "on": "Write",
         "detector": "destructive_command_guard", "with": {"keys": ["content"]}},
        # A declarative rule has no detector and must not appear in this table.
        {"id": "plain", "verdict": "block", "on": "Read",
         "when": {"arg": "file_path", "endswith": ".secret"}},
    ],
}


def test_a_detector_is_measured_with_all_of_its_rules_together():
    corpus = [
        SensorEvent("Bash", {"command": "rm -rf /"}),
        SensorEvent("Bash", {"command": "ls"}),
        SensorEvent("Write", {"content": "hello"}),
        SensorEvent("Read", {"file_path": "/tmp/a.secret"}),
    ]
    rows = measure_each_detector(DETECTOR_POLICY, corpus)
    assert [row["detector"] for row in rows] == ["destructive_command_guard"]
    row = rows[0]
    assert row["rules"] == ["bash-destructive", "write-destructive"]
    # Only the destructive Bash call is a false positive on this corpus; the
    # declarative Read rule would have caught the last event but is not part
    # of the detector's number.
    assert row["false_positives"] == 1
    assert row["verdicts"] == {"BLOCK": 1}
    assert row["evaluated"] == 4


def test_a_policy_without_detectors_has_no_detector_rows():
    assert measure_each_detector(POLICY, CORPUS) == []
