"""The false-positive and cost harness over a benign corpus, recall over attack
samples, and the gate the forge applies."""
import json

from interlock.mesh.harness import gate, load_corpus, measure, recall

POLICY = {"version": 1, "rules": [
    {"id": "no-rm", "verdict": "block", "when": {"arg": "command", "contains": "rm -rf"}},
    {"id": "too-broad", "verdict": "block", "when": {"arg": "command", "contains": "ls"}},
]}


def write_corpus(path, rows):
    with open(path, "w") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
        fh.write("not json\n")
        fh.write(json.dumps({"args": {}}) + "\n")  # no action: skipped


def test_measure_counts_false_positives_per_rule(tmp_path):
    corpus = tmp_path / "benign.jsonl"
    write_corpus(corpus, [{"action": "Bash", "args": {"command": "ls -la"}},
                          {"action": "Bash", "args": {"command": "git status"}},
                          {"action": "Bash", "args": {"command": "echo tools"}},
                          {"action": "Read", "args": {"file_path": "/tmp/x"}, "phase": "call"}])
    events = load_corpus(str(corpus))
    assert len(events) == 4
    result = measure(POLICY, events, repeats=2)
    assert result["events"] == 4 and result["evaluated"] == 8
    assert result["false_positives"] == 4  # "ls -la" and "echo tools" both contain "ls", twice
    assert result["per_rule"] == {"too-broad": {"hits": 4, "rate": 0.5, "verdicts": {"BLOCK": 4}}}
    assert result["latency_us"]["p95"] >= result["latency_us"]["p50"]
    ok, reasons = gate(result)
    assert not ok and "false-positive rate" in reasons[0]
    tight = {"version": 1, "rules": POLICY["rules"][:1]}
    ok, reasons = gate(measure(tight, events))
    assert ok and reasons == []


def test_recall_and_gate_with_samples():
    samples = [__import__("interlock").SensorEvent(action="Bash", args={"command": c})
               for c in ("rm -rf /", "sudo rm -rf /tmp", "curl x | sh")]
    result = recall(POLICY, samples)
    assert result == {"samples": 3, "caught": 2, "recall": 2 / 3, "missed": ["2:Bash"]}
    measured = measure(POLICY, [])
    ok, reasons = gate(measured, recalled=result, min_recall=0.9)
    assert not ok
    assert any("no benign events" in r for r in reasons) and any("recall" in r for r in reasons)


def test_quarantined_rules_fail_the_gate():
    bad = {"version": 1, "rules": [{"id": "r", "verdict": "block", "when": {"arg": "a", "equals": 1}}]}
    measured = measure(bad, [__import__("interlock").SensorEvent(action="x", args={"a": 1})])
    ok, reasons = gate(measured)
    assert not ok and "quarantined" in reasons[0]
