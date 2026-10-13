"""`interlock learn` and interlock.learn (R24).

The fixture mirrors the kickoff's live smoke log: search_web x3 and read_file
x1, every receipt recorded with verdict ALLOW. The CLI is driven through
``interlock.cli.main`` so the wiring in the COMMANDS table is exercised too.
"""
import json

import pytest

from interlock.cli import main
from interlock.enforce import Verdict
from interlock.event import SensorEvent
from interlock.learn import DEFAULT_NAME, RULE_ID, Baseline, build_policy, learn
from interlock.policy.declarative import load_policy
from interlock.receipt import Receipt
from interlock.sink import FileSink

KEY = b"l" * 32


def _write_log(path, actions, verdict="ALLOW"):
    """Write one receipt per action, in order, the way FileSink does."""
    sink = FileSink(str(path), key=KEY)
    for action in actions:
        sink.write(Receipt(ts=1.0, action=action, verdict=verdict, reason="observed",
                           policy_id="monitor", principal="agent-1", args_digest="0" * 64))
    return str(path)


def _fixture(path):
    """The smoke fixture: search_web x3, read_file x1, all ALLOW."""
    return _write_log(path, ["search_web", "search_web", "read_file", "search_web"])


def _evaluate(doc, action):
    return load_policy(doc).evaluate(SensorEvent(action=action, args={})).verdict


def test_cli_emits_a_deterministic_loadable_policy(tmp_path):
    log = _fixture(tmp_path / "receipts.jsonl")
    first, second = tmp_path / "a.json", tmp_path / "b.json"

    assert main(["learn", "--receipts", log, "--out", str(first)]) == 0
    assert main(["learn", "--receipts", log, "--out", str(second)]) == 0

    assert first.read_bytes() == second.read_bytes()  # deterministic
    assert first.read_text().endswith("\n")

    doc = json.loads(first.read_text())
    engine = load_policy(doc)
    assert engine.quarantined == []  # no rule silently skipped
    # Observed actions stay allowed; the unseen escalates rather than blocks.
    assert _evaluate(doc, "search_web") == Verdict.ALLOW
    assert _evaluate(doc, "read_file") == Verdict.ALLOW
    assert _evaluate(doc, "delete_everything") != Verdict.ALLOW


def test_cli_prints_a_one_line_summary(tmp_path, capsys):
    log = _fixture(tmp_path / "receipts.jsonl")
    out = tmp_path / "policy.json"
    assert main(["learn", "--receipts", log, "--out", str(out)]) == 0
    summary = capsys.readouterr().out
    assert summary.count("\n") == 1
    assert "4 allowed receipt(s)" in summary and "2 observed action(s)" in summary


def test_counts_and_evidence(tmp_path):
    log = _fixture(tmp_path / "receipts.jsonl")
    doc, baseline = learn(log)

    assert baseline.counts == {"read_file": 1, "search_web": 3}
    assert baseline.actions == ["read_file", "search_web"]  # deduped, sorted
    assert baseline.total == 4

    rule = doc["rules"][0]
    assert rule["id"] == RULE_ID
    assert rule["verdict"] == "escalate"
    assert rule["when"] == {"not": {"action": ["read_file", "search_web"]}}
    assert "read_file=1" in rule["description"]
    assert "search_web=3" in rule["description"]
    assert doc["name"] == DEFAULT_NAME


def test_draft_never_enforces(tmp_path):
    """c:0 - the draft escalates the unseen; it blocks and locks nothing."""
    log = _fixture(tmp_path / "receipts.jsonl")
    text = json.dumps(learn(log)[0])
    assert '"verdict": "block"' not in text
    assert '"locked": true' not in text
    assert all(rule["verdict"] == "escalate" for rule in json.loads(text)["rules"])


def test_only_allow_receipts_enter_the_envelope(tmp_path):
    path = tmp_path / "mixed.jsonl"
    sink = FileSink(str(path), key=KEY)
    sink.write(Receipt(ts=1.0, action="search_web", verdict="ALLOW"))
    sink.write(Receipt(ts=2.0, action="send_email", verdict="BLOCK", reason="no"))
    sink.write(Receipt(ts=3.0, action="post", verdict="MODIFY"))
    sink.write(Receipt(ts=4.0, action="wire_money", verdict="ESCALATE"))

    doc, baseline = learn(str(path))
    assert baseline.actions == ["search_web"]
    assert baseline.excluded == {"BLOCK": 1, "MODIFY": 1, "ESCALATE": 1}

    assert _evaluate(doc, "search_web") == Verdict.ALLOW
    # A refused action is never laundered into the envelope.
    assert _evaluate(doc, "send_email") != Verdict.ALLOW


def test_allow_verdict_is_case_insensitive(tmp_path):
    log = _write_log(tmp_path / "lower.jsonl", ["search_web"], verdict="allow")
    _, baseline = learn(log)
    assert baseline.actions == ["search_web"]


def test_dropped_receipts_are_artifacts_not_actions(tmp_path):
    path = tmp_path / "dropped.jsonl"
    sink = FileSink(str(path), key=KEY)
    sink.write(Receipt(ts=1.0, action="search_web", verdict="ALLOW"))
    sink.write(Receipt(ts=2.0, action="receipts.dropped", verdict="ALLOW",
                       reason="1 receipt(s) could not be written", policy_id="audit_sink"))
    _, baseline = learn(str(path))
    assert baseline.actions == ["search_web"]
    assert baseline.excluded == {"receipts.dropped": 1}


def test_output_is_order_independent(tmp_path):
    a = _write_log(tmp_path / "a.jsonl", ["read_file", "search_web", "read_file", "search_web"])
    b = _write_log(tmp_path / "b.jsonl", ["search_web", "read_file", "search_web", "read_file"])
    doc_a, baseline_a = learn(a)
    doc_b, baseline_b = learn(b)
    assert baseline_a.counts == baseline_b.counts == {"read_file": 2, "search_web": 2}
    assert json.dumps(doc_a, sort_keys=True) == json.dumps(doc_b, sort_keys=True)


def test_unreadable_lines_are_tolerated(tmp_path):
    log = _fixture(tmp_path / "torn.jsonl")
    with open(log, "a", encoding="utf-8") as fh:
        fh.write("{ this is not a receipt\n")
        fh.write("\n")
    doc, baseline = learn(log)
    assert baseline.counts == {"read_file": 1, "search_web": 3}
    assert load_policy(doc).quarantined == []


def test_name_override(tmp_path):
    log = _fixture(tmp_path / "receipts.jsonl")
    out = tmp_path / "policy.json"
    assert main(["learn", "--receipts", log, "--out", str(out), "--name", "acme-baseline"]) == 0
    assert json.loads(out.read_text())["name"] == "acme-baseline"


def test_build_policy_refuses_an_empty_baseline():
    with pytest.raises(ValueError):
        build_policy(Baseline())


def test_empty_log_writes_no_policy(tmp_path, capsys):
    path = tmp_path / "empty.jsonl"
    path.write_text("")
    out = tmp_path / "policy.json"
    assert main(["learn", "--receipts", str(path), "--out", str(out)]) == 3
    assert not out.exists()
    assert "no ALLOW-observed receipt" in capsys.readouterr().err


def test_log_with_only_refusals_writes_no_policy(tmp_path):
    path = tmp_path / "blocked.jsonl"
    sink = FileSink(str(path), key=KEY)
    sink.write(Receipt(ts=1.0, action="rm", verdict="BLOCK", reason="no"))
    out = tmp_path / "policy.json"
    assert main(["learn", "--receipts", str(path), "--out", str(out)]) == 3
    assert not out.exists()


def test_missing_log_writes_no_policy(tmp_path):
    out = tmp_path / "policy.json"
    assert main(["learn", "--receipts", str(tmp_path / "nope.jsonl"), "--out", str(out)]) == 3
    assert not out.exists()


def test_missing_arguments_are_a_usage_error(tmp_path, capsys):
    assert main(["learn"]) == 64
    assert main(["learn", "--receipts", str(tmp_path / "r.jsonl")]) == 64
    assert "--receipts and --out are required" in capsys.readouterr().err


def test_learn_accepts_receipt_iterables():
    receipts = [Receipt(ts=1.0, action="search_web", verdict="ALLOW"),
                Receipt(ts=2.0, action="search_web", verdict="ALLOW")]
    doc, baseline = learn(receipts)
    assert baseline.counts == {"search_web": 2}
    assert load_policy(doc).quarantined == []


def test_learn_returns_no_document_for_an_empty_log(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("")
    doc, baseline = learn(str(path))
    assert doc is None and baseline.empty
