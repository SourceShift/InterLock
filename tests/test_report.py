"""`interlock report` and interlock.report (R16)."""
import json

import pytest

import interlock
from interlock import Decision, deny_tool, guard, install, monitor
from interlock.cli import main
from interlock.receipt import Receipt, set_sink
from interlock.report import parse_since, read_receipts, render, summarize, verification
from interlock.sink import FileSink

KEY = b"r" * 32


@pytest.fixture
def log(tmp_path):
    """A log with known counts: 3 allowed calls (+3 results), 2 blocks,
    1 rewrite (+result), 2 monitor would-blocks (+results), 1 failure."""
    path = tmp_path / "audit.jsonl"
    set_sink(FileSink(str(path), key=KEY))

    def mask(event):
        if event.action == "post":
            return Decision.modify({"body": "[masked]"}, "masked", policy_id="pii")
        return None

    install(rules=[deny_tool("rm", policy_id="no_rm"), mask])

    @guard()
    def ok():
        return 1

    @guard()
    def rm():
        return 1

    @guard()
    def post(body):
        return body

    @monitor()
    def trial():
        return 1

    @guard()
    def broken():
        raise PermissionError("Operation not permitted")

    for _ in range(3):
        ok()
    for _ in range(2):
        with pytest.raises(interlock.Blocked):
            rm()
    post("secret")
    install(rules=[deny_tool("trial", policy_id="new_rule")])
    trial()
    trial()
    with pytest.raises(PermissionError):
        broken()
    set_sink(None)
    return path


def test_summary_counts(log):
    receipts, bad = read_receipts(str(log))
    assert bad == []
    s = summarize(receipts)
    # ALLOW: 3 ok calls + 3 results, post result, 2 trial results, broken call
    assert s["verdicts"] == {"ALLOW": 10, "BLOCK": 2, "MODIFY": 1}
    assert s["totals"]["calls"] == 7  # 3 ok + 2 rm + 1 post + 1 broken
    assert s["block_rate"] == pytest.approx(2 / 7)
    assert s["top_rules"][0] == {"policy_id": "no_rm", "count": 2, "verdicts": {"BLOCK": 2}}
    assert s["would_have"]["total"] == 2
    assert s["would_have"]["rows"] == [
        {"count": 2, "verdict": "BLOCK", "action": "trial", "policy_id": "new_rule"}]
    assert s["failed_outcomes"] == {"os": 1}
    assert s["latency_us"]["samples"] == 15  # every call and result decision
    assert s["dropped_receipts"] == 0


def test_verification(log):
    receipts, _ = read_receipts(str(log))
    assert verification(receipts)["status"] == "unverified"
    assert verification(receipts, key=KEY)["status"] == "verified"
    assert verification(receipts, key=b"wrong")["status"] == "broken"


def test_since_window():
    old = Receipt(ts=1000.0, action="a", verdict="BLOCK", policy_id="p")
    new = Receipt(ts=1000.0 + 86400 * 3, action="a", verdict="ALLOW")
    s = summarize([old, new], since_seconds=86400, now=new.ts + 10)
    assert s["totals"]["decisions"] == 1 and s["verdicts"] == {"ALLOW": 1}


@pytest.mark.parametrize("text, seconds", [
    ("30m", 1800), ("24h", 86400), ("7d", 604800), ("1w", 604800), ("0", None),
    ("all", None), (None, None),
])
def test_parse_since(text, seconds):
    assert parse_since(text) == seconds


def test_parse_since_rejects_garbage():
    with pytest.raises(ValueError):
        parse_since("yesterday")


def test_dropped_notices_are_summed():
    notice = Receipt(ts=1.0, action="receipts.dropped", verdict="ALLOW",
                     reason="3 receipt(s) could not be written; last error: OSError")
    assert summarize([notice])["dropped_receipts"] == 3


def test_coverage_gaps_are_counted_by_class():
    receipts = [
        Receipt(ts=1.0, action="run_shell", verdict="ALLOW",
                policy_id="coverage_gap", reason="coverage_gap: shell",
                coverage_gap="shell"),
        Receipt(ts=2.0, action="delete_file", verdict="ALLOW",
                policy_id="coverage_gap", coverage_gap="shell"),
        Receipt(ts=3.0, action="send_email", verdict="BLOCK",
                policy_id="fail_closed", coverage_gap="email"),
        Receipt(ts=4.0, action="run_shell", verdict="ALLOW"),
    ]

    summary = summarize(receipts)

    # Sorted by class, so two shell gaps and one email gap.
    assert summary["coverage_gaps"] == {"email": 1, "shell": 2}
    assert "Coverage gaps:    1 email, 2 shell" in render(
        summary, verification(receipts))


def test_coverage_gap_is_optional_and_round_trips():
    receipt = Receipt(ts=1.0, action="a", verdict="ALLOW", coverage_gap="shell")
    assert json.loads(receipt.to_json())["coverage_gap"] == "shell"
    assert Receipt.from_json(receipt.to_json()).coverage_gap == "shell"
    # Omitted while None, so every older receipt's MAC still verifies.
    assert "coverage_gap" not in json.loads(
        Receipt(ts=1.0, action="a", verdict="ALLOW").to_json())


def test_cli_json(log, tmp_path, capsys):
    key_file = tmp_path / "key"
    key_file.write_text(KEY.hex())
    assert main(["report", str(log), "--json", "--key-file", str(key_file)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["verification"]["status"] == "verified"
    assert out["verdicts"]["BLOCK"] == 2


def test_cli_monitor_view(log, capsys):
    assert main(["--no-color", "report", str(log), "--monitor"]) == 0
    out = capsys.readouterr().out
    assert "Would have intervened in 2 call(s):" in out
    assert "new_rule" in out
    assert "NOT verified" in out


def test_cli_human_view_never_prints_argument_values(log, capsys):
    main(["--no-color", "report", str(log)])
    out = capsys.readouterr().out
    assert "secret" not in out
    assert "no_rm" in out and "Call block rate" in out


def test_cli_broken_chain_exits_2(log, tmp_path, capsys):
    lines = log.read_text().splitlines()
    lines[1] = lines[1].replace('"verdict":"ALLOW"', '"verdict":"BLOCK"', 1)
    log.write_text("\n".join(lines) + "\n")
    key_file = tmp_path / "key"
    key_file.write_text(KEY.hex())
    assert main(["report", str(log), "--key-file", str(key_file), "--json"]) == 2


def test_cli_missing_file_exits_3(tmp_path):
    assert main(["report", str(tmp_path / "nope.jsonl")]) == 3


def test_cli_bad_duration_is_a_usage_error(log):
    assert main(["report", str(log), "--since", "soon"]) == 64
