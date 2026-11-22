"""``interlock sequence hydrate``: the receipt log seeds the live journal.

A hook host keeps its sequence journal in a SQLite file, but a restart or a
fresh install begins empty - the first ``http_post`` of the day is judged
against nothing. The command replays the call-phase receipts of a log into that
file, under the guard's own scope identity, so the next call sees the history
the receipts already record.
"""
from __future__ import annotations

from typing import Any

import pytest

from interlock import SensorEvent
from interlock.cli import main
from interlock.detectors.sequence_guard import sequence_guard
from interlock.receipt import Receipt
from interlock.sequence_ledger import JournalLedger

NOW = 1_700_000_000.0
PAIR = [["env_secret_read", "http_post"]]


def _receipt(action="read_file", *, span_id: Any = "run-1",
             principal="agent-1", phase="call", verdict="ALLOW"):
    return Receipt(ts=NOW, action=action, verdict=verdict, span_id=span_id,
                   principal=principal, phase=phase)


def _log(tmp_path, receipts):
    path = tmp_path / "audit.jsonl"
    path.write_text("".join(r.to_json() + "\n" for r in receipts),
                    encoding="utf-8")
    return path


def _hydrate(tmp_path, receipts, *extra):
    state = tmp_path / "journal" / "sequence.db"
    code = main(["sequence", "hydrate", "--log", str(_log(tmp_path, receipts)),
                 "--state", str(state), *extra])
    return code, state


def test_the_cli_seeds_the_journal_so_the_next_call_is_blocked(tmp_path, capsys):
    code, state = _hydrate(tmp_path, [
        _receipt("env_secret_read"), _receipt("read_file")])
    assert code == 0
    out = capsys.readouterr().out
    assert "2 action(s) across 1 scope(s)" in out

    # A fresh rule over the seeded file is the next process after a restart.
    rule = sequence_guard(PAIR, state=str(state))
    decision = rule(SensorEvent(action="http_post", args={},
                                principal="agent-1", span_id="run-1"))
    assert decision is not None and decision.verdict.name == "BLOCK"


def test_the_cli_canonicalises_and_scopes_like_the_guard(tmp_path):
    code, state = _hydrate(tmp_path, [
        _receipt("env.secret.read"),                 # canonical spelling
        _receipt("publish", span_id=None, principal="agent-2")])
    assert code == 0
    ledger = JournalLedger(str(state))
    assert ledger.journal("run-1", window=50) == ["env_secret_read"]
    assert ledger.journal("agent-2", window=50) == ["publish"]


def test_the_cli_ignores_result_phase_receipts(tmp_path):
    code, state = _hydrate(tmp_path, [
        _receipt("env_secret_read", phase="result"),
        _receipt("read_file")])
    assert code == 0
    assert JournalLedger(str(state)).journal("run-1", window=50) == ["read_file"]


def test_the_cli_honours_the_window(tmp_path):
    code, state = _hydrate(tmp_path, [_receipt("a"), _receipt("b"),
                                      _receipt("c")], "--window", "2")
    assert code == 0
    assert JournalLedger(str(state)).journal("run-1", window=50) == ["b", "c"]


def test_the_cli_refuses_a_relative_state_path(tmp_path, capsys):
    log = _log(tmp_path, [_receipt("read_file")])
    code = main(["sequence", "hydrate", "--log", str(log),
                 "--state", "sequence.db"])
    assert code == 64
    assert "absolute path" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--window", "--max-scopes"])
def test_the_cli_refuses_a_non_positive_bound(tmp_path, flag, capsys):
    log = _log(tmp_path, [_receipt("read_file")])
    code = main(["sequence", "hydrate", "--log", str(log),
                 "--state", str(tmp_path / "j.db"), flag, "0"])
    assert code == 64
    assert "positive integer" in capsys.readouterr().err


def test_the_cli_exits_three_on_an_unreadable_log(tmp_path, capsys):
    code = main(["sequence", "hydrate", "--log", str(tmp_path / "missing.jsonl"),
                 "--state", str(tmp_path / "j.db")])
    assert code == 3
    assert "cannot read" in capsys.readouterr().err


def test_the_cli_skips_an_unreadable_line_and_says_so(tmp_path, capsys):
    log = tmp_path / "audit.jsonl"
    log.write_text(_receipt("env_secret_read").to_json() + "\n"
                   + "{not json\n", encoding="utf-8")
    code = main(["sequence", "hydrate", "--log", str(log),
                 "--state", str(tmp_path / "j.db")])
    assert code == 0
    captured = capsys.readouterr()
    assert "1 action(s)" in captured.out
    assert "1 unreadable line(s)" in captured.err


def test_sequence_without_an_action_is_a_usage_error():
    assert main(["sequence"]) == 64
