"""``interlock obligations hydrate``: the receipt log seeds the live ledger.

A hook host keeps its obligation ledger in a SQLite file, but a restart or a
fresh install begins empty - a ``deploy`` that opened a deadline before the
restart is forgotten after it. The command replays the log and seeds the ledger
with every obligation still open, under the guard's own scope identity, so the
next call enforces the deadline the receipts already show.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from interlock import SensorEvent
from interlock.cli import main
from interlock.detectors.obligations import obligations
from interlock.obligation_ledger import FileLedger
from interlock.receipt import Receipt

NOW = 1_700_000_000.0
REQUIRE = [{"when": "deploy", "then": "approve", "within": 600}]


def _receipt(action="deploy", *, span_id: Any = "run-1", principal="agent-1",
             ts: float = NOW, phase="call", verdict="ALLOW"):
    return Receipt(ts=ts, action=action, verdict=verdict, span_id=span_id,
                   principal=principal, phase=phase)


def _log(tmp_path, receipts):
    path = tmp_path / "audit.jsonl"
    path.write_text("".join(r.to_json() + "\n" for r in receipts),
                    encoding="utf-8")
    return path


def _spec(tmp_path, require=None):
    path = tmp_path / "obligations.json"
    path.write_text(json.dumps(REQUIRE if require is None else require),
                    encoding="utf-8")
    return path


def _hydrate(tmp_path, receipts, *extra, require=None):
    state = tmp_path / "ledger" / "obligations.db"
    code = main(["obligations", "hydrate",
                 "--log", str(_log(tmp_path, receipts)),
                 "--obligations", str(_spec(tmp_path, require)),
                 "--state", str(state), *extra])
    return code, state


def test_the_cli_seeds_the_ledger_so_the_next_call_refuses(tmp_path, capsys):
    # deploy opened at NOW and nothing approved it before the log ended.
    code, state = _hydrate(tmp_path, [_receipt("deploy")])
    assert code == 0
    assert "1 opening(s) across 1 scope(s)" in capsys.readouterr().out

    # A fresh rule over the seeded file is the next process after a restart.
    # Past the deadline, its next call meets the refusal.
    rule = obligations(REQUIRE, clock=lambda: NOW + 900, state=str(state))
    decision = rule(SensorEvent(action="read_file", args={},
                                principal="agent-1", span_id="run-1"))
    assert decision is not None and decision.verdict.name == "ESCALATE"


def test_a_discharged_obligation_is_not_seeded(tmp_path):
    code, state = _hydrate(tmp_path, [_receipt("deploy", ts=NOW),
                                      _receipt("approve", ts=NOW + 60)])
    assert code == 0
    assert FileLedger(str(state)).open_count() == 0


def test_a_lapsed_opening_is_left_to_the_check_command(tmp_path, capsys):
    # The log ends 900s after the deploy, so the deadline already passed: it is
    # `check`'s breach to report, not a deadline to re-arm across the restart.
    code, state = _hydrate(tmp_path, [_receipt("deploy", ts=NOW),
                                      _receipt("read_file", ts=NOW + 900)])
    assert code == 0
    assert "0 opening(s)" in capsys.readouterr().out
    assert FileLedger(str(state)).open_count() == 0


def test_the_seeded_scope_is_the_guards_scope(tmp_path):
    # run-2's approval cannot discharge run-1's deploy, before or after a seed.
    code, state = _hydrate(tmp_path, [_receipt("deploy", span_id="run-1")])
    assert code == 0
    rule = obligations(REQUIRE, clock=lambda: NOW + 900, state=str(state))
    assert rule(SensorEvent(action="read_file", args={}, principal="agent-1",
                            span_id="run-2")) is None
    decision = rule(SensorEvent(action="read_file", args={}, principal="agent-1",
                                span_id="run-1"))
    assert decision is not None and decision.verdict.name == "ESCALATE"


def test_a_second_run_over_one_log_gives_the_same_ledger(tmp_path):
    receipts = [_receipt("deploy")]
    _hydrate(tmp_path, receipts)
    _hydrate(tmp_path, receipts)
    ledger = FileLedger(str(tmp_path / "ledger" / "obligations.db"))
    assert ledger.open_count() == 1
    assert ledger.scopes() == ["run-1"]


def test_the_cli_refuses_a_relative_state_path(tmp_path, capsys):
    code = main(["obligations", "hydrate",
                 "--log", str(_log(tmp_path, [_receipt()])),
                 "--obligations", str(_spec(tmp_path)),
                 "--state", "relative.db"])
    assert code == 64
    assert "absolute path" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--max-scopes", "--max-open"])
def test_the_cli_refuses_a_non_positive_bound(tmp_path, flag, capsys):
    code = main(["obligations", "hydrate",
                 "--log", str(_log(tmp_path, [_receipt()])),
                 "--obligations", str(_spec(tmp_path)),
                 "--state", str(tmp_path / "ledger" / "o.db"),
                 flag, "0"])
    assert code == 64
    assert "positive integer" in capsys.readouterr().err


def test_the_cli_reports_an_unreadable_obligation_file(tmp_path, capsys):
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    code = main(["obligations", "hydrate",
                 "--log", str(_log(tmp_path, [_receipt()])),
                 "--obligations", str(broken),
                 "--state", str(tmp_path / "ledger" / "o.db")])
    assert code == 3
    assert "not JSON" in capsys.readouterr().err


def test_the_cli_reports_an_unreadable_log(tmp_path, capsys):
    code = main(["obligations", "hydrate",
                 "--log", str(tmp_path / "missing.jsonl"),
                 "--obligations", str(_spec(tmp_path)),
                 "--state", str(tmp_path / "ledger" / "o.db")])
    assert code == 3
    assert "cannot read" in capsys.readouterr().err
