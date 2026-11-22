"""Obligations: parsing, the log check, the live rule and the CLI.

An obligation is the one rule shape interlock has that cannot be decided from a
single event - it needs a clock and the follow-up receipt. These tests pin each
verdict (discharged, pending, breached, breached-late), the scope identity that
keeps two runs apart, and the one-shot property that stops a lapsed obligation
from bricking a run.
"""
import json
from typing import Any, cast

import pytest

from interlock import Decision, SensorEvent, Verdict
from interlock import obligations as model
from interlock.detectors.obligations import obligations
from interlock.receipt import Receipt

NOW = 1_700_000_000.0


def _receipt(action="deploy", ts=NOW, verdict="ALLOW", *, span_id: Any = "run-1",
             principal: Any = "agent-1", phase="call", approval=None):
    return Receipt(ts=ts, action=action, verdict=verdict, span_id=span_id,
                   principal=principal, phase=phase, approval=approval)


def _event(action="deploy", span_id: Any = "run-1", principal: Any = "agent-1",
           phase="call"):
    return SensorEvent(action=action, args={}, principal=principal,
                       span_id=span_id, phase=phase)


DEPLOY_APPROVE = [{"when": "deploy", "then": "approve", "within": 600}]


class _Clock:
    """A clock a test can move, so deadlines are deterministic."""

    def __init__(self, start: float = NOW) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# --- parse ------------------------------------------------------------------


def test_parse_reads_a_bare_list_and_canonicalises_actions():
    (rule,) = model.parse([{"when": "fs.readFile", "then": "http.post", "within": 30}])
    assert (rule.when, rule.then, rule.within) == ("fs_read_file", "http_post", 30.0)


def test_parse_reads_the_wrapped_form():
    (rule,) = model.parse({"obligations": DEPLOY_APPROVE})
    assert rule.policy_id == model.POLICY_ID
    assert rule.approvals_only is False


def test_parse_keeps_an_explicit_policy_id_and_approvals_only():
    (rule,) = model.parse([{"when": "a", "then": "b", "within": 1,
                            "policy_id": "rotation", "approvals_only": True}])
    assert rule.policy_id == "rotation"
    assert rule.approvals_only is True


@pytest.mark.parametrize("spec", [
    "not a list",
    [],
    [{"when": "a", "then": "b"}],
    [{"when": "a", "then": "b", "within": 0}],
    [{"when": "a", "then": "b", "within": -5}],
    [{"when": "a", "then": "b", "within": "soon"}],
    [{"when": "a", "then": "b", "within": True}],
    [{"when": "a", "then": "a", "within": 5}],
    [{"when": "", "then": "b", "within": 5}],
    [{"when": "a", "then": "b", "within": 5, "withinn": 5}],
    [{"when": "a", "then": "b", "within": 5, "approvals_only": "yes"}],
    [{"when": "a", "then": "b", "within": 5, "policy_id": ""}],
    ["a"],
])
def test_parse_refuses_anything_malformed(spec):
    with pytest.raises(ValueError):
        model.parse(spec)


def test_parse_refuses_unknown_keys_beside_the_wrapper():
    with pytest.raises(ValueError):
        model.parse({"obligations": DEPLOY_APPROVE, "extra": True})


# --- evaluate: the log check ------------------------------------------------


def test_a_follow_up_inside_the_deadline_discharges():
    found = model.evaluate([_receipt("deploy"), _receipt("approve", NOW + 60)],
                           model.parse(DEPLOY_APPROVE))
    (status,) = found
    assert status.state == model.DISCHARGED
    assert status.late is False
    assert status.discharged_at == NOW + 60


def test_a_missing_follow_up_is_breached_once_the_clock_passes():
    found = model.evaluate([_receipt("deploy")], model.parse(DEPLOY_APPROVE),
                           now=NOW + 601)
    (status,) = found
    assert status.state == model.BREACHED
    assert status.late is False


def test_a_follow_up_after_the_deadline_is_breached_and_late():
    found = model.evaluate(
        [_receipt("deploy"), _receipt("approve", NOW + 900)],
        model.parse(DEPLOY_APPROVE))
    (status,) = found
    assert status.state == model.BREACHED
    assert status.late is True
    assert status.discharged_at == NOW + 900


def test_an_open_obligation_is_pending_against_the_newest_receipt():
    # Default clock: the log's own last timestamp, so two runs agree.
    found = model.evaluate([_receipt("deploy")], model.parse(DEPLOY_APPROVE))
    (status,) = found
    assert status.state == model.PENDING


def test_a_discharge_in_another_run_does_not_count():
    found = model.evaluate(
        [_receipt("deploy", span_id="run-1"),
         _receipt("approve", NOW + 5, span_id="run-2")],
        model.parse(DEPLOY_APPROVE), now=NOW + 601)
    (status,) = found
    assert status.state == model.BREACHED


def test_the_principal_stands_in_for_a_missing_span():
    found = model.evaluate(
        [_receipt("deploy", span_id=None, principal="agent-1"),
         _receipt("approve", NOW + 5, span_id=None, principal="agent-1")],
        model.parse(DEPLOY_APPROVE))
    (status,) = found
    assert status.state == model.DISCHARGED
    assert status.scope == "agent-1"


def test_an_anonymous_run_is_still_judged():
    found = model.evaluate(
        [_receipt("deploy", span_id=None, principal=None)],
        model.parse(DEPLOY_APPROVE), now=NOW + 601)
    (status,) = found
    assert status.scope == model.ANON
    assert status.state == model.BREACHED


@pytest.mark.parametrize("verdict", ["BLOCK", "ESCALATE"])
def test_a_call_that_did_not_run_opens_nothing(verdict):
    found = model.evaluate(
        [_receipt("deploy", verdict=verdict), _receipt("approve", NOW + 5)],
        model.parse(DEPLOY_APPROVE))
    assert found == []


def test_a_result_phase_receipt_neither_opens_nor_discharges():
    found = model.evaluate(
        [_receipt("deploy", phase="result"), _receipt("approve", NOW + 5)],
        model.parse(DEPLOY_APPROVE))
    assert found == []


def test_approvals_only_needs_a_stamped_approval():
    spec = model.parse([{"when": "deploy", "then": "approve", "within": 600,
                         "approvals_only": True}])
    plain = model.evaluate(
        [_receipt("deploy"), _receipt("approve", NOW + 5)], spec, now=NOW + 601)
    assert plain[0].state == model.BREACHED
    stamped = model.evaluate(
        [_receipt("deploy"), _receipt("approve", NOW + 5, approval="user:ana")],
        spec)
    assert stamped[0].state == model.DISCHARGED


def test_every_opening_is_reported_and_closed_in_order():
    receipts = [_receipt("deploy", NOW), _receipt("deploy", NOW + 10),
                _receipt("approve", NOW + 20)]
    found = model.evaluate(receipts, model.parse(DEPLOY_APPROVE))
    assert [status.opened_at for status in found] == [NOW, NOW + 10]
    assert [status.state for status in found] == [model.DISCHARGED, model.PENDING]


def test_counts_always_name_every_state():
    found = model.evaluate([_receipt("deploy")], model.parse(DEPLOY_APPROVE))
    assert model.counts(found) == {model.DISCHARGED: 0, model.PENDING: 1,
                                   model.BREACHED: 0}


def test_no_obligations_means_no_verdicts():
    assert model.evaluate([_receipt("deploy")], []) == []


# --- the live rule ----------------------------------------------------------


def test_the_rule_opens_on_when_and_closes_on_then():
    clock = _Clock()
    rule = obligations(DEPLOY_APPROVE, clock=clock)
    assert rule(_event("deploy")) is None
    clock.advance(60)
    assert rule(_event("approve")) is None
    clock.advance(10_000)
    assert rule(_event("unrelated")) is None  # nothing left open


def test_the_run_meets_a_refusal_on_the_call_after_the_deadline():
    clock = _Clock()
    rule = obligations(DEPLOY_APPROVE, clock=clock)
    assert rule(_event("deploy")) is None
    clock.advance(601)
    decision = cast(Decision, rule(_event("write_file")))
    assert decision.verdict is Verdict.ESCALATE
    assert decision.policy_id == "obligation"
    assert "deploy" in decision.reason and "600" in decision.reason


def test_a_breach_fires_once_so_the_run_is_not_bricked():
    clock = _Clock()
    rule = obligations(DEPLOY_APPROVE, clock=clock)
    rule(_event("deploy"))
    clock.advance(601)
    assert cast(Decision, rule(_event("write_file"))).verdict is Verdict.ESCALATE
    assert rule(_event("write_file")) is None


def test_on_breach_block_refuses_the_call():
    clock = _Clock()
    rule = obligations(DEPLOY_APPROVE, on_breach="block", clock=clock)
    rule(_event("deploy"))
    clock.advance(601)
    assert cast(Decision, rule(_event("write_file"))).verdict is Verdict.BLOCK


def test_a_late_discharge_is_allowed_through():
    # Refusing the compensating action would make the run worse; the log
    # check still reports it as breached.
    clock = _Clock()
    rule = obligations(DEPLOY_APPROVE, clock=clock)
    rule(_event("deploy"))
    clock.advance(900)
    assert rule(_event("approve")) is None
    assert rule(_event("unrelated")) is None


def test_one_run_cannot_discharge_another():
    clock = _Clock()
    rule = obligations(DEPLOY_APPROVE, clock=clock)
    rule(_event("deploy", span_id="run-1"))
    clock.advance(5)
    rule(_event("approve", span_id="run-2"))
    clock.advance(601)
    assert cast(Decision, rule(_event("x", span_id="run-1"))).verdict is Verdict.ESCALATE


def test_result_phase_events_are_ignored():
    clock = _Clock()
    rule = obligations(DEPLOY_APPROVE, clock=clock)
    assert rule(_event("deploy", phase="result")) is None
    clock.advance(601)
    assert rule(_event("write_file")) is None


def test_the_oldest_opening_lapses_first():
    clock = _Clock()
    rule = obligations([{"when": "deploy", "then": "approve", "within": 600}],
                       clock=clock)
    rule(_event("deploy"))
    clock.advance(300)
    rule(_event("deploy"))
    clock.advance(301)  # the first has lapsed, the second has not
    assert cast(Decision, rule(_event("x"))).verdict is Verdict.ESCALATE
    clock.advance(300)
    assert cast(Decision, rule(_event("x"))).verdict is Verdict.ESCALATE
    assert rule(_event("x")) is None


def test_max_open_evicts_the_oldest_opening():
    clock = _Clock()
    rule = obligations(DEPLOY_APPROVE, max_open=2, clock=clock)
    before = clock.now
    for _ in range(3):
        rule(_event("deploy"))
        clock.advance(1)
    # The first opening was evicted, so its lapse alone cannot fire.
    clock.now = before + 601
    rule(_event("approve"))            # closes the second
    clock.advance(601)
    assert cast(Decision, rule(_event("x"))).verdict is Verdict.ESCALATE
    assert rule(_event("x")) is None


def test_max_scopes_evicts_the_oldest_run():
    clock = _Clock()
    rule = obligations(DEPLOY_APPROVE, max_scopes=1, clock=clock)
    rule(_event("deploy", span_id="run-1"))
    rule(_event("deploy", span_id="run-2"))  # evicts run-1's ledger
    clock.advance(601)
    assert cast(Decision, rule(_event("x", span_id="run-2"))).verdict is Verdict.ESCALATE


def test_a_blank_action_is_ignored():
    clock = _Clock()
    rule = obligations(DEPLOY_APPROVE, clock=clock)
    assert rule(_event("")) is None


@pytest.mark.parametrize("kwargs", [
    {"on_breach": "deny"},
    {"on_breach": None},
    {"max_scopes": 0},
    {"max_open": -1},
    {"max_scopes": True},
    {"clock": 5},
])
def test_the_rule_refuses_a_malformed_configuration(kwargs):
    with pytest.raises(ValueError):
        obligations(DEPLOY_APPROVE, **kwargs)


def test_the_rule_refuses_approvals_only_at_construction():
    spec = [{"when": "deploy", "then": "approve", "within": 60,
             "approvals_only": True}]
    with pytest.raises(ValueError):
        obligations(spec)


# --- the durable ledger -----------------------------------------------------
#
# A hook host runs one process per tool call, so every test here builds a FRESH
# rule object over the same state file: that is what the next invocation sees.


def _state(tmp_path):
    return str(tmp_path / "ledger" / "obligations.db")


def test_a_state_file_carries_an_opening_to_the_next_process(tmp_path):
    clock = _Clock()
    obligations(DEPLOY_APPROVE, clock=clock, state=_state(tmp_path))(_event("deploy"))
    clock.advance(601)
    second = obligations(DEPLOY_APPROVE, clock=clock, state=_state(tmp_path))
    assert cast(Decision, second(_event("write_file"))).verdict is Verdict.ESCALATE


def test_a_state_file_carries_the_discharge(tmp_path):
    clock = _Clock()
    obligations(DEPLOY_APPROVE, clock=clock, state=_state(tmp_path))(_event("deploy"))
    clock.advance(60)
    second = obligations(DEPLOY_APPROVE, clock=clock, state=_state(tmp_path))
    assert second(_event("approve")) is None
    clock.advance(601)
    third = obligations(DEPLOY_APPROVE, clock=clock, state=_state(tmp_path))
    assert third(_event("write_file")) is None


def test_a_state_file_keeps_two_runs_apart(tmp_path):
    clock = _Clock()
    obligations(DEPLOY_APPROVE, clock=clock, state=_state(tmp_path))(
        _event("deploy", span_id="run-1"))
    obligations(DEPLOY_APPROVE, clock=clock, state=_state(tmp_path))(
        _event("approve", span_id="run-2"))
    clock.advance(601)
    rule = obligations(DEPLOY_APPROVE, clock=clock, state=_state(tmp_path))
    assert cast(Decision, rule(_event("x", span_id="run-1"))).verdict is Verdict.ESCALATE


def test_max_open_holds_across_processes(tmp_path):
    clock = _Clock()
    before = clock.now
    for _ in range(2):  # max_open=1, so the first opening must be evicted
        obligations(DEPLOY_APPROVE, max_open=1, clock=clock,
                    state=_state(tmp_path))(_event("deploy"))
        clock.advance(500)
    clock.now = before + 700  # the evicted opening's deadline has passed
    rule = obligations(DEPLOY_APPROVE, max_open=1, clock=clock,
                       state=_state(tmp_path))
    assert rule(_event("x")) is None
    clock.now = before + 1101  # the kept opening's deadline has passed
    rule = obligations(DEPLOY_APPROVE, max_open=1, clock=clock,
                       state=_state(tmp_path))
    assert cast(Decision, rule(_event("x"))).verdict is Verdict.ESCALATE


def test_max_scopes_holds_across_processes(tmp_path):
    clock = _Clock()
    obligations(DEPLOY_APPROVE, max_scopes=1, clock=clock,
                state=_state(tmp_path))(_event("deploy", span_id="run-1"))
    rule = obligations(DEPLOY_APPROVE, max_scopes=1, clock=clock,
                       state=_state(tmp_path))
    rule(_event("deploy", span_id="run-2"))  # evicts run-1
    clock.advance(601)
    rule = obligations(DEPLOY_APPROVE, max_scopes=1, clock=clock,
                       state=_state(tmp_path))
    assert rule(_event("x", span_id="run-1")) is None
    rule = obligations(DEPLOY_APPROVE, max_scopes=1, clock=clock,
                       state=_state(tmp_path))
    assert cast(Decision, rule(_event("x", span_id="run-2"))).verdict is Verdict.ESCALATE


def test_a_state_file_drops_a_deadline_the_policy_no_longer_lists(tmp_path):
    clock = _Clock()
    obligations(DEPLOY_APPROVE, clock=clock, state=_state(tmp_path))(_event("deploy"))
    revoked = [{"when": "deploy", "then": "revoke", "within": 600}]
    clock.advance(601)
    rule = obligations(revoked, clock=clock, state=_state(tmp_path))
    assert rule(_event("write_file")) is None


@pytest.mark.parametrize("state", ["relative.db", "", "   "])
def test_the_rule_refuses_a_state_path_it_cannot_trust(state):
    with pytest.raises(ValueError):
        obligations(DEPLOY_APPROVE, state=state)


def test_a_state_path_may_be_home_relative():
    # Expanded, not refused: resolve() is what makes it absolute.
    obligations(DEPLOY_APPROVE, state="~/interlock-never-written.db")


def test_no_state_file_is_written_until_a_call_arrives(tmp_path):
    path = tmp_path / "ledger" / "obligations.db"
    rule = obligations(DEPLOY_APPROVE, state=str(path))
    assert not path.exists()          # `interlock policy check` must not write
    rule(_event("unrelated"))
    assert path.exists()


def test_the_state_file_is_readable_only_by_its_owner(tmp_path):
    import stat

    path = tmp_path / "ledger" / "obligations.db"
    obligations(DEPLOY_APPROVE, state=str(path))(_event("deploy"))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_a_corrupt_state_file_falls_back_instead_of_raising(tmp_path):
    path = tmp_path / "ledger" / "obligations.db"
    path.parent.mkdir()
    path.write_bytes(b"this is not a sqlite database\n" * 64)
    clock = _Clock()
    rule = obligations(DEPLOY_APPROVE, clock=clock, state=str(path))
    assert rule(_event("deploy")) is None  # warned and fell back, never raised
    clock.advance(601)
    assert cast(Decision, rule(_event("x"))).verdict is Verdict.ESCALATE


def test_declarative_rule_binds_state(tmp_path):
    from interlock.obligation_ledger import FileLedger
    from interlock.policy.declarative import load_policy

    path = _state(tmp_path)

    def document():
        return {"version": 1, "rules": [{
            "id": "deploy-needs-approval",
            "detector": "obligations",
            "with": {"require": DEPLOY_APPROVE, "state": path},
        }]}

    first = load_policy(document())
    assert not first.quarantined
    first.evaluate(_event("deploy"))
    assert FileLedger(path).open_count() == 1
    second = load_policy(document())   # a separate host, the same state file
    second.evaluate(_event("approve"))
    assert FileLedger(path).open_count() == 0


# --- the CLI ----------------------------------------------------------------


def _cli(tmp_path, receipts, spec, *extra):
    from interlock.cli import main

    log = tmp_path / "audit.jsonl"
    log.write_text("".join(receipt.to_json() + "\n" for receipt in receipts),
                   encoding="utf-8")
    rules = tmp_path / "obligations.json"
    rules.write_text(json.dumps(spec), encoding="utf-8")
    return main(["obligations", "check", "--log", str(log),
                 "--obligations", str(rules), *extra])


def test_the_cli_exits_zero_when_every_obligation_is_kept(tmp_path, capsys):
    code = _cli(tmp_path, [_receipt("deploy"), _receipt("approve", NOW + 60)],
                DEPLOY_APPROVE)
    assert code == 0
    assert "1 discharged" in capsys.readouterr().out


def test_the_cli_exits_one_on_a_breach(tmp_path, capsys):
    code = _cli(tmp_path, [_receipt("deploy")], DEPLOY_APPROVE, "--now", str(NOW + 999))
    assert code == 1
    assert "1 breached" in capsys.readouterr().out


def test_the_cli_json_carries_each_verdict(tmp_path, capsys):
    code = _cli(tmp_path, [_receipt("deploy")], DEPLOY_APPROVE,
                "--now", str(NOW + 999), "--json")
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["breaches"] == 1
    (entry,) = payload["obligations"]
    assert entry["state"] == "breached"
    assert entry["late"] is False
    assert entry["when"] == "deploy" and entry["within"] == 600


def test_the_cli_exits_three_on_an_unusable_obligation_file(tmp_path, capsys):
    code = _cli(tmp_path, [_receipt("deploy")], [{"when": "a", "then": "b"}])
    assert code == 3
    assert "within" in capsys.readouterr().err


def test_the_cli_exits_sixty_four_on_a_bad_clock(tmp_path):
    code = _cli(tmp_path, [_receipt("deploy")], DEPLOY_APPROVE, "--now", "yesterday")
    assert code == 64
