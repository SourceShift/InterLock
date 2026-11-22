"""`interlock policy lint`: the rule set that cannot do what it says.

Loading answers "is each rule well formed". These checks answer "can these
rules ever work together" - an unsatisfiable condition, a rule an earlier
block decides before it, and a requirement whose action another rule refuses
for every call.
"""
from __future__ import annotations

import json

from interlock.cli import main
from interlock.policy.lint import (
    CONTRADICTS,
    SHADOWED,
    UNSATISFIABLE,
    lint_document,
)


def _doc(*rules):
    return {"version": 1, "rules": list(rules)}


def _codes(findings):
    return [finding.code for finding in findings]


def _write(tmp_path, doc):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


# --- unsatisfiable ------------------------------------------------------------


def test_two_different_actions_in_one_all_never_match():
    findings = lint_document(_doc({
        "id": "both", "verdict": "block",
        "when": {"all": [{"action": "deploy"}, {"action": "approve"}]}}))
    assert _codes(findings) == [UNSATISFIABLE]
    assert findings[0].rule == "both"


def test_disjoint_action_lists_in_one_all_never_match():
    findings = lint_document(_doc({
        "id": "both", "verdict": "block",
        "when": {"all": [{"action": "deploy"},
                         {"action": ["approve", "ship"]}]}}))
    assert _codes(findings) == [UNSATISFIABLE]


def test_an_overlapping_action_list_is_satisfiable():
    assert lint_document(_doc({
        "id": "fine", "verdict": "block",
        "when": {"all": [{"action": "deploy"},
                         {"action": ["deploy", "ship"]}]}})) == []


def test_a_glob_is_unknown_rather_than_empty():
    # A glob cannot be expanded here, so it narrows nothing and is not a finding.
    assert lint_document(_doc({
        "id": "globbed", "verdict": "block",
        "when": {"all": [{"action": "deploy"}, {"action": {"glob": "ap*"}}]}})) == []


# --- shadowed -----------------------------------------------------------------


def test_a_rule_after_an_identical_block_never_fires():
    findings = lint_document(_doc(
        {"id": "first", "verdict": "block", "when": {"action": "deploy"}},
        {"id": "second", "verdict": "escalate", "when": {"action": "deploy"}}))
    assert _codes(findings) == [SHADOWED]
    assert findings[0].rule == "second"
    assert "'first'" in findings[0].message


def test_an_escalate_does_not_shadow_later_rules():
    # The engine keeps the strongest escalation and keeps evaluating.
    assert lint_document(_doc(
        {"id": "first", "verdict": "escalate", "when": {"action": "deploy"}},
        {"id": "second", "verdict": "block", "when": {"action": "deploy"}})) == []


def test_a_different_condition_shadows_nothing():
    assert lint_document(_doc(
        {"id": "first", "verdict": "block", "when": {"action": "deploy"}},
        {"id": "second", "verdict": "block",
         "when": {"all": [{"action": "deploy"}, {"arg": "env", "eq": "prod"}]}})) == []


def test_a_shadow_rule_does_not_shadow():
    # A mode=shadow rule observes rather than decides, so it blocks nothing.
    assert lint_document(_doc(
        {"id": "watch", "verdict": "block", "when": {"action": "deploy"},
         "mode": "shadow"},
        {"id": "second", "verdict": "escalate", "when": {"action": "deploy"}})) == []


def test_a_quarantined_rule_shadows_nothing():
    earlier = {"id": "broken", "verdict": "block", "when": {"action": "deploy"},
               "mode": "nope"}
    later = {"id": "second", "verdict": "escalate", "when": {"action": "deploy"}}
    assert lint_document(_doc(earlier, later),
                         quarantined=["broken: 'mode' must be one of ['enforce', 'shadow']"]) == []


# --- contradicts-requirement ----------------------------------------------------


def _obligation(rule_id="deploy-approval", then="approve"):
    return {"id": rule_id, "detector": "obligations",
            "with": {"require": [{"when": "deploy", "then": then, "within": 600}]}}


def test_a_required_action_blocked_for_every_call_is_reported():
    findings = lint_document(_doc(
        _obligation(),
        {"id": "no-approve", "verdict": "block", "when": {"action": "approve"}}))
    assert _codes(findings) == [CONTRADICTS]
    assert findings[0].rule == "deploy-approval"
    assert "no-approve" in findings[0].message


def test_a_conditional_block_leaves_the_requirement_met():
    assert lint_document(_doc(
        _obligation(),
        {"id": "no-bot-approve", "verdict": "block",
         "when": {"all": [{"action": "approve"}, {"arg": "who", "eq": "bot"}]}})) == []


def test_a_requirement_with_no_blocker_is_clean():
    assert lint_document(_doc(_obligation())) == []


# --- the command line ---------------------------------------------------------


def test_the_cli_exits_one_on_a_finding(tmp_path, capsys):
    path = _write(tmp_path, _doc({
        "id": "both", "verdict": "block",
        "when": {"all": [{"action": "deploy"}, {"action": "approve"}]}}))
    assert main(["policy", "lint", str(path)]) == 1
    out = capsys.readouterr().out
    assert UNSATISFIABLE in out and "both" in out


def test_the_cli_exits_zero_when_nothing_is_wrong(tmp_path, capsys):
    path = _write(tmp_path, _doc(
        {"id": "no-rm", "verdict": "block",
         "when": {"arg": "command", "contains": "rm -rf"}}))
    assert main(["policy", "lint", str(path)]) == 0
    assert "no structural findings" in capsys.readouterr().out


def test_the_cli_prints_json(tmp_path, capsys):
    path = _write(tmp_path, _doc({
        "id": "both", "verdict": "block",
        "when": {"all": [{"action": "deploy"}, {"action": "approve"}]}}))
    main(["policy", "lint", str(path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["code"] == UNSATISFIABLE
    assert payload[0]["rule"] == "both"


def test_the_cli_exits_two_on_a_policy_that_does_not_load(tmp_path, capsys):
    path = tmp_path / "policy.json"
    path.write_text("{not json", encoding="utf-8")
    assert main(["policy", "lint", str(path)]) == 2
    assert "not valid JSON" in capsys.readouterr().err
