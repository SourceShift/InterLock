"""The skill digest rule: allow a pinned match, refuse a changed skill.

Covers the four branches the rule documents - a pinned match, a pinned
mismatch, an unknown skill and an unreadable one - through both an explicit pin
mapping and a pin file, plus the odd input the rule must skip instead of
crashing on. Every non-ALLOW decision must name ``skill`` and never leak a path
or a byte of a file into its reason.
"""
import types

import pytest

from interlock import SensorEvent, Verdict
import interlock.detectors.skill_digest_guard as mod
from interlock.detectors.skill_digest_guard import POLICY_ID, skill_digest_guard
from interlock.skills import save_pins, skill_digest


@pytest.fixture
def skill_root(tmp_path):
    root = tmp_path / "skills"
    directory = root / "reviewed"
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text("reviewed instructions\n", encoding="utf-8")
    return root


def _event(**args):
    return SensorEvent(action="Skill", args=args)


def _pin_for(root):
    return {"reviewed": skill_digest(str(root / "reviewed"))}


# --- the match path ---------------------------------------------------------


def test_a_pinned_unchanged_skill_is_allowed(skill_root):
    rule = skill_digest_guard(pins=_pin_for(skill_root), roots=[str(skill_root)])
    assert rule(_event(skill="reviewed")) is None


def test_the_name_falls_back_to_args_name(skill_root):
    pins = _pin_for(skill_root)
    (skill_root / "reviewed" / "SKILL.md").write_text("tampered\n", encoding="utf-8")
    rule = skill_digest_guard(pins=pins, roots=[str(skill_root)])
    assert rule(SensorEvent(action="Skill", args={"name": "reviewed"})).verdict is Verdict.BLOCK


def test_a_pin_file_is_read_and_matched(skill_root, tmp_path):
    pins = tmp_path / "skills.json"
    save_pins(str(pins), _pin_for(skill_root))
    rule = skill_digest_guard(pins_path=str(pins), roots=[str(skill_root)])
    assert rule(_event(skill="reviewed")) is None


# --- the mismatch path ------------------------------------------------------


def test_a_changed_skill_is_blocked_and_attributes_the_skill(skill_root):
    pins = _pin_for(skill_root)
    (skill_root / "reviewed" / "SKILL.md").write_text("tampered\n", encoding="utf-8")
    rule = skill_digest_guard(pins=pins, roots=[str(skill_root)])
    decision = rule(_event(skill="reviewed"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert decision.attributed_to == "skill"
    assert "reviewed" in decision.reason
    assert "tampered" not in decision.reason
    assert str(skill_root) not in decision.reason


def test_a_mismatch_can_escalate_instead(skill_root):
    pins = _pin_for(skill_root)
    (skill_root / "reviewed" / "SKILL.md").write_text("tampered\n", encoding="utf-8")
    rule = skill_digest_guard(
        pins=pins, roots=[str(skill_root)], on_mismatch="escalate")
    assert rule(_event(skill="reviewed")).verdict is Verdict.ESCALATE


# --- the unknown path -------------------------------------------------------


def test_an_unpinned_skill_is_allowed_by_default(skill_root):
    rule = skill_digest_guard(pins={}, roots=[str(skill_root)])
    assert rule(_event(skill="reviewed")) is None


def test_an_unpinned_skill_can_block_or_escalate(skill_root):
    for policy, verdict in (("block", Verdict.BLOCK),
                            ("escalate", Verdict.ESCALATE)):
        rule = skill_digest_guard(
            pins={}, roots=[str(skill_root)], on_unknown=policy)
        decision = rule(_event(skill="reviewed"))
        assert decision.verdict is verdict
        assert decision.attributed_to == "skill"


def test_a_pinned_skill_with_no_directory_is_unknown(skill_root):
    rule = skill_digest_guard(pins={"reviewed": "a" * 64}, roots=[str(skill_root)])
    assert rule(_event(skill="absent")) is None
    blocking = skill_digest_guard(
        pins={"absent": "a" * 64}, roots=[str(skill_root)], on_unknown="block")
    assert blocking(_event(skill="absent")).verdict is Verdict.BLOCK


def test_an_unreadable_pin_file_is_unknown(skill_root, tmp_path):
    pins = tmp_path / "skills.json"
    pins.write_text("{not json", encoding="utf-8")
    rule = skill_digest_guard(pins_path=str(pins), roots=[str(skill_root)])
    assert rule(_event(skill="reviewed")) is None
    blocking = skill_digest_guard(
        pins_path=str(pins), roots=[str(skill_root)], on_unknown="block")
    assert blocking(_event(skill="reviewed")).verdict is Verdict.BLOCK


def test_a_pin_file_reread_on_each_call_sees_a_repin(skill_root, tmp_path):
    pins = tmp_path / "skills.json"
    save_pins(str(pins), {"reviewed": "0" * 64})
    rule = skill_digest_guard(pins_path=str(pins), roots=[str(skill_root)])
    assert rule(_event(skill="reviewed")).verdict is Verdict.BLOCK
    save_pins(str(pins), _pin_for(skill_root))
    assert rule(_event(skill="reviewed")) is None


def test_the_default_pin_file_is_read_when_neither_is_given(
        skill_root, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    pins = tmp_path / ".interlock" / "skills.json"
    save_pins(str(pins), _pin_for(skill_root))

    rule = skill_digest_guard(roots=[str(skill_root)])
    assert rule(_event(skill="reviewed")) is None

    (skill_root / "reviewed" / "SKILL.md").write_text(
        "tampered instructions\n", encoding="utf-8")
    decision = rule(_event(skill="reviewed"))
    assert decision.verdict is Verdict.BLOCK
    assert decision.attributed_to == "skill"


# --- the error path ---------------------------------------------------------


def test_an_unreadable_directory_escalates(skill_root, monkeypatch):
    def boom(_path):
        raise ValueError("cannot read")

    monkeypatch.setattr(mod, "skill_digest", boom)
    rule = skill_digest_guard(pins=_pin_for(skill_root), roots=[str(skill_root)])
    decision = rule(_event(skill="reviewed"))
    assert decision.verdict is Verdict.ESCALATE
    assert decision.attributed_to == "skill"


def test_an_error_can_block(skill_root, monkeypatch):
    def boom(_path):
        raise OSError("cannot read")

    monkeypatch.setattr(mod, "skill_digest", boom)
    rule = skill_digest_guard(
        pins=_pin_for(skill_root), roots=[str(skill_root)], on_error="block")
    assert rule(_event(skill="reviewed")).verdict is Verdict.BLOCK


# --- odd input --------------------------------------------------------------


def test_a_non_skill_action_returns_none(skill_root):
    rule = skill_digest_guard(pins=_pin_for(skill_root), roots=[str(skill_root)])
    assert rule(SensorEvent(action="Bash", args={"skill": "reviewed"})) is None


def test_a_canonical_skill_spelling_matches(skill_root):
    pins = _pin_for(skill_root)
    (skill_root / "reviewed" / "SKILL.md").write_text("tampered\n", encoding="utf-8")
    rule = skill_digest_guard(pins=pins, roots=[str(skill_root)])
    assert rule(SensorEvent(action="skill", args={"skill": "reviewed"})).verdict is Verdict.BLOCK


def test_non_dict_args_return_none(skill_root):
    rule = skill_digest_guard(pins=_pin_for(skill_root), roots=[str(skill_root)])
    assert rule(SensorEvent(action="Skill", args=None)) is None
    assert rule(SensorEvent(action="Skill", args="reviewed")) is None


def test_a_missing_or_non_string_name_returns_none(skill_root):
    rule = skill_digest_guard(pins=_pin_for(skill_root), roots=[str(skill_root)])
    assert rule(_event()) is None
    assert rule(_event(skill=3)) is None
    assert rule(SensorEvent(action="Skill")) is None


def test_the_rule_never_raises_on_odd_events(skill_root):
    rule = skill_digest_guard(pins=_pin_for(skill_root), roots=[str(skill_root)])
    odd = [
        SensorEvent(action="Skill", args={"skill": "../escape"}),
        SensorEvent(action="Skill", args={"skill": "/etc"}),
        types.SimpleNamespace(action="Skill"),
        types.SimpleNamespace(action="Skill", args=[]),
    ]
    for event in odd:
        rule(event)  # the whole point: this must not raise


def test_an_invalid_policy_is_refused_at_construction():
    with pytest.raises(ValueError):
        skill_digest_guard(on_mismatch="deny")
    with pytest.raises(ValueError):
        skill_digest_guard(on_error="ignore")
