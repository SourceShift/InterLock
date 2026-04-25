"""Tests for the mass-assignment privilege-field guard.

Covers the allow path (ordinary profile fields), the block path (a
privilege-bearing field name in the payload), odd/non-str input that must not
crash, a JSON body that carries the field name inside a string value, and
end-to-end integration through the PolicyEngine.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.mass_assignment_guard import (
    PATTERN,
    POLICY_ID,
    mass_assignment_guard,
)


def test_benign_payload_is_allowed():
    """An ordinary update with no privilege field yields no opinion."""
    event = SensorEvent(action="update_profile", args={"display_name": "Amir"})
    assert mass_assignment_guard()(event) is None


def test_privilege_field_in_payload_is_blocked():
    """A payload naming is_admin / role is blocked, naming the offending arg."""
    event = SensorEvent(
        action="update_profile",
        args={"is_admin": "true", "role": "superuser"},
    )
    decision = mass_assignment_guard()(event)

    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID == "mass_assignment"


def test_reason_names_the_offending_argument():
    """The block reason identifies which argument carried the privilege field."""
    event = SensorEvent(action="update_user", args={"role": "admin"})
    decision = mass_assignment_guard()(event)

    assert decision is not None
    assert decision.reason == "mass_assignment: role"


def test_each_privilege_spelling_blocks():
    """Every field name in the pattern is caught, not just is_admin / role."""
    for field in (
        "is_admin",
        "role",
        "is_superuser",
        "permissions",
        "account_type",
        "is_staff",
    ):
        event = SensorEvent(action="update_user", args={field: "x"})
        decision = mass_assignment_guard()(event)
        assert decision is not None, field
        assert decision.verdict is Verdict.BLOCK, field


def test_non_str_values_do_not_crash_and_do_not_match():
    """Ints, bools, None, and nested containers are skipped, not stringified."""
    event = SensorEvent(
        action="update_profile",
        args={
            "retries": 5,
            "is_active": True,
            "note": None,
            "flags": ["a", "b"],
            "meta": {"role": "admin"},
        },
    )
    assert mass_assignment_guard()(event) is None


def test_non_dict_args_yields_no_opinion():
    """A missing or non-dict args must not raise."""
    none_args = SensorEvent(action="noop", args=None)  # type: ignore[arg-type]
    list_args = SensorEvent(action="noop", args=[])  # type: ignore[arg-type]
    assert mass_assignment_guard()(none_args) is None
    assert mass_assignment_guard()(list_args) is None


def test_privilege_field_inside_string_value_blocks():
    """A JSON body carrying the field name is caught even without the key."""
    event = SensorEvent(
        action="proxy_patch",
        args={"payload": '{"role": "admin"}'},
    )
    decision = mass_assignment_guard()(event)

    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_unrelated_word_is_not_a_match():
    """Word boundaries keep 'controller' from tripping the 'role' alternative."""
    event = SensorEvent(action="update_profile", args={"team": "controller"})
    assert mass_assignment_guard()(event) is None


def test_pattern_and_policy_id_constants():
    """The module exposes the compiled pattern and policy id for reuse."""
    assert PATTERN.search("is_admin") is not None
    assert PATTERN.search("display_name") is None
    assert POLICY_ID == "mass_assignment"


def test_engine_blocks_malicious_and_allows_benign():
    """PolicyEngine integration: BLOCK on the attack, ALLOW on the clean call."""
    engine = PolicyEngine(rules=[mass_assignment_guard()])

    malicious = SensorEvent(
        action="update_profile",
        args={"is_admin": "true", "role": "superuser"},
    )
    benign = SensorEvent(action="update_profile", args={"display_name": "Amir"})

    assert engine.evaluate(malicious).verdict is Verdict.BLOCK
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
