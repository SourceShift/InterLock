"""The two-tier evaluator (C6): classification, deadlines and fail-closed.

The local primary decides everything the out-of-process tier is not asked
about. Delegated classes get a short deadline; when the second opinion cannot
be had, the artifact's failure policy decides, and a policy we cannot name is
``irreversible`` and therefore closed.

The clock is injected so "the secondary took longer than the deadline" is
tested without sleeping, and so the deadline applies to the secondary only -
time-boxing the local engine would turn a slow rule into a policy change.
"""
from __future__ import annotations

import logging
import threading
import time

import pytest

from interlock.enforce import Decision, Verdict
from interlock.event import SensorEvent
from interlock.policy import tiers
from interlock.policy.artifact import FAILURE_POLICY_DEFAULTS


class Primary:
    """A local engine stub that records every event it decided."""

    def __init__(self, decision=None, failure_policy=None, kill=None):
        self.decision = decision or Decision.allow()
        self.failure_policy = (
            dict(FAILURE_POLICY_DEFAULTS) if failure_policy is None
            else dict(failure_policy)
        )
        self.calls = []
        if kill is not None:
            self.kill = kill

    def evaluate(self, event):
        self.calls.append(event)
        return self.decision


class Secondary:
    """An out-of-process engine stub; ``advance`` moves the fake clock."""

    def __init__(self, decision=None, *, supports_timeout=False, clock=None,
                 advance=0.0, error=None):
        self.decision = decision or Decision.block("remote", policy_id="remote-rule")
        self.supports_timeout = supports_timeout
        self.clock = clock
        self.advance = advance
        self.error = error
        self.calls = []
        self.timeouts = []

    def evaluate(self, event, **kwargs):
        self.calls.append(event)
        self.timeouts.append(kwargs.get("timeout"))
        if self.clock is not None:
            self.clock.advance(self.advance)
        if self.error is not None:
            raise self.error
        return self.decision


class Clock:
    """A monotonic clock whose value only moves when a test moves it."""

    def __init__(self, start=0.0):
        self.value = start

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def _event(action="run_shell"):
    return SensorEvent(action=action)


def _policy(**overrides):
    policy = dict(FAILURE_POLICY_DEFAULTS)
    policy["irreversible"] = "closed"
    policy.update(overrides)
    return policy


@pytest.fixture(autouse=True)
def _fresh_warnings():
    tiers.reset_warning_state()
    yield
    tiers.reset_warning_state()


# --- classification -------------------------------------------------------


@pytest.mark.parametrize(
    "action, expected",
    [
        ("Bash", "shell"),
        ("run_shell", "shell"),
        ("child_process.exec", "shell"),
        ("WebFetch", "egress"),
        ("http.fetch", "egress"),
        ("read_file", "read_only"),
        ("READ_FILE", "read_only"),
        ("write_file", "local"),
        # The coding-agent vocabulary is classified too, so a delegated tier
        # never sees an edit merely because nobody listed the spelling.
        ("Edit", "local"),
        ("Write", "local"),
        ("MultiEdit", "local"),
        ("TodoWrite", "local"),
        ("WebSearch", "granted_llm"),
        ("Task", "granted_llm"),
        ("delete_file", "delete"),
        ("send_email", "email"),
        ("stripe_charge", "payment"),
        ("llm_call", "granted_llm"),
        # Silence is not permission: an action nobody classified is the one
        # class we must never fail open for.
        ("frobnicate_everything", "irreversible"),
        ("", "irreversible"),
    ],
)
def test_action_class(action, expected):
    assert tiers.action_class(action) == expected


def test_classes_cover_every_failure_policy_key():
    assert set(tiers.CLASSES) == set(tiers.FAILURE_POLICY_DEFAULTS) | {"irreversible"}
    assert tiers.DELEGATED == frozenset({"shell", "egress", "delete", "email", "payment"})


def test_custom_classes_replace_the_defaults():
    classes = {"read_only": ["peek"], "shell": ["run"], "irreversible": []}
    assert tiers.action_class("peek", classes) == "read_only"
    assert tiers.action_class("read_file", classes) == "irreversible"
    with pytest.raises(ValueError):
        tiers.action_class("peek", {"not_a_class": ["peek"]})


# --- routing --------------------------------------------------------------


def test_read_only_never_touches_the_secondary():
    primary = Primary()
    clock = Clock()
    secondary = Secondary(clock=clock, supports_timeout=True, advance=1.0)
    evaluator = tiers.TieredEvaluator(primary, secondary=secondary, clock=clock)

    result = evaluator.evaluate(_event("read_file"))

    assert result.tier == "primary"
    assert result.class_ == "read_only"
    assert result.coverage_gap is False
    assert secondary.calls == []
    assert primary.calls


def test_delegated_class_uses_the_secondary():
    primary = Primary()
    secondary = Secondary(Decision.block("remote says no", policy_id="remote"))
    evaluator = tiers.TieredEvaluator(
        primary, secondary=secondary, clock=Clock(), deadline=0.05,
    )

    result = evaluator.evaluate(_event("run_shell"))

    assert result.tier == "secondary"
    assert result.decision.policy_id == "remote"
    assert primary.calls == []
    assert result.coverage_gap is False


def test_deadline_is_passed_only_when_the_secondary_supports_it():
    clock = Clock()
    supporting = Secondary(clock=clock, supports_timeout=True, advance=0.001)
    evaluator = tiers.TieredEvaluator(
        Primary(), secondary=supporting, clock=clock, deadline=0.002)
    evaluator.evaluate(_event())
    assert supporting.timeouts == [0.002]

    clock = Clock()
    plain = Secondary(clock=clock, supports_timeout=False)
    evaluator = tiers.TieredEvaluator(
        Primary(), secondary=plain, clock=clock, deadline=0.002)
    evaluator.evaluate(_event())
    assert plain.timeouts == [None]


def test_a_missing_secondary_fails_closed_for_a_closed_class():
    # "No daemon configured" is a secondary failure, so the class policy
    # decides. Shell is closed by default; it must never become an allow just
    # because there is no one to ask.
    primary = Primary()
    evaluator = tiers.TieredEvaluator(primary, secondary=None)

    result = evaluator.evaluate(_event("run_shell"))

    assert result.tier == "fail_closed"
    assert result.decision.verdict is Verdict.BLOCK
    assert result.decision.policy_id == "fail_closed"
    assert result.coverage_gap is False
    assert evaluator.coverage_gaps == {}
    assert primary.calls == []


def test_a_missing_secondary_is_a_coverage_gap_for_an_open_class():
    primary = Primary()
    evaluator = tiers.TieredEvaluator(
        primary, secondary=None, failure_policy=_policy(shell="open"))

    result = evaluator.evaluate(_event("run_shell"))

    assert result.tier == "primary"
    assert result.coverage_gap is True
    assert evaluator.coverage_gaps == {"shell": 1}
    assert result.decision.verdict is Verdict.ALLOW
    # The allow is marked, not dressed up as a policy decision.
    assert result.decision.policy_id == "coverage_gap"


def test_a_non_delegated_class_with_no_secondary_is_not_a_gap():
    evaluator = tiers.TieredEvaluator(Primary(), secondary=None)
    result = evaluator.evaluate(_event("write_file"))
    assert result.tier == "primary"
    assert result.coverage_gap is False
    assert evaluator.coverage_gaps == {}


# --- failure policy -------------------------------------------------------


def test_a_slow_secondary_fails_closed_for_shell():
    clock = Clock()
    secondary = Secondary(clock=clock, supports_timeout=True, advance=0.05)
    evaluator = tiers.TieredEvaluator(
        Primary(), secondary=secondary, clock=clock, deadline=0.002)

    result = evaluator.evaluate(_event("run_shell"))

    assert result.tier == "fail_closed"
    assert result.decision.verdict is Verdict.BLOCK
    assert result.decision.policy_id == "fail_closed"
    assert result.coverage_gap is False


def test_a_secondary_that_ignores_the_deadline_cannot_stretch_the_call():
    # A duck-typed secondary may ignore ``timeout=``. The join bounds the
    # verdict path with the wall clock, not with the secondary's goodwill.
    started = threading.Event()

    class Slow:
        supports_timeout = False

        def evaluate(self, event):
            started.set()
            time.sleep(0.2)
            return Decision.allow()

    evaluator = tiers.TieredEvaluator(
        Primary(), secondary=Slow(), deadline=0.01)

    began = time.monotonic()
    result = evaluator.evaluate(_event("run_shell"))
    elapsed = time.monotonic() - began

    assert started.is_set()
    assert result.tier == "fail_closed"
    assert result.decision.policy_id == "fail_closed"
    assert elapsed < 0.15, "the deadline did not bound the call: {:.3f}s".format(
        elapsed)


def test_an_unreachable_secondary_fails_closed_for_egress():
    secondary = Secondary(error=TimeoutError("no daemon"))
    evaluator = tiers.TieredEvaluator(Primary(), secondary=secondary)

    result = evaluator.evaluate(_event("net_fetch"))

    assert result.tier == "fail_closed"
    assert result.decision.policy_id == "fail_closed"


def test_an_open_class_falls_back_to_the_primary_and_records_the_gap():
    secondary = Secondary(error=TimeoutError("no daemon"))
    evaluator = tiers.TieredEvaluator(
        Primary(), secondary=secondary,
        failure_policy=_policy(shell="open"),
    )

    result = evaluator.evaluate(_event("run_shell"))

    assert result.tier == "primary"
    assert result.coverage_gap is True
    assert result.decision.verdict is Verdict.ALLOW
    assert evaluator.coverage_gaps == {"shell": 1}


def test_a_closed_class_never_returns_a_synthetic_allow():
    secondary = Secondary(error=TimeoutError("no daemon"))
    evaluator = tiers.TieredEvaluator(
        Primary(Decision.allow()), secondary=secondary,
        failure_policy=_policy(delete="closed"),
    )
    result = evaluator.evaluate(_event("delete_file"))
    assert result.decision.verdict is Verdict.BLOCK
    assert result.decision.policy_id == "fail_closed"


def test_the_default_policy_comes_from_the_artifact_plus_irreversible():
    primary = Primary(failure_policy=_policy(read_only="closed", email="closed"))
    evaluator = tiers.TieredEvaluator(primary)
    assert evaluator.failure_policy == _policy(read_only="closed", email="closed")
    assert evaluator.failure_policy["irreversible"] == "closed"


def test_an_explicit_policy_must_cover_every_class_including_irreversible():
    with pytest.raises(ValueError, match="irreversible"):
        tiers.TieredEvaluator(Primary(), failure_policy=dict(FAILURE_POLICY_DEFAULTS))
    with pytest.raises(ValueError, match="unknown"):
        tiers.TieredEvaluator(
            Primary(), failure_policy=_policy(catastrophe="closed"))
    with pytest.raises(ValueError, match="must be one of"):
        tiers.TieredEvaluator(Primary(), failure_policy=_policy(shell="maybe"))


# --- kill switch ----------------------------------------------------------


def test_the_kill_switch_is_checked_before_the_secondary():
    primary = Primary(Decision.block("killed", policy_id="kill"), kill={})
    secondary = Secondary()
    evaluator = tiers.TieredEvaluator(primary, secondary=secondary)

    result = evaluator.evaluate(_event("run_shell"))

    assert result.tier == "kill_switch"
    assert result.decision.policy_id == "kill"
    assert secondary.calls == []


# --- coverage warnings ----------------------------------------------------


def test_a_coverage_gap_warns_once_per_class(caplog):
    secondary = Secondary(error=TimeoutError("no daemon"))
    evaluator = tiers.TieredEvaluator(
        Primary(), secondary=secondary,
        failure_policy=_policy(shell="open", delete="open"))
    with caplog.at_level(logging.WARNING, logger="interlock"):
        evaluator.evaluate(_event("run_shell"))
        evaluator.evaluate(_event("run_shell"))
        evaluator.evaluate(_event("delete_file"))

    warnings = [r for r in caplog.records if "coverage_gap" in r.getMessage()]
    assert len(warnings) == 2  # shell once, delete once
    assert evaluator.coverage_gaps == {"shell": 2, "delete": 1}


# --- adapters -------------------------------------------------------------


def test_tier_engine_returns_a_decision_and_keeps_the_metadata():
    primary = Primary()
    primary.sha256 = "a" * 64
    primary.epoch = "1234567890abcdef"
    engine = tiers.TierEngine(tiers.TieredEvaluator(primary, secondary=None))

    decision = engine.evaluate(_event("read_file"))

    assert isinstance(decision, Decision)
    assert engine.last.tier == "primary"
    assert engine.sha256 == primary.sha256
    assert engine.epoch == primary.epoch


def test_tiered_evaluator_delegates_artifact_identity():
    primary = Primary()
    primary.artifact_bytes = b"{}"
    primary.epoch_for = lambda event: None
    evaluator = tiers.TieredEvaluator(primary)
    assert evaluator.artifact_bytes == b"{}"
    assert evaluator.epoch_for(_event()) is None
