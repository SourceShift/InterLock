"""remediation: a non-ALLOW decision may carry one line saying what would be
allowed instead. It rides on Decision, survives the declarative loader (native
and detector rules, and a ceiling escalation), reaches the agent through the
hook message, is clipped to one bounded line, and is rejected at load when it
is not a short non-empty string."""
import json

import pytest

from interlock import Decision, Verdict
from interlock.adapters import get_adapter, run_hook
from interlock.adapters.base import HookOutcome
from interlock.enforce import MAX_REMEDIATION
from interlock.policy.declarative import load_policy
from interlock.receipt import set_sink
from interlock.sink import InMemorySink

HINT = "write the file under the workspace instead"


def _block(**kwargs):
    return Decision.block("no", "policy", **kwargs)


# --- Decision ---------------------------------------------------------------


def test_default_is_none():
    assert Decision().remediation is None
    assert Decision.block("no", "p").remediation is None


def test_every_constructor_carries_the_hint():
    assert _block(remediation=HINT).remediation == HINT
    assert Decision.escalate("no", "p", remediation=HINT).remediation == HINT
    assert Decision.modify({}, "no", "p", remediation=HINT).remediation == HINT
    assert Decision.modify_result("x", "no", "p", remediation=HINT).remediation == HINT


# --- HookOutcome.message ----------------------------------------------------


def test_message_appends_the_hint_after_the_label():
    outcome = HookOutcome(Verdict.BLOCK, "destructive", "no-rm", remediation=HINT)
    assert outcome.message == "interlock: destructive [no-rm] - " + HINT


def test_allow_never_shows_the_hint():
    outcome = HookOutcome(Verdict.ALLOW, "fine", "p", remediation=HINT)
    assert outcome.message == "interlock: fine [p]"


def test_message_clips_the_hint_to_one_bounded_line():
    outcome = HookOutcome(Verdict.BLOCK, "no", "p", remediation="x" * 500)
    assert outcome.message.endswith("- " + "x" * MAX_REMEDIATION)
    assert len(outcome.message.split(" - ", 1)[1]) == MAX_REMEDIATION


# --- declarative loader -----------------------------------------------------


def _policy(rule):
    return load_policy({"version": 1, "rules": [rule]})


def _event(action="Bash", args=None):
    from interlock import SensorEvent
    return SensorEvent(action=action, args=args or {})


def test_native_rule_attaches_the_hint():
    engine = _policy({
        "id": "no-rm", "verdict": "block",
        "when": {"action": "Bash"},
        "reason": "destructive command",
        "remediation": HINT,
    })
    decision = engine.evaluate(_event())
    assert decision.verdict is Verdict.BLOCK
    assert decision.remediation == HINT


def test_native_rule_without_hint_stays_none():
    engine = _policy({
        "id": "no-rm", "verdict": "block", "when": {"action": "Bash"},
    })
    assert engine.evaluate(_event()).remediation is None


def test_detector_rule_attaches_the_hint():
    engine = _policy({
        "id": "cap-calls", "detector": "call_rate_limiter",
        "with": {"limit": 1},
        "on": ["Bash"],
        "remediation": "batch the calls into one script",
    })
    assert engine.evaluate(_event()).remediation is None  # first call allowed
    blocked = engine.evaluate(_event())
    assert blocked.verdict is Verdict.BLOCK
    assert blocked.remediation == "batch the calls into one script"


def test_a_detector_hint_is_not_overwritten():
    from interlock.policy.declarative import _remediated

    own = Decision.block("no", "p", remediation="from the detector")

    def rule(event):
        return own

    assert _remediated(rule, "from the loader")(_event()).remediation == "from the detector"


def test_allow_decision_is_not_given_a_hint():
    rule = _policy({
        "id": "watch", "verdict": "block",
        "when": {"action": "Nonexistent"},
        "remediation": HINT,
    })
    assert rule.evaluate(_event()).verdict is Verdict.ALLOW


def test_ceiling_escalation_keeps_the_hint():
    engine = _policy({
        "id": "no-rm", "verdict": "block", "ceiling": "escalate",
        "when": {"action": "Bash"}, "remediation": HINT,
    })
    decision = engine.evaluate(_event())
    assert decision.verdict is Verdict.ESCALATE
    assert decision.remediation == HINT


@pytest.mark.parametrize("bad", [42, "", "   ", None, ["x"]])
def test_bad_hint_is_rejected_at_load(bad):
    doc = {"version": 1, "rules": [{
        "id": "r", "verdict": "block", "when": {"action": "Bash"},
        **({"remediation": bad} if bad is not None else {"remediation": None}),
    }]}
    if bad is None:
        # ``null`` means "no hint" and is accepted.
        assert load_policy(doc).evaluate(_event()).remediation is None
        return
    engine = load_policy(doc)
    assert engine.quarantined
    assert "remediation" in engine.quarantined[0]


def test_overlong_hint_is_rejected_at_load():
    engine = load_policy({"version": 1, "rules": [{
        "id": "r", "verdict": "block", "when": {"action": "Bash"},
        "remediation": "x" * (MAX_REMEDIATION + 1),
    }]})
    assert engine.quarantined
    assert "at most 200" in engine.quarantined[0]


# --- hook end-to-end --------------------------------------------------------


@pytest.fixture
def sink():
    s = InMemorySink()
    set_sink(s)
    yield s
    set_sink(None)


def test_claude_deny_carries_the_hint(sink):
    engine = _policy({
        "id": "no-rm", "verdict": "block",
        "when": {"all": [{"action": "Bash"},
                         {"arg": "command", "contains": "rm -rf"}]},
        "reason": "recursive delete",
        "remediation": "delete the individual files",
    })
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": "rm -rf /tmp/x"},
               "session_id": "s1", "cwd": "/work/proj", "tool_use_id": "tu1"}
    stdout, _, _ = run_hook(get_adapter("claude-code"), payload, engine)
    reason = json.loads(stdout)["hookSpecificOutput"]["permissionDecisionReason"]
    assert "recursive delete" in reason
    assert reason.endswith("- delete the individual files")
