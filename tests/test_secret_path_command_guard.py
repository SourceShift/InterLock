"""Secret-path command guard: a shell read of a credential store is refused.

Covers the spellings a command can use to name a configured path - a tilde, a
``$HOME`` variable, a case variant and the directory itself - the clean
commands that get no opinion, the ``escalate`` verdict, and odd input the rule
must skip rather than crash on.

HOME is a temporary directory, so ``~`` and ``$HOME`` resolve there and no real
credential store is touched.
"""
from typing import Any

import pytest

from interlock import SensorEvent, Verdict
from interlock.detectors.secret_path_command_guard import (
    POLICY_ID,
    secret_path_command_guard,
)


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return str(tmp_path)


def _guard(home: str, **kwargs):
    return secret_path_command_guard(
        prefixes=[home + "/.ssh/", home + "/.aws/"],
        exact=[home + "/.netrc"],
        **kwargs
    )


def _event(**args):
    return SensorEvent(action="Bash", args=args)


# --- the block path ---------------------------------------------------------


def test_a_private_key_read_is_blocked(home):
    decision = _guard(home)(_event(command="cat ~/.ssh/id_rsa"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID
    assert decision.attributed_to == "command"


def test_a_recursive_grep_into_aws_is_blocked(home):
    decision = _guard(home)(_event(command="grep -r TOKEN ~/.aws"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_home_variable_is_expanded(home):
    decision = _guard(home)(_event(command="cat $HOME/.netrc"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_a_case_variant_of_a_secret_directory_is_blocked(home):
    # The default macOS filesystem is case-insensitive: ~/.SSH is ~/.ssh.
    decision = _guard(home)(_event(command="cat ~/.SSH/ID_RSA"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_the_secret_directory_itself_is_blocked(home):
    decision = _guard(home)(_event(command="ls ~/.ssh"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_dot_segments_are_collapsed(home):
    decision = _guard(home)(_event(command="cat ~/.ssh/../.netrc"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_a_redirect_target_is_inspected(home):
    decision = _guard(home)(_event(command="echo x > ~/.netrc"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_the_cmd_key_is_read_too(home):
    decision = _guard(home)(_event(cmd="cat ~/.ssh/id_rsa"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- the allow path ---------------------------------------------------------


def test_an_ordinary_file_read_gets_no_opinion(home):
    assert _guard(home)(_event(command="cat README.md")) is None


def test_an_unrelated_command_gets_no_opinion(home):
    assert _guard(home)(_event(command="git status")) is None


def test_a_similarly_named_sibling_is_not_the_secret_path(home):
    # ~/.ssh-notes is not ~/.ssh; the prefix comparison is on path segments.
    assert _guard(home)(_event(command="cat ~/.ssh-notes.md")) is None


def test_an_undeclared_key_is_not_scanned(home):
    assert _guard(home)(_event(file_path="~/.ssh/id_rsa")) is None


# --- the escalate variant ---------------------------------------------------


def test_escalate_asks_instead_of_blocking(home):
    decision = _guard(home, verdict="escalate")(_event(command="cat ~/.ssh/id_rsa"))
    assert decision is not None
    assert decision.verdict is Verdict.ESCALATE


def test_an_unknown_verdict_is_rejected():
    with pytest.raises(ValueError):
        secret_path_command_guard(prefixes=[], verdict="allow")


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_string_values_are_skipped(home):
    guard = _guard(home)
    assert guard(_event(command=None, timeout=3)) is None
    assert guard(_event(command=["cat", "~/.ssh/id_rsa"])) is None
    assert guard(_event(options={"command": "cat ~/.ssh/id_rsa"})) is None


def test_non_dict_args_get_no_opinion(home):
    none_args: Any = None
    str_args: Any = "cat ~/.ssh/id_rsa"
    assert _guard(home)(SensorEvent(action="Bash", args=none_args)) is None
    assert _guard(home)(SensorEvent(action="Bash", args=str_args)) is None


def test_a_command_the_parser_cannot_read_does_not_raise(home):
    # An unclosed quote leaves the parser partial; whatever it recovered is
    # still judged, and nothing raises.
    assert _guard(home)(_event(command='cat "~/.ssh/id_rsa')) is not None
    assert _guard(home)(_event(command='echo "unterminated')) is None
