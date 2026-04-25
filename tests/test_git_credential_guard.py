"""Git credential guard: block an argument that reads a git credential store.

Covers the BLOCK contract (the offending arg is named in the reason), the allow
path (an ordinary source path gets no opinion), both credential shapes the
pattern declares (store paths and the ``git config --get`` read form),
non-string / non-dict input that must be skipped rather than crashed on, and
end-to-end verdicts through the engine.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.git_credential_guard import (
    PATTERN,
    POLICY_ID,
    git_credential_guard,
)


def _event(**args):
    return SensorEvent(action="read_file", args=args)


# --- the block path ---------------------------------------------------------


def test_dot_git_credentials_is_blocked():
    decision = git_credential_guard()(_event(path="/home/user/.git-credentials"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == "git_credential_read"


def test_block_reason_names_the_offending_argument():
    decision = git_credential_guard()(_event(path="/home/user/.git-credentials"))
    assert decision is not None
    assert decision.reason == "git_credential_read: path"


def test_reason_names_whichever_argument_matched():
    decision = git_credential_guard()(_event(filename="n.py", dest="~/.netrc"))
    assert decision is not None
    assert decision.reason == "git_credential_read: dest"


def test_git_config_get_form_is_blocked():
    decision = git_credential_guard()(
        _event(cmd="git config --get remote.origin.url")
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_first_matching_argument_wins():
    decision = git_credential_guard()(
        _event(a="/etc/hosts", b="/home/user/.git-credentials")
    )
    assert decision is not None
    assert decision.reason == "git_credential_read: b"


# --- the allow path ---------------------------------------------------------


def test_ordinary_source_path_gets_no_opinion():
    assert git_credential_guard()(_event(path="src/main.py")) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = git_credential_guard()
    assert guard(_event(path="app/settings.py", mode="r", encoding="utf-8")) is None


def test_embedded_dot_git_is_blocked_but_config_source_is_not():
    # ".git/config" matches; a source file merely named "config.py" does not.
    assert git_credential_guard()(_event(path="/repo/.git/config")) is not None
    assert git_credential_guard()(_event(path="src/config.py")) is None


def test_empty_args_get_no_opinion():
    assert git_credential_guard()(SensorEvent(action="read_file", args={})) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = git_credential_guard()
    assert guard(_event(path=None, size=42)) is None
    assert guard(_event(flags={"nested": ".git-credentials"})) is None
    assert guard(_event(paths=[".git-credentials"])) is None


def test_non_dict_args_get_no_opinion():
    assert git_credential_guard()(SensorEvent(action="read_file", args=None)) is None
    assert git_credential_guard()(
        SensorEvent(action="read_file", args=".git-credentials")
    ) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "path" is reached.
    decision = git_credential_guard()(_event(size=42, path="~/.git-credentials"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "git_credential_read"
    assert PATTERN.search("/home/user/.git-credentials") is not None
    assert PATTERN.search("src/main.py") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[git_credential_guard()])

    malicious = SensorEvent(
        action="read_file", args={"path": "/home/user/.git-credentials"}
    )
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="read_file", args={"path": "src/main.py"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
