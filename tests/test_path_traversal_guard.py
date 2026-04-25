"""Path-traversal guard: block a file-tool argument that escapes its directory.

Covers the BLOCK contract (the offending arg is named in the reason), the
allow path (an ordinary relative path gets no opinion), each declared
encoding/root the pattern recognises, non-string and non-dict input that must
be skipped rather than crashed on, and end-to-end verdicts through the engine.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.path_traversal_guard import (
    PATTERN,
    POLICY_ID,
    path_traversal_guard,
)


def _event(**args):
    return SensorEvent(action="read_file", args=args)


# --- the block path ---------------------------------------------------------


def test_classic_posix_traversal_is_blocked():
    decision = path_traversal_guard()(_event(path="../../../../etc/passwd"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    decision = path_traversal_guard()(_event(path="../../../../etc/passwd"))
    assert decision is not None
    assert decision.reason == "path_traversal: path"


def test_reason_names_whichever_argument_matched():
    decision = path_traversal_guard()(_event(filename="safe.txt", dest="../../secret"))
    assert decision is not None
    assert decision.reason == "path_traversal: dest"


def test_first_matching_argument_wins():
    decision = path_traversal_guard()(_event(a="../../../x", b="../../../../y"))
    assert decision is not None
    assert decision.reason == "path_traversal: a"


def test_sensitive_root_without_traversal_is_blocked():
    # An absolute path needs no "../" to leave the sandbox.
    decision = path_traversal_guard()(_event(path="/etc/shadow"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- the allow path ---------------------------------------------------------


def test_ordinary_relative_path_gets_no_opinion():
    assert path_traversal_guard()(_event(path="reports/2026/q1.csv")) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = path_traversal_guard()
    assert guard(_event(path="data/input.txt", mode="r", encoding="utf-8")) is None


def test_lone_dots_are_not_a_traversal():
    # "./" stays put; only ".." escapes.
    assert path_traversal_guard()(_event(path="./reports/q1.csv")) is None


def test_empty_args_get_no_opinion():
    assert path_traversal_guard()(SensorEvent(action="read_file", args={})) is None


# --- encodings and roots the pattern declares -------------------------------


def test_each_declared_encoding_and_root_is_blocked():
    payloads = (
        "../secret",          # POSIX
        "..\\secret",         # Windows
        "%2e%2e/secret",      # percent-encoded POSIX
        "%2e%2e\\secret",     # percent-encoded Windows
        "/etc/passwd",        # sensitive root
        "~/.ssh/id_rsa",      # home-directory config
        "\\windows\\system32",  # sensitive root, Windows
    )
    guard = path_traversal_guard()
    for payload in payloads:
        decision = guard(_event(path=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


def test_traversal_embedded_mid_path_is_caught():
    decision = path_traversal_guard()(_event(path="reports/../../etc/passwd"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = path_traversal_guard()
    assert guard(_event(path=None, size=42)) is None
    assert guard(_event(flags={"nested": "../../etc/passwd"})) is None
    assert guard(_event(paths=["../../etc/passwd"])) is None


def test_non_dict_args_get_no_opinion():
    assert path_traversal_guard()(SensorEvent(action="read_file", args=None)) is None
    assert path_traversal_guard()(
        SensorEvent(action="read_file", args="../../etc/passwd")
    ) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "path" is reached.
    decision = path_traversal_guard()(_event(size=42, path="../../etc/passwd"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "path_traversal"
    assert PATTERN.search("../../etc/passwd") is not None
    assert PATTERN.search("reports/2026/q1.csv") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[path_traversal_guard()])

    malicious = SensorEvent(action="read_file", args={"path": "../../../../etc/passwd"})
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="read_file", args={"path": "reports/2026/q1.csv"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
