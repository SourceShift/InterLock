"""Sensitive-path write guard: block a write aimed at a credential/config path.

Covers the BLOCK contract (the offending arg is named in the reason), the
allow path (an ordinary output path gets no opinion), each sensitive fragment
the pattern declares, non-string and non-dict input that must be skipped rather
than crashed on, and end-to-end verdicts through the engine.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.sensitive_file_write_guard import (
    PATTERN,
    POLICY_ID,
    sensitive_file_write_guard,
)


def _event(**args):
    return SensorEvent(action="write_file", args=args)


# --- the block path ---------------------------------------------------------


def test_authorized_keys_write_is_blocked():
    decision = sensitive_file_write_guard()(_event(path="/root/.ssh/authorized_keys"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    decision = sensitive_file_write_guard()(_event(path="/root/.ssh/authorized_keys"))
    assert decision is not None
    assert decision.reason == "sensitive_write: path"


def test_reason_names_whichever_argument_matched():
    decision = sensitive_file_write_guard()(_event(dest="output/ok.txt", target="/etc/hosts"))
    assert decision is not None
    assert decision.reason == "sensitive_write: target"


def test_first_matching_argument_wins():
    decision = sensitive_file_write_guard()(_event(a="/etc/x", b="/boot/y"))
    assert decision is not None
    assert decision.reason == "sensitive_write: a"


# --- the allow path ---------------------------------------------------------


def test_ordinary_write_path_gets_no_opinion():
    assert sensitive_file_write_guard()(_event(path="output/summary.txt")) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = sensitive_file_write_guard()
    assert guard(_event(path="reports/q1.csv", mode="w", encoding="utf-8")) is None


def test_empty_args_get_no_opinion():
    assert sensitive_file_write_guard()(SensorEvent(action="write_file", args={})) is None


# --- fragments the pattern declares -----------------------------------------


def test_each_declared_fragment_is_blocked():
    payloads = (
        "/etc/passwd",                 # system config
        "/root/backup.sql",            # root home
        "/home/u/.ssh/config",         # ssh config
        "/home/u/.aws/credentials",    # aws credentials
        "project/.env",                # trailing .env
        "/home/u/.ssh/id_rsa",         # private key filename
        "keys/authorized_keys",        # authorized keys filename
        "/boot/grub.cfg",              # boot config
    )
    guard = sensitive_file_write_guard()
    for payload in payloads:
        decision = guard(_event(path=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = sensitive_file_write_guard()
    assert guard(_event(path=None, size=42)) is None
    assert guard(_event(flags={"target": "/etc/passwd"})) is None
    assert guard(_event(paths=["/etc/passwd"])) is None


def test_non_dict_args_get_no_opinion():
    assert sensitive_file_write_guard()(SensorEvent(action="write_file", args=None)) is None
    assert sensitive_file_write_guard()(
        SensorEvent(action="write_file", args="/etc/passwd")
    ) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "path" is reached.
    decision = sensitive_file_write_guard()(_event(size=42, path="/etc/shadow"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "sensitive_write"
    assert PATTERN.search("/root/.ssh/authorized_keys") is not None
    assert PATTERN.search("output/summary.txt") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[sensitive_file_write_guard()])

    malicious = SensorEvent(action="write_file", args={"path": "/root/.ssh/authorized_keys"})
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="write_file", args={"path": "output/summary.txt"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
