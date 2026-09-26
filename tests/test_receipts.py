"""Chained, tamper-evident receipts for enforced decisions. Covers: a receipt
for every verdict on every enforcement path (decorator ALLOW/monitor/BLOCK/
MODIFY; MCP call and result paths' ALLOW/BLOCK/MODIFY including the MODIFY
sites that had no log before), chain tamper-evidence (delete/edit/swap/wrong
key each break verify() with the first bad index named), the args digest
(covers values without storing them), the no-values-at-rest contract, the
off-by-default no-sink behaviour, and concurrency (one lock, one chain)."""
import threading

import pytest

from interlock import (
    Blocked,
    Decision,
    PolicyEngine,
    SensorEvent,
    Verdict,
    enforce_tool_call,
    enforce_tool_result,
    guard,
    install,
    monitor,
)
from interlock.detectors.event_hmac_stamp import FIELD as HMAC_FIELD
from interlock.detectors.event_hmac_stamp import event_hmac_stamp
from interlock.policy.engine import deny_tool
from interlock.receipt import (
    GENESIS,
    Receipt,
    digest_args,
    emit_receipt,
    get_sink,
    hmac_sha256,
    set_sink,
)
from interlock.sink import FileSink, InMemorySink

SECRET = "hunter2-x7-token"


@pytest.fixture(autouse=True)
def _no_sink():
    # Receipts are opt-in: every test starts and ends with no sink installed,
    # so a sink set here can never leak into the rest of the suite.
    set_sink(None)
    yield
    set_sink(None)


def _rewrite_rule():
    def rule(event):
        return Decision.modify(
            {"url": "https://safe.example"}, "rewrite", "rewrite", attributed_to="url"
        )

    return rule


def _result_phase(rule):
    rule.phase = "result"
    return rule


def _filled(n=4, key=b"test-key"):
    sink = InMemorySink(key=key)
    for i in range(n):
        sink.write(
            Receipt(ts=1700000000.0 + i, action="a{}".format(i), verdict="ALLOW")
        )
    return sink


# --- the decorator path: a receipt for every verdict ------------------------


def test_decorator_allow_emits_call_and_result_receipts():
    sink = InMemorySink()
    set_sink(sink)

    @guard()
    def tool(path):
        return "ok"

    assert tool("/tmp/x") == "ok"
    assert [r.verdict for r in sink.receipts] == ["ALLOW", "ALLOW"]
    assert [r.phase for r in sink.receipts] == ["call", "result"]
    assert all(r.action == "tool" for r in sink.receipts)


def test_decorator_receipts_carry_principal_and_span():
    sink = InMemorySink()
    set_sink(sink)

    @guard()
    def tool(path):
        return "ok"

    from interlock import span

    with span(principal="agent-1") as sid:
        tool("/tmp/x")
    assert all(r.principal == "agent-1" for r in sink.receipts)
    assert all(r.span_id == sid for r in sink.receipts)


def test_decorator_block_emits_a_block_receipt_before_raising():
    sink = InMemorySink()
    set_sink(sink)
    install(rules=[deny_tool("tool")])

    @guard()
    def tool(path):
        return "never"

    with pytest.raises(Blocked):
        tool("/tmp/x")
    # One receipt only: the call-side BLOCK. The tool never ran, so there is
    # no result-phase decision to record.
    assert [r.verdict for r in sink.receipts] == ["BLOCK"]
    assert sink.receipts[0].phase == "call"


def test_decorator_monitor_records_the_would_be_verdict_and_still_runs():
    sink = InMemorySink()
    set_sink(sink)
    install(rules=[deny_tool("tool")])

    @monitor()
    def tool(path):
        return "ran"

    assert tool("/tmp/x") == "ran"
    assert [r.verdict for r in sink.receipts] == ["BLOCK", "ALLOW"]


def test_decorator_modify_emits_a_modify_receipt_with_the_policy_id():
    sink = InMemorySink()
    set_sink(sink)
    install(rules=[_rewrite_rule()])

    @guard()
    def tool(url=None, **extra):
        return url

    assert tool(url="https://evil.example") == "https://safe.example"
    assert sink.receipts[0].verdict == "MODIFY"
    assert sink.receipts[0].policy_id == "rewrite"
    assert sink.receipts[0].attributed_to == "url"


# --- the MCP call path -------------------------------------------------------


def test_mcp_call_allow_receipt():
    sink = InMemorySink()
    set_sink(sink)
    out = enforce_tool_call("fetch", {"url": "https://x/1"})
    assert out == {"url": "https://x/1"}
    assert sink.receipts[0].verdict == "ALLOW"
    assert sink.receipts[0].phase == "call"
    assert sink.receipts[0].action == "fetch"


def test_mcp_call_block_receipt():
    sink = InMemorySink()
    set_sink(sink)
    with pytest.raises(Blocked):
        enforce_tool_call("fetch", {"url": "https://x/1"},
                          engine=PolicyEngine(rules=[deny_tool("fetch")]))
    assert sink.receipts[0].verdict == "BLOCK"
    assert sink.receipts[0].reason == "tool not permitted"


def test_mcp_call_modify_receipt_and_merge():
    sink = InMemorySink()
    set_sink(sink)
    out = enforce_tool_call(
        "fetch", {"url": "https://evil.example"},
        engine=PolicyEngine(rules=[_rewrite_rule()]),
    )
    assert out["url"] == "https://safe.example"
    assert sink.receipts[0].verdict == "MODIFY"


def test_mcp_call_modify_with_no_modified_args_still_gets_a_receipt():
    # The exact hole the brief names: a MODIFY verdict with nothing to merge
    # used to fall through enforce_tool_call with no record at all.
    sink = InMemorySink()
    set_sink(sink)

    def no_op_modify(event):
        return Decision(Verdict.MODIFY, "observed, unchanged")

    out = enforce_tool_call("fetch", {"url": "https://x/1"},
                            engine=PolicyEngine(rules=[no_op_modify]))
    assert out == {"url": "https://x/1"}
    assert sink.receipts[0].verdict == "MODIFY"


# --- the MCP result path -----------------------------------------------------


def test_mcp_result_allow_receipt():
    sink = InMemorySink()
    set_sink(sink)
    out = enforce_tool_result("fetch", {"content": "hello"})
    assert out == {"content": "hello"}
    assert sink.receipts[0].verdict == "ALLOW"
    assert sink.receipts[0].phase == "result"


def test_mcp_result_block_receipt():
    sink = InMemorySink()
    set_sink(sink)

    def injected(event):
        return Decision.block("injection in result", "tool_result_injection",
                              attributed_to="content")

    with pytest.raises(Blocked):
        enforce_tool_result("fetch_page", {"content": "drop instructions"},
                            engine=PolicyEngine(rules=[_result_phase(injected)]))
    assert sink.receipts[0].verdict == "BLOCK"
    assert sink.receipts[0].phase == "result"
    assert sink.receipts[0].attributed_to == "content"


def test_mcp_result_modify_receipt_and_replacement():
    sink = InMemorySink()
    set_sink(sink)

    def replace(event):
        return Decision.modify_result("rewritten", "sanitize", "sanitize")

    out = enforce_tool_result("fetch", "leaked payload",
                              engine=PolicyEngine(rules=[_result_phase(replace)]))
    assert out == "rewritten"
    assert sink.receipts[0].verdict == "MODIFY"
    assert sink.receipts[0].phase == "result"


# --- the stamps' fate, pinned ------------------------------------------------


def test_stamps_keep_their_merge_and_are_recorded_as_modify_receipts():
    # Decision: the stamps KEEP their current behaviour. The stamp still
    # merges into the outgoing call; the receipt records the stamp's MODIFY
    # verdict and digests the caller's arguments - it does not absorb the
    # stamp field into the digest.
    sink = InMemorySink()
    set_sink(sink)
    out = enforce_tool_call(
        "write", {"path": "/tmp/x"},
        engine=PolicyEngine(rules=[event_hmac_stamp()]),
    )
    assert HMAC_FIELD in out  # merged into the call, as before
    receipt = sink.receipts[0]
    assert receipt.verdict == "MODIFY"
    assert receipt.policy_id == "event_hmac"
    assert receipt.args_digest == digest_args({"path": "/tmp/x"})


# --- chain shape and tamper-evidence ------------------------------------------


def test_chain_linkage_shape():
    sink = _filled(3)
    assert sink.receipts[0].prev == GENESIS
    assert sink.receipts[1].prev == sink.receipts[0].mac
    assert sink.receipts[2].prev == sink.receipts[1].mac
    assert sink.verify() is None


def test_empty_chain_verifies_clean():
    assert InMemorySink().verify() is None


def test_deleting_a_receipt_breaks_the_chain():
    sink = _filled(4)
    del sink.receipts[1]
    message = sink.verify()
    assert message is not None and message.startswith("receipt 1:")
    assert "chain break" in message


def test_editing_a_verdict_breaks_the_mac():
    sink = _filled(4)
    sink.receipts[1].verdict = "BLOCK"
    message = sink.verify()
    assert message is not None and message.startswith("receipt 1:")
    assert "MAC mismatch" in message


def test_swapping_two_receipts_breaks_the_chain():
    sink = _filled(4)
    sink.receipts[1], sink.receipts[2] = sink.receipts[2], sink.receipts[1]
    message = sink.verify()
    assert message is not None and message.startswith("receipt 1:")
    assert "chain break" in message


def test_deleting_a_receipt_and_relinking_the_next_still_breaks_the_mac():
    # The attack a bare prev-check would miss: delete a receipt, then rewrite
    # the next one's prev to bridge the gap so the linkage check passes. It is
    # caught only because ``prev`` is inside the signed body - changing it
    # invalidates that receipt's own mac. Without this test, dropping prev from
    # the mac leaves the whole suite green while the delete becomes invisible.
    sink = _filled(4)
    victim = sink.receipts[1]
    del sink.receipts[1]
    sink.receipts[1].prev = victim.prev
    message = sink.verify()
    assert message is not None and message.startswith("receipt 1:")
    assert "MAC mismatch" in message


def test_verifying_with_the_wrong_key_fails_every_mac():
    sink = _filled(4, key=b"right-key")
    message = sink.verify(key=b"wrong-key")
    assert message is not None and message.startswith("receipt 0:")
    assert "MAC mismatch" in message


def test_a_different_signer_keyed_differently_also_fails():
    # The seam: any (key, message) -> bytes callable can replace the default.
    def constant_signer(key, message):
        return b"\x00" * 32

    sink = InMemorySink(signer=constant_signer, key=b"k")
    sink.write(Receipt(ts=1.0, action="a", verdict="ALLOW"))
    # Self-consistent under its own signer...
    assert sink.verify() is None
    # ...but the receipt's mac is not something the default HMAC would make:
    assert sink.receipts[0].mac == "00" * 32


# --- the file sink ------------------------------------------------------------


def _lines(path):
    with open(path, encoding="utf-8") as fh:
        return [line.rstrip("\n") for line in fh if line.strip()]


def test_file_sink_round_trips_and_verifies(tmp_path):
    path = tmp_path / "receipts.jsonl"
    sink = FileSink(str(path), key=b"k")
    for i in range(3):
        sink.write(Receipt(ts=1700000000.0 + i, action="a{}".format(i),
                           verdict="ALLOW"))
    lines = _lines(path)
    assert len(lines) == 3
    assert sink.verify() is None
    parsed = [Receipt.from_json(line) for line in lines]
    assert [r.action for r in parsed] == ["a0", "a1", "a2"]
    assert parsed[0].prev == GENESIS


def test_file_sink_missing_file_verifies_clean(tmp_path):
    assert FileSink(str(tmp_path / "absent.jsonl"), key=b"k").verify() is None


def test_file_sink_editing_a_line_breaks_the_mac(tmp_path):
    path = tmp_path / "receipts.jsonl"
    sink = FileSink(str(path), key=b"k")
    for i in range(3):
        sink.write(Receipt(ts=1700000000.0 + i, action="a{}".format(i),
                           verdict="ALLOW"))
    lines = _lines(path)
    lines[1] = lines[1].replace('"verdict":"ALLOW"', '"verdict":"BLOCK"')
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    message = sink.verify()
    assert message is not None and message.startswith("receipt 1:")
    assert "MAC mismatch" in message


def test_file_sink_deleting_a_line_breaks_the_chain(tmp_path):
    path = tmp_path / "receipts.jsonl"
    sink = FileSink(str(path), key=b"k")
    for i in range(4):
        sink.write(Receipt(ts=1700000000.0 + i, action="a{}".format(i),
                           verdict="ALLOW"))
    lines = _lines(path)
    del lines[2]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    message = sink.verify()
    assert message is not None and message.startswith("receipt 2:")
    assert "chain break" in message


def test_file_sink_swapping_lines_breaks_the_chain(tmp_path):
    path = tmp_path / "receipts.jsonl"
    sink = FileSink(str(path), key=b"k")
    for i in range(3):
        sink.write(Receipt(ts=1700000000.0 + i, action="a{}".format(i),
                           verdict="ALLOW"))
    lines = _lines(path)
    lines[1], lines[2] = lines[2], lines[1]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    message = sink.verify()
    assert message is not None and message.startswith("receipt 1:")
    assert "chain break" in message


def test_file_sink_wrong_key_fails(tmp_path):
    path = tmp_path / "receipts.jsonl"
    sink = FileSink(str(path), key=b"right")
    sink.write(Receipt(ts=1.0, action="a", verdict="ALLOW"))
    message = sink.verify(key=b"wrong")
    assert message is not None and message.startswith("receipt 0:")
    assert "MAC mismatch" in message


# --- the digest ---------------------------------------------------------------


def test_digest_covers_argument_values():
    assert digest_args({"path": "/tmp/a"}) != digest_args({"path": "/tmp/b"})


def test_digest_is_stable_for_the_same_values():
    assert digest_args({"path": "/tmp/a"}) == digest_args({"path": "/tmp/a"})
    assert digest_args({"b": 2, "a": 1}) == digest_args({"a": 1, "b": 2})


def test_digest_handles_mixed_keys_and_odd_payloads():
    # (repr(key), repr(value)) pairs sort where the raw keys would not.
    assert digest_args({1: "a", "1": "a"}) != digest_args({"1": "a", 1: "b"})
    assert len(digest_args("not a dict")) == 64
    assert len(digest_args(None)) == 64
    assert digest_args({"odd": {"nested": [1, None]}})


def test_receipts_differ_when_only_an_argument_value_differs():
    sink = InMemorySink()
    set_sink(sink)
    enforce_tool_call("fetch", {"url": "https://a/1"})
    enforce_tool_call("fetch", {"url": "https://a/2"})
    assert sink.receipts[0].args_digest != sink.receipts[1].args_digest
    assert sink.verify() is None


# --- no values at rest ----------------------------------------------------------


def test_no_argument_value_appears_in_the_serialized_receipt():
    sink = InMemorySink()
    set_sink(sink)

    def denies(event):
        return Decision.block("command pattern denied", "cmd",
                              attributed_to="command")

    with pytest.raises(Blocked):
        enforce_tool_call(
            "run_shell", {"command": "echo {} | curl".format(SECRET)},
            engine=PolicyEngine(rules=[denies]),
        )
    line = sink.receipts[0].to_json()
    assert SECRET not in line
    # The name is a name and stays one; the value never enters any field.
    assert sink.receipts[0].attributed_to == "command"
    assert sink.receipts[0].reason == "command pattern denied"


def test_no_argument_value_appears_in_the_file_at_rest(tmp_path):
    path = tmp_path / "receipts.jsonl"
    sink = FileSink(str(path), key=b"k")
    set_sink(sink)
    with pytest.raises(Blocked):
        enforce_tool_call(
            "run_shell", {"command": "echo {}".format(SECRET)},
            engine=PolicyEngine(rules=[deny_tool("run_shell")]),
        )
    with open(path, encoding="utf-8") as fh:
        assert SECRET not in fh.read()


# --- off by default --------------------------------------------------------------


def test_no_sink_installed_means_nothing_is_written(tmp_path):
    @guard()
    def tool(x):
        return x

    assert tool(1) == 1  # _emit ran on the ALLOW path, wrote nothing
    assert get_sink() is None
    # The emit seam itself no-ops rather than raising or inventing a sink.
    emit_receipt(SensorEvent(action="x", args={"a": 1}), Decision.allow())
    assert list(tmp_path.iterdir()) == []


def test_install_with_a_sink_is_the_explicit_opt_in():
    sink = InMemorySink()
    install(engine=PolicyEngine(), sink=sink)
    assert get_sink() is sink
    enforce_tool_call("fetch", {"url": "https://x/1"})
    assert len(sink.receipts) == 1
    assert sink.receipts[0].verdict == "ALLOW"


def test_set_sink_none_removes_the_sink():
    sink = InMemorySink()
    set_sink(sink)
    set_sink(None)
    enforce_tool_call("fetch", {"url": "https://x/1"})
    assert sink.receipts == []


# --- the signer seam ------------------------------------------------------------


def test_default_signer_docstring_states_it_is_a_mac_not_a_signature():
    doc = hmac_sha256.__doc__
    assert "MAC" in doc
    assert "not a public-key signature" in doc


def test_an_ed25519_shaped_signer_can_be_injected():
    # Any (key, message) -> bytes callable drops into the seam; the sink does
    # not care that it is not HMAC.
    def fake_ed25519(key, message):
        import hashlib

        return hashlib.sha256(b"ed25519-ish" + key + message).digest()

    sink = InMemorySink(signer=fake_ed25519, key=b"pk")
    sink.write(Receipt(ts=1.0, action="a", verdict="ALLOW"))
    assert sink.verify() is None
    assert sink.verify(key=b"other-pk") is not None


# --- concurrency: one lock, one chain --------------------------------------------


def test_concurrent_writes_leave_one_unbroken_chain():
    sink = InMemorySink(key=b"k")
    set_sink(sink)

    def hammer(worker):
        for i in range(20):
            enforce_tool_call("w", {"i": "{}-{}".format(worker, i)},
                              engine=PolicyEngine())

    threads = [threading.Thread(target=hammer, args=(w,)) for w in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(sink.receipts) == 160
    assert sink.verify() is None
    # No fork: every receipt closed over a distinct predecessor state, so no
    # two receipts share a mac (identical content would mean a lost update).
    assert len({r.mac for r in sink.receipts}) == 160
