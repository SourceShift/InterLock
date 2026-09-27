"""The wire protocol: the value codec, the frames, and the refusals.

Two properties get their own tests because they are security properties, not
style. A value the codec cannot carry must *raise* rather than be coerced - a
sanitizer that quietly declines to sanitize is worse than one that refuses. And
an unknown key must be refused rather than ignored: a client that misspells
``args`` as ``arg`` would otherwise present the engine an argument-less event,
which finds no opinion and allows.

No socket is opened here. This is the half of the protocol that is a pure
function of its input, which is why it can be tested without a daemon.
"""
from __future__ import annotations

import pytest

from interlock.enforce import Decision, Verdict
from interlock.event import SensorEvent
from interlock.wire import (
    MAX_LINE,
    PROTOCOL_VERSION,
    Unrepresentable,
    WireError,
    canonical,
    decode_line,
    decode_value,
    encode_frame,
    encode_value,
    error_frame,
    parse_request,
    parse_response,
    request_frame,
    response_frame,
)


class Opaque:
    """A value with no JSON form; a rule that returns one must be refused."""


def _request(**event):
    event.setdefault("args", {})
    return {"v": PROTOCOL_VERSION, "id": "op-1", "event": event}


def _response(**fields):
    frame = {
        "v": PROTOCOL_VERSION,
        "id": "op-1",
        "verdict": 0,
        "reason": "",
        "policy_id": None,
        "attributed_to": None,
        "modified_args": None,
        "modified_result": None,
    }
    frame.update(fields)
    return frame


def test_max_line_is_the_documented_bound():
    assert MAX_LINE == 8 * 1024 * 1024


def test_canonical_is_sorted_and_tight():
    assert canonical({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_canonical_refuses_nan():
    # The stdlib would emit ``NaN``, which is not JSON and which a strict
    # parser (JS JSON.parse) rejects. Refusing at the boundary explains itself.
    with pytest.raises(Unrepresentable):
        canonical(float("nan"))


# --- the value codec ---------------------------------------------------------


@pytest.mark.parametrize(
    "value", [None, True, False, 0, 1.5, "s", [1, "a"], {"k": [1, 2]}]
)
def test_plain_json_values_survive_the_round_trip(value):
    assert decode_value(encode_value(value)) == value


def test_bytes_are_escaped_and_restored():
    payload = b"\x00\x01\xff"
    encoded = encode_value(payload)
    assert encoded == {"__interlock__": "bytes", "b64": "AAH/"}
    assert decode_value(encoded) == payload


def test_a_set_becomes_a_sorted_list():
    # JSON has no set and no canonical member order; sorting keeps it stable.
    assert encode_value({3, 1, 2}) == [1, 2, 3]


def test_a_frozenset_becomes_a_sorted_list():
    assert encode_value(frozenset({2, 1})) == [1, 2]


def test_a_tuple_becomes_a_list():
    assert encode_value((1, 2)) == [1, 2]


def test_a_non_string_key_is_refused_not_coerced():
    # json.dumps would silently turn the int key into "1", handing the tool a
    # key it never received.
    with pytest.raises(Unrepresentable):
        encode_value({1: "a"})


def test_an_unrepresentable_object_is_refused():
    with pytest.raises(Unrepresentable):
        encode_value(Opaque())


def test_a_nan_inside_an_argument_is_refused():
    with pytest.raises(Unrepresentable):
        encode_value({"x": float("inf")})


def test_a_dict_that_merely_contains_the_tag_is_not_decoded_as_bytes():
    # Only the *exact* envelope shape is a bytes escape; an argument dict that
    # happens to carry the tag key passes through untouched.
    value = {"__interlock__": "passthrough", "b64": "AAH/"}
    assert decode_value(value) == value


def test_a_malformed_bytes_envelope_is_refused():
    with pytest.raises(WireError) as excinfo:
        decode_value({"__interlock__": "bytes", "b64": "not base64!!"})
    assert excinfo.value.code == "bad_request"


def test_bytes_nested_in_structures_round_trip():
    value = {"files": [b"\x01", {"blob": b"\x02"}]}
    assert decode_value(encode_value(value)) == value


# --- decode_line -------------------------------------------------------------


def test_decode_line_accepts_bytes_and_str():
    raw = encode_frame({"v": PROTOCOL_VERSION, "id": "x"})
    assert decode_line(raw)["id"] == "x"
    assert decode_line(raw.decode("utf-8"))["id"] == "x"


def test_decode_line_refuses_a_wrong_version():
    with pytest.raises(WireError) as excinfo:
        decode_line('{"v":2,"id":"x"}')
    assert excinfo.value.code == "bad_version"


def test_decode_line_refuses_malformed_json():
    with pytest.raises(WireError) as excinfo:
        decode_line('{"v":1,"id":')
    assert excinfo.value.code == "bad_request"


def test_decode_line_refuses_a_non_object():
    with pytest.raises(WireError) as excinfo:
        decode_line("[1, 2]")
    assert excinfo.value.code == "bad_request"


def test_decode_line_refuses_invalid_utf8():
    with pytest.raises(WireError) as excinfo:
        decode_line(b"\xff\xfe")
    assert excinfo.value.code == "bad_request"


def test_encode_frame_ends_in_a_newline():
    assert encode_frame({"v": 1}).endswith(b"\n")


# --- parse_request -----------------------------------------------------------


def test_parse_request_reads_an_event():
    op_id, event = parse_request(
        _request(action="read_file", args={"path": "/tmp/x"}, phase="call")
    )
    assert op_id == "op-1"
    assert event.action == "read_file"
    assert event.args == {"path": "/tmp/x"}
    assert event.phase == "call"


def test_parse_request_defaults_phase_to_call():
    _, event = parse_request(_request(action="ping"))
    assert event.phase == "call"


def test_parse_request_carries_identity_fields():
    _, event = parse_request(
        _request(action="ping", principal="a", parent_principal="b", span_id="s")
    )
    assert event.principal == "a"
    assert event.parent_principal == "b"
    assert event.span_id == "s"


def test_parse_request_decodes_bytes_arguments():
    _, event = parse_request(
        _request(action="write_file", args={"data": encode_value(b"\x00\xff")})
    )
    assert event.args == {"data": b"\x00\xff"}


def test_parse_request_carries_the_timestamp():
    _, event = parse_request(_request(action="ping", ts=123.5))
    assert event.ts == 123.5


def test_parse_request_requires_args_present():
    frame = {"v": PROTOCOL_VERSION, "id": "i", "event": {"action": "ping"}}
    with pytest.raises(WireError) as excinfo:
        parse_request(frame)
    assert excinfo.value.code == "bad_request"


def test_parse_request_refuses_a_misspelled_args_key():
    frame = {"v": PROTOCOL_VERSION, "id": "i", "event": {"action": "ping", "arg": {}}}
    with pytest.raises(WireError) as excinfo:
        parse_request(frame)
    assert excinfo.value.code == "bad_request"


def test_parse_request_refuses_non_object_args():
    frame = {"v": PROTOCOL_VERSION, "id": "i", "event": {"action": "ping", "args": []}}
    with pytest.raises(WireError) as excinfo:
        parse_request(frame)
    assert excinfo.value.code == "bad_request"


def test_parse_request_refuses_an_unknown_event_key():
    frame = {
        "v": PROTOCOL_VERSION,
        "id": "i",
        "event": {"action": "ping", "args": {}, "extra": 1},
    }
    with pytest.raises(WireError) as excinfo:
        parse_request(frame)
    assert excinfo.value.code == "bad_request"


def test_parse_request_refuses_a_misspelled_phase():
    # "Result" is not "result"; accepting it would run a result rule call-side.
    with pytest.raises(WireError) as excinfo:
        parse_request(_request(action="ping", phase="Result"))
    assert excinfo.value.code == "bad_request"


def test_parse_request_refuses_an_empty_id():
    frame = {"v": PROTOCOL_VERSION, "id": "", "event": {"action": "ping", "args": {}}}
    with pytest.raises(WireError) as excinfo:
        parse_request(frame)
    assert excinfo.value.code == "bad_request"


def test_parse_request_refuses_a_non_finite_timestamp():
    with pytest.raises(WireError) as excinfo:
        parse_request(_request(action="ping", ts=float("inf")))
    assert excinfo.value.code == "bad_request"


def test_parse_request_refuses_an_unknown_request_key():
    frame = {"v": PROTOCOL_VERSION, "id": "i", "event": {"action": "ping", "args": {}}, "x": 1}
    with pytest.raises(WireError) as excinfo:
        parse_request(frame)
    assert excinfo.value.code == "bad_request"


# --- responses ---------------------------------------------------------------


def test_response_frame_round_trips_a_block():
    parsed = parse_response(
        response_frame("op-1", Decision.block("no", "p", attributed_to="path")),
        "op-1",
    )
    assert parsed.verdict == Verdict.BLOCK
    assert parsed.reason == "no"
    assert parsed.policy_id == "p"
    assert parsed.attributed_to == "path"


def test_response_frame_round_trips_bytes_result():
    parsed = parse_response(
        response_frame("op-1", Decision.modify_result(b"\x00\x01\xff", "binary", "p")),
        "op-1",
    )
    assert parsed.modified_result == b"\x00\x01\xff"


def test_a_none_result_survives_as_no_replacement():
    # None is a legitimate wire value: it is how the in-process path reads "a
    # MODIFY with no replacement", so the wire must not conflate it with an
    # absent field.
    parsed = parse_response(
        response_frame("op-1", Decision.modify_result(None, "none", "p")), "op-1"
    )
    assert parsed.modified_result is None


def test_response_frame_round_trips_modified_args():
    parsed = parse_response(
        response_frame("op-1", Decision.modify({"path": "/tmp/q"}, "q", "p")),
        "op-1",
    )
    assert parsed.modified_args == {"path": "/tmp/q"}


def test_an_unrepresentable_result_raises_so_the_caller_fails_closed():
    with pytest.raises(Unrepresentable):
        response_frame("op-1", Decision.modify_result(Opaque(), "opaque", "p"))


def test_a_non_dict_modified_args_is_an_internal_error():
    decision = Decision(Verdict.MODIFY, "bad", "p", modified_args="not a dict")
    with pytest.raises(WireError) as excinfo:
        response_frame("op-1", decision)
    assert excinfo.value.code == "internal"


def test_parse_response_raises_on_an_error_frame():
    frame = error_frame("op-1", "unrepresentable", "no replacement available")
    with pytest.raises(WireError) as excinfo:
        parse_response(frame, "op-1")
    assert excinfo.value.code == "unrepresentable"


def test_parse_response_refuses_a_mismatched_id():
    with pytest.raises(WireError) as excinfo:
        parse_response(response_frame("op-1", Decision.allow()), "op-2")
    assert excinfo.value.code == "bad_request"


def test_parse_response_refuses_an_unknown_verdict():
    with pytest.raises(WireError) as excinfo:
        parse_response(_response(verdict=7), "op-1")
    assert excinfo.value.code == "bad_request"


def test_parse_response_refuses_a_boolean_verdict():
    # bool is an int subclass; True must not be read as verdict 1.
    with pytest.raises(WireError) as excinfo:
        parse_response(_response(verdict=True), "op-1")
    assert excinfo.value.code == "bad_request"


def test_parse_response_refuses_a_non_string_reason():
    with pytest.raises(WireError) as excinfo:
        parse_response(_response(reason=3), "op-1")
    assert excinfo.value.code == "bad_request"


def test_parse_response_refuses_a_non_object_modified_args():
    with pytest.raises(WireError) as excinfo:
        parse_response(_response(modified_args=[1]), "op-1")
    assert excinfo.value.code == "bad_request"


def test_error_frame_has_no_verdict_key():
    frame = error_frame("op-1", "too_large", "too big")
    assert "verdict" not in frame
    assert frame["error"] == {"code": "too_large", "message": "too big"}


# --- the whole exchange, minus the socket ------------------------------------


def test_a_request_survives_encode_decode_parse():
    event = SensorEvent(
        action="ping", args={"n": [1, 2]}, principal="a", phase="call"
    )
    op_id, parsed = parse_request(decode_line(encode_frame(request_frame("op-1", event))))
    assert op_id == "op-1"
    assert parsed.action == "ping"
    assert parsed.args == {"n": [1, 2]}
    assert parsed.principal == "a"


def test_request_frame_omits_absent_identity_fields():
    frame = request_frame("op-1", SensorEvent(action="ping"))
    assert "principal" not in frame["event"]
    assert "span_id" not in frame["event"]
    assert "parent_principal" not in frame["event"]


def test_a_result_phase_request_keeps_its_phase():
    event = SensorEvent(action="fetch", args={"result": "x"}, phase="result")
    _, parsed = parse_request(request_frame("op-1", event))
    assert parsed.phase == "result"
