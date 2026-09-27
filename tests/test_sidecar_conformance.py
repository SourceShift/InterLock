"""Replay the language-neutral corpus through a real daemon.

The corpus (``tests/conformance/events.json``) is the interface between the
Python engine and the Node.js client that lands in stage 2. This suite is the
Python half of that contract: it proves the daemon *answers exactly what the
file says*, so another-language client can be checked against the same file and
"same policy, same decision" stops being an assertion and becomes a test.

Three checks, each a different failure the corpus exists to catch:

- the stored file is what the generator produces (a hand-edit cannot diverge
  silently),
- the daemon honours every verdict, including the field-survival cases a naive
  parity test would miss (``attributed_to`` as a *name*, result-phase routing,
  a bytes replacement),
- the negatives are refused - a permissive parser would turn a client typo
  into an allow.
"""
from __future__ import annotations

import os

import pytest

from interlock import Blocked
from interlock.event import SensorEvent
from interlock.receipt import get_sink, set_sink
from interlock.sidecar import server as server_mod
from interlock.sidecar.client import RemoteEngine
from interlock.testing.conformance import (
    build,
    load_corpus,
    materialise_modified_result,
)
from interlock.testing.fixtures import CONFORMANCE_ENGINE
from interlock.testing.harness import send_raw, serve
from interlock.sink import InMemorySink
from interlock.wire import decode_value, encode_value

CORPUS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "conformance", "events.json"
)

CORPUS = load_corpus(CORPUS_PATH)
CASES = CORPUS["cases"]
NEGATIVES = CORPUS["negatives"]


def _event(payload):
    return SensorEvent(
        action=payload["action"],
        args=dict(payload.get("args", {})),
        principal=payload.get("principal"),
        parent_principal=payload.get("parent_principal"),
        phase=payload.get("phase", "call"),
    )


@pytest.fixture
def remote(sock_path):
    """A ``RemoteEngine`` pointed at a daemon serving the fixture engine."""
    path = sock_path()
    engine = RemoteEngine(path)
    with serve(CONFORMANCE_ENGINE, path):
        yield engine
    engine.close()


def _assert_matches(decision, expect, *, as_wire=False):
    """Compare a decision to a stored expectation.

    ``as_wire=True`` runs the decision's payloads through the value codec
    first. The corpus describes *the wire's* value space - a set is stored as a
    sorted list, bytes as hex - so an in-process decision (whose set is a real
    set) matches the file only once it has been through the same encoder.
    """
    assert decision.verdict.name == expect["verdict"], (
        "verdict {} did not match {}".format(decision.verdict.name, expect["verdict"])
    )
    assert decision.reason == expect["reason"]
    assert decision.policy_id == expect["policy_id"]
    assert decision.attributed_to == expect["attributed_to"]

    args = decision.modified_args
    result = decision.modified_result
    if as_wire:
        args = None if args is None else decode_value(encode_value(args))
        result = None if result is None else decode_value(encode_value(result))

    assert args == expect["modified_args"]
    wanted_result = materialise_modified_result(expect.get("modified_result"))
    assert result == wanted_result


def test_the_corpus_file_is_in_sync_with_the_generator():
    # A hand-edited events.json fails here rather than letting the Python side
    # and the stored file drift apart.
    assert CORPUS["corpus_version"] == build()["corpus_version"]
    assert load_corpus(CORPUS_PATH) == build()


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_the_corpus_verdicts_are_honoured(remote, case):
    name = case["name"]
    expect = case["expect"]
    event = _event(case["event"])

    if "error" in expect:
        # The rewrite has no JSON form, so the daemon cannot say what it
        # decided and says so; the client treats that as a block.
        with pytest.raises(Blocked) as excinfo:
            remote.evaluate(event)
        assert expect["error"] in excinfo.value.decision.reason, name
        return

    _assert_matches(remote.evaluate(event), expect)


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_the_in_process_engine_agrees_with_the_wire(case):
    """The corpus means one thing, and both paths must read it the same.

    The single exception is the case whose whole point is that the wire cannot
    carry the in-process answer: the engine returns a MODIFY whose replacement
    has no JSON form, and the wire is required to fail closed where the
    in-process path would return the value.
    """
    name = case["name"]
    expect = case["expect"]
    decision = CONFORMANCE_ENGINE.evaluate(_event(case["event"]))

    if "error" in expect:
        assert decision.verdict.name == "MODIFY", name
        return

    _assert_matches(decision, expect, as_wire=True)


@pytest.mark.parametrize(
    "negative",
    [n for n in NEGATIVES if n["kind"] == "frame"],
    ids=[n["name"] for n in NEGATIVES if n["kind"] == "frame"],
)
def test_frame_negatives_are_refused(sock_path, negative):
    path = sock_path()
    with serve(CONFORMANCE_ENGINE, path):
        reply = send_raw(path, negative["line"])
    assert reply["error"]["code"] == negative["error"]


def test_the_oversized_negative_is_refused(sock_path, monkeypatch):
    # The corpus marks this one by behaviour rather than by a stored line,
    # because a stored 8 MiB line would be silly. The limit is patched down and
    # the frame is never parsed - the size check runs first.
    negative = next(n for n in NEGATIVES if n["kind"] == "oversized")
    monkeypatch.setattr(server_mod, "MAX_LINE", 4096)
    path = sock_path()
    with serve(CONFORMANCE_ENGINE, path):
        reply = send_raw(path, "x" * 5000)
    assert reply["error"]["code"] == negative["error"]


def test_the_harness_restores_the_previous_sink(sock_path):
    # The sink is process-global and the root conftest resets only the *engine*,
    # so a harness that failed to restore would leak one test's sink into the
    # next. Drive it with a sentinel to prove the restore, not just an absence.
    previous = object()
    set_sink(previous)
    try:
        with serve(CONFORMANCE_ENGINE, sock_path(), sink=InMemorySink()):
            assert get_sink() is not previous
        assert get_sink() is previous
    finally:
        set_sink(None)
