"""The policy playground: ``build_rules``/``evaluate`` in
:mod:`interlock.console.playground`, and the ``POST /api/evaluate`` /
``GET /api/presets`` routes built on top of them.

Each test is named for the claim it proves:

- an empty or missing ``rules`` list is ``no_rules``, more than 32 rules is
  ``too_many_rules`` (F13, F14),
- more than 200 events, or none, is ``too_many_events`` (F14),
- a detector module the catalog does not list is ``unknown_detector``, and a
  factory name the module does not export is ``unknown_factory`` (F15, F16),
- kwargs that do not bind to the factory's signature is ``bad_kwargs``, naming
  the offending key (F17),
- an event that is not an object, is missing its action, or carries an
  unknown key, is ``bad_event`` - an unknown key is refused rather than
  silently dropped (F19),
- a rule that raises while judging one event answers that event BLOCK with
  ``policy_id`` ``console.rule_error`` without aborting the rest of the
  request (Edge cases, with a test-only rule factory patched in),
- building rules calls every factory fresh, so a stateful rule's count does
  not survive from one ``evaluate()`` call to the next (Edge cases, F21),
- every preset's own rules and events evaluate to its own ``expect`` (A3),
- the HTTP route answers 200 with the same shape, 415 for a non-JSON body,
  and lists exactly the five presets (F5, F6, AC6).
"""
from __future__ import annotations

import contextlib
import http.client
import importlib
import json
import threading
from pathlib import Path
from typing import Iterator, Optional

from interlock.console import playground
from interlock.console.server import ConsoleServer


@contextlib.contextmanager
def _serve(static_root: Path) -> Iterator[ConsoleServer]:
    server = ConsoleServer(("127.0.0.1", 0), static_root)
    thread = threading.Thread(
        target=server.serve_forever, daemon=True, name="interlock-console-playground-test"
    )
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _request(
    server: ConsoleServer,
    path: str,
    *,
    method: str = "GET",
    body: Optional[bytes] = None,
    content_type: Optional[str] = "application/json",
):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5.0)
    try:
        headers = {"Content-Type": content_type} if content_type is not None else {}
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        return response, response.read()
    finally:
        conn.close()


def _post(server: ConsoleServer, payload: dict, **kwargs):
    return _request(
        server, "/api/evaluate", method="POST", body=json.dumps(payload).encode("utf-8"), **kwargs
    )


# --- build_rules / evaluate: errors ------------------------------------------


def test_missing_or_empty_rules_is_no_rules():
    for bad in (None, [], "not-a-list", {}):
        try:
            playground.build_rules(bad)
            assert False, "expected PlaygroundError"
        except playground.PlaygroundError as exc:
            assert exc.code == "no_rules"


def test_more_than_32_rules_is_too_many_rules():
    rule = {"detector": "execution_guard", "factory": "execution_guard", "kwargs": {}}
    try:
        playground.build_rules([rule] * (playground.MAX_RULES + 1))
        assert False, "expected PlaygroundError"
    except playground.PlaygroundError as exc:
        assert exc.code == "too_many_rules"


def test_more_than_200_or_zero_events_is_too_many_events():
    rules = [{"detector": "execution_guard", "factory": "execution_guard", "kwargs": {}}]
    for bad_events in ([], [{"action": "x"}] * (playground.MAX_EVENTS + 1)):
        try:
            playground.evaluate(rules, bad_events)
            assert False, "expected PlaygroundError"
        except playground.PlaygroundError as exc:
            assert exc.code == "too_many_events"


def test_unknown_detector_module_is_unknown_detector():
    try:
        playground.build_rules([{"detector": "os", "factory": "system", "kwargs": {}}])
        assert False, "expected PlaygroundError"
    except playground.PlaygroundError as exc:
        assert exc.code == "unknown_detector"
        assert exc.index == 0


def test_unknown_factory_on_known_module_is_unknown_factory():
    try:
        playground.build_rules(
            [{"detector": "shell_injection_guard", "factory": "re", "kwargs": {}}]
        )
        assert False, "expected PlaygroundError"
    except playground.PlaygroundError as exc:
        assert exc.code == "unknown_factory"
        assert exc.index == 0


def test_bad_kwargs_names_the_offending_key():
    try:
        playground.build_rules(
            [
                {
                    "detector": "execution_guard",
                    "factory": "execution_guard",
                    "kwargs": {"nope": 1},
                }
            ]
        )
        assert False, "expected PlaygroundError"
    except playground.PlaygroundError as exc:
        assert exc.code == "bad_kwargs"
        assert "nope" in exc.message


def test_bad_event_shapes():
    rules = [{"detector": "execution_guard", "factory": "execution_guard", "kwargs": {}}]
    bad_events = [
        "not-an-object",
        {},  # missing action
        {"action": ""},  # empty action
        {"action": "x", "args": "not-an-object"},
        {"action": "x", "phase": "sideways"},
        {"action": "x", "principal": 7},
        {"action": "x", "arg": {}},  # misspelled "args" must not be ignored
    ]
    for bad_event in bad_events:
        try:
            playground.evaluate(rules, [bad_event])
            assert False, "expected PlaygroundError for {!r}".format(bad_event)
        except playground.PlaygroundError as exc:
            assert exc.code == "bad_event", bad_event


# --- edge cases ---------------------------------------------------------


def test_rule_that_raises_blocks_fail_closed_and_later_events_still_run(monkeypatch):
    # interlock/detectors/__init__.py re-exports execution_guard the function
    # under the same name as its submodule, shadowing the submodule as a
    # package attribute - importlib.import_module (what playground.py itself
    # uses to resolve a catalog-validated module name) still finds the real
    # submodule object via sys.modules, so patching through it is what
    # playground.py will actually see.
    execution_guard_module = importlib.import_module("interlock.detectors.execution_guard")

    calls = {"n": 0}

    def _raising_factory(**_kwargs) -> Rule:
        def rule(event):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("boom")
            return None

        return rule

    # catalog.build_catalog() is cached for the life of the process and is
    # only willing to list a factory whose __module__ matches the detector
    # module and whose return annotation names "Rule" - true of the real
    # execution_guard factory, not of a bare stand-in. Match both so this
    # test passes whether some earlier test has already warmed the cache
    # (then the real factory is what's cached) or this test is the one that
    # warms it (then the patched factory itself must look catalog-eligible).
    _raising_factory.__module__ = execution_guard_module.__name__
    monkeypatch.setattr(execution_guard_module, "execution_guard", _raising_factory)

    results = playground.evaluate(
        [{"detector": "execution_guard", "factory": "execution_guard", "kwargs": {}}],
        [
            {"action": "run_shell", "args": {"cmd": "ls"}},
            {"action": "run_shell", "args": {"cmd": "ls"}},
        ],
    )

    assert results[0]["verdict"] == "BLOCK"
    assert results[0]["policy_id"] == "console.rule_error"
    assert results[1]["verdict"] == "ALLOW"
    assert results[1]["index"] == 1


def test_fresh_engine_per_call_does_not_carry_state():
    rules = [
        {"detector": "call_rate_limiter", "factory": "call_rate_limiter", "kwargs": {"limit": 2}}
    ]
    events = [
        {"action": "search", "args": {"q": "interlock"}, "principal": "agent-1"},
        {"action": "search", "args": {"q": "interlock"}, "principal": "agent-1"},
        {"action": "search", "args": {"q": "interlock"}, "principal": "agent-1"},
    ]

    first = [r["verdict"] for r in playground.evaluate(rules, events)]
    second = [r["verdict"] for r in playground.evaluate(rules, events)]

    assert first == ["ALLOW", "ALLOW", "BLOCK"]
    assert second == ["ALLOW", "ALLOW", "BLOCK"]


def test_every_preset_expect_matches_its_own_evaluation():
    assert sorted(p["id"] for p in playground.PRESETS) == sorted(
        ["destructive-shell", "egress", "pii", "result-injection", "rate-limit"]
    )
    for preset in playground.PRESETS:
        results = playground.evaluate(preset["rules"], preset["events"])
        assert [r["verdict"] for r in results] == list(preset["expect"]), preset["id"]


# --- HTTP route -----------------------------------------------------------


def test_evaluate_route_answers_200_for_destructive_shell(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _post(
            server,
            {
                "rules": [
                    {"detector": "execution_guard", "factory": "execution_guard", "kwargs": {}}
                ],
                "events": [
                    {"action": "run_shell", "args": {"cmd": "rm -rf /"}},
                    {"action": "run_shell", "args": {"cmd": "ls -la"}},
                ],
            },
        )

    assert response.status == 200
    payload = json.loads(body)
    results = payload["results"]
    assert [r["verdict"] for r in results] == ["BLOCK", "ALLOW"]
    assert [r["verdict_code"] for r in results] == [1, 0]
    assert results[0]["policy_id"] == "execution_guard"


def test_evaluate_route_rejects_non_json_content_type_with_415(tmp_path):
    with _serve(tmp_path) as server:
        response, _body = _post(
            server,
            {"rules": [], "events": []},
            content_type="text/plain",
        )

    assert response.status == 415


def test_evaluate_route_answers_400_with_error_code_for_no_rules(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _post(server, {"rules": [], "events": [{"action": "x"}]})

    assert response.status == 400
    assert json.loads(body)["error"]["code"] == "no_rules"


def test_presets_route_lists_exactly_the_five_presets(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _request(server, "/api/presets")

    assert response.status == 200
    payload = json.loads(body)
    assert sorted(p["id"] for p in payload["presets"]) == sorted(
        ["destructive-shell", "egress", "pii", "result-injection", "rate-limit"]
    )
