"""The scopes and sandbox inspector: ``resolve_scope()`` in
:mod:`interlock.console.inspector`, and the ``POST /api/scopes/resolve``,
``GET /api/scopes/example`` and ``GET /api/sandbox`` routes built on top of it.

Each test is named for the claim it proves:

- resolving the example for ``root/acme/agent42`` unions ``allowed_hosts`` up
  the tree and overrides ``cpu_seconds`` from the most specific binding (F9,
  F14, AC1),
- the sandbox profile and backend/enforced/not_enforced it reports equal a
  local ``compile_profile``/``select_backend().wrap`` computation for the
  same resolved params (F10, AC2),
- a principal with no bindings of its own inherits only what its bound
  ancestors grant, and gets a locked (``cpu_seconds`` null) profile where
  none was bound (F9, F10, F20, AC3),
- an event's verdict, when given, comes from the engine compiled for that
  scope with the event's principal forced to the request's principal (F11,
  AC4), and is ``null`` when no event was given,
- a delegated binding that grants more than its delegator resolves to is
  ``delegation_over_grant`` (F18), a binding to an undefined template is
  ``unknown_template`` (F17), a document/template/binding outside the
  documented shape is ``bad_document`` (F15), and an empty principal is
  ``bad_principal`` (F16) - checked ahead of document shape, so a malformed
  document never masks a bad principal,
- a delegation chain deeper than the registry's bound is
  ``delegation_depth_exceeded`` (F18),
- a rule template's detector/factory/kwargs are validated exactly as the
  playground validates a rule: an unknown detector module or factory name is
  refused at template-parse time, and kwargs that do not bind to the
  factory's signature, or a factory the resolved params make raise, are
  refused at resolve time (Architecture, Errors),
- a malformed event is ``bad_event``, exactly as the playground defines it
  (Errors),
- ``GET /api/sandbox`` and ``GET /api/scopes/example`` answer with exactly
  what the library/spec define (F13, F14, AC6),
- resolving never calls ``subprocess.Popen`` or ``os.fork`` - it computes a
  sandbox plan, it never starts one (Edge cases, A2).
"""
from __future__ import annotations

import contextlib
import copy
import http.client
import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Iterator, Optional

from interlock.brace import KNOWN_TOKENS, available_backends, compile_profile, select_backend
from interlock.console import inspector
from interlock.console.playground import PlaygroundError
from interlock.console.server import ConsoleServer
from interlock.policy.scopes import SCOPE_BACKEND


@contextlib.contextmanager
def _serve(static_root: Path) -> Iterator[ConsoleServer]:
    server = ConsoleServer(("127.0.0.1", 0), static_root)
    thread = threading.Thread(
        target=server.serve_forever, daemon=True, name="interlock-console-inspector-test"
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


def _example_document() -> dict:
    return copy.deepcopy(inspector.EXAMPLE_DOCUMENT)


def _resolve(server: ConsoleServer, principal: str, *, event: Optional[dict] = None, document: Optional[dict] = None, **kwargs):
    payload = {"document": document if document is not None else inspector.EXAMPLE_DOCUMENT, "principal": principal}
    if event is not None:
        payload["event"] = event
    return _request(
        server, "/api/scopes/resolve", method="POST", body=json.dumps(payload).encode("utf-8"), **kwargs
    )


# --- resolve: the example document --------------------------------------


def test_resolve_example_for_agent42_unions_hosts_and_overrides_cpu(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _resolve(server, "root/acme/agent42")

    assert response.status == 200
    payload = json.loads(body)
    assert payload["scope"] == ["root", "acme", "agent42"]
    assert payload["scope_backend"] == SCOPE_BACKEND
    assert payload["resolved"]["egress_allowlist"]["allowed_hosts"] == ["api.acme.com", "api.internal"]
    assert payload["resolved"]["sandbox_limits"]["cpu_seconds"] == 5


def test_sandbox_profile_and_backend_match_local_computation(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _resolve(server, "root/acme/agent42")

    assert response.status == 200
    sandbox = json.loads(body)["sandbox"]
    profile = sandbox["profile"]
    assert profile["allow_network"] is True
    assert profile["allowed_hosts"] == ["api.acme.com", "api.internal"]
    assert profile["cpu_seconds"] == 5

    backend = select_backend()
    local_profile = compile_profile(
        {
            "egress_allowlist": {"allowed_hosts": {"api.acme.com", "api.internal"}},
            "sandbox_limits": {"cpu_seconds": 5},
        }
    )
    enforced = sorted(backend.wrap(local_profile, ["/usr/bin/true"]).enforced)
    assert sandbox["backend"] == backend.name
    assert sandbox["enforced"] == enforced
    assert sandbox["not_enforced"] == sorted(set(KNOWN_TOKENS) - set(enforced))
    assert sandbox["available_backends"] == available_backends()


def test_resolve_example_for_unbound_globex_inherits_root_only(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _resolve(server, "root/globex/bot1")

    assert response.status == 200
    payload = json.loads(body)
    assert payload["resolved"]["egress_allowlist"]["allowed_hosts"] == ["api.internal"]
    assert payload["sandbox"]["profile"]["cpu_seconds"] is None


def test_decision_verdicts_match_the_egress_allowlist_under_each_scope(tmp_path):
    cases = [
        ("root/acme/agent42", "https://evil.example/collect", "BLOCK"),
        ("root/acme/agent42", "https://api.acme.com/notes", "ALLOW"),
        ("root/globex/bot1", "https://api.acme.com/notes", "BLOCK"),
    ]
    with _serve(tmp_path) as server:
        for principal, url, want in cases:
            event = {"action": "http_post", "args": {"url": url, "body": "hi"}}
            response, body = _resolve(server, principal, event=event)
            assert response.status == 200
            assert json.loads(body)["decision"]["verdict"] == want, (principal, url)


def test_no_event_means_a_null_decision(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _resolve(server, "root/acme/agent42")

    assert response.status == 200
    assert json.loads(body)["decision"] is None


# --- resolve: errors -----------------------------------------------------


def test_delegation_over_grant_is_refused(tmp_path):
    document = _example_document()
    document["bindings"]["root/acme/agent42"].append(
        {
            "template_id": "egress_allowlist",
            "params": {"allowed_hosts": ["exfil.example"]},
            "delegated_from": "root/globex",
        }
    )
    with _serve(tmp_path) as server:
        response, body = _resolve(server, "root/acme/agent42", document=document)

    assert response.status == 400
    assert json.loads(body)["error"]["code"] == "delegation_over_grant"


def test_unknown_template_binding_is_refused(tmp_path):
    document = _example_document()
    document["bindings"]["root/acme/agent42"] = [{"template_id": "nope", "params": {}}]
    with _serve(tmp_path) as server:
        response, body = _resolve(server, "root/acme/agent42", document=document)

    assert response.status == 400
    assert json.loads(body)["error"]["code"] == "unknown_template"


def test_bad_document_binding_shape_is_refused(tmp_path):
    document = _example_document()
    document["bindings"]["root/acme/agent42"] = [{"template_id": "sandbox_limits", "param": {"cpu_seconds": 5}}]
    with _serve(tmp_path) as server:
        response, body = _resolve(server, "root/acme/agent42", document=document)

    assert response.status == 400
    assert json.loads(body)["error"]["code"] == "bad_document"


def test_empty_principal_is_bad_principal_even_with_a_malformed_document(tmp_path):
    # The same malformed binding as test_bad_document_binding_shape_is_refused:
    # an empty principal must win regardless, never masked by the document's
    # own problems.
    document = _example_document()
    document["bindings"]["root/acme/agent42"] = [{"template_id": "sandbox_limits", "param": {"cpu_seconds": 5}}]
    with _serve(tmp_path) as server:
        response, body = _resolve(server, "", document=document)

    assert response.status == 400
    assert json.loads(body)["error"]["code"] == "bad_principal"


def test_delegation_depth_exceeded_is_refused():
    bindings = {"level0": [{"template_id": "egress_allowlist", "params": {"allowed_hosts": ["api.internal"]}}]}
    previous = "level0"
    for level in range(1, 20):
        current = "level{}".format(level)
        bindings[current] = [
            {
                "template_id": "egress_allowlist",
                "params": {"allowed_hosts": ["api.internal"]},
                "delegated_from": previous,
            }
        ]
        previous = current
    document = {
        "templates": {
            "egress_allowlist": {
                "detector": "data_egress",
                "factory": "network_egress_guard",
                "union_params": ["allowed_hosts"],
            }
        },
        "bindings": bindings,
    }

    try:
        inspector.resolve_scope(document, previous, None)
        assert False, "expected PlaygroundError"
    except PlaygroundError as exc:
        assert exc.code == "delegation_depth_exceeded"


def test_unknown_detector_template_is_refused():
    document = {
        "templates": {"t": {"detector": "os", "factory": "system"}},
        "bindings": {"root": [{"template_id": "t", "params": {}}]},
    }
    try:
        inspector.resolve_scope(document, "root", None)
        assert False, "expected PlaygroundError"
    except PlaygroundError as exc:
        assert exc.code == "unknown_detector"


def test_unknown_factory_template_is_refused():
    document = {
        "templates": {"t": {"detector": "shell_injection_guard", "factory": "re"}},
        "bindings": {"root": [{"template_id": "t", "params": {}}]},
    }
    try:
        inspector.resolve_scope(document, "root", None)
        assert False, "expected PlaygroundError"
    except PlaygroundError as exc:
        assert exc.code == "unknown_factory"


def test_bad_kwargs_on_a_rule_templates_resolved_params_is_refused():
    document = {
        "templates": {"guard": {"detector": "execution_guard", "factory": "execution_guard"}},
        "bindings": {"root": [{"template_id": "guard", "params": {"nope": 1}}]},
    }
    try:
        inspector.resolve_scope(document, "root", None)
        assert False, "expected PlaygroundError"
    except PlaygroundError as exc:
        assert exc.code == "bad_kwargs"
        assert "nope" in exc.message


def test_factory_failed_is_reported_when_the_resolved_params_break_the_factory():
    document = {
        "templates": {
            "egress_allowlist": {
                "detector": "data_egress",
                "factory": "network_egress_guard",
                "union_params": ["allowed_hosts"],
            }
        },
        # allowed_hosts binds fine (it is just a keyword argument), but 42 is
        # not iterable - the factory itself raises once it is called.
        "bindings": {"root": [{"template_id": "egress_allowlist", "params": {"allowed_hosts": 42}}]},
    }
    try:
        inspector.resolve_scope(document, "root", None)
        assert False, "expected PlaygroundError"
    except PlaygroundError as exc:
        assert exc.code == "factory_failed"
        assert exc.message == "TypeError"


def test_bad_event_shape_is_refused():
    try:
        inspector.resolve_scope(_example_document(), "root/acme/agent42", {"action": ""})
        assert False, "expected PlaygroundError"
    except PlaygroundError as exc:
        assert exc.code == "bad_event"


def test_resolve_route_rejects_non_json_content_type_with_415(tmp_path):
    with _serve(tmp_path) as server:
        response, _body = _resolve(server, "root/acme/agent42", content_type="text/plain")

    assert response.status == 415


# --- GET /api/scopes/example and GET /api/sandbox ------------------------


def test_example_route_returns_the_spec_example(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _request(server, "/api/scopes/example")

    assert response.status == 200
    payload = json.loads(body)
    assert payload["document"] == inspector.EXAMPLE_DOCUMENT
    assert payload["principal"] == "root/acme/agent42"
    assert payload["event"]["action"] == "http_post"
    assert payload["event"]["args"]["url"] == "https://evil.example/collect"


def test_sandbox_route_matches_the_library(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _request(server, "/api/sandbox")

    assert response.status == 200
    payload = json.loads(body)
    assert payload["available_backends"] == available_backends()
    assert payload["selected"] == select_backend().name
    assert payload["known_tokens"] == sorted(KNOWN_TOKENS)


# --- the never-spawn rule (A2) --------------------------------------------


def test_resolving_never_spawns_a_process(tmp_path, monkeypatch):
    def _fail(*_args, **_kwargs):
        raise AssertionError("inspector must never spawn a process while resolving")

    monkeypatch.setattr(subprocess, "Popen", _fail)
    monkeypatch.setattr(os, "fork", _fail)

    with _serve(tmp_path) as server:
        response, body = _resolve(server, "root/acme/agent42")

    assert response.status == 200
    assert json.loads(body)["resolved"]["sandbox_limits"]["cpu_seconds"] == 5
