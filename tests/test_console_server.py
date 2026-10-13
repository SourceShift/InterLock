"""The console server's security envelope: the one health endpoint, the JSON
error shape, and the checks every later endpoint inherits for free.

Each test is named for the claim it proves:

- the health endpoint answers with the three JSON headers every ``/api/``
  response carries (AC1),
- an unknown API path and an unsupported method on a known one get distinct
  error codes rather than the same generic failure (AC3),
- a request whose Host header does not name this server is refused before it
  reaches a route - the DNS-rebinding defence (AC4),
- a static path that resolves outside the static directory, by ``..`` or by
  its percent-encoded form, answers 404 and never returns the file (AC5),
- ``--host`` outside the loopback set is refused before a socket ever opens,
  both from the CLI (AC2) and from :class:`ConsoleServer` itself.

The server is hosted in-process, in a daemon thread, the same way
:func:`interlock.testing.harness.serve` hosts the sidecar daemon for its own
tests - a real socket, not a mock.
"""
from __future__ import annotations

import contextlib
import http.client
import json
import threading
from pathlib import Path
from typing import Iterator, Optional

import pytest

import interlock
from interlock.console.__main__ import main
from interlock.console.server import ConsoleServer


@contextlib.contextmanager
def _serve(static_root: Path) -> Iterator[ConsoleServer]:
    server = ConsoleServer(("127.0.0.1", 0), static_root)
    thread = threading.Thread(
        target=server.serve_forever, daemon=True, name="interlock-console-test"
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
    host: Optional[str] = None,
):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5.0)
    try:
        headers = {"Host": host} if host is not None else {}
        conn.request(method, path, headers=headers)
        response = conn.getresponse()
        body = response.read()
        return response, body
    finally:
        conn.close()


def test_health_answers_ok_with_version_and_json_headers(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _request(server, "/api/health")

    assert response.status == 200
    assert response.getheader("Content-Type") == "application/json; charset=utf-8"
    assert response.getheader("Cache-Control") == "no-store"
    assert response.getheader("X-Content-Type-Options") == "nosniff"
    payload = json.loads(body)
    assert payload["status"] == "ok"
    assert payload["version"] == interlock.__version__


def test_unknown_api_path_is_404_not_found(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _request(server, "/api/does-not-exist")

    assert response.status == 404
    assert json.loads(body)["error"]["code"] == "not_found"


def test_unsupported_method_on_known_path_is_405_method_not_allowed(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _request(server, "/api/health", method="DELETE")

    assert response.status == 405
    assert json.loads(body)["error"]["code"] == "method_not_allowed"


def test_wrong_host_header_is_403_forbidden_host(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _request(server, "/api/health", host="evil.example")

    assert response.status == 403
    assert json.loads(body)["error"]["code"] == "forbidden_host"


def test_localhost_host_header_is_allowed(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _request(
            server, "/api/health", host="localhost:{}".format(server.server_port)
        )

    assert response.status == 200
    assert json.loads(body)["status"] == "ok"


def test_dotdot_path_outside_static_root_is_404_and_never_leaks(tmp_path):
    static_root = tmp_path / "web" / "dist"
    static_root.mkdir(parents=True)
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-MARKER")

    with _serve(static_root) as server:
        response, body = _request(server, "/../secret.txt")

    assert response.status == 404
    assert b"TOP-SECRET-MARKER" not in body


def test_percent_encoded_dotdot_path_is_404_and_never_leaks(tmp_path):
    static_root = tmp_path / "web" / "dist"
    static_root.mkdir(parents=True)
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-MARKER")

    with _serve(static_root) as server:
        response, body = _request(server, "/..%2fsecret.txt")

    assert response.status == 404
    assert b"TOP-SECRET-MARKER" not in body


def test_static_file_inside_root_is_served(tmp_path):
    static_root = tmp_path / "web" / "dist"
    static_root.mkdir(parents=True)
    (static_root / "hello.txt").write_text("hi")

    with _serve(static_root) as server:
        response, body = _request(server, "/hello.txt")

    assert response.status == 200
    assert body == b"hi"


def test_missing_static_root_answers_404_without_crashing(tmp_path):
    missing = tmp_path / "does" / "not" / "exist"

    with _serve(missing) as server:
        response, _body = _request(server, "/")

    assert response.status == 404


def test_cli_rejects_non_loopback_host(capsys):
    rc = main(["--host", "0.0.0.0", "--port", "0"])

    assert rc == 2
    captured = capsys.readouterr()
    assert "loopback" in captured.err.lower()


def test_console_server_refuses_to_construct_on_non_loopback_host(tmp_path):
    with pytest.raises(ValueError):
        ConsoleServer(("0.0.0.0", 0), tmp_path)
