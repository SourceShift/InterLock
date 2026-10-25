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

A further batch, named for the 06-console-gap-closure D1 acceptance entries
they prove (AC2, AC3, AC4, AC6, AC7, AC8, AC21), covers the server envelope
that spec restates with its own gate: the JSON error shape for a
standard-library-raised error and for a handler exception, the shared POST
body reader's size/content-type/parse limits, the HTML security headers and
not-built page, and the access log line's shape.

The server is hosted in-process, in a daemon thread, the same way
:func:`interlock.testing.harness.serve` hosts the sidecar daemon for its own
tests - a real socket, not a mock.
"""
from __future__ import annotations

import contextlib
import http.client
import json
import re
import socket
import threading
import time
from pathlib import Path
from typing import Iterator, Optional

import pytest

import interlock
from interlock.console.__main__ import main
from interlock.console.server import ROUTES, ConsoleServer


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
    headers: Optional[dict] = None,
    body: Optional[bytes] = None,
):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5.0)
    try:
        all_headers = dict(headers or {})
        if host is not None:
            all_headers["Host"] = host
        conn.request(method, path, body=body, headers=all_headers)
        response = conn.getresponse()
        response_body = response.read()
        return response, response_body
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
    # Feature modules (catalog, audit) contribute these through the health
    # contributor list rather than replacing the route (F6, AC8).
    assert payload["detectors"] > 0
    assert payload["receipts"] is False
    assert payload["verify"] is False


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


@pytest.mark.parametrize(
    "path",
    [
        "/%00",  # decodes to an embedded null byte - rejected by resolve()
        "/" + "a" * 300,  # a single segment over NAME_MAX (255) on POSIX
    ],
)
def test_filesystem_rejected_static_path_is_404_with_one_access_line(
    tmp_path, capsys, path
):
    # Both paths make resolve()/is_file() raise (OSError or ValueError)
    # instead of just failing the is_relative_to check; this must still
    # answer 404 and log exactly one access line (F5), not let the
    # exception escape to socketserver's default traceback handler and
    # leave the client with a dropped connection.
    static_root = tmp_path / "web" / "dist"
    static_root.mkdir(parents=True)

    with _serve(static_root) as server:
        response, body = _request(server, path)

        captured_err = ""
        for _ in range(50):
            captured_err += capsys.readouterr().err
            if "ms" in captured_err:
                break
            time.sleep(0.05)

    assert response.status == 404
    assert body == b"not found"
    lines = [line for line in captured_err.splitlines() if line.strip()]
    assert len(lines) == 1
    assert re.match(r"^GET .* 404 [0-9]+(\.[0-9]+)? ?ms$", lines[0])


def test_static_file_inside_root_is_served(tmp_path):
    static_root = tmp_path / "web" / "dist"
    static_root.mkdir(parents=True)
    (static_root / "hello.txt").write_text("hi")

    with _serve(static_root) as server:
        response, body = _request(server, "/hello.txt")

    assert response.status == 200
    assert body == b"hi"


def test_missing_static_root_serves_not_built_page(tmp_path):
    missing = tmp_path / "does" / "not" / "exist"

    with _serve(missing) as server:
        response, body = _request(server, "/")

    assert response.status == 200
    assert response.getheader("Content-Type") == "text/html; charset=utf-8"
    assert response.getheader("X-Frame-Options") == "DENY"
    assert "default-src 'self'" in response.getheader("Content-Security-Policy")
    assert b"npm --prefix web run build" in body


def test_static_index_html_carries_security_headers(tmp_path):
    static_root = tmp_path / "web" / "dist"
    static_root.mkdir(parents=True)
    (static_root / "index.html").write_text("<!doctype html><title>x</title>")

    with _serve(static_root) as server:
        response, _body = _request(server, "/")

    assert response.status == 200
    assert response.getheader("X-Frame-Options") == "DENY"
    assert "default-src 'self'" in response.getheader("Content-Security-Policy")


def test_cli_rejects_non_loopback_host(capsys):
    rc = main(["--host", "0.0.0.0", "--port", "0"])

    assert rc == 2
    captured = capsys.readouterr()
    assert "loopback" in captured.err.lower()


def test_console_server_refuses_to_construct_on_non_loopback_host(tmp_path):
    with pytest.raises(ValueError):
        ConsoleServer(("0.0.0.0", 0), tmp_path)


def test_unsupported_http_method_is_501_with_json_error_shape(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _request(server, "/api/health", method="FOO")

    assert response.status == 501
    assert response.getheader("Content-Type").startswith("application/json")
    payload = json.loads(body)
    assert payload["error"]["code"]
    assert payload["error"]["message"]


def test_post_body_reader_shares_size_type_and_parse_limits(tmp_path):
    # /api/evaluate and /api/scopes/resolve both read their body through the
    # one shared reader in server.py (A2); exercising it through either route
    # proves the reader itself, not that particular route's logic.
    with _serve(tmp_path) as server:
        oversized, oversized_body = _request(
            server,
            "/api/evaluate",
            method="POST",
            headers={"Content-Type": "application/json", "Content-Length": "2000000"},
            body=b"{}",
        )
        wrong_type, wrong_type_body = _request(
            server,
            "/api/evaluate",
            method="POST",
            headers={"Content-Type": "text/plain"},
            body=b"{}",
        )
        bad_json, bad_json_body = _request(
            server,
            "/api/evaluate",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=b"{bad",
        )

    assert oversized.status == 413
    assert json.loads(oversized_body)["error"]["code"] == "payload_too_large"
    assert wrong_type.status == 415
    assert json.loads(wrong_type_body)["error"]["code"] == "unsupported_media_type"
    assert bad_json.status == 400
    assert json.loads(bad_json_body)["error"]["code"] == "bad_json"


def test_handler_exception_answers_500_internal_error_in_json_shape(tmp_path):
    def _raise(_handler):
        raise RuntimeError("boom")

    ROUTES["/api/__test_raises__"] = {"GET": _raise}
    try:
        with _serve(tmp_path) as server:
            response, body = _request(server, "/api/__test_raises__")
    finally:
        del ROUTES["/api/__test_raises__"]

    assert response.status == 500
    payload = json.loads(body)
    assert payload["error"]["code"] == "internal_error"
    assert payload["error"]["message"]


def test_access_log_line_has_method_path_status_duration_and_hides_query_and_headers(
    tmp_path, capsys
):
    with _serve(tmp_path) as server:
        _request(
            server,
            "/api/health?token=QUERYMARKER",
            headers={"X-Probe": "HEADERMARKER"},
        )

        captured_err = ""
        for _ in range(50):
            captured_err += capsys.readouterr().err
            if "ms" in captured_err:
                break
            time.sleep(0.05)

    assert re.search(r"^GET /api/health 200 [0-9]+(\.[0-9]+)? ?ms$", captured_err, re.MULTILINE)
    assert "QUERYMARKER" not in captured_err
    assert "HEADERMARKER" not in captured_err


def test_unsupported_http_method_still_logs_one_access_line(tmp_path, capsys):
    # The standard library rejects an unknown method (`FOO`) in
    # handle_one_request, before do_GET/_dispatch ever run - send_error is
    # the only hook left to write the one F5 line this request still owes.
    with _serve(tmp_path) as server:
        _request(server, "/api/health", method="FOO")

        captured_err = ""
        for _ in range(50):
            captured_err += capsys.readouterr().err
            if "ms" in captured_err:
                break
            time.sleep(0.05)

    lines = [line for line in captured_err.splitlines() if line.strip()]
    assert len(lines) == 1
    assert re.match(r"^FOO /api/health 501 [0-9]+(\.[0-9]+)? ?ms$", lines[0])


def test_malformed_request_line_still_logs_one_access_line(tmp_path, capsys):
    # A 4-word request line fails parse_request's word-count check *after*
    # it has parsed a valid HTTP version but *before* self.path - or even
    # self.command - is ever assigned (F5 covers every request, not only
    # the ones for which routing got far enough to see a path).
    with _serve(tmp_path) as server:
        sock = socket.create_connection(("127.0.0.1", server.server_port), timeout=5.0)
        try:
            sock.sendall(b"GET /x extra HTTP/1.1\r\n\r\n")
            response = sock.recv(4096)
        finally:
            sock.close()

        captured_err = ""
        for _ in range(50):
            captured_err += capsys.readouterr().err
            if "ms" in captured_err:
                break
            time.sleep(0.05)

    assert response.startswith(b"HTTP/1.0 400")
    lines = [line for line in captured_err.splitlines() if line.strip()]
    assert len(lines) == 1
    assert re.match(r"^- - 400 [0-9]+(\.[0-9]+)? ?ms$", lines[0])


def _stderr_after(capsys, marker: str = "ms") -> str:
    captured = ""
    for _ in range(50):
        captured += capsys.readouterr().err
        if marker in captured:
            break
        time.sleep(0.05)
    return captured


@pytest.mark.skipif(
    hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0,
    reason="root reads a mode-000 file anyway",
)
def test_unreadable_static_file_answers_500_with_one_access_line_and_no_traceback(
    tmp_path, capsys
):
    # read_bytes() raising inside the static path used to escape to
    # socketserver: a status-0 access line, a 30-line traceback and a dropped
    # connection. One exception boundary in _dispatch now covers static and API
    # routes alike.
    static_root = tmp_path / "web" / "dist"
    static_root.mkdir(parents=True)
    secret = static_root / "locked.txt"
    secret.write_text("x")
    secret.chmod(0)
    try:
        with _serve(static_root) as server:
            response, body = _request(server, "/locked.txt")
            captured_err = _stderr_after(capsys)
    finally:
        secret.chmod(0o600)

    assert response.status == 500
    assert json.loads(body)["error"]["code"] == "internal_error"
    lines = [line for line in captured_err.splitlines() if line.strip()]
    assert len(lines) == 1, captured_err
    assert re.match(r"^GET /locked\.txt 500 [0-9]+(\.[0-9]+)? ?ms$", lines[0])
    assert "Traceback" not in captured_err


def test_a_client_that_went_away_closes_quietly_with_one_access_line(tmp_path, capsys):
    # A write to a client that already hung up raises BrokenPipeError inside the
    # handler; that is no error worth a traceback, and nothing can be sent back.
    def _client_gone(_handler):
        raise BrokenPipeError(32, "Broken pipe")

    ROUTES["/api/__test_client_gone__"] = {"GET": _client_gone}
    try:
        with _serve(tmp_path) as server:
            with pytest.raises((http.client.RemoteDisconnected, ConnectionError)):
                _request(server, "/api/__test_client_gone__")
            captured_err = _stderr_after(capsys)
    finally:
        del ROUTES["/api/__test_client_gone__"]

    lines = [line for line in captured_err.splitlines() if line.strip()]
    assert len(lines) == 1, captured_err
    assert lines[0].startswith("GET /api/__test_client_gone__ ")
    assert "Traceback" not in captured_err


def test_server_handle_error_is_silent_for_a_gone_client_and_one_line_otherwise(
    tmp_path, capsys
):
    # Outside _dispatch's boundary (a reset while the request line is read, or
    # during the final flush) socketserver's default printed a full traceback.
    server = ConsoleServer(("127.0.0.1", 0), tmp_path)
    try:
        try:
            raise ConnectionResetError(54, "Connection reset by peer")
        except ConnectionResetError:
            server.handle_error(None, ("127.0.0.1", 1))
        assert capsys.readouterr().err == ""
        try:
            raise RuntimeError("secret detail from a request")
        except RuntimeError:
            server.handle_error(None, ("127.0.0.1", 1))
        err = capsys.readouterr().err
    finally:
        server.server_close()
    assert err == "interlock-console: RuntimeError while handling a request\n"
    assert "Traceback" not in err and "secret detail" not in err


def test_mesh_endpoint_reads_the_configured_directory(tmp_path):
    """The Mesh page's route reports this node's real mesh state, and an
    unconfigured directory reads as off rather than as an error."""
    import os

    root = tmp_path / "dist"
    root.mkdir()
    mesh_dir = tmp_path / "mesh"
    mesh_dir.mkdir()
    with _serve(root) as server:
        server.mesh_dir = os.path.abspath(str(mesh_dir))
        response, body = _request(server, "/api/mesh")
        assert response.status == 200
        document = json.loads(body)
        assert document["configured"] is False
        assert document["dir"] == os.path.abspath(str(mesh_dir))
        assert document["report"]["layers"] == [] and document["report"]["enabled_at"] is None
