"""The receipt log viewer: ``GET /api/receipts``, ``GET /api/receipts/verify``
and ``GET /api/receipts/stream``, plus the ``receipts``/``verify`` keys
``/api/health`` gains once the console is started with ``--receipts``.

Each test is named for the claim it proves:

- started without ``--receipts``, every ``/api/receipts`` route answers 404
  ``receipts_not_configured`` and ``/api/health`` reports ``receipts: false`` (AC7),
- a 3-receipt log answers with ``total``/``count_all`` 3, newest first, each
  receipt carrying its file index and a 64-hex ``mac`` (AC1),
- ``/api/receipts/verify`` reports ``intact`` with the log's count and head
  mac (AC2), ``broken`` naming the tampered receipt after an on-disk edit
  (AC3), and ``unverified`` when the console has no key (AC4),
- ``verdict``, ``action`` and ``order`` filter and order the list, and a
  ``verdict`` or ``order`` value outside the listed ones answers 400
  ``bad_query`` (AC5),
- a stream opened before a receipt is appended sends ``event: hello`` then
  ``event: receipt`` for the append, and verify still reports intact
  afterwards (AC6),
- the key's hex text never appears in any response body or in the console's
  own output, and a missing ``--key-file`` path exits with status 2 (AC8).

The server is hosted in-process, in a daemon thread, the same way
:mod:`tests.test_console_server` hosts it for the health-endpoint tests.
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

from interlock.console.__main__ import main
from interlock.console.server import ConsoleServer
from interlock.receipt import Receipt
from interlock.sink import FileSink

KEYHEX = "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff"


@contextlib.contextmanager
def _serve(
    static_root: Path,
    *,
    receipts_path: Optional[str] = None,
    receipts_key: Optional[bytes] = None,
) -> Iterator[ConsoleServer]:
    server = ConsoleServer(
        ("127.0.0.1", 0),
        static_root,
        receipts_path=receipts_path,
        receipts_key=receipts_key,
    )
    thread = threading.Thread(
        target=server.serve_forever, daemon=True, name="interlock-console-audit-test"
    )
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


def _request(server: ConsoleServer, path: str, *, method: str = "GET"):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5.0)
    try:
        conn.request(method, path)
        response = conn.getresponse()
        body = response.read()
        return response, body
    finally:
        conn.close()


def _write_fixture(path: Path, key: bytes) -> None:
    sink = FileSink(str(path), key=key)
    for action, verdict in [
        ("run_shell", "BLOCK"),
        ("http_post", "MODIFY"),
        ("search", "ALLOW"),
    ]:
        sink.write(
            Receipt(
                ts=time.time(),
                action=action,
                verdict=verdict,
                reason="fixture " + action,
                policy_id="fixture",
                principal="agent-1",
                args_digest="0" * 64,
            )
        )


def _open_stream(server: ConsoleServer, path: str) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", server.server_port), timeout=5.0)
    request = "GET {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n".format(
        path, server.server_port
    )
    sock.sendall(request.encode("ascii"))
    return sock


def _read_until(sock: socket.socket, marker: bytes, deadline: float) -> bytes:
    buf = b""
    while marker not in buf:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(
                "timed out waiting for {!r}; got {!r}".format(marker, buf)
            )
        sock.settimeout(remaining)
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError(
                "connection closed before {!r}; got {!r}".format(marker, buf)
            )
        buf += chunk
    return buf


def test_receipts_routes_404_and_health_false_without_receipts_flag(tmp_path):
    with _serve(tmp_path) as server:
        response, body = _request(server, "/api/receipts")
        _, verify_body = _request(server, "/api/receipts/verify")
        health_response, health_body = _request(server, "/api/health")

    assert response.status == 404
    assert json.loads(body)["error"]["code"] == "receipts_not_configured"
    assert json.loads(verify_body)["error"]["code"] == "receipts_not_configured"
    assert health_response.status == 200
    assert json.loads(health_body)["receipts"] is False


def test_receipts_lists_newest_first_with_total_count_all_and_mac(tmp_path):
    key = bytes.fromhex(KEYHEX)
    receipts_path = tmp_path / "receipts.jsonl"
    _write_fixture(receipts_path, key)

    with _serve(tmp_path, receipts_path=str(receipts_path), receipts_key=key) as server:
        response, body = _request(server, "/api/receipts")

    assert response.status == 200
    payload = json.loads(body)
    assert payload["total"] == payload["count_all"] == 3
    receipts = payload["receipts"]
    assert [r["action"] for r in receipts] == ["search", "http_post", "run_shell"]
    assert [r["index"] for r in receipts] == [2, 1, 0]
    assert all(re.fullmatch(r"[0-9a-f]{64}", r["mac"]) for r in receipts)
    for field in ("ts", "verdict", "reason", "policy_id", "principal", "phase", "args_digest", "prev"):
        assert field in receipts[0]


def test_verify_reports_intact_with_count_and_head(tmp_path):
    key = bytes.fromhex(KEYHEX)
    receipts_path = tmp_path / "receipts.jsonl"
    _write_fixture(receipts_path, key)
    last_mac = json.loads(receipts_path.read_text().splitlines()[-1])["mac"]

    with _serve(tmp_path, receipts_path=str(receipts_path), receipts_key=key) as server:
        response, body = _request(server, "/api/receipts/verify")

    assert response.status == 200
    payload = json.loads(body)
    assert payload["status"] == "intact"
    assert payload["count"] == 3
    assert payload["head"] == last_mac


def test_verify_reports_broken_after_tamper(tmp_path):
    key = bytes.fromhex(KEYHEX)
    receipts_path = tmp_path / "receipts.jsonl"
    _write_fixture(receipts_path, key)
    lines = receipts_path.read_text().splitlines()
    lines[1] = lines[1].replace("fixture http_post", "tampered")
    receipts_path.write_text("\n".join(lines) + "\n")

    with _serve(tmp_path, receipts_path=str(receipts_path), receipts_key=key) as server:
        response, body = _request(server, "/api/receipts/verify")

    assert response.status == 200
    payload = json.loads(body)
    assert payload["status"] == "broken"
    assert "receipt 1" in payload["problem"]


def test_verify_reports_broken_for_unparseable_line_instead_of_crashing(tmp_path):
    key = bytes.fromhex(KEYHEX)
    receipts_path = tmp_path / "receipts.jsonl"
    _write_fixture(receipts_path, key)
    with receipts_path.open("a", encoding="utf-8") as fh:
        fh.write("not valid json\n")

    with _serve(tmp_path, receipts_path=str(receipts_path), receipts_key=key) as server:
        response, body = _request(server, "/api/receipts/verify")

    assert response.status == 200
    payload = json.loads(body)
    assert payload["status"] == "broken"
    assert payload["problem"]


def test_receipts_marks_unparseable_line_unreadable_instead_of_failing(tmp_path):
    key = bytes.fromhex(KEYHEX)
    receipts_path = tmp_path / "receipts.jsonl"
    _write_fixture(receipts_path, key)
    with receipts_path.open("a", encoding="utf-8") as fh:
        fh.write("not valid json\n")

    with _serve(tmp_path, receipts_path=str(receipts_path), receipts_key=key) as server:
        response, body = _request(server, "/api/receipts")

    assert response.status == 200
    payload = json.loads(body)
    assert payload["count_all"] == 4
    unreadable = [r for r in payload["receipts"] if r.get("unreadable")]
    assert len(unreadable) == 1
    assert unreadable[0]["index"] == 3


def test_verify_reports_unverified_without_key_file(tmp_path):
    key = bytes.fromhex(KEYHEX)
    receipts_path = tmp_path / "receipts.jsonl"
    _write_fixture(receipts_path, key)

    with _serve(tmp_path, receipts_path=str(receipts_path)) as server:
        response, body = _request(server, "/api/receipts/verify")

    assert response.status == 200
    assert json.loads(body)["status"] == "unverified"


def test_query_filters_by_verdict_action_and_order(tmp_path):
    key = bytes.fromhex(KEYHEX)
    receipts_path = tmp_path / "receipts.jsonl"
    _write_fixture(receipts_path, key)

    with _serve(tmp_path, receipts_path=str(receipts_path), receipts_key=key) as server:
        response, body = _request(server, "/api/receipts?verdict=BLOCK")
        payload = json.loads(body)
        assert payload["total"] == 1
        assert [r["action"] for r in payload["receipts"]] == ["run_shell"]

        response, body = _request(server, "/api/receipts?action=search")
        payload = json.loads(body)
        assert payload["total"] == 1
        assert [r["action"] for r in payload["receipts"]] == ["search"]

        response, body = _request(server, "/api/receipts?order=asc")
        assert json.loads(body)["receipts"][0]["action"] == "run_shell"


def test_invalid_verdict_value_is_400_bad_query(tmp_path):
    key = bytes.fromhex(KEYHEX)
    receipts_path = tmp_path / "receipts.jsonl"
    _write_fixture(receipts_path, key)

    with _serve(tmp_path, receipts_path=str(receipts_path), receipts_key=key) as server:
        response, body = _request(server, "/api/receipts?verdict=MAYBE")

    assert response.status == 400
    assert json.loads(body)["error"]["code"] == "bad_query"


def test_invalid_order_value_is_400_bad_query(tmp_path):
    key = bytes.fromhex(KEYHEX)
    receipts_path = tmp_path / "receipts.jsonl"
    _write_fixture(receipts_path, key)

    with _serve(tmp_path, receipts_path=str(receipts_path), receipts_key=key) as server:
        response, body = _request(server, "/api/receipts?order=sideways")

    assert response.status == 400
    assert json.loads(body)["error"]["code"] == "bad_query"


def test_stream_sends_hello_then_appended_receipt(tmp_path):
    key = bytes.fromhex(KEYHEX)
    receipts_path = tmp_path / "receipts.jsonl"
    _write_fixture(receipts_path, key)

    with _serve(tmp_path, receipts_path=str(receipts_path), receipts_key=key) as server:
        sock = _open_stream(server, "/api/receipts/stream")
        try:
            buf = _read_until(sock, b"event: hello", time.monotonic() + 5.0)
            assert b"text/event-stream" in buf

            FileSink(str(receipts_path), key=key).write(
                Receipt(
                    ts=time.time(),
                    action="live_probe_action",
                    verdict="ALLOW",
                    reason="appended",
                    principal="agent-1",
                )
            )

            buf += _read_until(sock, b"event: receipt", time.monotonic() + 5.0)
            assert b"live_probe_action" in buf
        finally:
            sock.close()

        _, verify_body = _request(server, "/api/receipts/verify")

    verify_payload = json.loads(verify_body)
    assert verify_payload["status"] == "intact"
    assert verify_payload["count"] == 4


def test_key_hex_never_appears_in_any_response_body(tmp_path, capsys):
    key = bytes.fromhex(KEYHEX)
    receipts_path = tmp_path / "receipts.jsonl"
    _write_fixture(receipts_path, key)

    with _serve(tmp_path, receipts_path=str(receipts_path), receipts_key=key) as server:
        _, health_body = _request(server, "/api/health")
        _, receipts_body = _request(server, "/api/receipts?order=asc")
        _, verify_body = _request(server, "/api/receipts/verify")

    needle = KEYHEX[:16].encode("ascii")
    assert needle not in health_body
    assert needle not in receipts_body
    assert needle not in verify_body
    captured = capsys.readouterr()
    assert KEYHEX[:16] not in captured.out
    assert KEYHEX[:16] not in captured.err


def test_missing_key_file_path_exits_with_status_2(tmp_path, capsys):
    receipts_path = tmp_path / "receipts.jsonl"
    receipts_path.write_text("")

    rc = main(
        [
            "--port",
            "0",
            "--receipts",
            str(receipts_path),
            "--key-file",
            str(tmp_path / "no-such-key"),
        ]
    )

    assert rc == 2
    captured = capsys.readouterr()
    assert captured.err.strip()
    assert KEYHEX[:16] not in captured.err
