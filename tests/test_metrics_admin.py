"""In-process metrics and the sidecar admin endpoint (hoop review H6)."""
import http.client
import json
import socket

import pytest

from interlock import deny_tool, guard, install, metrics
from interlock.detectors.pii_argument_guard import pii_argument_guard
from interlock.interceptors.mcp import enforce_tool_call
from interlock.sidecar.admin import parse_address, start


def test_decisions_are_counted_without_a_sink():
    install(rules=[deny_tool("rm", policy_id="no-rm"),
                   pii_argument_guard(entities=["EMAIL_ADDRESS"], verdict="mask")])

    @guard()
    def rm():
        return 1

    for _ in range(2):
        with pytest.raises(Exception):
            rm()
    enforce_tool_call("send", {"to": "ada@example.com"})
    snap = metrics.snapshot()
    assert snap["by_verdict"]["BLOCK"] == 2
    assert snap["top_policies"]["no-rm"] == 2
    assert snap["masked"] == {"EMAIL_ADDRESS": 1}
    assert snap["latency_us"]["count"] >= 3


def test_prometheus_text():
    metrics.record("BLOCK", "call", 'weird"id', elapsed_us=120, masked={"IBAN_CODE": 2})
    metrics.record("ESCALATE", "call", "ask", approval="pending:r-1")
    text = metrics.render_prometheus()
    assert 'interlock_decisions_total{verdict="BLOCK",phase="call",policy="weird\\"id"} 1' in text
    assert 'interlock_masked_total{entity="IBAN_CODE"} 2' in text
    assert 'interlock_escalations_total{outcome="pending"} 1' in text
    assert 'interlock_evaluation_microseconds_bucket{le="250"} 1' in text
    assert 'interlock_evaluation_microseconds_bucket{le="+Inf"} 1' in text
    assert "interlock_evaluation_microseconds_count 1" in text


@pytest.mark.parametrize("address", ["0.0.0.0:19000", "10.0.0.1:19000", "127.0.0.1:x"])
def test_admin_binds_loopback_only(address):
    with pytest.raises(ValueError):
        parse_address(address)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_admin_endpoints():
    port = free_port()
    server = start("127.0.0.1:{}".format(port), lambda: {"rules": ["a"], "epoch": "e"})
    try:
        def get(path, host="127.0.0.1"):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", path, headers={"Host": "{}:{}".format(host, port)})
            response = conn.getresponse()
            body = response.read().decode()
            conn.close()
            return response.status, body, response.getheader("Access-Control-Allow-Origin")

        assert get("/healthz")[:2] == (200, "ok\n")
        status, body, cors = get("/stats")
        assert status == 200 and "decisions" in json.loads(body) and cors is None
        assert "interlock_decisions_total" in get("/metrics")[1]
        assert json.loads(get("/config")[1]) == {"rules": ["a"], "epoch": "e"}
        assert get("/nope")[0] == 404
        assert get("/healthz", host="evil.example")[0] == 403
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/healthz", body="x", headers={"Host": "localhost"})
        assert conn.getresponse().status == 405
        conn.close()
    finally:
        server.shutdown()
        server.server_close()
