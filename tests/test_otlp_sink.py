"""OTLP/HTTP JSON export of receipts: ``OtlpSink``.

Covers the field mapping (the severity table and the attribute allow-list), the
no-argument-value contract (nothing but the allow-listed metadata is exported),
the local chain staying byte-identical to a plain chained sink, a collector
outage that changes no verdict and loses no record, the buffer flushing on
recovery, and the live loopback smoke from the kickoff: a real OTLP/HTTP
receiver on a free port, one guarded call, one exported record.

Every test owns its receiver and shuts its sink down, and an autouse fixture
clears the process-global sink, so neither a bound port nor the exporter thread
leaks into the rest of the suite.
"""
from __future__ import annotations

import dataclasses
import http.server
import json
import socket
import threading
import time

import pytest

from interlock import Blocked, Verdict, guard, install, span
from interlock.policy.engine import deny_tool
from interlock.receipt import GENESIS, Receipt, get_sink, set_sink
from interlock.sink import InMemorySink, OtlpSink

KEY = b"k" * 32
# A distinctive argument value that must never reach the collector. The smoke
# uses "hello"; a value no other field could plausibly contain makes the
# absence assertion meaningful.
SENTINEL = "S3CRET-ARGVALUE-9f3a"


# -- the guarded tools the tests drive ---------------------------------------

@guard()
def ping(x: str) -> str:
    return x


@guard()
def drop_table(table: str) -> str:
    return "dropped " + table


# -- fixtures ----------------------------------------------------------------

@pytest.fixture(autouse=True)
def _sink_isolation():
    """No sink leaks in or out, and no exporter thread outlives its test."""
    set_sink(None)
    yield
    sink = get_sink()
    if isinstance(sink, OtlpSink):
        sink.close()
    set_sink(None)


@pytest.fixture
def receiver():
    server = Receiver()
    try:
        yield server
    finally:
        server.stop()


# -- the loopback OTLP/HTTP receiver -----------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 (http.server's spelling)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", "replace")
        self.server.requests.append(  # type: ignore[attr-defined]
            {"path": self.path, "headers": dict(self.headers), "body": body}
        )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):  # keep the test output quiet
        pass


class Receiver:
    """A real loopback OTLP/HTTP endpoint that records what it receives."""

    def __init__(self, port: int = 0):
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Handler)
        self._server.requests = []
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def requests(self):
        return list(self._server.requests)

    @property
    def bodies(self):
        return [request["body"] for request in self._server.requests]

    def url(self, path: str = "/v1/logs") -> str:
        return "http://127.0.0.1:{}{}".format(self.port, path)

    def wait_for(self, count: int = 1, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if len(self._server.requests) >= count:
                return True
            time.sleep(0.02)
        return False

    def stop(self):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2.0)


def free_port() -> int:
    """A loopback port that is currently free (nothing is listening on it)."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    try:
        return probe.getsockname()[1]
    finally:
        probe.close()


# -- helpers -----------------------------------------------------------------

def _receipt(verdict: str = "ALLOW", action: str = "ping", **overrides) -> Receipt:
    fields = dict(
        ts=1_700_000_000.0,
        action=action,
        verdict=verdict,
        reason="",
        policy_id=None,
        principal=None,
        span_id=None,
        phase="call",
        args_digest="0" * 64,
    )
    fields.update(overrides)
    return Receipt(**fields)


def _first_log_record(envelope: dict) -> dict:
    return envelope["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]


def _log_record(body: str) -> dict:
    return _first_log_record(json.loads(body))


def _attributes(record: dict) -> dict:
    return {a["key"]: list(a["value"].values())[0] for a in record["attributes"]}


def _wait_until(predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


# -- field mapping -----------------------------------------------------------

def test_severity_mapping_per_verdict():
    sink = OtlpSink("http://127.0.0.1:1/v1/logs", key=KEY)
    try:
        expected = {
            "ALLOW": (9, "INFO"),
            "MODIFY": (13, "WARN"),
            "BLOCK": (17, "ERROR"),
            "ESCALATE": (17, "ERROR"),
        }
        for verdict, (number, text) in expected.items():
            record = _first_log_record(sink._envelope(_receipt(verdict=verdict)))
            assert record["severityNumber"] == number, verdict
            assert record["severityText"] == text, verdict

        # An unrecognized verdict still gets a defined severity: never 0
        # (unspecified), never a raise.
        unknown = _first_log_record(sink._envelope(_receipt(verdict="SOMETHING_NEW")))
        assert unknown["severityNumber"] > 0
        assert unknown["severityText"]
    finally:
        sink.close()


def test_attributes_mapped_from_receipt():
    sink = OtlpSink("http://127.0.0.1:1/v1/logs", key=KEY)
    try:
        envelope = sink._envelope(
            _receipt(
                verdict="BLOCK",
                action="drop_table",
                policy_id="db.v1",
                reason="tool not permitted",
                principal="acme/agent42",
                span_id="span-1234abcd",
            )
        )
        record = _first_log_record(envelope)
        attributes = _attributes(record)
        assert attributes["action"] == "drop_table"
        assert attributes["principal"] == "acme/agent42"
        assert attributes["policy_id"] == "db.v1"
        assert attributes["reason"] == "tool not permitted"
        assert attributes["span_id"] == "span-1234abcd"
        # The allow-list is exact: no other receipt field becomes an attribute
        # (no args_digest, masked, policy_epoch, ...).
        assert set(attributes) == {
            "action",
            "principal",
            "policy_id",
            "reason",
            "span_id",
        }
        # The service name is a resource attribute, not a log attribute.
        resource = envelope["resourceLogs"][0]["resource"]["attributes"]
        assert {a["key"]: list(a["value"].values())[0] for a in resource} == {
            "service.name": "interlock"
        }
    finally:
        sink.close()


# -- the local chain is untouched --------------------------------------------

def test_local_receipt_chain_is_unchanged():
    sink = OtlpSink("http://127.0.0.1:1/v1/logs", key=KEY)
    plain = InMemorySink(key=KEY)
    try:
        for verdict, action in (("ALLOW", "ping"), ("BLOCK", "drop_table")):
            base = _receipt(verdict=verdict, action=action, policy_id="db.v1")
            # dataclasses.replace gives each sink its own copy: write() sets
            # prev/mac on the object it is handed.
            sink.write(dataclasses.replace(base))
            plain.write(dataclasses.replace(base))

        # The installed sink's own chain still verifies, and it is byte-for-byte
        # what a plain chained sink produced from the same decisions.
        assert sink.verify() is None
        assert [r.to_json() for r in sink.receipts] == [
            r.to_json() for r in plain.receipts
        ]
        assert sink.receipts[0].prev == GENESIS
        assert sink.head == sink.receipts[-1].mac
        assert sink.receipts[-1].prev == sink.receipts[0].mac
    finally:
        sink.close()


# -- no argument values leave the process ------------------------------------

def test_no_argument_value_leak_is_redacted(receiver):
    sink = OtlpSink(receiver.url(), key=KEY)
    install(
        sink=sink,
        rules=[deny_tool("drop_table", reason="tool not permitted", policy_id="db.v1")],
    )
    try:
        with span(principal="acme/agent1"):
            with pytest.raises(Blocked):
                drop_table(SENTINEL)

        assert receiver.wait_for(1), "no record reached the collector"
        body = receiver.bodies[0]
        # The whole POSTed body is inspected, exactly as the smoke does: the
        # argument value must not appear anywhere in it.
        assert SENTINEL not in body, "argument value leaked into the export"

        record = _log_record(body)
        attributes = _attributes(record)
        # ... yet the decision itself is fully exported, so the check above is
        # not vacuous: the fixed reason and the metadata are there.
        assert attributes["action"] == "drop_table"
        assert attributes["reason"] == "tool not permitted"
        assert attributes["policy_id"] == "db.v1"
        assert attributes["principal"] == "acme/agent1"
        assert set(attributes) == {
            "action",
            "principal",
            "policy_id",
            "reason",
            "span_id",
        }
        # The digest is not an attribute either - only the allow-list is.
        assert "args_digest" not in json.dumps(record)
        # The body carries the verdict and the action name, no payload.
        assert record["body"]["stringValue"] == "BLOCK drop_table"
    finally:
        set_sink(None)
        sink.close()


# -- a collector outage ------------------------------------------------------

def test_collector_outage_keeps_verdict_and_retains_record():
    port = free_port()  # nothing is listening: the collector is down
    sink = OtlpSink(
        "http://127.0.0.1:{}/v1/logs".format(port), key=KEY, retry_interval=0.05
    )
    install(
        sink=sink,
        rules=[deny_tool("drop_table", reason="tool not permitted", policy_id="db.v1")],
    )
    try:
        with pytest.raises(Blocked) as caught:
            drop_table("orders")

        # The verdict is the policy's, unchanged: the export never raised into
        # the guarded call. A sink that had raised would have produced the
        # fail-closed Blocked with policy id "audit_sink" instead.
        assert caught.value.decision.verdict is Verdict.BLOCK
        assert caught.value.decision.policy_id == "db.v1"
        assert caught.value.decision.reason == "tool not permitted"

        assert _wait_until(lambda: sink.failed >= 1), "no export was attempted"
        assert sink.sent == 0
        # The record is retained (still buffered), not dropped.
        assert sink.pending >= 1
        assert sink.receipts[-1].action == "drop_table"
        assert sink.verify() is None
    finally:
        set_sink(None)
        sink.close()


def test_collector_recovery_flushes_buffered_record():
    port = free_port()  # nothing is listening yet
    sink = OtlpSink(
        "http://127.0.0.1:{}/v1/logs".format(port), key=KEY, retry_interval=0.05
    )
    install(
        sink=sink,
        rules=[deny_tool("drop_table", reason="tool not permitted", policy_id="db.v1")],
    )
    try:
        with pytest.raises(Blocked):
            drop_table("orders")
        assert _wait_until(lambda: sink.failed >= 1), "no export was attempted"
        assert sink.sent == 0 and sink.pending >= 1

        # The collector comes back on the same port...
        receiver = Receiver(port)
        try:
            assert receiver.wait_for(1), "the withheld record never flushed"
            record = _log_record(receiver.bodies[0])
            attributes = _attributes(record)
            assert attributes["action"] == "drop_table"
            assert attributes["policy_id"] == "db.v1"
            assert record["severityNumber"] == 17
            assert record["severityText"] == "ERROR"
            # ... and the buffer drains.
            assert _wait_until(lambda: sink.pending == 0), "buffer never drained"
            assert sink.sent >= 1
        finally:
            receiver.stop()
    finally:
        set_sink(None)
        sink.close()


# -- the kickoff live smoke --------------------------------------------------

def test_live_loopback_smoke_exports_record(receiver):
    """The kickoff smoke, in-process: a loopback OTLP/HTTP receiver on a free
    port, the sink installed at its /v1/logs URL, one guarded call."""
    sink = OtlpSink(endpoint=receiver.url())
    install(sink=sink, rules=[lambda event: None])
    try:
        ping("hello")

        assert receiver.wait_for(1), "no record reached the receiver"
        line = receiver.bodies[0]
        record = _log_record(line)
        attributes = _attributes(record)

        assert attributes["action"] == "ping", attributes
        assert attributes["policy_id"] and attributes["span_id"], attributes
        assert "hello" not in line, "argument value leaked into the export"
        # The endpoint is POSTed to as given - no path appended or it 404s.
        assert receiver.requests[0]["path"] == "/v1/logs"

        print("R23 smoke pass")
    finally:
        set_sink(None)
        sink.close()
