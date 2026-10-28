"""The connector cycle: enroll once, spool metadata, retry, acknowledge, stop.

``run_once`` is a fixed four-step cycle. The retry policy lives here (not in
the transport), an acknowledgement is what removes a spooled batch, and the
cursor and ``last_sync`` move only after a 2xx - so a reconnect resumes at the
last acknowledged point. ``410`` is terminal and never a fallback.
"""
from __future__ import annotations

import gzip
import json
import threading

import pytest

from interlock.cloud.connector.config import CloudHome, HomeError
from interlock.sensor import DEFAULT_RING_BYTES
from interlock.cloud.connector.runner import (
    MAX_BACKOFF,
    MIN_BACKOFF,
    Connector,
)
from interlock.cloud.connector.transport import FakeTransport, TransportError
from interlock.cloud.enrollment import generate_agent_key
from interlock.cloud.identity import (
    generate_host_seed,
    key_id,
    public_key_hex,
)


class _Clock:
    def __init__(self, value=5000.0):
        self.value = float(value)

    def __call__(self):
        return self.value


class _Queue:
    def __init__(self, reviews):
        self.reviews = list(reviews)

    def list(self, status="pending"):
        return list(self.reviews)

    def binding_of(self, review_id):
        return "binding-" + str(review_id)


def test_on_file_masks_the_preview_and_keeps_the_exact_allow_list(tmp_path):
    connector, _home, _transport, _raw, _public = _connector(
        tmp_path, queue=_Queue([]))
    review = {
        "id": "rev-1", "status": "pending", "action": "shell",
        "phase": "propose", "principal": "alice", "requester": "bob",
        "args_digest": "abc123", "created": 10.0, "pending_until": 20.0,
        "args_preview": "SECRET ARGS", "preview": "write ada@example.com",
    }

    assert connector.on_file(review) is True

    batches = connector.spool.batches()
    assert len(batches) == 1
    record = json.loads(gzip.decompress(batches[0].path.read_bytes()))
    columns = {
        "review_id", "binding", "action", "phase", "principal", "requester",
        "policy_id", "reason", "args_digest", "preview", "mask_counts",
        "created", "pending_until", "min_approvals", "allow_self_approval",
        "approval_ttl",
    }
    assert set(record) == columns
    assert record["review_id"] == "rev-1"
    assert record["binding"] == "binding-rev-1"
    assert record["args_digest"] == "abc123"
    assert "ada@example.com" not in json.dumps(record)
    assert record["mask_counts"] == {"EMAIL_ADDRESS": 1}
    # The requester is a stable label, not the local user name.
    assert record["requester"] != "bob"
    assert record["requester"].startswith("hmac:")
    assert "SECRET" not in json.dumps(record)
    assert batches[0].kind == "security"
    assert batches[0].sensor == "reviews"


def test_on_file_without_a_queue_cannot_upload_without_a_binding(tmp_path):
    connector, _home, _transport, _raw, _public = _connector(tmp_path)
    assert connector.on_file({"id": "rev-1"}) is False
    assert connector.spool.count == 0


def _home(tmp_path, *, clock=None):
    home = CloudHome(tmp_path / "home")
    raw, _prefix, _digest = generate_agent_key()
    seed = generate_host_seed()
    public_hex = public_key_hex(seed)
    home.save({
        "url": "https://cloud.example",
        "org_id": "org-1",
        "host_id": "host-1",
        "agent_key_id": "key-1",
        "agent_key": raw,
        "host_key_id": key_id(public_hex),
        "host_public_key": public_hex,
        "plane_public_keys": {"approval": "", "policy": "", "receipt": ""},
        "spool_dir": "spool",
        "state_dir": "state",
    })
    home.save_seed(seed)
    return home, raw, public_hex


def _connector(tmp_path, responses=None, **kwargs):
    home, raw, public_hex = _home(tmp_path)
    transport = FakeTransport(responses)
    kwargs.setdefault("clock", _Clock())
    return Connector(home, transport, **kwargs), home, transport, raw, public_hex


def _state(connector):
    return json.loads(connector.state_path.read_text())


# -- enrollment ---------------------------------------------------------

def test_enroll_writes_a_0600_config_and_the_local_seed_once(tmp_path):
    home = CloudHome(tmp_path / "home")
    response = {
        "host_id": "host-9", "agent_key_id": "key-9",
        "org_id": "org-9", "agent_key": generate_agent_key()[0],
        "plane_public_keys": {"approval": "", "policy": "", "receipt": ""},
        "poll_after": 300,
    }
    transport = FakeTransport([(201, {}, json.dumps(response).encode())])
    connector = Connector(home, transport, clock=_Clock())

    result = connector.enroll("https://cloud.example", "ilkt_org-9_secret",
                              "box")

    assert result == {"ok": True, "host_id": "host-9",
                      "agent_key_id": "key-9", "org_id": "org-9"}
    assert len(transport.calls) == 1
    method, path, body, headers = transport.calls[0]
    assert (method, path) == ("POST", "/v1/enroll")
    assert "authorization" not in headers
    sent = json.loads(body)
    assert sent["token"] == "ilkt_org-9_secret"
    assert sent["host_name"] == "box"
    assert sent["host_public_key"] == public_key_hex(home.load_seed())
    assert sent["host_key_id"] == key_id(sent["host_public_key"])
    assert home.load()["agent_key"] == response["agent_key"]
    # FR-032: enrollment points the connector at the host receipt log, so a
    # freshly enrolled host streams receipts instead of silently shipping none.
    assert home.load()["receipt_log"] == str(home.root / "receipts.jsonl")
    assert connector.receipt_tailer() is not None
    assert home.config_path.stat().st_mode & 0o077 == 0
    assert home.seed_path.stat().st_mode & 0o077 == 0


def test_a_single_use_enrollment_token_is_never_retried(tmp_path):
    home = CloudHome(tmp_path / "home")
    transport = FakeTransport(
        [(500, {"retry-after": "1"}, b'{"error":{"code":"unavailable"}}')])
    connector = Connector(home, transport, sleep=lambda seconds: None)

    result = connector.enroll("https://cloud.example", "ilkt_org_secret")

    assert result["ok"] is False
    assert result["status"] == 500
    assert result["error"] == "unavailable"
    assert len(transport.calls) == 1
    assert not home.exists()


def test_enroll_refuses_a_plain_http_url_off_loopback(tmp_path):
    home = CloudHome(tmp_path / "home")
    connector = Connector(home, FakeTransport())
    with pytest.raises(HomeError):
        connector.enroll("http://cloud.example", "ilkt_org_secret")


# -- review metadata ----------------------------------------------------

def test_on_file_without_an_id_is_a_no_op(tmp_path):
    connector, _home, _transport, _raw, _public = _connector(tmp_path)
    assert connector.on_file({"status": "pending"}) is False
    assert connector.spool.count == 0


def test_on_file_never_raises_into_the_callers_queue(tmp_path):
    connector, _home, _transport, _raw, _public = _connector(tmp_path)

    class _Broken:
        @property
        def id(self):
            raise RuntimeError("boom")

    assert connector.on_file(_Broken()) is False


# -- one cycle ----------------------------------------------------------

def test_a_successful_cycle_uploads_acks_and_persists_both_markers(tmp_path):
    connector, _home, transport, _raw, _public = _connector(
        tmp_path,
        [
            (201, {}, b'{"ok":true}'),
            (200, {}, json.dumps({"cursor": 7, "poll_after": 42}).encode()),
            (200, {}, json.dumps({"poll_after": 42}).encode()),
        ],
    )
    connector.spool.add("security", b'{"review_id":"rev-1"}',
                        host="host-1", sensor="reviews")

    result = connector.run_once()

    assert result == {"ok": True, "reviews": 0, "uploaded": 1,
                      "receipts_spooled": 0, "poll_after": 42,
                      "revoked": False, "error": None}
    assert connector.spool.count == 0
    paths = [(method, path.split("?")[0]) for method, path, _b, _h
             in transport.calls]
    assert paths == [("POST", "/v1/reviews"), ("GET", "/v1/grants"),
                     ("POST", "/v1/hosts/self")]
    state = _state(connector)
    assert state["cursor"] == 7
    assert state["last_sync"] == 5000.0
    assert state["revoked"] is False
    assert state["last_error"] is None


def test_a_failed_grants_poll_does_not_persist_its_cursor(tmp_path):
    connector, _home, _transport, _raw, _public = _connector(
        tmp_path,
        [
            (500, {}, b'{"error":{"code":"unavailable"}}'),
            (200, {}, json.dumps({"cursor": 9}).encode()),
        ],
        max_attempts=1,
    )

    result = connector.run_once()

    assert result["ok"] is False
    assert result["error"] == "unavailable"
    state = _state(connector)
    assert state["cursor"] == 0
    assert state["last_sync"] == 5000.0


def test_a_failed_heartbeat_does_not_advance_last_sync(tmp_path):
    connector, _home, _transport, _raw, _public = _connector(
        tmp_path,
        [
            (200, {}, json.dumps({"cursor": 3}).encode()),
            (500, {}, b"{}"),
        ],
        max_attempts=1,
    )

    result = connector.run_once()

    assert result["ok"] is False
    state = _state(connector)
    assert state["cursor"] == 3
    assert state["last_sync"] is None
    assert state["last_error"] == "request failed"


def test_pending_reviews_are_reconciled_and_uploaded(tmp_path):
    home, _raw, _public = _home(tmp_path)
    transport = FakeTransport()
    queue = _Queue([{"id": "rev-1"}, {"id": "rev-2"}])
    connector = Connector(home, transport, queue=queue, clock=_Clock())

    result = connector.run_once()

    assert result["reviews"] == 2
    assert result["uploaded"] == 2
    assert connector.spool.count == 0


# -- retry policy -------------------------------------------------------

def test_retry_after_is_honoured_without_jitter(tmp_path):
    connector, _home, transport, _raw, _public = _connector(
        tmp_path,
        [(429, {"Retry-After": "2"}, b"{}"),
         (200, {}, b'{"ok":true}')],
        max_attempts=3,
    )
    slept = []
    connector.sleep = slept.append

    status, _headers, _body = connector._request("GET", "/v1/grants")

    assert status == 200
    assert slept == [2.0]
    assert len(transport.calls) == 2


def test_a_malformed_retry_after_is_ignored_and_the_cycle_survives(tmp_path):
    connector, _home, transport, _raw, _public = _connector(
        tmp_path,
        [(503, {"retry-after": "not a delta or a date"}, b"{}"),
         (200, {}, b'{"ok":true}')],
        max_attempts=2,
    )
    slept = []
    connector.sleep = slept.append
    connector.random_fn = lambda low, high: high

    status, _headers, _body = connector._request("GET", "/v1/grants")

    assert status == 200
    assert len(transport.calls) == 2
    assert slept == [MIN_BACKOFF]


@pytest.mark.parametrize("status_code", [400, 403])
def test_a_client_error_is_returned_without_retrying(tmp_path, status_code):
    connector, _home, transport, _raw, _public = _connector(
        tmp_path,
        [(status_code, {}, b'{"error":{"code":"forbidden"}}'),
         (200, {}, b"{}")],
        max_attempts=4,
    )
    slept = []
    connector.sleep = slept.append

    status, _headers, body = connector._request("GET", "/v1/grants")

    assert status == status_code
    assert body == b'{"error":{"code":"forbidden"}}'
    assert len(transport.calls) == 1
    assert slept == []


def test_server_errors_are_retried_with_jittered_backoff(tmp_path):
    connector, _home, transport, _raw, _public = _connector(
        tmp_path, [(503, {}, b"{}")] * 3 + [(200, {}, b"{}")],
        max_attempts=4,
    )
    slept = []
    connector.sleep = slept.append
    connector.random_fn = lambda low, high: high

    status, _headers, _body = connector._request("GET", "/v1/grants")

    assert status == 200
    assert len(transport.calls) == 4
    assert slept == [1.0, 2.0, 4.0]


def test_backoff_is_bounded_and_uses_full_jitter(tmp_path):
    connector, _home, _transport, _raw, _public = _connector(tmp_path)
    connector.random_fn = lambda low, high: high
    assert connector._backoff(0) == MIN_BACKOFF
    assert connector._backoff(20) == MAX_BACKOFF
    connector.random_fn = lambda low, high: low
    assert connector._backoff(5) == 0.0


def test_transport_failures_exhaust_attempts_and_raise(tmp_path):
    connector, _home, transport, _raw, _public = _connector(
        tmp_path, [TransportError("down")] * 4, max_attempts=4)
    slept = []
    connector.sleep = slept.append

    with pytest.raises(TransportError) as exc:
        connector._request("GET", "/v1/grants")

    assert "down" in str(exc.value)
    assert len(transport.calls) == 4
    assert len(slept) == 3


# -- revocation ---------------------------------------------------------

def test_a_410_on_upload_is_terminal_and_leaves_the_batch(tmp_path):
    connector, _home, transport, _raw, _public = _connector(
        tmp_path, [(410, {}, b'{"error":{"code":"revoked"}}')])
    connector.spool.add("security", b"x", host="host-1", sensor="reviews")

    result = connector.run_once()

    assert result["revoked"] is True
    assert result["ok"] is False
    assert connector.spool.count == 1
    assert _state(connector)["revoked"] is True
    assert len(transport.calls) == 1

    again = connector.run_once()
    assert again["revoked"] is True
    assert len(transport.calls) == 1


def test_a_410_on_grants_stops_before_the_heartbeat(tmp_path):
    connector, _home, transport, _raw, _public = _connector(
        tmp_path, [(410, {}, b'{"error":{"code":"revoked"}}')])

    result = connector.run_once()

    assert result["revoked"] is True
    assert [(method, path.split("?")[0]) for method, path, _b, _h
            in transport.calls] == [("GET", "/v1/grants")]


def test_run_forever_returns_1_on_a_recorded_revocation(tmp_path):
    connector, home, transport, _raw, _public = _connector(tmp_path)
    state_dir = home.root / "state"
    state_dir.mkdir(mode=0o700)
    (state_dir / "connector.json").write_text(json.dumps({
        "cursor": 0, "last_sync": None, "revoked": True,
        "last_error": "revoked", "poll_after": 300,
    }))

    assert connector.run_forever(threading.Event()) == 1
    assert transport.calls == []


def test_run_once_without_a_config_is_not_enrolled(tmp_path):
    connector = Connector(CloudHome(tmp_path / "empty"), FakeTransport())
    result = connector.run_once()
    assert result == {"ok": False, "reviews": 0, "revoked": False,
                      "error": "not enrolled"}


# -- status and leave ---------------------------------------------------

def test_status_has_exactly_the_documented_keys_and_no_agent_key(tmp_path):
    connector, _home, _transport, raw, _public = _connector(tmp_path)

    status = connector.status()

    assert set(status) == {
        "connected", "last_sync", "url", "org_id", "host_id",
        "spool_batches", "spool_bytes", "dropped_batches", "ring", "queue_lag",
        "cursor", "grant_seq", "last_ack_seq", "grants_applied",
        "grants_refused", "grants_acked", "last_grant_applied",
        "last_grant_refusal", "revoked", "last_error",
        "receipts_offset", "receipts_line", "receipts_pending_bytes",
        "last_receipt_error", "last_receipt_ack", "verification_level",
    }
    assert raw not in json.dumps(status)
    assert status["url"] == "https://cloud.example"
    assert status["connected"] is False
    assert status["revoked"] is False


def test_status_reports_ring_counters_and_gaps_only(tmp_path):
    connector, _home, _transport, _raw, _public = _connector(tmp_path)

    ring = connector.status()["ring"]

    assert ring == {
        "capacity_bytes": DEFAULT_RING_BYTES,
        "bytes": 0,
        "dropped_entries": 0,
        "dropped_by_kind": {"security": 0, "observability": 0},
        "gaps": [],
    }


def test_status_is_connected_after_a_successful_cycle(tmp_path):
    connector, _home, _transport, _raw, _public = _connector(tmp_path)
    connector.run_once()
    status = connector.status()
    assert status["connected"] is True
    assert status["last_sync"] == 5000.0


def test_leave_removes_config_and_seed_but_keeps_the_spool(tmp_path):
    connector, home, _transport, _raw, _public = _connector(tmp_path)
    connector.spool.add("security", b"x", host="host-1", sensor="reviews")

    result = connector.leave(confirmed=True)

    assert result["removed"] is True
    assert result["spool_remains"] is True
    assert not home.config_path.exists() and not home.seed_path.exists()
    assert (home.root / "spool").is_dir()
    assert connector.config is None


def test_headers_carry_the_key_and_org_hint_only_when_authenticated(tmp_path):
    connector, _home, _transport, raw, _public = _connector(tmp_path)

    signed = connector.headers()
    assert signed["authorization"] == "Bearer " + raw
    assert signed["x-interlock-host"] == "host-1"
    assert signed["x-interlock-org"] == "org-1"
    assert signed["x-interlock-version"]

    anonymous = connector.headers(auth=False)
    assert "authorization" not in anonymous
    assert "x-interlock-host" not in anonymous
