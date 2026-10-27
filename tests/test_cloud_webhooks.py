"""C7 webhooks: signing, retry policy, privacy and the outbox.

Every test is named for the claim it proves. The load-bearing ones are the
signing vector (a receiver can verify without importing this package), the
payload privacy rule (a preview or an argument can never reach a subscriber)
and the no-redirect rule (a 3xx is a final failure, never a hop).
"""
from __future__ import annotations

import hashlib
import os
import uuid

import pytest

# Sealing a webhook secret needs the optional ``cryptography`` dependency (it
# reaches interlock/cloud/crypto.py). The Python matrix jobs install ``.[dev]``
# only, so every registration would answer 503 there; the cloud job installs
# ``.[dev,cloud]`` and is where this file really runs. Skip, never fail.
pytest.importorskip("cryptography")

from interlock.cloud import webhooks
from interlock.cloud.connector import transport
from tests._c4_helpers import KEK, NOW, call, make_app, post_json

SECRET = "whsec_client_supplied_secret_value"
URL = "https://hooks.example.test/interlock"


# -- helpers ------------------------------------------------------------

def _webhook(env, *, url=URL, events=("review.created",), secret=SECRET):
    """Register through the route so the stored secret is sealed as in prod."""
    status, _headers, body, _raw = post_json(
        env, "/v1/webhooks", env.headers,
        {"url": url, "events": list(events), "secret": secret})
    assert status == 201, body
    return body["webhook"]


def _emit(env, event="review.created", data=None):
    return webhooks.emit(
        env.store, env.org.id, event,
        data if data is not None else {"review_id": "rev-1", "count": 1},
        now=NOW)


class _RecordingTransport:
    """A transport double: records the request and replays one response."""

    calls = []
    response = (200, {}, b'{"ok":true}')

    def __init__(self, base_url="", **_kwargs):
        self.base_url = base_url

    def request(self, method, path, body=None, *, headers=None, timeout=30):
        type(self).calls.append({
            "method": method, "url": path, "body": body,
            "headers": dict(headers or {}), "timeout": timeout,
        })
        return type(self).response


@pytest.fixture(autouse=True)
def _clean_transport():
    _RecordingTransport.calls = []
    _RecordingTransport.response = (200, {}, b'{"ok":true}')
    yield


# -- signing ------------------------------------------------------------

def test_the_signing_vector_is_t_v1_over_the_exact_bytes():
    body = b'{"event":"review.created"}'
    header = webhooks.sign_delivery(b"whsec_test", body, t=1700000000)
    assert header == (
        "t=1700000000,v1="
        "2fbeadc4c45498cfe0547b2ae24fcce59855c87c3d39dd81fa3e0e0ba46300ef"
    )
    assert header.startswith("t=1700000000,v1=")


def test_verify_accepts_the_exact_bytes_and_refuses_a_tampered_or_stale_one():
    body = b'{"event":"review.created"}'
    header = webhooks.sign_delivery(b"whsec_test", body, t=1700000000)
    assert webhooks.verify_delivery(b"whsec_test", body, header, now=1700000000)
    assert not webhooks.verify_delivery(
        b"whsec_test", body + b" ", header, now=1700000000)
    assert not webhooks.verify_delivery(
        b"other", body, header, now=1700000000)
    assert not webhooks.verify_delivery(
        b"whsec_test", body, header, now=1700000000 + 301)
    assert not webhooks.verify_delivery(
        b"whsec_test", body, "garbage", now=1700000000)


def test_a_secret_is_hashed_for_lookup_and_sealed_for_signing():
    secret = webhooks.generate_secret().encode("utf-8")
    assert secret.startswith(b"whsec_")
    digest = webhooks.hash_secret(secret)
    assert len(digest) == 64 and digest != secret.decode()
    sealed = webhooks.seal_secret(secret, kek=KEK.encode(), org_id="org-1")
    assert secret not in sealed
    assert webhooks.open_secret(
        sealed, kek=KEK.encode(), org_id="org-1") == secret


def test_a_sealed_secret_only_opens_for_its_org():
    secret = webhooks.generate_secret().encode("utf-8")
    sealed = webhooks.seal_secret(secret, kek=KEK.encode(), org_id="org-1")
    with pytest.raises(webhooks.WebhookError):
        webhooks.open_secret(sealed, kek=KEK.encode(), org_id="org-2")
    with pytest.raises(webhooks.WebhookError):
        webhooks.open_secret(b"short", kek=KEK.encode(), org_id="org-1")


def test_postgres_round_trips_the_sealed_secret_as_raw_bytes():
    """The production store binds ``bytea`` as bytes, never as a latin-1 str.

    Ciphertext is arbitrary binary: a NUL raises DataError and a non-UTF-8
    byte is re-encoded and the secret fails authentication at delivery. Only a
    real Postgres (not MemoryStore) exercises that boundary.
    """
    pytest.importorskip("psycopg")
    dsn = os.environ.get("IL_CLOUD_DSN")
    if not dsn:
        pytest.skip("set IL_CLOUD_DSN to exercise the Postgres bytea path")
    from interlock.cloud import migrate
    from interlock.cloud.store import PostgresStore

    migrate.run(dsn)
    store = PostgresStore(dsn)
    org = store.create_org(slug="wh" + uuid.uuid4().hex[:10], name="Webhook")
    secret = webhooks.generate_secret().encode("utf-8")
    sealed = webhooks.seal_secret(secret, kek=KEK.encode(), org_id=org.id)
    created = store.webhook_create_endpoint(
        org.id, URL, ["review.created"], webhooks.hash_secret(secret), sealed,
        now=NOW)
    fetched = store.webhook_endpoint_by_id(org.id, created["id"])
    assert fetched["secret_enc"] == sealed
    assert webhooks.open_secret(
        fetched["secret_enc"], kek=KEK.encode(), org_id=org.id) == secret


# -- URL policy ---------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://hooks.example.test/x",
    "http://127.0.0.1:9000/hook",
    "http://[::1]:9000/hook",
    "http://localhost:9000/hook",
])
def test_the_url_policy_accepts_https_and_loopback_http(url):
    assert webhooks.validate_url(url) == url


@pytest.mark.parametrize("url", [
    "http://hooks.example.test/x",
    "ftp://hooks.example.test/x",
    "https://user:pass@hooks.example.test/x",
    "https://hooks.example.test/x#fragment",
    "https:///nohost",
    "",
    None,
])
def test_the_url_policy_refuses_plain_http_off_loopback_and_userinfo(url):
    with pytest.raises(webhooks.WebhookError):
        webhooks.validate_url(url)


@pytest.mark.parametrize("url", [
    "https://169.254.169.254/latest/meta-data",
    "https://10.0.0.5/hook",
    "https://192.168.1.10/hook",
    "https://172.16.0.1/hook",
    "https://[fd00::1]/hook",
    "https://[fe80::1]/hook",
    "https://metadata.google.internal/computeMetadata/v1/",
    "https://service.internal/hook",
])
def test_the_url_policy_refuses_private_link_local_and_metadata_targets(url):
    with pytest.raises(webhooks.WebhookError):
        webhooks.validate_url(url)


def test_a_name_that_resolves_private_is_refused(monkeypatch):
    def private(*_args, **_kwargs):
        return [(2, 1, 6, "", ("10.1.2.3", 0))]

    monkeypatch.setattr(webhooks.socket, "getaddrinfo", private)
    with pytest.raises(webhooks.WebhookError):
        webhooks.validate_url("https://hooks.example.test/interlock")


def test_a_name_that_resolves_public_is_accepted(monkeypatch):
    def public(*_args, **_kwargs):
        return [(2, 1, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(webhooks.socket, "getaddrinfo", public)
    assert webhooks.validate_url("https://hooks.example.test/interlock") == (
        "https://hooks.example.test/interlock")


def test_events_are_a_closed_list_and_are_de_duplicated_in_order():
    assert webhooks.validate_events(
        ["review.created", "grant.issued", "review.created"]
    ) == ["review.created", "grant.issued"]
    with pytest.raises(webhooks.WebhookError):
        webhooks.validate_events(["review.created", "review.exploded"])
    with pytest.raises(webhooks.WebhookError):
        webhooks.validate_events([])


# -- payload privacy ----------------------------------------------------

def test_a_payload_carries_only_ids_statuses_and_counts():
    payload = webhooks.build_payload("review.created", {
        "review_id": "rev-1", "count": 2, "status": "pending",
        "at": NOW,
    })
    assert payload == {
        "event": "review.created", "review_id": "rev-1", "count": 2,
        "status": "pending", "at": NOW,
    }
    with pytest.raises(webhooks.WebhookError):
        webhooks.build_payload("review.created", {"preview": "secret text"})
    with pytest.raises(webhooks.WebhookError):
        webhooks.build_payload("review.created", {"args": {"cmd": "rm -rf"}})
    with pytest.raises(webhooks.WebhookError):
        webhooks.build_payload("review.created", {"preview_text": "x"})
    with pytest.raises(webhooks.WebhookError):
        webhooks.build_payload("review.created", {"review_id": {"nested": 1}})


def test_a_payload_refuses_an_overlong_value_and_an_unknown_event():
    with pytest.raises(webhooks.WebhookError):
        webhooks.build_payload("review.created", {"review_id": "x" * 201})
    with pytest.raises(webhooks.WebhookError):
        webhooks.build_payload("not.an.event", {})


def test_emit_swallows_a_bad_payload_and_writes_nothing():
    env = make_app()
    env.session.step_up_at = NOW
    _webhook(env)
    assert webhooks.emit(env.store, env.org.id, "review.created",
                         {"preview": "secret"}, now=NOW) == 0
    assert env.store.webhook_due(env.org.id, NOW) == []


# -- retry and redirect policy -----------------------------------------

def test_the_retry_ladder_is_one_second_to_two_hours_then_repeats():
    assert [webhooks.delivery_plan(500, attempt) for attempt in range(8)] == [
        1.0, 5.0, 30.0, 300.0, 1800.0, 7200.0, 7200.0, 7200.0,
    ]


@pytest.mark.parametrize("status", [200, 201, 204, 301, 302, 400, 401, 404,
                                    410, 422])
def test_success_redirect_and_permanent_4xx_are_final(status):
    assert webhooks.delivery_plan(status, 0) is None


@pytest.mark.parametrize("status", [0, 408, 429, 500, 502, 503])
def test_transport_failure_408_429_and_5xx_retry(status):
    assert webhooks.delivery_plan(status, 0) == 1.0


def test_retry_after_wins_and_is_capped_at_the_last_ladder_step():
    assert webhooks.delivery_plan(429, 0, retry_after=12) == 12.0
    assert webhooks.delivery_plan(503, 0, retry_after=99999) == 7200.0
    assert webhooks.delivery_plan(503, 0, retry_after="soon") == 1.0


def test_a_redirect_is_never_followed_by_the_transport():
    handler = transport._NoRedirect()
    assert handler.redirect_request(
        None, None, 302, "Found", {}, "https://elsewhere.test") is None


# -- routes -------------------------------------------------------------

def test_registering_a_webhook_requires_a_fresh_step_up():
    env = make_app()
    status, _headers, body, _raw = post_json(
        env, "/v1/webhooks", env.headers,
        {"url": URL, "events": ["review.created"]})
    assert status == 403
    assert body["error"]["code"] == "step_up_required"


def test_the_secret_is_returned_once_and_never_listed_again():
    env = make_app()
    env.session.step_up_at = NOW
    _webhook(env)

    status, _headers, listed, _raw = call(
        env.app, "/v1/webhooks", headers=env.headers)
    assert status == 200
    text = str(listed)
    assert SECRET not in text
    assert "secret" not in listed["webhooks"][0]
    assert "secret_hash" not in listed["webhooks"][0]
    assert "secret_enc" not in listed["webhooks"][0]


def test_registration_refuses_plain_http_off_loopback_and_unknown_events():
    env = make_app()
    env.session.step_up_at = NOW
    status, _headers, body, _raw = post_json(
        env, "/v1/webhooks", env.headers,
        {"url": "http://hooks.example.test/x", "events": ["review.created"]})
    assert status == 422
    status, _headers, body, _raw = post_json(
        env, "/v1/webhooks", env.headers,
        {"url": URL, "events": ["review.exploded"]})
    assert status == 422


def test_registration_without_a_kek_is_503_not_a_plaintext_fallback():
    import dataclasses

    env = make_app()
    env.session.step_up_at = NOW
    env.app._preview_kek = None
    env.app.config = dataclasses.replace(env.app.config, preview_kek="")
    status, _headers, body, _raw = post_json(
        env, "/v1/webhooks", env.headers,
        {"url": URL, "events": ["review.created"]})
    assert status == 503
    assert body["error"]["code"] == "webhooks_unconfigured"


# -- delivery -----------------------------------------------------------

def test_a_delivery_signs_the_body_and_records_status_duration_and_digest(
        monkeypatch):
    monkeypatch.setattr(transport, "UrllibTransport", _RecordingTransport)
    env = make_app()
    env.session.step_up_at = NOW
    webhook = _webhook(env)
    assert _emit(env) == 1
    due = env.store.webhook_due(env.org.id, NOW)
    assert len(due) == 1

    update = webhooks._deliver_once(env.app, due[0])
    assert update["status"] == "delivered"
    assert update["attempts"] == 1
    assert update["response_status"] == 200
    assert update["delivered_at"] == NOW
    assert update["duration_ms"] >= 0
    assert update["body_digest"] == hashlib.sha256(b'{"ok":true}').hexdigest()
    assert update["next_attempt"] is None

    sent = _RecordingTransport.calls[0]
    assert sent["method"] == "POST"
    assert sent["url"] == URL
    assert sent["timeout"] == webhooks.DELIVERY_TIMEOUT
    header = sent["headers"][webhooks.SIGNATURE_HEADER]
    assert webhooks.verify_delivery(
        SECRET.encode("utf-8"), sent["body"], header, now=NOW)

    env.store.webhook_update_delivery(env.org.id, due[0]["id"], **update)
    listed = env.store.webhook_list_endpoints(env.org.id)[0]
    assert listed["id"] == webhook["id"]
    assert listed["pending"] == 0
    assert listed["failures"] == 0
    assert listed["last_delivery"] is not None


def test_the_outgoing_payload_has_no_preview_or_arguments(monkeypatch):
    monkeypatch.setattr(transport, "UrllibTransport", _RecordingTransport)
    env = make_app()
    env.session.step_up_at = NOW
    _webhook(env)
    _emit(env, data={"review_id": "rev-1", "count": 1, "preview": "no"})
    # emit builds the payload first, so this call wrote nothing.
    assert env.store.webhook_due(env.org.id, NOW) == []

    _emit(env)
    row = env.store.webhook_due(env.org.id, NOW)[0]
    webhooks._deliver_once(env.app, row)
    body = _RecordingTransport.calls[-1]["body"].decode("utf-8")
    assert "preview" not in body and "args" not in body
    assert "rev-1" in body


def test_a_permanent_failure_is_not_retried_and_a_5xx_is(monkeypatch):
    monkeypatch.setattr(transport, "UrllibTransport", _RecordingTransport)
    env = make_app()
    env.session.step_up_at = NOW
    _webhook(env)
    _emit(env)
    row = env.store.webhook_due(env.org.id, NOW)[0]

    _RecordingTransport.response = (404, {}, b"no")
    update = webhooks._deliver_once(env.app, row)
    assert update["status"] == "failed"
    assert update["next_attempt"] is None

    _RecordingTransport.response = (503, {"retry-after": "12"}, b"later")
    update = webhooks._deliver_once(env.app, row)
    assert update["status"] == "pending"
    assert update["next_attempt"] == NOW + 12.0


def test_a_3xx_is_a_final_failure_never_a_followed_redirect(monkeypatch):
    monkeypatch.setattr(transport, "UrllibTransport", _RecordingTransport)
    env = make_app()
    env.session.step_up_at = NOW
    _webhook(env)
    _emit(env)
    row = env.store.webhook_due(env.org.id, NOW)[0]
    _RecordingTransport.response = (302, {"location": "https://elsewhere.test"}, b"")
    update = webhooks._deliver_once(env.app, row)
    assert update["status"] == "failed"
    assert update["next_attempt"] is None
    assert len(_RecordingTransport.calls) == 1


def test_retrying_stops_after_the_twenty_four_hour_horizon(monkeypatch):
    """FR-060 bounds retrying at 24 hours; the ladder alone repeats forever."""
    monkeypatch.setattr(transport, "UrllibTransport", _RecordingTransport)
    env = make_app()
    env.session.step_up_at = NOW
    _webhook(env)
    _emit(env)
    row = env.store.webhook_due(env.org.id, NOW)[0]
    _RecordingTransport.response = (503, {}, b"later")

    fresh = webhooks._deliver_once(env.app, dict(row))
    assert fresh["status"] == "pending"

    stale = dict(row)
    stale["created"] = NOW - webhooks.RETRY_HORIZON
    update = webhooks._deliver_once(env.app, stale)
    assert update["status"] == "failed"
    assert update["next_attempt"] is None
    assert update["last_error"] == "retry horizon reached"


def test_a_disabled_endpoint_stops_new_fanout_and_pending_deliveries(monkeypatch):
    monkeypatch.setattr(transport, "UrllibTransport", _RecordingTransport)
    env = make_app()
    env.session.step_up_at = NOW
    webhook = _webhook(env)
    assert _emit(env) == 1
    row = env.store.webhook_due(env.org.id, NOW)[0]

    status, _headers, body, _raw = call(
        env.app, "/v1/webhooks/" + webhook["id"], method="DELETE",
        headers=env.headers)
    assert status == 200 and body["disabled"] is True

    assert _emit(env) == 0
    update = webhooks._deliver_once(env.app, row)
    assert update["status"] == "failed"
    assert update["last_error"] == "endpoint disabled"
    assert _RecordingTransport.calls == []

    history, _cursor = env.store.webhook_deliveries(
        env.org.id, webhook["id"], limit=10)
    assert len(history) == 1


def test_delivery_history_is_metadata_only(monkeypatch):
    monkeypatch.setattr(transport, "UrllibTransport", _RecordingTransport)
    env = make_app()
    env.session.step_up_at = NOW
    webhook = _webhook(env)
    _emit(env)
    row = env.store.webhook_due(env.org.id, NOW)[0]
    update = webhooks._deliver_once(env.app, row)
    env.store.webhook_update_delivery(env.org.id, row["id"], **update)

    status, _headers, body, _raw = call(
        env.app, "/v1/webhooks/{}/deliveries".format(webhook["id"]),
        headers=env.headers)
    assert status == 200, body
    delivery = body["deliveries"][0]
    assert delivery["body_digest"] == update["body_digest"]
    assert delivery["duration_ms"] == update["duration_ms"]
    assert "payload" not in delivery and "body" not in delivery
    assert "secret_enc" not in body["webhook"]
    assert "secret_hash" not in body["webhook"]


def test_delivery_listing_refuses_a_foreign_or_unknown_endpoint():
    env = make_app()
    status, _headers, body, _raw = call(
        env.app, "/v1/webhooks/wh_missing/deliveries", headers=env.headers)
    assert status == 404


def test_drain_once_processes_a_due_row(monkeypatch):
    import asyncio

    monkeypatch.setattr(transport, "UrllibTransport", _RecordingTransport)
    env = make_app()
    env.session.step_up_at = NOW
    _webhook(env)
    _emit(env)
    assert asyncio.run(webhooks.drain_once(env.app, now=NOW)) == 1
    rows, _cursor = env.store.webhook_deliveries(
        env.org.id, env.store.webhook_list_endpoints(env.org.id)[0]["id"])
    assert rows[0]["status"] == "delivered"


# -- workers skip deleted orgs -----------------------------------------

def test_a_deleted_org_is_never_drained(monkeypatch):
    import asyncio

    monkeypatch.setattr(transport, "UrllibTransport", _RecordingTransport)
    env = make_app()
    env.session.step_up_at = NOW
    _webhook(env)
    _emit(env)
    env.store.org_tombstone(env.org.id, now=NOW)
    assert asyncio.run(webhooks.drain_once(env.app, now=NOW)) == 0
    assert _RecordingTransport.calls == []
