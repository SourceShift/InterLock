"""Single-use enrollment: token shape, storage, and the ``/v1/enroll`` route.

The token is ``ilkt_<org id>_<secret>``; only its SHA-256 is stored, and the
one atomic claim is a conditional update that reports whether it won. The route
turns a valid token into exactly one host with exactly one scoped agent key,
and hands both secrets back exactly once.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from interlock.cloud.enrollment import (
    AGENT_SCOPES,
    generate_agent_key,
    hash_token,
    parse_agent_key,
)
from interlock.cloud.identity import generate_host_seed, key_id, public_key_hex
from interlock.cloud.store import MemoryStore


# -- helpers ------------------------------------------------------------

def _call(instance, path, method="GET", headers=None, body=b"", query=b""):
    sent = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": path,
        "raw_path": path.encode(), "query_string": query,
        "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": ("127.0.0.1", 1234), "server": ("127.0.0.1", 8787),
    }
    asyncio.run(instance(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    single = {}
    for name, value in start["headers"]:
        single.setdefault(name.decode(), value.decode())
    raw = b"".join(m.get("body", b"") for m in sent
                   if m["type"] == "http.response.body")
    payload = json.loads(raw) if raw else None
    return start["status"], single, payload


class _Clock:
    def __init__(self, value=1000.0):
        self.value = float(value)

    def __call__(self):
        return self.value


def _setup(role="admin", clock=None):
    from interlock.cloud.app import CloudApp
    from interlock.cloud.config import CloudConfig

    clock = clock or _Clock()
    store = MemoryStore()
    org = store.create_org(slug="acme", name="Acme")
    user = store.create_user(org, issuer="https://idp.example",
                             subject="u1", email="a@acme.test", role=role)
    app = CloudApp(CloudConfig(session_secret="s" * 32), store=store,
                   ping=lambda dsn: True, clock=clock)
    raw = app.sessions.login(user)
    session = store.session_by_token_hash(app.sessions.hash(raw),
                                          org_id=org.id)
    headers = {
        "cookie": "__Host-il_session=" + app.sessions.cookie_value(org.id, raw),
        "x-csrf-token": app.sessions.csrf_token(session.id),
        "content-type": "application/json",
    }
    return app, store, org, user, session, headers, clock


def _mint(app, headers, **body):
    status, _headers, payload = _call(
        app, "/v1/admin/enrollment-tokens", method="POST", headers=headers,
        body=json.dumps(body).encode(),
    )
    return status, payload


def _enroll_body(token, *, seed=None, public_hex=None, host_key_id=None):
    seed = seed or generate_host_seed()
    public_hex = public_hex or public_key_hex(seed)
    return {
        "token": token,
        "host_name": "box",
        "host_public_key": public_hex,
        "host_key_id": host_key_id or key_id(public_hex),
        "connector_version": "test",
    }


# -- the two credential formats ----------------------------------------

def test_enrollment_token_carries_its_org_and_stores_only_the_hash():
    store = MemoryStore()
    org = store.create_org(slug="acme", name="Acme")

    token_id, raw = store.create_enrollment_token(org.id, "box", ttl=120)

    assert raw.startswith("ilkt_" + org.id + "_")
    stored = store.enrollment_token_by_id(org.id, token_id)
    assert stored.token_hash == hash_token(raw)
    assert stored.token_hash != raw
    public = stored.public()
    assert set(public) == {"id", "host_name", "expires_at", "used"}
    assert public["id"] == token_id
    assert public["host_name"] == "box"
    assert public["used"] is False
    assert "token" not in public and "token_hash" not in public


def test_token_is_single_use_at_the_store_layer():
    store = MemoryStore()
    org = store.create_org(slug="acme", name="Acme")
    token_id, raw = store.create_enrollment_token(org.id, now=1000.0, ttl=60)

    first = store.consume_enrollment_token(raw, now=1001.0)
    assert first is not None and first.id == token_id
    assert store.consume_enrollment_token(raw, now=1002.0) is None
    assert store.enrollment_token_by_id(org.id, token_id).used_at == 1001.0


def test_expired_token_is_not_consumed():
    store = MemoryStore()
    org = store.create_org(slug="acme", name="Acme")
    _token_id, raw = store.create_enrollment_token(org.id, now=1000.0, ttl=60)

    assert store.consume_enrollment_token(raw, now=1060.0) is None


def test_malformed_token_is_not_consumed():
    store = MemoryStore()
    for raw in ("", "nope", "ilkt_", "ilkt_only-org", "ilkt__secret", None):
        assert store.consume_enrollment_token(raw) is None


def test_a_similar_token_in_another_org_does_not_match():
    store = MemoryStore()
    org_a = store.create_org(slug="a", name="A")
    org_b = store.create_org(slug="b", name="B")
    _token_id, raw = store.create_enrollment_token(org_a.id)
    forged = raw.replace(org_a.id, org_b.id, 1)

    assert store.consume_enrollment_token(forged) is None
    assert store.consume_enrollment_token(raw) is not None


def test_agent_key_has_the_fixed_shape_and_a_sha256_hash():
    raw, prefix, digest = generate_agent_key()

    parsed = parse_agent_key(raw)
    assert parsed == (prefix, raw)
    # token_hex(4) is lowercase hex, but a digit-only draw is still valid and
    # ".islower()" is False for "89714827" — assert the alphabet, not the case.
    assert len(prefix) == 8 and all(c in "0123456789abcdef" for c in prefix)
    assert len(raw) == len("ilk_") + 8 + 1 + 43
    assert digest == hash_token(raw)
    assert raw not in digest


def test_a_digit_only_prefix_is_still_a_valid_agent_key(monkeypatch):
    """Regression: token_hex(4) can draw only digits, and "89714827".islower()
    is False while the key is perfectly valid."""
    monkeypatch.setattr("interlock.cloud.enrollment.secrets.token_hex",
                        lambda n: "89714827")
    raw, prefix, _digest = generate_agent_key()

    assert prefix == "89714827"
    assert parse_agent_key(raw) == (prefix, raw)


@pytest.mark.parametrize("raw", [
    "",
    "ilk_",
    "not-an-agent-key",
    "ilkt_0123abcd_" + "A" * 43,
    "ilk_0123ABCD_" + "A" * 43,
    "ilk_0123abcd_" + "A" * 42,
    "ilk_0123abcd_" + "A" * 44,
    "ilk_0123abc_" + "A" * 43,
    "ilk_0123abcd_" + "A" * 42 + "!",
    None,
    b"ilk_0123abcd_" + b"A" * 43,
])
def test_parse_agent_key_rejects_anything_off_format(raw):
    assert parse_agent_key(raw) is None


# -- the admin mint route ----------------------------------------------

def test_admin_mints_a_token_and_sees_it_once():
    app, store, org, user, _session, headers, _clock = _setup()

    status, payload = _mint(app, headers, host_name="box", ttl=120)

    assert status == 201
    assert payload["token"].startswith("ilkt_" + org.id + "_")
    assert payload["host_name"] == "box"
    assert payload["id"].startswith("et_")
    stored = store.enrollment_token_by_id(org.id, payload["id"])
    assert stored.token_hash == hash_token(payload["token"])
    assert payload["token"] not in json.dumps(
        [entry.public() for entry in store.audit_list(org.id)])
    assert store.audit_list(org.id)[-1].event == "enrollment.token_created"
    assert store.audit_list(org.id)[-1].actor == user.id


def test_token_minting_requires_an_admin_role():
    app, _store, _org, _user, _session, headers, _clock = _setup("reviewer")
    status, payload = _mint(app, headers)
    assert status == 403
    assert payload["error"]["code"] == "forbidden"


def test_token_minting_requires_a_session():
    app, _store, _org, _user, _session, _headers, _clock = _setup()
    status, _headers, payload = _call(app, "/v1/admin/enrollment-tokens", method="POST",
                            headers={"content-type": "application/json"},
                            body=b"{}")
    assert status == 401
    assert payload["error"]["code"] == "unauthenticated"


@pytest.mark.parametrize("body", [
    {"ttl": 0},
    {"ttl": 59},
    {"ttl": 7 * 24 * 60 * 60 + 1},
    {"ttl": "soon"},
    {"ttl": True},
    {"host_name": ""},
    {"host_name": 5},
    {"unexpected": 1},
])
def test_token_minting_rejects_bad_input(body):
    app, _store, _org, _user, _session, headers, _clock = _setup()
    status, payload = _mint(app, headers, **body)
    assert status == 422
    assert payload["error"]["code"] == "invalid_request"


# -- the public enroll route -------------------------------------------

def test_enroll_registers_one_host_with_one_scoped_agent_key():
    app, store, org, _user, _session, headers, _clock = _setup()
    _status, minted = _mint(app, headers, host_name="minted-name")
    seed = generate_host_seed()
    public_hex = public_key_hex(seed)

    status, _headers, payload = _call(
        app, "/v1/enroll", method="POST",
        headers={"content-type": "application/json"},
        body=json.dumps(_enroll_body(minted["token"], public_hex=public_hex,
                                     host_key_id=key_id(public_hex))).encode(),
    )

    assert status == 201
    assert payload["org_id"] == org.id
    assert payload["host_id"].startswith("host_")
    assert payload["agent_key_id"].startswith("key_")
    assert payload["plane_public_keys"] == {
        "approval": "", "policy": "", "receipt": ""}
    assert payload["poll_after"] == 300
    assert parse_agent_key(payload["agent_key"]) is not None

    host = store.host_by_id(org.id, payload["host_id"])
    assert host.state == "active"
    assert host.name == "box"
    assert host.public_keys == [{"id": key_id(public_hex),
                                "public_key": public_hex}]
    assert host.owner_subject.startswith("enrollment-token:et_")

    keys = store.list_agent_keys(org.id, host.id)
    assert len(keys) == 1
    assert keys[0].id == payload["agent_key_id"]
    assert tuple(keys[0].scopes) == AGENT_SCOPES
    assert keys[0].secret_hash == hash_token(payload["agent_key"])
    assert payload["agent_key"] not in json.dumps([key.public() for key in keys])

    events = [entry.event for entry in store.audit_list(org.id)]
    assert "host.enrolled" in events
    detail = store.audit_list(org.id)[-1].detail
    assert detail["agent_key_id"] == payload["agent_key_id"]
    assert payload["agent_key"] not in json.dumps(detail)


def test_a_used_token_cannot_enroll_a_second_host():
    app, store, org, _user, _session, headers, _clock = _setup()
    _status, minted = _mint(app, headers)
    first = _enroll_body(minted["token"])
    status, _headers, _payload = _call(
        app, "/v1/enroll", method="POST",
        headers={"content-type": "application/json"},
        body=json.dumps(first).encode())
    assert status == 201

    status, _headers, payload = _call(
        app, "/v1/enroll", method="POST",
        headers={"content-type": "application/json"},
        body=json.dumps(first).encode())

    assert status == 401
    assert payload["error"]["code"] == "token_invalid"
    assert len(store.list_hosts(org.id)) == 1


def test_an_expired_token_cannot_enroll():
    app, store, org, _user, _session, headers, clock = _setup()
    status, minted = _mint(app, headers, ttl=60)
    assert status == 201

    clock.value += 61
    status, _headers, payload = _call(
        app, "/v1/enroll", method="POST",
        headers={"content-type": "application/json"},
        body=json.dumps(_enroll_body(minted["token"])).encode())

    assert status == 401
    assert payload["error"]["code"] == "token_invalid"
    assert store.list_hosts(org.id) == []


def test_enroll_needs_no_cookie_and_ignores_one():
    app, _store, _org, _user, _session, _headers, _clock = _setup()
    status, _headers, payload = _call(
        app, "/v1/enroll", method="POST",
        headers={"cookie": "__Host-il_session=whatever",
                 "content-type": "application/json"},
        body=b"{}")
    assert status == 401
    assert payload["error"]["code"] == "token_invalid"


@pytest.mark.parametrize("public_hex,submitted", [
    ("abc", None),
    ("00" * 31, None),
    ("zz" * 32, None),
    (public_key_hex(generate_host_seed()), "0" * 64),
])
def test_enroll_rejects_a_bad_or_mismatched_public_key(public_hex, submitted):
    app, _store, _org, _user, _session, headers, _clock = _setup()
    _status, minted = _mint(app, headers)
    body = {
        "token": minted["token"],
        "host_name": "box",
        "host_public_key": public_hex,
    }
    if submitted is not None:
        body["host_key_id"] = submitted
    status, _headers, payload = _call(
        app, "/v1/enroll", method="POST",
        headers={"content-type": "application/json"},
        body=json.dumps(body).encode())
    assert status == 422
    assert payload["error"]["code"] == "invalid_request"
