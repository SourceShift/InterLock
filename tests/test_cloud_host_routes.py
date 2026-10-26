"""The C2 HTTP surface: mint, enroll, heartbeat, fleet, rotate and revoke.

Enrollment is the only public route. The heartbeat is an *agent* route with an
exact literal path, so ``/v1/hosts/self`` never folds onto the human
``/v1/hosts/{id}`` permission. Rotation and revocation are admin actions with
a fresh step-up; a revocation is read from the row on every request, so the
next heartbeat is ``410 revoked`` with no cache to wait out.
"""
from __future__ import annotations

import asyncio
import datetime
import json

import pytest

from interlock.cloud.auth import rbac
from interlock.cloud.auth.agent import AgentAuthError, agent_authenticate
from interlock.cloud.enrollment import parse_agent_key
from interlock.cloud.identity import generate_host_seed, key_id, public_key_hex
from interlock.cloud.store import MemoryStore


class _Clock:
    def __init__(self, value=2_000_000_000.0):
        self.value = float(value)

    def __call__(self):
        return self.value


def _call(instance, path, method="GET", headers=None, body=b""):
    sent = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": path,
        "raw_path": path.encode(), "query_string": b"",
        "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": ("127.0.0.1", 1234), "server": ("127.0.0.1", 8787),
    }
    asyncio.run(instance(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in sent
                   if m["type"] == "http.response.body")
    return start["status"], json.loads(raw) if raw else None


def _setup(role="admin"):
    from interlock.cloud.app import CloudApp
    from interlock.cloud.config import CloudConfig

    clock = _Clock()
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


def _post(app, path, headers, body=None):
    return _call(app, path, method="POST", headers=headers,
                 body=json.dumps(body or {}).encode())


def _enroll(app, headers):
    status, minted = _post(app, "/v1/admin/enrollment-tokens", headers,
                           {"host_name": "box"})
    assert status == 201
    seed = generate_host_seed()
    public_hex = public_key_hex(seed)
    status, payload = _call(
        app, "/v1/enroll", method="POST",
        headers={"content-type": "application/json"},
        body=json.dumps({
            "token": minted["token"],
            "host_name": "box",
            "host_public_key": public_hex,
            "host_key_id": key_id(public_hex),
            "connector_version": "test",
        }).encode(),
    )
    assert status == 201
    return payload, minted, public_hex


def _agent_headers(org, raw_key):
    return {
        "authorization": "Bearer " + raw_key,
        "x-interlock-org": org.id,
        "content-type": "application/json",
    }


def _step_up(app, session, clock):
    app.sessions.mark_step_up(session, "webauthn", now=clock.value)
    return session


# -- fleet --------------------------------------------------------------

def test_fleet_lists_hosts_with_keys_versions_and_no_secrets():
    app, _store, _org, _user, _session, headers, _clock = _setup()
    enrolled, _token, public_hex = _enroll(app, headers)

    status, payload = _call(app, "/v1/hosts", headers=headers)

    assert status == 200
    assert len(payload["hosts"]) == 1
    host = payload["hosts"][0]
    assert host["id"] == enrolled["host_id"]
    assert host["name"] == "box"
    assert host["state"] == "active"
    assert host["public_keys"] == [{"id": key_id(public_hex),
                                    "public_key": public_hex}]
    assert host["key_ids"] == [enrolled["agent_key_id"]]
    assert host["keys_version"] == 1
    assert host["revoked"] is False
    assert host["last_seen"] is None
    assert set(host["keys"][0]) == {
        "id", "prefix", "host_id", "scopes", "expires_at", "revoked_at",
        "revoked",
    }
    assert enrolled["agent_key"] not in json.dumps(payload)


@pytest.mark.parametrize("role", ["reviewer", "auditor"])
def test_fleet_is_admin_only(role):
    app, _store, _org, _user, _session, headers, _clock = _setup(role)
    status, payload = _call(app, "/v1/hosts", headers=headers)
    assert status == 403
    assert payload["error"]["code"] == "forbidden"


def test_get_host_returns_one_host_and_hides_foreign_ids():
    app, store, org, _user, _session, headers, _clock = _setup()
    enrolled, _token, _public = _enroll(app, headers)

    status, payload = _call(app, "/v1/hosts/" + enrolled["host_id"],
                            headers=headers)
    assert status == 200
    assert payload["host"]["id"] == enrolled["host_id"]

    foreign_org = store.create_org(slug="other", name="Other")
    foreign = store.create_host(foreign_org.id, "foreign", owner_subject="x")
    status, payload = _call(app, "/v1/hosts/" + foreign.id, headers=headers)
    assert status == 404
    assert payload["error"]["code"] == "not_found"

    status, payload = _call(app, "/v1/hosts/host_missing", headers=headers)
    assert status == 404


# -- heartbeat ----------------------------------------------------------

def test_heartbeat_updates_last_seen_and_reports_the_key_version():
    app, store, org, _user, _session, _headers, clock = _setup()
    enrolled, _token, _public = _enroll(app, _headers)

    status, payload = _post(
        app, "/v1/hosts/self", _agent_headers(org, enrolled["agent_key"]),
        {"connector_version": "test", "spool_depth": 0, "cursor": 0})

    assert status == 200
    assert payload["host_id"] == enrolled["host_id"]
    assert payload["server_time"] == clock.value
    assert payload["keys_version"] == 1
    assert payload["poll_after"] == 300
    assert store.host_by_id(org.id, enrolled["host_id"]).last_seen == clock.value


def test_heartbeat_is_an_agent_route_not_a_session_route():
    app, _store, _org, _user, _session, headers, _clock = _setup()

    status, payload = _post(app, "/v1/hosts/self", headers)

    assert status == 403
    assert payload["error"]["code"] == "forbidden"
    assert ("POST", "/v1/hosts/self") not in rbac.PERMISSIONS
    assert rbac.agent_route("POST", "/v1/hosts/self") == (
        "POST", "/v1/hosts/self")
    assert rbac.agent_route("GET", "/v1/hosts/self") is None
    assert rbac.agent_route("POST", "/v1/hosts/123") is None


def test_heartbeat_rejects_a_malformed_bearer():
    app, _store, org, _user, _session, _headers, _clock = _setup()
    status, payload = _post(
        app, "/v1/hosts/self",
        {"authorization": "Bearer not-a-key", "x-interlock-org": org.id})
    assert status == 401
    assert payload["error"]["code"] == "unauthenticated"


# -- rotation -----------------------------------------------------------

def test_rotation_requires_a_fresh_step_up():
    app, store, org, _user, _session, headers, _clock = _setup()
    enrolled, _token, _public = _enroll(app, headers)

    status, payload = _post(app, "/v1/keys", headers,
                            {"host_id": enrolled["host_id"]})

    assert status == 403
    assert payload["error"]["code"] == "step_up_required"
    assert len(store.list_agent_keys(org.id, enrolled["host_id"])) == 1


def test_rotation_issues_a_new_key_and_retires_the_old_one_after_24_hours():
    app, store, org, _user, session, headers, clock = _setup()
    enrolled, _token, _public = _enroll(app, headers)
    _step_up(app, session, clock)

    status, payload = _post(app, "/v1/keys", headers,
                            {"host_id": enrolled["host_id"]})

    assert status == 201
    assert payload["keys_version"] == 2
    assert payload["host_id"] == enrolled["host_id"]
    assert parse_agent_key(payload["agent_key"]) is not None
    retire_at = datetime.datetime.fromisoformat(
        payload["previous_keys_expire_at"]).timestamp()
    assert retire_at == pytest.approx(clock.value + 24 * 60 * 60)

    keys = {key.id: key for key in
            store.list_agent_keys(org.id, enrolled["host_id"])}
    old = keys[enrolled["agent_key_id"]]
    assert old.expires == clock.value + 24 * 60 * 60
    assert keys[payload["agent_key_id"]].expires is None

    # The overlap is real: both keys authenticate during it.
    for raw in (enrolled["agent_key"], payload["agent_key"]):
        assert agent_authenticate(store, raw).host_id == enrolled["host_id"]
    # And the predecessor stops exactly at its expiry.
    with pytest.raises(AgentAuthError):
        agent_authenticate(store, enrolled["agent_key"],
                           now=clock.value + 24 * 60 * 60 + 1)


def test_rotation_scopes_can_be_narrowed_but_not_invented():
    app, _store, _org, _user, session, headers, clock = _setup()
    enrolled, _token, _public = _enroll(app, headers)
    _step_up(app, session, clock)

    status, _payload = _post(app, "/v1/keys", headers, {
        "host_id": enrolled["host_id"], "scopes": ["poll:grants"]})
    assert status == 201

    status, payload = _post(app, "/v1/keys", headers, {
        "host_id": enrolled["host_id"], "scopes": ["root:everything"]})
    assert status == 422
    assert payload["error"]["code"] == "invalid_request"


def test_rotation_of_an_unknown_host_is_404():
    app, _store, _org, _user, session, headers, clock = _setup()
    _step_up(app, session, clock)
    status, payload = _post(app, "/v1/keys", headers, {"host_id": "host_x"})
    assert status == 404
    assert payload["error"]["code"] == "not_found"


# -- revocation ---------------------------------------------------------

def test_revocation_is_immediate_on_the_next_heartbeat():
    app, store, org, _user, session, headers, clock = _setup()
    enrolled, _token, _public = _enroll(app, headers)
    _step_up(app, session, clock)

    status, payload = _post(
        app, "/v1/keys/{}/revoke".format(enrolled["agent_key_id"]), headers)

    assert status == 200
    assert payload["revoked"] is True
    assert payload["keys_version"] == 2
    assert payload["revoked_at"] is not None

    status, payload = _post(
        app, "/v1/hosts/self", _agent_headers(org, enrolled["agent_key"]))
    assert status == 410
    assert payload["error"]["code"] == "revoked"

    status, fleet = _call(app, "/v1/hosts", headers=headers)
    assert status == 200
    assert fleet["hosts"][0]["revoked"] is True


def test_revocation_requires_step_up_and_a_known_key():
    app, _store, _org, _user, _session, headers, _clock = _setup()
    enrolled, _token, _public = _enroll(app, headers)
    path = "/v1/keys/{}/revoke".format(enrolled["agent_key_id"])

    status, payload = _post(app, path, headers)
    assert status == 403
    assert payload["error"]["code"] == "step_up_required"

    _step_up(app, _session, _clock)
    status, payload = _post(app, "/v1/keys/key_missing/revoke", headers)
    assert status == 404
    assert payload["error"]["code"] == "not_found"


def test_revoking_twice_is_idempotent():
    app, store, org, _user, session, headers, clock = _setup()
    enrolled, _token, _public = _enroll(app, headers)
    _step_up(app, session, clock)
    path = "/v1/keys/{}/revoke".format(enrolled["agent_key_id"])

    first_status, first = _post(app, path, headers)
    second_status, second = _post(app, path, headers)

    assert (first_status, second_status) == (200, 200)
    assert first["revoked_at"] == second["revoked_at"]
    assert second["keys_version"] == 2
    assert len(store.list_agent_keys(org.id, enrolled["host_id"])) == 1


def test_revocation_is_audited_without_the_key_value():
    app, store, org, _user, session, headers, clock = _setup()
    enrolled, _token, _public = _enroll(app, headers)
    _step_up(app, session, clock)
    _post(app, "/v1/keys/{}/revoke".format(enrolled["agent_key_id"]), headers)

    entries = [entry for entry in store.audit_list(org.id)
               if entry.event == "agent_key.revoked"]
    assert len(entries) == 1
    assert entries[0].detail["agent_key_id"] == enrolled["agent_key_id"]
    assert enrolled["agent_key"] not in json.dumps(entries[0].public())
