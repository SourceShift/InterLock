"""Agent-key authentication: prefix lookup, constant-time hash, revocation.

An agent key is not a session and not a role: it carries one host and one
scope set. The store is looked up by its public prefix, the presented key is
hashed and compared in constant time, and the row is read on every call, so a
revocation is immediate. ``410 revoked`` is distinct from ``401`` for every
other failure.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from interlock.cloud.auth.agent import (
    AgentAuthError,
    AgentRevoked,
    KeyContext,
    agent_authenticate,
    require_scope,
)
from interlock.cloud.enrollment import generate_agent_key
from interlock.cloud.store import MemoryStore


def _seed(store=None, *, scopes=None, expires=None):
    store = store or MemoryStore()
    org = store.create_org(slug="acme", name="Acme")
    host = store.create_host(org.id, "box", owner_subject="tester")
    raw, prefix, digest = generate_agent_key()
    if scopes is None:
        scopes = ["ingest:reviews", "ingest:receipts", "pull:policy",
                  "poll:grants"]
    key = store.create_agent_key(org.id, host.id, prefix=prefix,
                                 secret_hash=digest,
                                 scopes=list(scopes), expires=expires)
    return store, org, host, raw, key


# -- store-level authentication -----------------------------------------

def test_a_raw_key_authenticates_to_its_host_and_scopes():
    store, org, host, raw, key = _seed(
        scopes=["ingest:reviews", "ingest:receipts", "pull:policy",
                "poll:grants"])

    context = agent_authenticate(store, raw, now=1000.0)

    assert isinstance(context, KeyContext)
    assert context.org_id == org.id
    assert context.host_id == host.id
    assert context.key_id == key.id
    assert context.scopes == ("ingest:reviews", "ingest:receipts",
                              "pull:policy", "poll:grants")
    assert context.keys_version == 1
    assert context.host_state == "active"


def test_a_bearer_header_with_the_org_hint_is_also_accepted():
    store, org, host, raw, _key = _seed(scopes=["poll:grants"])
    context = agent_authenticate(store, {
        "authorization": "Bearer " + raw,
        "x-interlock-org": org.id,
    })
    assert context.host_id == host.id


def test_the_org_hint_selects_the_org_and_a_wrong_one_misses():
    store, org, _host, raw, _key = _seed()
    other = store.create_org(slug="other", name="Other")
    assert agent_authenticate(
        store, {"authorization": "Bearer " + raw,
                "x-interlock-org": org.id}).org_id == org.id
    with pytest.raises(AgentAuthError) as exc:
        agent_authenticate(store, {"authorization": "Bearer " + raw,
                                   "x-interlock-org": other.id})
    assert exc.value.status == 401
    assert exc.value.code == "unauthenticated"


def test_malformed_key_material_is_401_before_any_lookup():
    store, _org, _host, _raw, _key = _seed()
    for header in (None, {}, {"authorization": "Basic abc"},
                   {"authorization": "Bearer "},
                   "ilk_not-a-key"):
        with pytest.raises(AgentAuthError) as exc:
            agent_authenticate(store, header)
        assert exc.value.status == 401
        assert exc.value.code == "unauthenticated"


def test_an_unknown_prefix_is_401_not_410():
    store, _org, _host, _raw, _key = _seed()
    with pytest.raises(AgentAuthError) as exc:
        agent_authenticate(store, "ilk_00000000_" + "A" * 43)
    assert exc.value.status == 401


def test_a_wrong_secret_with_a_real_prefix_is_401():
    store, _org, _host, raw, _key = _seed()
    prefix = raw.split("_")[1]
    with pytest.raises(AgentAuthError) as exc:
        agent_authenticate(store, "ilk_{}_{}".format(prefix, "A" * 43))
    assert exc.value.status == 401
    assert exc.value.code == "unauthenticated"


def test_a_revoked_key_is_410_revoked():
    store, org, _host, raw, key = _seed()
    store.revoke_agent_key(org.id, key.id, now=1000.0)

    with pytest.raises(AgentRevoked) as exc:
        agent_authenticate(store, raw)

    assert exc.value.status == 410
    assert exc.value.code == "revoked"
    assert isinstance(exc.value, AgentAuthError)


def test_an_expired_key_is_401():
    store, _org, _host, raw, _key = _seed(expires=2000.0)
    assert agent_authenticate(store, raw, now=1999.0).host_id
    with pytest.raises(AgentAuthError) as exc:
        agent_authenticate(store, raw, now=2000.0)
    assert exc.value.status == 401


def test_a_disabled_host_is_401():
    store, org, host, raw, _key = _seed()
    store.set_host_state(org.id, host.id, "disabled")
    with pytest.raises(AgentAuthError) as exc:
        agent_authenticate(store, raw)
    assert exc.value.status == 401
    assert "not active" in str(exc.value)


def test_unknown_scopes_are_dropped_and_scope_checks_refuse():
    store, _org, _host, raw, _key = _seed(
        scopes=["ingest:reviews", "made:up"])
    context = agent_authenticate(store, raw)
    assert context.scopes == ("ingest:reviews",)
    assert context.has_scope("ingest:reviews")
    assert not context.has_scope("ingest:receipts")

    require_scope(context, "ingest:reviews")
    require_scope(context, None)
    with pytest.raises(AgentAuthError) as exc:
        require_scope(context, "ingest:receipts")
    assert exc.value.status == 403
    assert exc.value.code == "forbidden"


def test_keys_version_moves_with_rotation_and_revocation():
    store, org, host, raw, first = _seed()
    assert agent_authenticate(store, raw).keys_version == 1
    second_raw, second_prefix, second_hash = generate_agent_key()
    second = store.create_agent_key(org.id, host.id, prefix=second_prefix,
                                    secret_hash=second_hash)
    assert agent_authenticate(store, second_raw).keys_version == 2
    store.revoke_agent_key(org.id, second.id)
    assert agent_authenticate(store, raw).keys_version == 3
    # The store sorts by the random key id, not creation order: compare sets.
    assert {item.id for item in store.list_agent_keys(org.id, host.id)} == {
        first.id, second.id}


def test_postgres_refuses_an_org_less_prefix_lookup():
    from interlock.cloud.store import PostgresStore

    store = PostgresStore("postgresql://unused")
    with pytest.raises(ValueError):
        store.agent_key_by_prefix("0123abcd")


# -- through the ASGI app ------------------------------------------------

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


def _app():
    from interlock.cloud.app import CloudApp
    from interlock.cloud.config import CloudConfig

    store = MemoryStore()
    org = store.create_org(slug="acme", name="Acme")
    host = store.create_host(org.id, "box", owner_subject="tester")
    raw, prefix, digest = generate_agent_key()
    key = store.create_agent_key(org.id, host.id, prefix=prefix,
                                 secret_hash=digest,
                                 scopes=["poll:grants"])
    app = CloudApp(CloudConfig(session_secret="s" * 32), store=store,
                   ping=lambda dsn: True)
    return app, store, org, host, raw, key


def test_agent_key_reaches_its_literal_agent_route():
    app, _store, org, host, raw, _key = _app()
    status, payload = _call(
        app, "/v1/hosts/self", method="POST",
        headers={"authorization": "Bearer " + raw,
                 "x-interlock-org": org.id,
                 "content-type": "application/json"},
        body=b"{}")
    assert status == 200
    assert payload["host_id"] == host.id
    assert payload["keys_version"] == 1


def test_agent_key_on_a_human_route_is_403():
    app, _store, org, _host, raw, _key = _app()
    status, payload = _call(
        app, "/v1/org",
        headers={"authorization": "Bearer " + raw,
                 "x-interlock-org": org.id})
    assert status == 403
    assert payload["error"]["code"] == "forbidden"


def test_missing_bearer_on_an_agent_route_is_401():
    app, _store, _org, _host, _raw, _key = _app()
    status, payload = _call(app, "/v1/hosts/self", method="POST", body=b"{}")
    assert status == 401
    assert payload["error"]["code"] == "unauthenticated"


def test_a_revoked_key_gets_410_over_http():
    app, store, org, _host, raw, key = _app()
    store.revoke_agent_key(org.id, key.id)
    status, payload = _call(
        app, "/v1/hosts/self", method="POST",
        headers={"authorization": "Bearer " + raw,
                 "x-interlock-org": org.id,
                 "content-type": "application/json"},
        body=b"{}")
    assert status == 410
    assert payload["error"]["code"] == "revoked"


def test_a_bearer_on_a_public_route_is_ignored_by_the_enroll_handler():
    app, _store, _org, _host, raw, _key = _app()
    status, payload = _call(
        app, "/v1/enroll", method="POST",
        headers={"authorization": "Bearer " + raw,
                 "content-type": "application/json"},
        body=b"{}")
    assert status == 401
    assert payload["error"]["code"] == "token_invalid"
