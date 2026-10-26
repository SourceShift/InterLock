"""Cross-org probes: a foreign id is 404, never 403, and never writes."""
from __future__ import annotations

import asyncio
import json
import os
import uuid

import pytest

from interlock.cloud.app import CloudApp
from interlock.cloud.config import CloudConfig
from interlock.cloud.store import CrossOrgAccess, MemoryStore, PostgresStore

DSN = os.environ.get("IL_CLOUD_TEST_DSN")


def _memory_store():
    return MemoryStore()


def _postgres_store():
    return PostgresStore(DSN)


CASES = [pytest.param("memory", _memory_store, id="memory")]
if DSN:
    CASES.append(pytest.param("postgres", _postgres_store, id="postgres"))


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


def _seed(factory):
    suffix = uuid.uuid4().hex[:12]
    store = factory()
    org_a = store.create_org(slug="a-" + suffix, name="Org A")
    org_b = store.create_org(slug="b-" + suffix, name="Org B")
    admin = store.create_user(org_a, issuer="https://idp.example",
                              subject="a-admin", email="admin@a.test",
                              role="admin")
    foreign = store.create_user(org_b, issuer="https://idp.example",
                                subject="b-user", email="user@b.test",
                                role="owner")
    app = CloudApp(CloudConfig(session_secret="s" * 32), store=store,
                   ping=lambda dsn: True)
    raw = app.sessions.login(admin)
    session = store.session_by_token_hash(app.sessions.hash(raw),
                                          org_id=org_a.id)
    headers = {
        "cookie": "__Host-il_session=" + app.sessions.cookie_value(org_a.id, raw),
        "x-csrf-token": app.sessions.csrf_token(session.id),
        "content-type": "application/json",
    }
    return store, org_a, org_b, admin, foreign, app, headers


@pytest.mark.parametrize("name,factory", CASES)
def test_foreign_member_patch_is_404_and_writes_nothing(name, factory):
    store, org_a, org_b, _admin, foreign, app, headers = _seed(factory)
    status, _single, payload = _call(
        app, "/v1/members/" + foreign.id, method="PATCH", headers=headers,
        body=json.dumps({"role": "auditor"}).encode(),
    )
    assert status == 404, name
    assert payload["error"]["code"] == "not_found"
    still = store.user_by_id(org_b.id, foreign.id)
    assert still is not None and still.role == "owner"
    assert not [entry for entry in store.audit_list(org_a.id)
                if entry.event == "member.updated"]


@pytest.mark.parametrize("name,factory", CASES)
def test_foreign_member_delete_is_404_and_writes_nothing(name, factory):
    store, org_a, _org_b, _admin, foreign, app, headers = _seed(factory)
    status, _single, payload = _call(
        app, "/v1/members/" + foreign.id, method="DELETE", headers=headers,
    )
    assert status == 404, name
    assert payload["error"]["code"] == "not_found"
    assert store.user_by_id(foreign.org_id, foreign.id) is not None


@pytest.mark.parametrize("name,factory", CASES)
def test_missing_member_id_is_404_not_403(name, factory):
    _store, _org_a, _org_b, _admin, _foreign, app, headers = _seed(factory)
    status, _single, payload = _call(
        app, "/v1/members/does-not-exist", method="DELETE", headers=headers,
    )
    assert status == 404, name
    assert payload["error"]["code"] == "not_found"


@pytest.mark.parametrize("name,factory", CASES)
def test_member_list_never_crosses_the_org_boundary(name, factory):
    _store, org_a, _org_b, admin, foreign, app, headers = _seed(factory)
    status, _single, payload = _call(app, "/v1/members", headers=headers)
    assert status == 200, name
    ids = [member["id"] for member in payload["members"]]
    assert admin.id in ids
    assert foreign.id not in ids


@pytest.mark.parametrize("name,factory", CASES)
def test_org_view_is_the_callers_org(name, factory):
    _store, org_a, org_b, _admin, _foreign, app, headers = _seed(factory)
    status, _single, payload = _call(app, "/v1/org", headers=headers)
    assert status == 200, name
    assert payload["slug"] == org_a.slug
    assert payload["slug"] != org_b.slug


def test_memory_store_raises_cross_org_access_on_a_direct_read():
    store = MemoryStore()
    org_a = store.create_org(slug="a", name="A")
    org_b = store.create_org(slug="b", name="B")
    user = store.create_user(org_a, issuer="i", subject="s", role="admin")
    with pytest.raises(CrossOrgAccess):
        store.user_by_id(org_b.id, user.id)
