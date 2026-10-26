"""Org/member administration: invite, role change, disable, delete and audit."""
from __future__ import annotations

import asyncio
import json

import pytest

from interlock.cloud.app import CloudApp
from interlock.cloud.auth.sessions import Unauthenticated
from interlock.cloud.config import CloudConfig
from interlock.cloud.store import MemoryStore


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
    single, multi = {}, {}
    for name, value in start["headers"]:
        key, text = name.decode(), value.decode()
        single.setdefault(key, text)
        multi.setdefault(key, []).append(text)
    raw = b"".join(m.get("body", b"") for m in sent
                   if m["type"] == "http.response.body")
    payload = json.loads(raw) if raw else None
    return start["status"], single, multi, payload


def _setup(role="owner", oidc=None, oidc_config=False):
    store = MemoryStore()
    org = store.create_org(slug="acme", name="Acme")
    user = store.create_user(org, issuer="https://idp.example", subject="u1",
                             email="owner@acme.test", role=role)
    values = {"session_secret": "s" * 32}
    if oidc_config:
        values.update({
            "oidc_issuer": "https://idp.example",
            "oidc_client_id": "client-1",
            "oidc_redirect_uri": "https://cloud.example/v1/auth/callback",
        })
    app = CloudApp(CloudConfig(**values), store=store, oidc=oidc,
                   ping=lambda dsn: True)
    raw = app.sessions.login(user)
    session = store.session_by_token_hash(app.sessions.hash(raw))
    headers = {
        "cookie": "__Host-il_session=" + app.sessions.cookie_value(org.id, raw),
        "x-csrf-token": app.sessions.csrf_token(session.id),
        "content-type": "application/json",
    }
    return app, store, org, user, headers


def _json_body(payload):
    return json.dumps(payload).encode("utf-8")


def _page(instance, path, query=b""):
    """Fetch a server-rendered page: its body is HTML, not JSON."""
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "GET", "scheme": "http", "path": path,
        "raw_path": path.encode(), "query_string": query,
        "headers": [], "client": ("127.0.0.1", 1234),
        "server": ("127.0.0.1", 8787),
    }
    asyncio.run(instance(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    single = {}
    for name, value in start["headers"]:
        single.setdefault(name.decode(), value.decode())
    raw = b"".join(m.get("body", b"") for m in sent
                   if m["type"] == "http.response.body")
    return start["status"], single, raw


def test_invite_creates_an_invited_member_and_an_audit_row():
    app, store, org, _user, headers = _setup()
    status, _single, _multi, payload = _call(
        app, "/v1/members/invite", method="POST", headers=headers,
        body=_json_body({"email": "new@acme.test", "role": "reviewer"}),
    )
    assert status == 201
    assert payload["member"]["status"] == "invited"
    assert payload["member"]["role"] == "reviewer"
    assert payload["member"]["email"] == "new@acme.test"

    events = [entry.event for entry in store.audit_list(org.id)]
    assert "member.invited" in events


def test_role_change_is_audited_with_before_and_after_hashes():
    app, store, org, _user, headers = _setup()
    _status, _single, _multi, invited = _call(
        app, "/v1/members/invite", method="POST", headers=headers,
        body=_json_body({"email": "new@acme.test", "role": "reviewer"}),
    )
    member_id = invited["member"]["id"]

    status, _single, _multi, payload = _call(
        app, "/v1/members/" + member_id, method="PATCH", headers=headers,
        body=_json_body({"role": "admin"}),
    )
    assert status == 200
    assert payload["member"]["role"] == "admin"

    updated = [entry for entry in store.audit_list(org.id)
               if entry.event == "member.updated"]
    assert updated
    detail = updated[-1].detail
    assert detail["target"] == member_id
    assert detail["before_hash"] != detail["after_hash"]


def test_disable_revokes_the_members_sessions():
    app, store, org, _user, headers = _setup()
    member = store.create_user(org, issuer="https://idp.example",
                               subject="u2", email="b@acme.test",
                               role="reviewer")
    raw = app.sessions.login(member)

    status, _single, _multi, payload = _call(
        app, "/v1/members/" + member.id, method="PATCH", headers=headers,
        body=_json_body({"status": "disabled"}),
    )
    assert status == 200
    assert payload["member"]["status"] == "disabled"
    with pytest.raises(Unauthenticated):
        app.sessions.resolve(raw)
    assert any(entry.event == "member.updated"
               for entry in store.audit_list(org.id))


def test_delete_removes_the_member_and_revokes_sessions():
    app, store, org, _user, headers = _setup()
    member = store.create_user(org, issuer="https://idp.example",
                               subject="u3", email="c@acme.test",
                               role="reviewer")
    raw = app.sessions.login(member)

    status, _single, _multi, payload = _call(
        app, "/v1/members/" + member.id, method="DELETE", headers=headers,
    )
    assert status == 200
    assert payload == {"deleted": True}
    assert store.user_by_id(org.id, member.id) is None
    with pytest.raises(Unauthenticated):
        app.sessions.resolve(raw)
    assert any(entry.event == "member.deleted"
               for entry in store.audit_list(org.id))


def test_every_admin_mutation_writes_an_audit_row():
    app, store, org, _user, headers = _setup()
    _call(app, "/v1/members/invite", method="POST", headers=headers,
          body=_json_body({"email": "new@acme.test", "role": "auditor"}))
    events = [entry.event for entry in store.audit_list(org.id)]
    assert events == ["member.invited"]

    _call(app, "/v1/org", method="PATCH", headers=headers,
          body=_json_body({"name": "Acme Renamed"}))
    events = [entry.event for entry in store.audit_list(org.id)]
    assert events == ["member.invited", "org.updated"]


def test_login_refuses_a_protocol_relative_next():
    class FakeOIDC:
        def authorization_url(self, state, nonce, challenge):
            return "https://idp.example/authorize?state=" + state

    app, _store, _org, _user, _headers = _setup(oidc=FakeOIDC(),
                                                oidc_config=True)
    status, _single, _multi, payload = _call(
        app, "/v1/auth/login", query=b"next=//evil.example",
    )
    assert status == 422
    assert payload["error"]["code"] == "invalid_request"


def test_login_sets_short_lived_state_nonce_and_pkce_cookies():
    class FakeOIDC:
        def authorization_url(self, state, nonce, challenge):
            return "https://idp.example/authorize?state=" + state

    app, _store, _org, _user, _headers = _setup(oidc=FakeOIDC(),
                                                oidc_config=True)
    status, single, multi, _payload = _call(
        app, "/v1/auth/login", query=b"next=/v1/me",
    )
    assert status == 302
    assert single["location"].startswith("https://idp.example/authorize")
    cookies = " ".join(multi.get("set-cookie", []))
    for name in ("il_oidc_state", "il_oidc_nonce", "il_oidc_verifier",
                 "il_oidc_next"):
        assert name + "=" in cookies
    assert "HttpOnly" in cookies
    assert "Max-Age=600" in cookies


# -- the two server-rendered pages --------------------------------------

def test_the_two_pages_carry_the_documented_csp_and_no_script():
    app, _store, _org, _user, _headers = _setup()
    for path in ("/", "/login"):
        status, single, body = _page(app, path)
        assert status == 200
        assert single["content-type"] == "text/html; charset=utf-8"
        assert single["content-security-policy"] == (
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"
        )
        assert b"<script" not in body.lower()
        assert b"http://" not in body
        assert b"https://" not in body


def test_the_login_page_escapes_the_next_path():
    app, _store, _org, _user, _headers = _setup()
    status, _single, body = _page(
        app, "/login",
        query=b"next=%2Fx%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    )
    assert status == 200
    assert b"<script" not in body.lower()
    assert b"&lt;script&gt;" in body
