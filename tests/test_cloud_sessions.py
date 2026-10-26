"""Server-side sessions: cookie attributes, expiry, touch throttle and CSRF."""
from __future__ import annotations

import asyncio
import json

import pytest

from interlock.cloud import http
from interlock.cloud.auth import sessions as sessions_module
from interlock.cloud.auth.sessions import (
    SessionExpired,
    SessionManager,
    Unauthenticated,
)
from interlock.cloud.store import MemoryStore


def _fixture(clock=lambda: 1000.0, **kwargs):
    store = MemoryStore()
    org = store.create_org(slug="acme", name="Acme")
    user = store.create_user(org, issuer="https://idp.example", subject="u1",
                             email="a@acme.test", role="owner")
    manager = SessionManager(store, b"k" * 32, clock=clock, **kwargs)
    return store, org, user, manager


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
    return start["status"], single, multi, payload, raw


def _app():
    from interlock.cloud.app import CloudApp
    from interlock.cloud.config import CloudConfig

    store = MemoryStore()
    org = store.create_org(slug="acme", name="Acme")
    user = store.create_user(org, issuer="https://idp.example", subject="u1",
                             email="a@acme.test", role="owner")
    app = CloudApp(CloudConfig(session_secret="s" * 32), store=store,
                   ping=lambda dsn: True)
    return store, org, user, app


# -- cookie attributes --------------------------------------------------

def test_session_cookie_has_the_fr_049_attributes_exactly():
    cookie = http.session_cookie("raw-token", 43200)
    assert cookie == (
        "__Host-il_session=raw-token; Secure; Path=/; HttpOnly; "
        "SameSite=Lax; Max-Age=43200"
    )
    assert "Domain" not in cookie


def test_csrf_cookie_is_readable_by_script_not_http_only():
    cookie = http.csrf_cookie("csrf-token", 43200)
    assert cookie.startswith("il_csrf=csrf-token; Secure; Path=/;")
    assert "HttpOnly" not in cookie
    assert "SameSite=Lax" in cookie


def test_hash_is_deterministic_and_never_the_raw_token():
    store, _org, user, manager = _fixture()
    raw = manager.login(user)
    digest = manager.hash(raw)
    assert digest == manager.hash(raw)
    assert digest != raw
    assert len(digest) == 64
    assert manager.hash_token(raw) == digest


def test_cookie_value_carries_the_org_and_keeps_the_raw_form_valid():
    store, org, user, manager = _fixture()
    raw = manager.login(user)
    value = manager.cookie_value(org.id, raw)
    assert manager.split_cookie(value) == (org.id, raw)
    assert manager.resolve_cookie(value).id == user.id
    assert manager.resolve(raw).id == user.id


# -- expiry -------------------------------------------------------------

def test_idle_expiry_deletes_the_session():
    now = [1000.0]
    store, _org, user, manager = _fixture(clock=lambda: now[0])
    raw = manager.login(user)

    now[0] = 1000.0 + manager.idle + 1
    with pytest.raises(SessionExpired):
        manager.resolve(raw)
    assert store.session_by_token_hash(manager.hash(raw)) is None


def test_absolute_expiry_deletes_the_session():
    now = [1000.0]
    store, _org, user, manager = _fixture(clock=lambda: now[0],
                                          idle=10 ** 9, absolute=100)
    raw = manager.login(user)

    now[0] = 1101.0
    with pytest.raises(SessionExpired):
        manager.resolve(raw)
    assert store.session_by_token_hash(manager.hash(raw)) is None


def test_unknown_token_is_unauthenticated():
    _store, _org, _user, manager = _fixture()
    with pytest.raises(Unauthenticated):
        manager.resolve("not-a-token")


def test_raw_token_is_never_stored_and_never_echoed():
    store, _org, user, manager = _fixture()
    raw = manager.login(user)
    session = store.session_by_token_hash(manager.hash(raw))

    # Only the SHA-256 hash is at rest; neither the raw token nor the raw
    # CSRF value appears in any stored field.
    assert session.token_hash == manager.hash(raw)
    assert raw not in repr(session)
    assert manager.csrf_token(session.id) not in repr(session)
    assert all(raw != value for value in vars(session).values())

    with pytest.raises(Unauthenticated) as exc:
        manager.resolve(raw + "tampered")
    assert raw not in str(exc.value)


def test_touch_is_throttled_to_once_a_minute():
    now = [1000.0]
    store, _org, user, manager = _fixture(clock=lambda: now[0])
    raw = manager.login(user)
    session = store.session_by_token_hash(manager.hash(raw))

    now[0] = 1030.0
    manager.resolve(raw)
    assert session.last_seen == 1000.0

    now[0] = 1060.0
    manager.resolve(raw)
    assert session.last_seen == 1060.0


# -- CSRF ---------------------------------------------------------------

def test_csrf_accepts_only_the_session_token():
    store, _org, user, manager = _fixture()
    raw = manager.login(user)
    session = store.session_by_token_hash(manager.hash(raw))
    token = manager.csrf_token(session.id)

    assert manager.check_csrf(session, token) is True
    assert manager.check_csrf(session, token + "x") is False
    assert manager.check_csrf(session, "") is False
    assert manager.check_csrf(session, None) is False


def test_csrf_uses_compare_digest(monkeypatch):
    store, _org, user, manager = _fixture()
    raw = manager.login(user)
    session = store.session_by_token_hash(manager.hash(raw))

    calls = []
    real = sessions_module.hmac.compare_digest

    def recording(left, right):
        calls.append((left, right))
        return real(left, right)

    monkeypatch.setattr(sessions_module.hmac, "compare_digest", recording)
    assert manager.check_csrf(session, manager.csrf_token(session.id))
    assert calls, "CSRF comparison must go through hmac.compare_digest"


# -- revocation ---------------------------------------------------------

def test_disable_user_revokes_every_session():
    store, org, user, manager = _fixture()
    raw_one = manager.login(user)
    raw_two = manager.login(user)

    assert manager.disable_user(org.id, user.id) == 2
    with pytest.raises(Unauthenticated):
        manager.resolve(raw_one)
    with pytest.raises(Unauthenticated):
        manager.resolve(raw_two)


def test_a_disabled_user_cannot_resolve_an_existing_session():
    store, org, user, manager = _fixture()
    raw = manager.login(user)
    store.set_user_status(org.id, user.id, "disabled")

    with pytest.raises(Unauthenticated):
        manager.resolve(raw)
    assert store.session_by_token_hash(manager.hash(raw)) is None


# -- the logout route ---------------------------------------------------

def test_logout_deletes_the_session_and_clears_both_cookies():
    store, org, user, app = _app()
    raw = app.sessions.login(user)
    session = store.session_by_token_hash(app.sessions.hash(raw))
    headers = {
        "cookie": "__Host-il_session=" + app.sessions.cookie_value(org.id, raw),
        "x-csrf-token": app.sessions.csrf_token(session.id),
    }

    status, _single, multi, payload, _raw = _call(
        app, "/v1/auth/logout", method="POST", headers=headers,
    )
    assert status == 200
    assert payload == {"status": "logged_out"}
    cookies = multi["set-cookie"]
    assert any(c.startswith("__Host-il_session=") and "Max-Age=0" in c
               for c in cookies)
    assert any(c.startswith("il_csrf=") and "Max-Age=0" in c
               for c in cookies)
    assert store.session_by_token_hash(app.sessions.hash(raw)) is None


# -- nothing leaks ------------------------------------------------------

def test_no_response_body_or_log_line_carries_the_token(capsys):
    store, org, user, app = _app()
    raw = app.sessions.login(user)
    cookie = app.sessions.cookie_value(org.id, raw)
    session = store.session_by_token_hash(app.sessions.hash(raw))
    csrf = app.sessions.csrf_token(session.id)

    status, _single, _multi, payload, body = _call(
        app, "/v1/me",
        headers={"cookie": "__Host-il_session=" + cookie},
    )
    assert status == 200
    text = body.decode("utf-8")
    for secret in (raw, cookie, csrf):
        assert secret not in text
        assert secret not in json.dumps(payload)

    captured = capsys.readouterr()
    for secret in (raw, cookie, csrf):
        assert secret not in captured.out
        assert secret not in captured.err

    # The stored row holds the hash, never the raw token or the CSRF value.
    assert session.token_hash == app.sessions.hash(raw)
    assert raw not in repr(session)
    assert csrf not in repr(session)
