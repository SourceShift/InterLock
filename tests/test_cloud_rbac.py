"""Deny-by-default RBAC: the full role x route matrix plus HTTP ordering."""
from __future__ import annotations

import asyncio
import json

import pytest

from interlock.cloud.auth import rbac
from interlock.cloud.auth.rbac import Forbidden, authorize
from interlock.cloud.store import MemoryStore

ROLES = ("owner", "admin", "reviewer", "auditor")


def _concrete(route):
    return route.replace("{id}", "member-1")


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


def _app_and_session(role="admin"):
    from interlock.cloud.app import CloudApp
    from interlock.cloud.config import CloudConfig

    store = MemoryStore()
    org = store.create_org(slug="acme", name="Acme")
    user = store.create_user(org, issuer="https://idp.example", subject="u1",
                             email="a@acme.test", role=role)
    app = CloudApp(CloudConfig(session_secret="s" * 32), store=store,
                   ping=lambda dsn: True)
    raw = app.sessions.login(user)
    session = store.session_by_token_hash(app.sessions.hash(raw))
    headers = {
        "cookie": "__Host-il_session=" + app.sessions.cookie_value(org.id, raw),
        "x-csrf-token": app.sessions.csrf_token(session.id),
    }
    return app, store, org, user, headers


# -- matrix -------------------------------------------------------------

@pytest.mark.parametrize("method,route", sorted(rbac.PERMISSIONS))
def test_every_permission_row_allows_exactly_its_roles(method, route):
    path = _concrete(route)
    allowed = rbac.PERMISSIONS[(method, route)]
    for role in ROLES:
        if role in allowed:
            assert authorize(role, method, path) is None
        else:
            with pytest.raises(Forbidden):
                authorize(role, method, path)


@pytest.mark.parametrize("method,path", [
    ("POST", "/v1/hosts"),
    ("DELETE", "/v1/hosts/host-1"),
    ("GET", "/v1/receipts"),
    ("GET", "/v1/nope"),
    ("POST", "/v1/org"),
    ("GET", "/v1/auth/whatever"),
])
def test_every_unlisted_route_denies_for_every_role(method, path):
    for role in ROLES + ("agent",):
        with pytest.raises(Forbidden):
            authorize(role, method, path)


def test_agent_has_no_route_in_this_epic():
    for method, route in sorted(rbac.PERMISSIONS):
        with pytest.raises(Forbidden):
            authorize("agent", method, _concrete(route))


@pytest.mark.parametrize("method,path", sorted(rbac.PUBLIC_ROUTES))
def test_public_routes_need_no_role(method, path):
    assert authorize("auditor", method, path) is None


@pytest.mark.parametrize("method,path", sorted(rbac.AUTHENTICATED_ROUTES))
def test_authenticated_routes_allow_every_fixed_role(method, path):
    for role in ROLES:
        assert authorize(role, method, path) is None


def test_normalize_route_maps_parameters():
    assert rbac.normalize_route("/v1/members/abc") == "/v1/members/{id}"
    assert rbac.normalize_route("/v1/members") == "/v1/members"
    assert rbac.normalize_route("/v1/hosts/host-1") == "/v1/hosts/{id}"
    assert rbac.normalize_route(
        "/v1/keys/key-1/revoke") == "/v1/keys/{id}/revoke"


def test_agent_routes_are_literal_and_separate_from_the_human_matrix():
    assert rbac.AGENT_ROUTES == {
        ("POST", "/v1/hosts/self"): None,
        ("POST", "/v1/reviews"): None,
        ("GET", "/v1/grants"): None,
        ("POST", "/v1/grants/ack"): None,
        ("POST", "/v1/receipts"): "ingest:receipts",
        ("POST", "/v1/checkpoints"): "ingest:receipts",
        # C5: the pull side of policy distribution, plus the by-sha artifact
        # fetch (a variable route, matched by pattern rather than literally).
        ("GET", "/v1/hints"): "pull:policy",
        ("GET", "/v1/manifest"): "pull:policy",
        ("GET", "/v1/kills"): "pull:policy",
        ("GET", "/v1/artifacts/{sha256}"): "pull:policy",
    }
    for method, route in rbac.AGENT_ROUTES:
        assert (method, route) not in rbac.PERMISSIONS
    # ``/v1/hosts/self`` must not normalize onto the human fleet detail row.
    assert rbac.agent_route("POST", "/v1/hosts/self") == (
        "POST", "/v1/hosts/self")
    assert rbac.agent_route("GET", "/v1/hosts/self") is None
    assert rbac.agent_route("POST", "/v1/hosts/host-1") is None
    assert rbac.required_agent_scope("POST", "/v1/hosts/self") is None
    assert rbac.required_agent_scope("POST", "/v1/hosts/host-1") is None


def test_enrollment_is_public_but_every_other_c2_route_is_not():
    assert rbac.is_public("POST", "/v1/enroll")
    for method, route in [
        ("POST", "/v1/admin/enrollment-tokens"),
        ("GET", "/v1/hosts"),
        ("GET", "/v1/hosts/host-1"),
        ("POST", "/v1/keys"),
        ("POST", "/v1/keys/key-1/revoke"),
        ("POST", "/v1/hosts/self"),
    ]:
        assert not rbac.is_public(method, route)
        with pytest.raises(Forbidden):
            authorize("member", method, route)


# -- HTTP ordering ------------------------------------------------------

def test_a_role_absent_from_the_row_gets_403_before_any_lookup():
    app, _store, _org, _user, headers = _app_and_session("auditor")
    status, _headers, payload = _call(
        app, "/v1/org", method="PATCH", headers=headers,
        body=json.dumps({"name": "renamed"}).encode(),
    )
    assert status == 403
    assert payload["error"]["code"] == "forbidden"


def test_an_allowed_role_reaches_the_handler():
    app, _store, _org, _user, headers = _app_and_session("admin")
    status, _headers, payload = _call(app, "/v1/members", headers=headers)
    assert status == 200
    assert payload["members"][0]["email"] == "a@acme.test"


def test_missing_session_is_401_not_404():
    app, _store, _org, _user, _headers = _app_and_session("admin")
    status, _headers, payload = _call(app, "/v1/members")
    assert status == 401
    assert payload["error"]["code"] == "unauthenticated"


def test_missing_csrf_is_403_even_for_an_allowed_role():
    app, _store, _org, _user, headers = _app_and_session("owner")
    headers = dict(headers)
    headers.pop("x-csrf-token")
    status, _headers, payload = _call(
        app, "/v1/org", method="PATCH", headers=headers,
        body=json.dumps({"name": "renamed"}).encode(),
    )
    assert status == 403
    assert payload["error"]["code"] == "csrf"
