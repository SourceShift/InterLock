"""OIDC/PKCE: authorization URL shape, claim matrix, no token leakage."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import sys
import types
from urllib.parse import parse_qs, urlparse

import pytest

from interlock.cloud.auth.oidc import AuthError, OIDCClient

ISSUER = "https://idp.example"
CLIENT_ID = "client-1"
REDIRECT = "https://cloud.example/v1/auth/callback"

DISCOVERY = {
    "issuer": ISSUER,
    "authorization_endpoint": "https://idp.example/authorize",
    "token_endpoint": "https://idp.example/token",
    "jwks_uri": "https://idp.example/jwks",
}


class FakeHttp:
    def __init__(self, discovery=None, token=None):
        self.discovery = dict(discovery or DISCOVERY)
        self.token = token or {}
        self.calls = []

    def __call__(self, method, url, data=None, headers=None):
        self.calls.append((method, url, data, headers))
        if method == "GET":
            return 200, {"content-type": "application/json"}, json.dumps(
                self.discovery).encode("utf-8")
        return 200, {"content-type": "application/json"}, json.dumps(
            self.token).encode("utf-8")


class FakeVerifier:
    def __init__(self, claims):
        self.claims = dict(claims)
        self.calls = []

    def verify(self, token, *, issuer, audience, nonce, now):
        self.calls.append({
            "token": token, "issuer": issuer, "audience": audience,
            "nonce": nonce, "now": now,
        })
        return dict(self.claims)


def _client(http=None, verifier=None, clock=lambda: 1000.0):
    return OIDCClient(ISSUER, CLIENT_ID, "client-secret", REDIRECT,
                      http=http or FakeHttp(), verifier=verifier,
                      clock=clock)


def _claims(**overrides):
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "exp": 1100,
        "iat": 950,
        "nonce": "nonce-1",
        "email_verified": True,
        "sub": "u1",
        "email": "a@acme.test",
    }
    claims.update(overrides)
    return claims


# -- authorization URL --------------------------------------------------

def test_authorization_url_carries_code_pkce_state_and_nonce():
    url = _client().authorization_url("state-1", "nonce-1", "challenge-1")
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    assert parsed.scheme == "https"
    assert parsed.netloc == "idp.example"
    assert parsed.path == "/authorize"
    assert query["response_type"] == ["code"]
    assert query["client_id"] == [CLIENT_ID]
    assert query["redirect_uri"] == [REDIRECT]
    assert query["scope"] == ["openid email profile"]
    assert query["state"] == ["state-1"]
    assert query["nonce"] == ["nonce-1"]
    assert query["code_challenge"] == ["challenge-1"]
    assert query["code_challenge_method"] == ["S256"]


def test_pkce_pair_is_sha256_s256():
    verifier, challenge = OIDCClient.pkce_pair()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")
    assert challenge == expected
    assert "=" not in challenge
    assert len(verifier) >= 43


def test_discovery_is_cached_for_ten_minutes():
    http = FakeHttp()
    client = _client(http=http)
    client.discovery()
    client.discovery()
    assert len([call for call in http.calls if call[0] == "GET"]) == 1


@pytest.mark.parametrize("issuer", ["https://evil.example",
                                    "https://idp.example.evil",
                                    "https://idp.exampl"])
def test_discovery_requires_an_exact_issuer_match(issuer):
    discovery = dict(DISCOVERY, issuer=issuer)
    client = _client(http=FakeHttp(discovery=discovery))
    with pytest.raises(AuthError) as exc:
        client.discovery()
    assert exc.value.code == "bad_issuer"


# -- claim matrix -------------------------------------------------------

@pytest.mark.parametrize("claim_overrides,code", [
    ({"iss": "https://evil.example"}, "bad_issuer"),
    ({"aud": "someone-else"}, "bad_audience"),
    ({"aud": ["a", "b"]}, "bad_audience"),
    ({"exp": 900}, "expired"),
    ({"iat": 1200}, "expired"),
    ({"nonce": "other"}, "bad_nonce"),
    ({"email_verified": False}, "email_unverified"),
    ({"sub": ""}, "missing_subject"),
    ({"email": ""}, "missing_subject"),
])
def test_claim_matrix_rejects_every_violation(claim_overrides, code):
    client = _client()
    with pytest.raises(AuthError) as exc:
        client.validate_claims(_claims(**claim_overrides), nonce="nonce-1")
    assert exc.value.code == code


def test_audience_accepts_a_list_or_matching_azp():
    client = _client()
    client.validate_claims(_claims(aud=["x", CLIENT_ID]), nonce="nonce-1")
    client.validate_claims(_claims(aud="x", azp=CLIENT_ID), nonce="nonce-1")


def test_claim_matrix_accepts_the_valid_claims():
    client = _client()
    result = client.validate_claims(_claims(), nonce="nonce-1")
    assert result["sub"] == "u1"
    assert result["email"] == "a@acme.test"


# -- token exchange -----------------------------------------------------

def test_exchange_validates_claims_and_returns_no_tokens():
    token = {
        "access_token": "SECRET-ACCESS",
        "refresh_token": "SECRET-REFRESH",
        "id_token": "header.payload.signature",
        "token_type": "Bearer",
    }
    verifier = FakeVerifier(_claims())
    client = _client(http=FakeHttp(token=token), verifier=verifier)
    client.nonce = "nonce-1"

    claims = client.exchange("code-1", "verifier-1")

    assert claims["sub"] == "u1"
    assert claims["email"] == "a@acme.test"
    rendered = json.dumps(claims)
    for secret in ("SECRET-ACCESS", "SECRET-REFRESH", "header.payload.signature"):
        assert secret not in rendered
    assert "access_token" not in claims
    assert "refresh_token" not in claims
    assert verifier.calls[0]["audience"] == CLIENT_ID
    assert verifier.calls[0]["nonce"] == "nonce-1"


def test_exchange_requires_a_bearer_token_type():
    token = {
        "access_token": "a", "refresh_token": "r",
        "id_token": "header.payload.signature", "token_type": "bearer",
    }
    client = _client(http=FakeHttp(token=token),
                     verifier=FakeVerifier(_claims()))
    with pytest.raises(AuthError) as exc:
        client.exchange("code-1", "verifier-1", nonce="nonce-1")
    assert exc.value.code == "invalid_request"


def test_exchange_posts_a_urlencoded_token_request_with_a_timeout_seam():
    token = {
        "access_token": "a", "refresh_token": "r",
        "id_token": "header.payload.signature", "token_type": "Bearer",
    }
    http = FakeHttp(token=token)
    client = _client(http=http, verifier=FakeVerifier(_claims()))
    client.exchange("code-1", "verifier-1", nonce="nonce-1")

    post = [call for call in http.calls if call[0] == "POST"][0]
    assert post[1] == DISCOVERY["token_endpoint"]
    assert b"grant_type=authorization_code" in post[2]
    assert b"code_verifier=verifier-1" in post[2]
    assert post[3]["content-type"] == "application/x-www-form-urlencoded"


# -- the login round trip ------------------------------------------------

class FakeOIDC:
    """A provider stand-in: no network, the claims it is given."""

    def __init__(self, claims):
        self.claims = dict(claims)
        self.exchanges = []

    def exchange(self, code, code_verifier, *, nonce=None):
        self.exchanges.append((code, code_verifier, nonce))
        return dict(self.claims)


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


def _login_app(claims, *, org_client_id=None):
    from interlock.cloud.app import CloudApp
    from interlock.cloud.config import CloudConfig
    from interlock.cloud.store import MemoryStore

    store = MemoryStore()
    org = store.create_org(slug="acme", name="Acme", sso_issuer=ISSUER,
                           sso_client_id=org_client_id)
    store.add_org_domain(org.id, "acme.test")
    app = CloudApp(
        CloudConfig(session_secret="s" * 32, oidc_issuer=ISSUER,
                    oidc_client_id=CLIENT_ID, oidc_redirect_uri=REDIRECT),
        store=store, oidc=FakeOIDC(claims), ping=lambda dsn: True,
    )
    return store, org, app


def _round_trip_cookies(state="state-1", next_path="/v1/me"):
    return "; ".join([
        "il_oidc_state=" + state,
        "il_oidc_nonce=nonce-1",
        "il_oidc_verifier=verifier-1",
        "il_oidc_next=" + next_path,
    ])


def _callback(app, cookies=None, query=b"code=code-1&state=state-1"):
    return _call(app, "/v1/auth/callback", query=query,
                 headers={"cookie": cookies or _round_trip_cookies()})


def test_callback_creates_a_session_and_redirects_to_next():
    _store, _org, app = _login_app(_claims())
    status, single, multi, _payload, _raw = _callback(app)

    assert status == 302
    assert single["location"] == "/v1/me"
    cookies = multi["set-cookie"]
    assert any(c.startswith("__Host-il_session=") for c in cookies)
    assert any(c.startswith("il_csrf=") for c in cookies)
    # The one-time round-trip cookies are cleared on the way out.
    for name in ("il_oidc_state", "il_oidc_nonce", "il_oidc_verifier",
                 "il_oidc_next"):
        assert any(c.startswith(name + "=") and "Max-Age=0" in c
                   for c in cookies)


def test_the_session_cookie_authorises_a_request_and_leaks_no_token():
    _store, _org, app = _login_app(_claims())
    _status, _single, multi, _payload, body = _callback(app)
    cookie = [c for c in multi["set-cookie"]
              if c.startswith("__Host-il_session=")][0]
    value = cookie.split(";", 1)[0].split("=", 1)[1]

    # The redirect itself carries no body, so the raw token is not echoed.
    assert body == b""
    assert value not in body.decode()

    status, _single, _multi, payload, body = _call(
        app, "/v1/me", headers={"cookie": "__Host-il_session=" + value},
    )
    assert status == 200
    assert payload["email"] == "a@acme.test"
    assert payload["org"] == "acme"
    # JIT membership hands out the least-privileged fixed role.
    assert payload["role"] == "auditor"
    assert payload["step_up_at"] is None
    assert value not in body.decode()


def test_a_mismatched_state_is_refused():
    _store, _org, app = _login_app(_claims())
    status, _single, _multi, payload, _raw = _callback(
        app, cookies=_round_trip_cookies(state="other-state"))

    assert status == 403
    assert payload["error"]["code"] == "csrf"


def test_an_unprovisioned_identity_is_refused():
    _store, _org, app = _login_app(_claims(email="stranger@elsewhere.test"))
    status, _single, _multi, payload, _raw = _callback(app)

    assert status == 403
    assert payload["error"]["code"] == "not_provisioned"


def test_an_org_that_pins_its_client_id_refuses_another_audience():
    _store, _org, app = _login_app(_claims(aud="another-client"),
                                   org_client_id=CLIENT_ID)
    status, _single, _multi, payload, _raw = _callback(app)

    assert status == 403
    assert payload["error"]["code"] == "bad_audience"


def test_the_cli_keeps_the_identity_settings_from_the_environment(monkeypatch):
    from interlock.cloud import __main__ as cloud_main

    monkeypatch.setenv("IL_CLOUD_DSN", "postgresql://localhost/interlock")
    monkeypatch.setenv("IL_CLOUD_SESSION_SECRET", "s" * 32)
    monkeypatch.setenv("IL_CLOUD_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("IL_CLOUD_OIDC_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("IL_CLOUD_OIDC_ORG_SLUG", "acme")

    captured = {}

    def fake_run(app, **kwargs):
        captured["config"] = app.config

    class _StubServer:
        def __init__(self, config):
            captured.setdefault("metrics", []).append(config)

        def run(self):
            pass

    monkeypatch.setitem(sys.modules, "uvicorn", types.SimpleNamespace(
        run=fake_run, Server=_StubServer,
        Config=lambda app, **kwargs: {"app": app, **kwargs},
    ))
    assert cloud_main.main([]) == 0

    config = captured["config"]
    assert config.oidc_issuer == ISSUER
    assert config.oidc_client_id == CLIENT_ID
    assert config.oidc_org_slug == "acme"
    assert config.session_secret == "s" * 32
    # The dedicated metrics listener is constructed on the main thread and
    # binds loopback only; args reaching uvicorn.run stay the control plane's.
    assert captured["metrics"][0]["host"] == config.metrics_host != "0.0.0.0"
