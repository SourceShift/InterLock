"""The hosted, server-rendered review UI (C3, FR-017 .. FR-024).

Every page is built on the plane, sized for a 390 px phone, styled inline,
and rendered from escaped tenant data. The list never decrypts a preview and
no page puts one in a URL. The only asset is the same-origin step-up script,
which the one per-page CSP allows.
"""
from __future__ import annotations

import asyncio
import re

from interlock.cloud.app import CloudApp
from interlock.cloud.config import CloudConfig
from interlock.cloud.crypto import encrypt_preview, parse_kek
from interlock.cloud.grants import generate_seed
from interlock.cloud.http import CSP
from interlock.cloud.store import MemoryStore
from interlock.cloud.ui import UI_CSP, VIEWPORT

NOW = 2_000_000_000.0
KEK = "cd" * 32
PREVIEW = "deploy <script>alert('p')</script> to ada@example.com"


class _FakeStepUp:
    def begin(self, user_id, method):
        return {"challenge_id": "ch-1"}

    def finish(self, challenge_id, assertion, now=None):
        assert (challenge_id, assertion) == ("ch-1", "123456")
        return {"method": "totp", "at": NOW}


def _call(app, path, *, method="GET", headers=None, body=b"", query=b""):
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
    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    header_list = [(name.decode(), value.decode())
                   for name, value in start["headers"]]
    raw = b"".join(m.get("body", b"") for m in sent
                   if m["type"] == "http.response.body")
    return start["status"], header_list, raw.decode("utf-8")


def _header(headers, name):
    values = [value for key, value in headers if key.lower() == name.lower()]
    assert len(values) == 1, (name, values)
    return values[0]


def _setup(role="reviewer", *, step_up=False):
    store = MemoryStore()
    org = store.create_org(slug="acme", name="Acme")
    user = store.create_user(org, issuer="https://idp.example", subject="u1",
                             email="u1@acme.test", role=role)
    host = store.create_host(org, "box", owner_subject="owner", last_seen=NOW)
    app = CloudApp(
        CloudConfig(session_secret="s" * 32, preview_kek=KEK),
        store=store, ping=lambda dsn: True, clock=lambda: NOW,
        approval_seed=generate_seed(),
    )
    raw = app.sessions.login(user)
    session = store.session_by_token_hash(app.sessions.hash(raw))
    if step_up:
        app.sessions.mark_step_up(session, "totp", now=NOW)
    headers = {
        "cookie": "__Host-il_session=" + app.sessions.cookie_value(org.id, raw),
        "x-csrf-token": app.sessions.csrf_token(session.id),
    }
    return app, store, org, user, host, session, headers


def _review(store, org, host, review_id="rev-1", **overrides):
    values = {
        "binding": "b" * 64, "action": "shell", "phase": "call",
        "principal": "agent", "requester": "bob", "policy_id": "p-1",
        "reason": "publishing", "args_digest": "d" * 64,
        "preview_enc": encrypt_preview(PREVIEW, kek=parse_kek(KEK),
                                       org_id=org.id),
        "mask_counts": {"EMAIL_ADDRESS": 1}, "created": NOW - 65,
        "pending_until": NOW + 600, "min_approvals": 1,
        "allow_self_approval": True, "approval_ttl": 900.0,
    }
    values.update(overrides)
    return store.upsert_review(org.id, host.id, review_id, **values)


def _form_body(**fields):
    from urllib.parse import urlencode
    return urlencode(fields).encode()


def _form_headers(base, **extra):
    headers = dict(base)
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers.update(extra)
    return headers


# -- the page envelope --------------------------------------------------

def test_the_list_page_has_the_390px_viewport_and_one_ui_csp():
    app, store, org, _user, host, _session, headers = _setup()

    status, response_headers, html = _call(app, "/reviews", headers=headers)

    assert status == 200
    assert 'name="viewport" content="{}"'.format(VIEWPORT) in html
    assert "width=390, initial-scale=1" in html
    csp = _header(response_headers, "content-security-policy")
    assert csp == UI_CSP
    assert csp.startswith(CSP)
    assert "script-src 'self'" in csp
    assert "base-uri 'none'" in csp and "frame-ancestors 'none'" in csp
    assert _header(response_headers, "x-content-type-options") == "nosniff"
    assert _header(response_headers, "content-type").startswith("text/html")


def test_the_list_is_inline_only_and_contains_no_preview_or_script():
    app, store, org, _user, host, _session, headers = _setup()
    _review(store, org, host)

    status, _headers, html = _call(app, "/reviews", headers=headers)

    assert status == 200
    assert "<style>" in html and "<script" not in html and "<link" not in html
    assert "ada@example.com" not in html
    assert "alert('p')" not in html
    hrefs = re.findall(r'href="([^"]*)"', html)
    assert hrefs and all("ada@example.com" not in href for href in hrefs)
    assert "Pending" in html and "Approved" in html and "All" in html


def test_the_detail_page_serves_exactly_the_same_origin_script():
    app, store, org, _user, host, _session, headers = _setup()
    _review(store, org, host)

    status, response_headers, html = _call(app, "/reviews/rev-1",
                                           headers=headers)

    assert status == 200
    scripts = re.findall(r"<script[^>]*>", html)
    assert scripts == ['<script src="/static/stepup.js" defer>']
    assert "<style>" in html and "<link" not in html
    assert _header(response_headers, "content-security-policy") == UI_CSP


def test_the_step_up_script_is_public_and_text_javascript():
    app, _store, _org, _user, _host, _session, _headers = _setup()

    status, response_headers, body = _call(app, "/static/stepup.js")

    assert status == 200
    assert _header(response_headers, "content-type").startswith("text/javascript")
    assert _header(response_headers, "x-content-type-options") == "nosniff"
    assert "navigator.credentials.get" in body
    assert "webauthn" in body


# -- escaping and disclosure -------------------------------------------

def test_tenant_fields_and_the_preview_are_escaped():
    app, store, org, _user, host, _session, headers = _setup()
    _review(store, org, host, action='<img src=x onerror="alert(1)">',
            reason='"><img src=x onerror=alert(2)>')

    status, _headers, html = _call(app, "/reviews/rev-1", headers=headers)

    assert status == 200
    assert "<img src=x" not in html
    assert "&lt;img src=x" in html
    assert "onerror=alert(2)&gt;" in html or "onerror=alert(2)" in html
    # The preview is escaped inside <pre>, not injected as markup.
    assert "<script>alert('p')</script>" not in html
    assert "&lt;script&gt;alert(&#x27;p&#x27;)&lt;/script&gt;" in html
    assert "ada@example.com" in html  # the reviewer may read it


def test_the_decrypted_preview_is_audited_on_the_html_page():
    app, store, org, user, host, _session, headers = _setup()
    _review(store, org, host)

    _call(app, "/reviews/rev-1", headers=headers)

    entries = [entry for entry in store.audit_list(org.id)
               if entry.event == "review.disclosed"]
    assert len(entries) == 1
    assert entries[0].actor == user.id
    assert entries[0].detail["review_id"] == "rev-1"
    assert entries[0].detail["host_id"] == host.id


def test_an_auditor_and_an_unknown_id_both_get_the_same_404_page():
    auditor_app, auditor_store, auditor_org, _u, auditor_host, _s, auditor_headers = \
        _setup("auditor")
    _review(auditor_store, auditor_org, auditor_host)
    status, _headers, html = _call(auditor_app, "/reviews/rev-1",
                                   headers=auditor_headers)
    assert status == 404
    assert "No such review." in html
    assert "ada@example.com" not in html

    app, _store, _org, _user, _host, _session, headers = _setup()
    status, _headers, html = _call(app, "/reviews/rev-missing",
                                   headers=headers)
    assert status == 404
    assert "No such review." in html


def test_the_review_id_is_percent_encoded_in_links():
    app, store, org, _user, host, _session, headers = _setup()
    _review(store, org, host, review_id="r/../one")

    _status, _headers, html = _call(app, "/reviews", headers=headers)

    hrefs = re.findall(r'href="([^"]*)"', html)
    review_links = [href for href in hrefs if href.startswith("/reviews/r")]
    assert review_links == ["/reviews/r%2F..%2Fone"]


# -- the decision form --------------------------------------------------

def test_the_pending_detail_renders_the_decision_and_step_up_forms():
    app, store, org, _user, host, session, headers = _setup()
    _review(store, org, host)

    _status, _headers, html = _call(app, "/reviews/rev-1", headers=headers)

    token = app.sessions.csrf_token(session.id)
    assert 'name="csrf" value="{}"'.format(token) in html
    assert 'name="decision" value="approve"' in html
    assert 'name="decision" value="reject"' in html
    assert 'name="decision" value="revoke"' in html
    assert 'name="approve_anyway"' in html
    assert 'name="reason"' in html
    assert "Step-up" in html and "One-time code" in html
    assert "data-stepup-webauthn" in html


def test_a_fresh_step_up_hides_the_step_up_form():
    app, store, org, _user, host, _session, headers = _setup(step_up=True)
    _review(store, org, host)

    _status, _headers, html = _call(app, "/reviews/rev-1", headers=headers)

    assert "One-time code" not in html
    assert "data-stepup-webauthn" not in html
    assert 'name="decision" value="approve"' in html


def test_a_decided_review_has_no_decision_form():
    app, store, org, _user, host, _session, headers = _setup(step_up=True)
    _review(store, org, host)
    store.record_decision(org.id, "rev-1", reviewer="u2",
                          step_up_method="totp", step_up_at=NOW,
                          decision="approve", status="rejected",
                          decided_by="https://idp.example#u2", now=NOW)

    _status, _headers, html = _call(app, "/reviews/rev-1", headers=headers)

    assert 'name="decision" value="approve"' not in html
    assert "Decided by" in html and "https://idp.example#u2" in html
    assert "rejected" in html


def test_a_form_post_without_the_csrf_field_is_403():
    app, store, org, _user, host, _session, headers = _setup(step_up=True)
    _review(store, org, host)
    post_headers = _form_headers({k: v for k, v in headers.items()
                                  if k != "x-csrf-token"})

    status, _headers, html = _call(
        app, "/reviews/rev-1/decision", method="POST", headers=post_headers,
        body=_form_body(decision="approve"))

    assert status == 403
    assert "CSRF" in html or "forbidden" in html.lower()


def test_a_decision_without_a_fresh_step_up_is_403_and_settles_nothing():
    # FR-020 is enforced by the decision itself, so a form post that skips the
    # step-up page cannot mint a grant that claims one happened.
    app, store, org, _user, host, session, headers = _setup()
    _review(store, org, host)
    token = app.sessions.csrf_token(session.id)
    post_headers = _form_headers({k: v for k, v in headers.items()
                                  if k != "x-csrf-token"})

    status, _headers, html = _call(
        app, "/reviews/rev-1/decision", method="POST", headers=post_headers,
        body=_form_body(csrf=token, decision="approve", reason="ship it"))

    assert status == 403
    assert "step-up" in html.lower()
    assert store.review_by_id(org.id, "rev-1").status == "pending"
    assert store.grants_after(org.id, host.id, 0) == []


def test_a_non_urlencoded_form_post_is_415_with_a_valid_csrf_header():
    app, store, org, _user, host, _session, headers = _setup(step_up=True)
    _review(store, org, host)
    headers = dict(headers, **{"content-type": "application/json"})

    status, _headers, _body = _call(
        app, "/reviews/rev-1/decision", method="POST", headers=headers,
        body=b'{"decision":"approve"}')

    assert status == 415


def test_a_step_up_form_marks_the_session_and_audits_then_decision_works():
    app, store, org, user, host, session, headers = _setup()
    _review(store, org, host)
    app.step_up_service = _FakeStepUp()
    token = app.sessions.csrf_token(session.id)
    post_headers = _form_headers({k: v for k, v in headers.items()
                                  if k != "x-csrf-token"})

    status, response_headers, _body = _call(
        app, "/reviews/rev-1/step-up", method="POST", headers=post_headers,
        body=_form_body(csrf=token, method="totp", challenge_id="ch-1",
                        code="123456"))

    assert status == 303
    assert _header(response_headers, "location") == "/reviews/rev-1"
    assert session.step_up_at == NOW and session.step_up_method == "totp"
    entries = [entry for entry in store.audit_list(org.id)
               if entry.event == "review.step_up"]
    assert len(entries) == 1
    assert entries[0].actor == user.id
    assert entries[0].detail == {"review_id": "rev-1", "method": "totp",
                                 "ip": "127.0.0.1", "at": NOW}

    status, response_headers, _body = _call(
        app, "/reviews/rev-1/decision", method="POST", headers=post_headers,
        body=_form_body(csrf=token, decision="approve", reason="ship it"))

    assert status == 303
    assert _header(response_headers, "location") == "/reviews/rev-1"
    review = store.review_by_id(org.id, "rev-1")
    assert review.status == "approved"
    assert review.decided_by == "https://idp.example#u1"
    grant = store.grants_after(org.id, host.id, 0)[0]
    assert grant["decision"] == "approve"


def test_a_decision_refusal_renders_a_notice_with_the_same_page():
    app, store, org, _user, host, session, headers = _setup()
    _review(store, org, host, pending_until=NOW - 1)
    app.sessions.mark_step_up(session, "totp", now=NOW)
    token = app.sessions.csrf_token(session.id)
    post_headers = _form_headers(headers)

    status, _headers, html = _call(
        app, "/reviews/rev-1/decision", method="POST", headers=post_headers,
        body=_form_body(csrf=token, decision="approve"))

    assert status == 409
    assert "has expired" in html
    assert 'role="alert"' in html
    assert store.grants_after(org.id, host.id, 0) == []
