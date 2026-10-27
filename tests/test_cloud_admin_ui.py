"""C7 server-rendered admin pages: role gate, escaping, paging and privacy.

The pages exist for the incident-response case, so the properties that matter
are that the wrong role cannot read them, that an audit value is escaped, and
that a page never renders a preview, an argument or a raw detail object - only
the action, the actor, ids and digests.
"""
from __future__ import annotations

import datetime
import hashlib
import json

import pytest

from interlock.cloud.http import CSP
from interlock.cloud.ui import UI_CSP
from tests._c4_helpers import (
    NOW, add_agent_key, call, chain, ingest, make_app,
)


def _html(env, path, *, query=b"", headers=None):
    status, response_headers, _body, raw = call(
        env.app, path, headers=headers if headers is not None else env.headers,
        query=query)
    return status, response_headers, raw.decode("utf-8")


def _audit(env, event, *, actor=None, **detail):
    return env.store.audit_append(
        env.org.id, event, actor=actor, detail=detail or None)


# -- role gate and headers ---------------------------------------------

@pytest.mark.parametrize("role", ["owner", "admin", "auditor"])
def test_owner_admin_and_auditor_may_read_both_pages(role):
    env = make_app(role=role)
    for path in ("/admin/audit", "/admin/hosts"):
        status, _headers, raw = _html(env, path)
        assert status == 200, path
        assert "<h1>interlock</h1>" in raw


@pytest.mark.parametrize("role", ["reviewer"])
def test_a_reviewer_cannot_read_the_admin_pages(role):
    env = make_app(role=role)
    for path in ("/admin/audit", "/admin/hosts"):
        status, _headers, _raw = _html(env, path)
        assert status == 403


def test_both_pages_carry_the_one_ui_csp_and_nosniff():
    env = make_app()
    for path in ("/admin/audit", "/admin/hosts"):
        status, headers, _raw = _html(env, path)
        assert status == 200
        assert headers["content-security-policy"] == UI_CSP
        assert headers["content-security-policy"].startswith(CSP)
        assert "script-src 'self'" in headers["content-security-policy"]
        assert "frame-ancestors 'none'" in headers["content-security-policy"]
        assert headers["x-content-type-options"] == "nosniff"


def test_the_pages_navigate_to_each_other():
    env = make_app()
    _status, _headers, raw = _html(env, "/admin/audit")
    assert 'href="/reviews"' in raw
    assert 'href="/admin/audit"' in raw
    assert 'href="/admin/hosts"' in raw


# -- escaping -----------------------------------------------------------

def test_every_tenant_value_is_escaped():
    env = make_app()
    _audit(env, "<b>review.created</b>",
           actor="<script>alert(1)</script>",
           ip="<img src=x onerror=alert(1)>",
           target="<svg/onload=alert(1)>")
    status, _headers, raw = _html(env, "/admin/audit")
    assert status == 200
    assert "<script>alert(1)</script>" not in raw
    assert "<svg/onload" not in raw
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in raw
    assert "&lt;b&gt;review.created&lt;/b&gt;" in raw


# -- privacy ------------------------------------------------------------

def test_a_detail_object_is_never_rendered_even_when_it_holds_secrets():
    env = make_app()
    _audit(env, "review.uploaded", actor="alice",
           preview="SECRET-PREVIEW-TEXT", args={"cmd": "rm -rf /"},
           secret="SECRET-KEY", body="SECRET-BODY")
    _status, _headers, raw = _html(env, "/admin/audit")
    for secret in ("SECRET-PREVIEW-TEXT", "SECRET-KEY", "SECRET-BODY",
                   "rm -rf"):
        assert secret not in raw
    assert "review.uploaded" in raw


def test_the_hash_columns_show_recorded_before_and_after_digests():
    env = make_app()
    before = "a" * 64
    after = "b" * 64
    _audit(env, "policy.published", before_sha256=before, after_sha256=after)
    _status, _headers, raw = _html(env, "/admin/audit")
    assert 'title="{}"'.format(before) in raw
    assert 'title="{}"'.format(after) in raw
    assert before[:16] in raw and after[:16] in raw


def test_an_entry_without_a_recorded_hash_gets_a_digest_of_its_detail():
    env = make_app()
    _audit(env, "review.decided", review_id="rev-1", status="approved")
    detail = {"review_id": "rev-1", "status": "approved"}
    expected = hashlib.sha256(json.dumps(
        detail, sort_keys=True, separators=(",", ":"),
        default=str).encode("utf-8")).hexdigest()
    _status, _headers, raw = _html(env, "/admin/audit")
    assert expected[:16] in raw
    assert 'title="{}"'.format(expected) in raw


# -- filters ------------------------------------------------------------

def test_the_actor_and_action_filters_select_by_substring():
    env = make_app()
    _audit(env, "review.decided", actor="alice")
    _audit(env, "review.created", actor="bob")
    _audit(env, "manifest.published", actor="alice")
    _status, _headers, raw = _html(env, "/admin/audit", query=b"actor=alice")
    assert "review.decided" in raw and "manifest.published" in raw
    assert "review.created" not in raw
    _status, _headers, raw = _html(env, "/admin/audit",
                                   query=b"action=manifest")
    assert "manifest.published" in raw
    assert "review.decided" not in raw and "review.created" not in raw


def test_the_date_filters_are_inclusive_and_reject_a_bad_date():
    env = make_app()
    entry = _audit(env, "review.created", actor="alice")
    day = datetime.datetime.fromtimestamp(
        entry.created, tz=datetime.timezone.utc).date().isoformat()
    _status, _headers, raw = _html(
        env, "/admin/audit", query="from={}&to={}".format(day, day).encode())
    assert "review.created" in raw
    _status, _headers, raw = _html(env, "/admin/audit", query=b"to=2000-01-01")
    assert "No audit entries match" in raw
    status, _headers, _body = _html(env, "/admin/audit", query=b"from=soon")
    assert status == 422


@pytest.mark.parametrize("name", ["preview", "raw", "args", "arguments",
                                  "payload", "body", "q"])
def test_a_content_or_unknown_filter_is_refused(name):
    env = make_app()
    status, _headers, _raw = _html(
        env, "/admin/audit", query="{}={}".format(name, "x").encode())
    assert status == 422


# -- paging -------------------------------------------------------------

def test_the_audit_page_pages_at_twenty_five_rows():
    env = make_app()
    for index in range(30):
        _audit(env, "event.{:02d}".format(index), actor="alice")
    _status, _headers, first = _html(env, "/admin/audit")
    assert first.count("<tr>") == 26  # header row plus 25 entries
    assert "Next page" in first
    assert "event." in first
    _status, _headers, second = _html(env, "/admin/audit", query=b"cursor=25")
    assert second.count("<tr>") == 6
    assert "Next page" not in second


def test_the_hosts_page_pages_and_shows_key_counts():
    env = make_app()
    first_key = add_agent_key(env)
    raw, prefix, digest = __import__(
        "interlock.cloud.enrollment", fromlist=["generate_agent_key"]
    ).generate_agent_key()
    env.store.create_agent_key(env.org.id, env.host.id, prefix=prefix,
                               secret_hash=digest, scopes=["ingest:receipts"])
    key = env.store.list_agent_keys(env.org.id, env.host.id)[0]
    env.store.revoke_agent_key(env.org.id, key.id, now=NOW)

    status, _headers, raw_page = _html(env, "/admin/hosts")
    assert status == 200
    assert env.host.id in raw_page
    assert "box" in raw_page
    assert "active" in raw_page
    assert "1 active / 2 total" in raw_page

    for index in range(26):
        env.store.create_host(env.org.id, "box-{:02d}".format(index),
                              owner_subject="owner-x", last_seen=NOW)
    _status, _headers, page = _html(env, "/admin/hosts")
    assert page.count("<tr>") == 26
    assert "Next page" in page
    _status, _headers, page = _html(env, "/admin/hosts", query=b"cursor=25")
    assert "Next page" not in page


# -- export delegates to C4 --------------------------------------------

def _seeded(count=3):
    env = make_app(role="auditor")
    headers = add_agent_key(env)
    receipts = chain(b"h" * 32, count=count)
    status, _headers, body, _raw = ingest(env, headers, receipts)
    assert status == 200, body
    return env, receipts[0].mac


def test_the_export_link_requires_a_host_and_then_returns_jsonl():
    env, _mac = _seeded()
    status, _headers, _raw = _html(env, "/admin/audit/export")
    assert status == 422
    status, headers, _body, raw = call(
        env.app, "/admin/audit/export", headers=env.headers,
        query=("host=" + env.host.id).encode())
    assert status == 200
    assert headers["content-type"].startswith("application/x-ndjson")
    lines = [line for line in raw.decode("utf-8").splitlines() if line]
    assert len(lines) == 3
    assert all(json.loads(line).get("mac") for line in lines)


def test_the_export_path_audits_the_export_like_c4():
    env, _mac = _seeded()
    status, _headers, _body, _raw = call(
        env.app, "/admin/audit/export", headers=env.headers,
        query=("host=" + env.host.id).encode())
    assert status == 200
    events = [entry.event for entry in env.store.audit_list(env.org.id)]
    assert "receipts.exported" in events
