"""C7 org deletion: a tombstone that revokes access and retains evidence.

Deletion is not a cascade. Access - agent keys, sessions, unredeemed enrollment
tokens, preview ciphertext and webhook secrets - goes immediately; receipts and
the audit trail stay, with the org marked deleted, for the retention period.
"""
from __future__ import annotations

import json

import pytest

from tests._c4_helpers import (
    NOW, add_agent_key, call, chain, ingest, make_app,
)


def _delete(env, *, confirm="acme", headers=None):
    merged = dict(headers if headers is not None else env.headers)
    merged.setdefault("content-type", "application/json")
    return call(
        env.app, "/v1/org", method="DELETE", headers=merged,
        body=json.dumps({"confirm": confirm}).encode(),
    )


def _fresh_delete(env, **kwargs):
    env.session.step_up_at = NOW
    return _delete(env, **kwargs)


def _seed_org_assets(env):
    """One of everything deletion must touch, plus one it must keep."""
    headers = add_agent_key(env)
    receipts = chain(b"h" * 32, count=2)
    status, _h, body, _raw = ingest(env, headers, receipts)
    assert status == 200, body

    review = env.store.upsert_review(
        env.org.id, env.host.id, "rev-delete-1", binding="b1",
        action="shell", phase="call", preview_enc=b"ciphertext",
        args_digest="d" * 64)
    token_id, _raw_token = env.store.create_enrollment_token(
        env.org.id, now=NOW)
    env.store.webhook_create_endpoint(
        env.org.id, "https://hooks.example.test/x", ["review.created"],
        "hash", b"sealed", now=NOW)
    env.store.audit_append(env.org.id, "review.uploaded", actor=env.user.id)
    return headers, receipts, review, token_id


# -- authorization ------------------------------------------------------

def test_deletion_needs_the_owner_role_and_a_fresh_step_up():
    env = make_app(role="admin")
    env.session.step_up_at = NOW
    status, _headers, body, _raw = _delete(env)
    assert status == 403

    env = make_app(role="owner")
    status, _headers, body, _raw = _delete(env)
    assert status == 403
    assert body["error"]["code"] == "step_up_required"


def test_the_typed_confirmation_must_repeat_the_slug():
    env = make_app()
    env.session.step_up_at = NOW
    status, _headers, body, _raw = _delete(env, confirm="wrong")
    assert status == 422
    assert body["error"]["code"] == "invalid_request"
    assert env.store.org_by_id(env.org.id).deleted_at is None


def test_an_already_tombstoned_org_is_404_even_to_its_own_session():
    # The session is gone the moment the tombstone lands, so a second delete
    # never reaches the handler's 409 guard: the org is invisible first.
    env = make_app()
    env.store.org_tombstone(env.org.id, now=NOW)
    status, _headers, body, _raw = _fresh_delete(env)
    assert status == 404
    assert body["error"]["code"] == "not_found"


# -- the tombstone ------------------------------------------------------

def test_deletion_tombstones_the_org_and_writes_exactly_one_audit_row():
    env = make_app()
    _seed_org_assets(env)
    before = len(env.store.audit_list(env.org.id))

    status, _headers, body, _raw = _fresh_delete(env)
    assert status == 200, body
    assert body["deleted"] is True
    assert body["org"]["deleted"] is True
    assert env.store.org_by_id(env.org.id).deleted_at == NOW
    assert body["retained"] == ["receipts", "audit"]

    entries = env.store.audit_list(env.org.id)
    deleted = [entry for entry in entries if entry.event == "org.deleted"]
    assert len(entries) == before + 1
    assert len(deleted) == 1
    assert deleted[0].actor == env.user.id
    assert deleted[0].detail["slug"] == "acme"
    assert deleted[0].detail["retained"] == ["receipts", "audit"]
    assert deleted[0].detail["revoked_keys"] == 1


def test_the_deleted_org_is_404_for_a_session_and_410_for_its_agent_key():
    env = make_app()
    agent_headers, _receipts, _review, _token = _seed_org_assets(env)

    status, _headers, body, _raw = _fresh_delete(env)
    assert status == 200, body

    status, _headers, body, _raw = call(
        env.app, "/v1/org", headers=env.headers)
    assert status == 401

    status, _headers, body, _raw = call(
        env.app, "/v1/grants", headers=agent_headers)
    assert status == 410
    assert body["error"]["code"] == "revoked"


def test_deletion_revokes_keys_sessions_tokens_previews_and_secrets():
    env = make_app()
    _headers, _receipts, review, token_id = _seed_org_assets(env)
    webhook = env.store.webhook_list_endpoints(env.org.id)[0]

    status, _headers, body, _raw = _fresh_delete(env)
    assert status == 200, body
    assert body["revoked_keys"] == 1
    assert body["sessions"] == 1

    assert all(key.revoked_at is not None
               for key in env.store.list_agent_keys(env.org.id))
    token = env.store.enrollment_token_by_id(env.org.id, token_id)
    assert token is not None and token.used_at is not None

    kept = env.store.review_by_id(env.org.id, review.id, env.host.id)
    assert kept is not None and kept.preview_enc is None

    raw_webhook = env.store.webhook_endpoint_by_id(env.org.id, webhook["id"])
    assert raw_webhook["active"] is False
    assert raw_webhook["secret_hash"] is None
    assert raw_webhook["secret_enc"] is None


def test_receipts_and_the_audit_trail_survive_deletion():
    env = make_app()
    _headers, receipts, _review, _token = _seed_org_assets(env)
    status, _headers, body, _raw = _fresh_delete(env)
    assert status == 200, body

    retained = env.store.receipts_since(env.org.id, env.host.id, cursor=0)
    assert len(retained) == len(receipts)
    events = [entry.event for entry in env.store.audit_list(env.org.id)]
    assert "review.uploaded" in events
    assert "org.deleted" in events


def test_a_deleted_org_no_longer_fans_out_webhooks():
    env = make_app()
    _seed_org_assets(env)
    from interlock.cloud import webhooks

    status, _headers, body, _raw = _fresh_delete(env)
    assert status == 200, body
    assert webhooks.emit(
        env.store, env.org.id, "review.created", {"review_id": "rev-2"},
        now=NOW) == 0


def test_delete_refuses_a_body_that_is_not_json():
    env = make_app()
    env.session.step_up_at = NOW
    status, _headers, body, _raw = call(
        env.app, "/v1/org", method="DELETE",
        headers=dict(env.headers, **{"content-type": "application/json"}),
        body=b"not json")
    assert status == 422
    assert body["error"]["code"] == "invalid_request"
