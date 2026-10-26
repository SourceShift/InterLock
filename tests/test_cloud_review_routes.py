"""The plane's review API: masked upload, list, detail and decisions (C3).

The connector uploads through an agent key; a reviewer uses a session. The
plane re-checks the upload allow-list, encrypts the preview at rest, audits
every disclosure, and turns a decision into a signed grant - only after a
fresh step-up, the org's four-eyes rules and the stale-host override.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from interlock.cloud.app import CloudApp
from interlock.cloud.auth.stepup import StepUpService
from interlock.cloud.config import CloudConfig
from interlock.cloud.enrollment import generate_agent_key
from interlock.cloud.grants import (
    GENESIS,
    GRANT_MAX_TTL,
    approval_public_key,
    generate_seed,
    verify_grant,
)
from interlock.cloud.store import MemoryStore

# Preview encryption needs the optional ``cryptography`` dependency. The Python
# matrix jobs install ``.[dev]`` only, so every upload that carries a preview
# would 500 there; the cloud job installs ``.[dev,cloud]`` and is where this
# file really runs. Skip when the dep is absent, never fail.
pytest.importorskip("cryptography")

NOW = 2_000_000_000.0
KEK = "ab" * 32


def _call(app, path, *, method="GET", headers=None, body=None, query=b""):
    sent = []
    payload = b"" if body is None else body

    async def receive():
        return {"type": "http.request", "body": payload, "more_body": False}

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
    single = {}
    for name, value in start["headers"]:
        single.setdefault(name.decode(), value.decode())
    raw = b"".join(m.get("body", b"") for m in sent
                   if m["type"] == "http.response.body")
    return start["status"], single, json.loads(raw) if raw else None


def _login(app, org, user):
    raw = app.sessions.login(user)
    session = app.store.session_by_token_hash(app.sessions.hash(raw))
    headers = {
        "cookie": "__Host-il_session=" + app.sessions.cookie_value(org.id, raw),
        "x-csrf-token": app.sessions.csrf_token(session.id),
    }
    return headers, session


def _app_with_user(role="reviewer", *, now=NOW, owner="owner-x",
                   last_seen=None, subject="u1", seed=None):
    store = MemoryStore()
    org = store.create_org(slug="acme", name="Acme")
    user = store.create_user(org, issuer="https://idp.example", subject=subject,
                             email=subject + "@acme.test", role=role)
    host = store.create_host(
        org, "box", owner_subject=owner,
        last_seen=now - 10 if last_seen is None else last_seen)
    app = CloudApp(
        CloudConfig(session_secret="s" * 32, preview_kek=KEK),
        store=store, ping=lambda dsn: True, clock=lambda: now,
        approval_seed=seed or generate_seed(),
    )
    headers, session = _login(app, org, user)
    return app, store, org, user, host, headers, session


def _agent_headers(store, org, host):
    raw, prefix, digest = generate_agent_key()
    store.create_agent_key(org.id, host.id, prefix=prefix, secret_hash=digest,
                           scopes=["ingest:reviews"])
    return {
        "authorization": "Bearer " + raw,
        "x-interlock-org": org.id,
        "x-interlock-host": host.id,
        "content-type": "application/json",
    }


def _upload_body(review_id="rev-1", **overrides):
    body = {
        "review_id": review_id,
        "binding": "b" * 64,
        "action": "shell",
        "phase": "call",
        "principal": "agent",
        "requester": "hmac:" + "0" * 32,
        "policy_id": "p-1",
        "reason": "publishing",
        "args_digest": "d" * 64,
        "preview": "deploy to ada@example.com",
        "mask_counts": {"EMAIL_ADDRESS": 1},
        "created": NOW - 10,
        "pending_until": NOW + 600,
        "min_approvals": 1,
        "allow_self_approval": True,
        "approval_ttl": 900.0,
    }
    body.update(overrides)
    return body


def _upload(app, headers, body=None, **overrides):
    record = _upload_body(**overrides) if body is None else body
    return _call(app, "/v1/reviews", method="POST", headers=headers,
                 body=json.dumps(record).encode())


def _decide(app, headers, review_id, decision="approve", **extra):
    body = {"decision": decision}
    body.update(extra)
    headers = dict(headers, **{"content-type": "application/json"})
    return _call(app, "/v1/reviews/{}/decision".format(review_id),
                 method="POST", headers=headers,
                 body=json.dumps(body).encode())


# -- upload -------------------------------------------------------------

def test_an_agent_uploads_the_exact_allow_list_and_the_preview_is_encrypted():
    app, store, org, _user, host, _headers, _session = _app_with_user()
    agent = _agent_headers(store, org, host)

    status, _headers, payload = _upload(app, agent)

    assert status == 200
    review = payload["review"]
    assert review["id"] == "rev-1"
    assert review["status"] == "pending"
    assert review["host_id"] == host.id
    assert "binding" not in review
    assert "preview" not in review and "preview_enc" not in review
    stored = store.review_by_id(org.id, "rev-1")
    assert stored.binding == "b" * 64
    assert stored.preview_enc is not None
    assert b"ada@example.com" not in stored.preview_enc


@pytest.mark.parametrize("forbidden", ["event", "args", "raw", "arguments"])
def test_the_plane_refuses_a_raw_call_under_any_name(forbidden):
    app, store, org, _user, host, _headers, _session = _app_with_user()
    agent = _agent_headers(store, org, host)
    body = _upload_body()
    body[forbidden] = {"cmd": "npm publish"}

    status, _headers, payload = _upload(app, agent, body)

    assert status == 422
    assert payload["error"]["code"] == "invalid_request"
    assert store.review_by_id(org.id, "rev-1") is None


def test_unknown_fields_and_missing_required_fields_are_422():
    app, store, org, _user, host, _headers, _session = _app_with_user()
    agent = _agent_headers(store, org, host)

    status, _headers, payload = _upload(app, agent,
                                        _upload_body(extra="nope"))
    assert status == 422 and payload["error"]["code"] == "invalid_request"

    body = _upload_body()
    body.pop("binding")
    status, _headers, payload = _upload(app, agent, body)
    assert status == 422

    body = _upload_body()
    body.pop("action")
    status, _headers, _payload = _upload(app, agent, body)
    assert status == 422


@pytest.mark.parametrize("field,value", [
    ("preview", 7),
    ("mask_counts", {"EMAIL_ADDRESS": -1}),
    ("mask_counts", {"EMAIL_ADDRESS": True}),
    ("min_approvals", 0),
    ("min_approvals", True),
    ("allow_self_approval", "yes"),
    ("approval_ttl", "soon"),
    ("created", "yesterday"),
])
def test_bad_field_types_are_422(field, value):
    app, store, org, _user, host, _headers, _session = _app_with_user()
    agent = _agent_headers(store, org, host)
    status, _headers, payload = _upload(
        app, agent, _upload_body(**{field: value}))
    assert status == 422
    assert payload["error"]["code"] == "invalid_request"


def test_an_upload_is_idempotent_but_a_changed_binding_conflicts():
    app, store, org, _user, host, _headers, _session = _app_with_user()
    agent = _agent_headers(store, org, host)

    assert _upload(app, agent)[0] == 200
    assert _upload(app, agent)[0] == 200

    status, _headers, payload = _upload(app, agent,
                                        _upload_body(binding="c" * 64))
    assert status == 409
    assert payload["error"]["code"] == "review_conflict"


def test_a_human_session_may_not_upload_and_an_agent_may_not_list():
    app, store, org, _user, host, headers, _session = _app_with_user()
    agent = _agent_headers(store, org, host)

    status, _headers, payload = _upload(app, headers)
    assert status == 403 and payload["error"]["code"] == "forbidden"

    status, _headers, payload = _call(app, "/v1/reviews", headers=agent)
    assert status == 403 and payload["error"]["code"] == "forbidden"


def test_a_revoked_agent_key_is_410():
    app, store, org, _user, host, _headers, _session = _app_with_user()
    raw, prefix, digest = generate_agent_key()
    key = store.create_agent_key(org.id, host.id, prefix=prefix,
                                 secret_hash=digest, scopes=["ingest:reviews"])
    assert store.revoke_agent_key(org.id, key.id).revoked_at is not None
    agent = {"authorization": "Bearer " + raw, "x-interlock-org": org.id,
             "content-type": "application/json"}

    status, _headers, payload = _upload(app, agent)

    assert status == 410
    assert payload["error"]["code"] == "revoked"


# -- list and detail ----------------------------------------------------

def test_list_filters_pages_and_never_carries_a_preview():
    app, store, org, _user, host, headers, _session = _app_with_user()
    agent = _agent_headers(store, org, host)
    for index, created in enumerate((NOW, NOW - 1, NOW - 2)):
        assert _upload(app, agent, _upload_body(
            review_id="rev-{}".format(index), created=created,
            preview="secret-{}".format(index)))[0] == 200

    status, _headers, first = _call(app, "/v1/reviews", query=b"limit=2",
                                    headers=headers)
    assert status == 200
    assert [item["id"] for item in first["reviews"]] == ["rev-0", "rev-1"]
    assert first["next_cursor"] == 2
    assert "preview" not in first["reviews"][0]
    assert "secret-0" not in json.dumps(first)

    status, _headers, second = _call(
        app, "/v1/reviews", query=b"limit=2&cursor=2", headers=headers)
    assert status == 200
    assert [item["id"] for item in second["reviews"]] == ["rev-2"]
    assert second["next_cursor"] is None

    status, _headers, pending = _call(app, "/v1/reviews", query=b"status=pending",
                                      headers=headers)
    assert status == 200 and len(pending["reviews"]) == 3
    status, _headers, none = _call(app, "/v1/reviews", query=b"status=approved",
                                   headers=headers)
    assert status == 200 and none["reviews"] == []


@pytest.mark.parametrize("query", [
    b"limit=0", b"limit=101", b"limit=two", b"cursor=x", b"status=bogus",
])
def test_bad_list_filters_are_422(query):
    app, _store, _org, _user, _host, headers, _session = _app_with_user()
    status, _headers, payload = _call(app, "/v1/reviews", query=query,
                                      headers=headers)
    assert status == 422
    assert payload["error"]["code"] == "invalid_request"


def test_detail_decrypts_the_preview_and_audits_every_disclosure():
    app, store, org, user, host, headers, session = _app_with_user()
    agent = _agent_headers(store, org, host)
    _upload(app, agent)

    status, _headers, payload = _call(app, "/v1/reviews/rev-1", headers=headers)

    assert status == 200
    assert payload["preview"] == "deploy to ada@example.com"
    assert payload["mask_counts"] == {"EMAIL_ADDRESS": 1}
    assert "preview_enc" not in payload["review"]
    entries = [entry for entry in store.audit_list(org.id)
               if entry.event == "review.disclosed"]
    assert len(entries) == 1
    assert entries[0].actor == user.id
    assert entries[0].detail == {"review_id": "rev-1", "host_id": host.id,
                                 "ip": "127.0.0.1", "at": NOW}

    _call(app, "/v1/reviews/rev-1", headers=headers)
    assert len([entry for entry in store.audit_list(org.id)
                if entry.event == "review.disclosed"]) == 2


def test_an_auditor_cannot_list_or_open_a_review():
    app, store, org, _user, host, _headers, _session = _app_with_user()
    agent = _agent_headers(store, org, host)
    _upload(app, agent)
    auditor_headers, _session = _login(app, org, store.create_user(
        org, issuer="https://idp.example", subject="aud", email="aud@acme.test",
        role="auditor"))

    status, _headers, payload = _call(app, "/v1/reviews",
                                      headers=auditor_headers)
    assert status == 403
    assert payload["error"]["code"] == "forbidden"

    # The detail row is allowed for an auditor, and the handler answers 404:
    # an auditor never sees a preview, and the refusal is deliberately
    # indistinguishable from an unknown id.
    status, _headers, payload = _call(app, "/v1/reviews/rev-1",
                                      headers=auditor_headers)
    assert status == 404
    assert payload["error"]["code"] == "not_found"
    assert not [entry for entry in store.audit_list(org.id)
                if entry.event == "review.disclosed"]


def test_an_unknown_review_is_404():
    app, _store, _org, _user, _host, headers, _session = _app_with_user()
    status, _headers, payload = _call(app, "/v1/reviews/rev-missing",
                                      headers=headers)
    assert status == 404
    assert payload["error"]["code"] == "not_found"


def test_a_review_from_another_org_is_404_and_never_listed():
    app, store, org, _user, _host, headers, _session = _app_with_user()
    other = store.create_org(slug="other", name="Other")
    other_host = store.create_host(other, "far", owner_subject="them",
                                   last_seen=NOW)
    store.upsert_review(other.id, other_host.id, "rev-other",
                        binding="z" * 64, action="shell", phase="call",
                        created=NOW)
    store.create_user(other, issuer="https://idp.example", subject="them",
                      email="them@other.test", role="reviewer")

    status, _headers, payload = _call(app, "/v1/reviews/rev-other",
                                      headers=headers)
    assert status == 404
    assert payload["error"]["code"] == "not_found"

    status, _headers, listing = _call(app, "/v1/reviews", headers=headers)
    assert status == 200 and listing["reviews"] == []


# -- decisions ----------------------------------------------------------

def test_a_decision_requires_a_fresh_step_up_before_parsing_the_body():
    app, store, org, _user, host, headers, _session = _app_with_user()
    agent = _agent_headers(store, org, host)
    _upload(app, agent)

    status, _headers, payload = _decide(app, headers, "rev-1")

    assert status == 403
    assert payload["error"]["code"] == "step_up_required"
    assert store.review_by_id(org.id, "rev-1").status == "pending"


def test_a_stale_step_up_is_not_fresh():
    app, store, org, _user, host, headers, session = _app_with_user()
    agent = _agent_headers(store, org, host)
    _upload(app, agent)
    app.sessions.mark_step_up(session, "totp", now=NOW - 400)

    status, _headers, payload = _decide(app, headers, "rev-1")

    assert status == 403
    assert payload["error"]["code"] == "step_up_required"


def test_an_approve_returns_a_verifiable_grant_and_settles_the_review():
    seed = generate_seed()
    app, store, org, user, host, headers, session = _app_with_user(seed=seed)
    agent = _agent_headers(store, org, host)
    _upload(app, agent)
    app.sessions.mark_step_up(session, "totp", now=NOW)

    status, _headers, payload = _decide(app, headers, "rev-1")

    assert status == 200
    assert payload["status"] == "approved"
    assert payload["seq"] == 1
    grants = store.grants_after(org.id, host.id, 0)
    assert len(grants) == 1
    grant = grants[0]
    assert grant["grant_id"] == payload["grant_id"]
    assert verify_grant(grant, approval_public_key(seed), org_id=org.id,
                        host_id=host.id, now=NOW) is None
    assert grant["review_id"] == "rev-1"
    assert grant["binding"] == "b" * 64
    assert grant["decision"] == "approve"
    assert grant["seq"] == 1 and grant["prev"] == GENESIS
    assert grant["approver"] == {"issuer": "https://idp.example",
                                 "subject": "u1", "email": "u1@acme.test"}
    assert grant["step_up"] == {"method": "totp", "at": NOW}
    assert grant["issued_at"] == NOW
    assert grant["expires_at"] - grant["issued_at"] == 300
    assert grant["expires_at"] - grant["issued_at"] <= GRANT_MAX_TTL
    review = store.review_by_id(org.id, "rev-1")
    assert review.status == "approved"
    assert review.decided_by == "https://idp.example#u1"
    assert review.approval_until == NOW + 300  # min(ttl, grant expiry)
    assert store.grant_head(org.id, host.id) == {"seq": 1,
                                                 "sig": grant["sig"]}


def test_reject_and_revoke_are_signed_with_their_own_decision():
    app, store, org, _user, host, headers, session = _app_with_user()
    agent = _agent_headers(store, org, host)
    _upload(app, agent, _upload_body(review_id="rev-reject"))
    _upload(app, agent, _upload_body(review_id="rev-revoke"))
    app.sessions.mark_step_up(session, "totp", now=NOW)

    status, _headers, payload = _decide(app, headers, "rev-reject",
                                        decision="reject", reason="no")
    assert status == 200 and payload["status"] == "rejected"
    status, _headers, payload = _decide(app, headers, "rev-revoke",
                                        decision="revoke")
    assert status == 200 and payload["status"] == "revoked"
    grants = store.grants_after(org.id, host.id, 0)
    assert [grant["decision"] for grant in grants] == ["reject", "revoke"]
    assert [grant["seq"] for grant in grants] == [1, 2]
    assert grants[1]["prev"] == grants[0]["sig"]


def test_an_unknown_decision_is_422():
    app, store, org, _user, host, headers, session = _app_with_user()
    agent = _agent_headers(store, org, host)
    _upload(app, agent)
    app.sessions.mark_step_up(session, "totp", now=NOW)

    status, _headers, payload = _decide(app, headers, "rev-1",
                                        decision="maybe")

    assert status == 422
    assert payload["error"]["code"] == "invalid_request"


def test_a_decided_review_cannot_be_decided_again():
    app, store, org, _user, host, headers, session = _app_with_user()
    agent = _agent_headers(store, org, host)
    _upload(app, agent)
    app.sessions.mark_step_up(session, "totp", now=NOW)
    assert _decide(app, headers, "rev-1")[0] == 200

    status, _headers, payload = _decide(app, headers, "rev-1",
                                        decision="reject")

    assert status == 409
    assert payload["error"]["code"] == "review_not_pending"


def test_an_expired_review_is_refused():
    app, store, org, _user, host, headers, session = _app_with_user()
    agent = _agent_headers(store, org, host)
    _upload(app, agent, _upload_body(pending_until=NOW - 1))
    app.sessions.mark_step_up(session, "totp", now=NOW)

    status, _headers, payload = _decide(app, headers, "rev-1")

    assert status == 409
    assert payload["error"]["code"] == "review_expired"
    assert store.grants_after(org.id, host.id, 0) == []


def test_four_eyes_needs_two_distinct_subjects_and_only_signs_at_quorum():
    app, store, org, _first, host, first_headers, first_session = _app_with_user()
    second = store.create_user(org, issuer="https://idp.example",
                               subject="u2", email="u2@acme.test",
                               role="reviewer")
    second_headers, second_session = _login(app, org, second)
    agent = _agent_headers(store, org, host)
    _upload(app, agent, _upload_body(min_approvals=2))

    app.sessions.mark_step_up(first_session, "totp", now=NOW)
    app.sessions.mark_step_up(second_session, "webauthn", now=NOW)

    status, _headers, payload = _decide(app, first_headers, "rev-1")
    assert status == 202
    assert payload == {"status": "pending_approvals", "approvals": 1,
                       "required": 2}
    assert store.review_by_id(org.id, "rev-1").status == "pending"
    assert store.grants_after(org.id, host.id, 0) == []

    status, _headers, payload = _decide(app, first_headers, "rev-1")
    assert status == 409
    assert payload["error"]["code"] == "distinct_approver_required"

    status, _headers, payload = _decide(app, second_headers, "rev-1")
    assert status == 200
    assert payload["status"] == "approved"
    review = store.review_by_id(org.id, "rev-1")
    assert review.approvers == ["u1", "u2"]
    assert review.decided_by == "https://idp.example#u2"
    assert len(store.grants_after(org.id, host.id, 0)) == 1


def test_the_owner_may_not_self_approve_when_the_review_forbids_it():
    app, store, org, _user, host, headers, session = _app_with_user(
        owner="u1")
    agent = _agent_headers(store, org, host)
    _upload(app, agent, _upload_body(allow_self_approval=False))
    app.sessions.mark_step_up(session, "totp", now=NOW)

    status, _headers, payload = _decide(app, headers, "rev-1")

    assert status == 403
    assert payload["error"]["code"] == "forbidden"
    assert store.review_by_id(org.id, "rev-1").status == "pending"


def test_a_stale_host_requires_approve_anyway_and_a_reason():
    app, store, org, _user, host, headers, session = _app_with_user(
        last_seen=NOW - 400)
    agent = _agent_headers(store, org, host)
    _upload(app, agent)
    app.sessions.mark_step_up(session, "totp", now=NOW)

    status, _headers, payload = _decide(app, headers, "rev-1")
    assert status == 409
    assert payload["error"]["code"] == "approve_anyway_required"
    assert store.grants_after(org.id, host.id, 0) == []

    status, _headers, payload = _decide(app, headers, "rev-1",
                                        approve_anyway=True, reason="   ")
    assert status == 409

    status, _headers, payload = _decide(app, headers, "rev-1",
                                        approve_anyway=True,
                                        reason="host is being rebuilt")
    assert status == 200
    assert payload["status"] == "approved"


def test_a_fresh_host_needs_no_override():
    app, store, org, _user, host, headers, session = _app_with_user()
    agent = _agent_headers(store, org, host)
    _upload(app, agent)
    app.sessions.mark_step_up(session, "totp", now=NOW)

    status, _headers, payload = _decide(app, headers, "rev-1")

    assert status == 200
    assert payload["status"] == "approved"


def test_decision_input_types_are_validated():
    app, store, org, _user, host, headers, session = _app_with_user()
    agent = _agent_headers(store, org, host)
    _upload(app, agent)
    app.sessions.mark_step_up(session, "totp", now=NOW)

    json_headers = dict(headers, **{"content-type": "application/json"})
    status, _headers, _ = _call(
        app, "/v1/reviews/rev-1/decision", method="POST", headers=json_headers,
        body=json.dumps({"decision": "approve", "reason": 3}).encode())
    assert status == 422

    status, _headers, _ = _call(
        app, "/v1/reviews/rev-1/decision", method="POST", headers=json_headers,
        body=json.dumps({"decision": "approve",
                         "approve_anyway": "yes"}).encode())
    assert status == 422

    status, _headers, _ = _call(
        app, "/v1/reviews/rev-1/decision", method="POST", headers=json_headers,
        body=json.dumps({"decision": "approve", "unknown": 1}).encode())
    assert status == 422


def test_the_grant_chain_advances_across_reviews():
    app, store, org, _user, host, headers, session = _app_with_user()
    agent = _agent_headers(store, org, host)
    _upload(app, agent, _upload_body(review_id="rev-a"))
    _upload(app, agent, _upload_body(review_id="rev-b"))
    app.sessions.mark_step_up(session, "totp", now=NOW)

    first = _decide(app, headers, "rev-a")[2]
    second = _decide(app, headers, "rev-b")[2]

    grants = store.grants_after(org.id, host.id, 0)
    assert [grant["seq"] for grant in grants] == [1, 2]
    assert grants[0]["prev"] == GENESIS
    assert grants[1]["prev"] == grants[0]["sig"]
    assert first["grant_id"] != second["grant_id"]
    assert [grant["grant_id"] for grant in grants] == [
        first["grant_id"], second["grant_id"]]


def test_the_step_up_method_is_carried_into_the_grant():
    app, store, org, _user, host, headers, session = _app_with_user()
    agent = _agent_headers(store, org, host)
    _upload(app, agent)
    app.sessions.mark_step_up(session, "webauthn", now=NOW)

    _decide(app, headers, "rev-1")

    grant = store.grants_after(org.id, host.id, 0)[0]
    assert grant["step_up"] == {"method": "webauthn", "at": NOW}
    assert StepUpService.fresh(NOW, now=NOW)
