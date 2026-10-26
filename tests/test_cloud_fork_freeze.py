"""Forks freeze receipt ingest only; an administrator unfreezes deliberately.

``409 chain_fork`` records the break, opens an admin alert and sets
``ingest_frozen``. The same host can still poll grants and heartbeat, which is
what lets an operator investigate. Unfreezing needs a fresh step-up and a
reason, and is audited (FR-036).
"""
from __future__ import annotations

import pytest

from interlock.cloud.store import ReceiptFork

from _c4_helpers import (
    NOW,
    add_agent_key,
    call,
    chain,
    ingest,
    make_app,
    post_json,
)


def _env():
    env = make_app(role="owner")
    headers = add_agent_key(env)
    first = chain(b"h" * 32, count=2)
    status, _headers, body, _raw = ingest(env, headers, first)
    assert status == 200, body
    return env, headers, first


def _fork(env, headers):
    bad = chain(b"x" * 32, count=1)
    return ingest(env, headers, bad)


def test_a_fork_freezes_ingest_and_opens_an_admin_alert():
    env, headers, _first = _env()

    status, _headers, body, _raw = _fork(env, headers)

    assert status == 409
    assert body["error"]["code"] == "chain_fork"
    assert env.host.state == "ingest_frozen"
    events = [entry.event for entry in env.store.audit_list(env.org.id)]
    assert "receipts.fork" in events
    assert "alert.opened" in events
    alert = [entry for entry in env.store.audit_list(env.org.id)
             if entry.event == "alert.opened"][0]
    assert alert.detail["kind"] == "receipt_chain_fork"
    assert alert.detail["host_id"] == env.host.id


def test_a_frozen_host_cannot_ingest_but_can_poll_and_heartbeat():
    env, headers, first = _env()
    assert _fork(env, headers)[0] == 409

    continuation = chain(b"h" * 32, count=1, start=first[-1].mac)
    status, _headers, body, _raw = ingest(env, headers, continuation)
    assert status == 409
    assert body["error"]["code"] == "ingest_frozen"

    grants = call(env.app, "/v1/grants", headers=headers,
                  query=b"cursor=0&wait=0")
    assert grants[0] == 200
    heartbeat = post_json(env, "/v1/hosts/self", headers, {})
    assert heartbeat[0] == 200


def test_an_exact_replay_is_idempotent_and_does_not_freeze():
    env, headers, first = _env()

    status, _headers, body, _raw = ingest(env, headers, first)

    assert status == 200
    assert body["replay"] is True
    assert body["accepted"] == 0
    assert env.host.state == "active"
    assert not any(entry.event == "receipts.fork"
                   for entry in env.store.audit_list(env.org.id))


def test_a_lost_race_in_the_store_is_also_a_fork():
    env, headers, first = _env()
    continuation = chain(b"h" * 32, count=1, start=first[-1].mac)

    def _raise(*_args, **_kwargs):
        raise ReceiptFork("locked head moved")

    env.store.append_receipts = _raise
    status, _headers, body, _raw = ingest(env, headers, continuation)

    assert status == 409
    assert body["error"]["code"] == "chain_fork"
    assert env.host.state == "ingest_frozen"


def test_unfreezing_requires_a_fresh_step_up_and_a_reason():
    env, headers, first = _env()
    assert _fork(env, headers)[0] == 409
    path = "/v1/hosts/{}/unfreeze".format(env.host.id)

    status, _headers, body, _raw = post_json(
        env, path, env.headers, {"reason": "operator reviewed the log"})
    assert status == 403
    assert body["error"]["code"] == "step_up_required"

    env.app.sessions.mark_step_up(env.session, "totp", now=NOW)
    status, _headers, body, _raw = post_json(env, path, env.headers, {})
    assert status == 422
    assert body["error"]["code"] == "invalid_request"

    status, _headers, body, _raw = post_json(
        env, path, env.headers, {"reason": "operator reviewed the log"})
    assert status == 200, body
    assert body["host"]["state"] == "active"
    assert env.host.state == "active"
    events = [entry.event for entry in env.store.audit_list(env.org.id)]
    assert "host.unfrozen" in events

    continuation = chain(b"h" * 32, count=1, start=first[-1].mac)
    assert ingest(env, headers, continuation)[0] == 200


def test_unfreezing_a_host_that_is_not_frozen_is_a_conflict():
    env, _headers, _first = _env()
    path = "/v1/hosts/{}/unfreeze".format(env.host.id)
    env.app.sessions.mark_step_up(env.session, "totp", now=NOW)

    status, _headers, body, _raw = post_json(
        env, path, env.headers, {"reason": "no fork happened"})

    assert status == 409
    assert body["error"]["code"] == "host_not_frozen"


def test_a_reviewer_cannot_unfreeze():
    env = make_app(role="reviewer")
    env.host.state = "ingest_frozen"
    env.app.sessions.mark_step_up(env.session, "totp", now=NOW)

    status, _headers, body, _raw = post_json(
        env, "/v1/hosts/{}/unfreeze".format(env.host.id), env.headers,
        {"reason": "not my job"})

    assert status == 403
    assert body["error"]["code"] == "forbidden"


def test_a_forked_batch_stores_nothing_at_all():
    # The batch links for one receipt and forks on the next. The store's
    # contract is the Postgres one - a fork rolls the whole batch back - so
    # the linked receipt must not be left behind (FR-036, FR-037).
    env = make_app(role="owner")
    good = chain(b"h" * 32, count=1)
    broken = chain(b"h" * 32, count=1, start="f" * 64)

    with pytest.raises(ReceiptFork):
        env.store.append_receipts(env.org.id, env.host.id, good + broken)

    assert env.store.receipt_macs(env.org.id, env.host.id) == []
    head = env.store.receipt_head(env.org.id, env.host.id)
    assert head["head_mac"] is None
    assert int(head["count"]) == 0
