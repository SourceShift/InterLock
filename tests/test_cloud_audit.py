"""Auditor receipt search and verified JSONL export (FR-038 .. FR-040).

Search is host/time/action/verdict/principal/policy/text filtered and cursor
paged. The export walks the host chain with its pinned verifier and refuses
before the first byte when the chain is broken. There is no preview or raw
argument surface: those query names are refused outright.
"""
from __future__ import annotations

import json

from interlock.receipt import Receipt

from _c4_helpers import (
    add_agent_key,
    call,
    chain,
    ed25519_chain,
    ed25519_host,
    ingest,
    make_app,
)


def _seeded(role="auditor", *, count=3, **fields):
    env = make_app(role=role)
    headers = add_agent_key(env)
    receipts = chain(b"h" * 32, count=count, **fields)
    status, _headers, body, _raw = ingest(env, headers, receipts)
    assert status == 200, body
    return env, headers, receipts


def _search(env, **params):
    query = "&".join(
        "{}={}".format(name, value) for name, value in params.items()).encode()
    return call(env.app, "/v1/audit", headers=env.headers, query=query)


def test_an_auditor_searches_receipts_by_host():
    env, _headers, receipts = _seeded()

    status, _headers, body, _raw = _search(env, host=env.host.id)

    assert status == 200
    assert len(body["receipts"]) == 3
    assert [item["action"] for item in body["receipts"]] == ["shell"] * 3
    assert body["receipts"][0]["verification"] == "linkage_only"
    assert body["receipts"][0]["mac"] == receipts[0].mac


def test_search_filters_by_action_verdict_principal_and_policy():
    env = make_app(role="auditor")
    headers = add_agent_key(env)
    first = chain(b"h" * 32, count=1, action="shell", verdict="ALLOW",
                  principal="alice", policy_id="p-1",
                  base_ts=2_000_000_000.0)
    second = chain(b"h" * 32, count=1, action="filesystem.write",
                   verdict="BLOCK", principal="bob", policy_id="p-2",
                   base_ts=2_000_000_100.0, start=first[-1].mac)
    assert ingest(env, headers, first + second)[0] == 200

    assert len(_search(env, action="filesystem.write")[2]["receipts"]) == 1
    assert len(_search(env, verdict="BLOCK")[2]["receipts"]) == 1
    assert len(_search(env, principal="alice")[2]["receipts"]) == 1
    assert len(_search(env, policy_id="p-2")[2]["receipts"]) == 1
    assert len(_search(env, q="FILESYSTEM")[2]["receipts"]) == 1


def test_search_filters_a_time_range_as_epoch_or_iso():
    env, _headers, _receipts = _seeded()

    epoch = _search(env, host=env.host.id, **{
        "from": "1999999940", "to": "1999999941"})
    assert epoch[0] == 200
    assert len(epoch[2]["receipts"]) == 2

    iso = _search(env, host=env.host.id, **{
        "from": "2033-05-18T03:32:20Z", "to": "2033-05-18T03:32:21Z"})
    assert iso[0] == 200
    assert len(iso[2]["receipts"]) == 2


def test_search_pages_with_a_cursor_and_caps_the_limit():
    env, _headers, _receipts = _seeded(count=5)

    first = _search(env, host=env.host.id, limit=2)
    assert first[0] == 200
    assert len(first[2]["receipts"]) == 2
    cursor = first[2]["next_cursor"]
    second = _search(env, host=env.host.id, limit=2, cursor=cursor)
    assert second[2]["receipts"][0]["seq"] == 3

    assert _search(env, limit=101)[0] == 422
    assert _search(env, limit=0)[0] == 422


def test_search_refuses_preview_and_raw_query_names():
    env, _headers, _receipts = _seeded()

    for name in ("preview", "raw", "args", "arguments"):
        status, _headers, body, _raw = _search(env, **{name: "x"})
        assert status == 422
        assert body["error"]["code"] == "invalid_request"


def test_search_refuses_a_verification_filter_it_cannot_apply():
    # FR-038 lists the filters; ``verification`` is not one. It must be
    # refused like any unknown name rather than accepted and ignored - an
    # auditor who asked for "only unverified" and got everything back would
    # read the result as a statement about the chain.
    env, _headers, _receipts = _seeded()

    status, _headers, body, _raw = _search(env, verification="verified")

    assert status == 422
    assert body["error"]["code"] == "invalid_request"


def test_search_caps_the_free_text_needle():
    env, _headers, _receipts = _seeded()

    assert _search(env, q="a" * 200)[0] == 200
    status, _headers, body, _raw = _search(env, q="a" * 201)
    assert status == 422
    assert body["error"]["code"] == "invalid_request"


def test_a_reviewer_cannot_search_receipts():
    env, _headers, _receipts = _seeded(role="reviewer")
    status, _headers, body, _raw = _search(env, host=env.host.id)
    assert status == 403
    assert body["error"]["code"] == "forbidden"


def test_export_returns_verified_jsonl_for_the_host_chain():
    env, _headers, receipts = _seeded()

    status, headers, _body, raw = call(
        env.app, "/v1/audit/export", headers=env.headers,
        query=("host=" + env.host.id).encode())

    assert status == 200
    assert headers["content-type"] == "application/x-ndjson"
    lines = [line for line in raw.decode().splitlines() if line]
    assert len(lines) == len(receipts)
    assert [Receipt.from_json(line) for line in lines] == receipts


def test_export_refuses_a_broken_ed25519_chain_before_writing():
    env = make_app(role="auditor")
    seed, _public = ed25519_host(env)
    headers = add_agent_key(env)
    receipts = ed25519_chain(seed, count=3)
    assert ingest(env, headers, receipts)[0] == 200
    # Edit one stored receipt's signed body; the mac no longer covers it.
    for row in env.store.receipts.values():
        if row["mac"] == receipts[1].mac:
            row["body"]["action"] = "rm"

    status, _headers, body, raw = call(
        env.app, "/v1/audit/export", headers=env.headers,
        query=("host=" + env.host.id).encode())

    assert status == 409
    assert body["error"]["code"] == "chain_broken"
    # The refusal has an error body, but no receipt line was written.
    assert b'"action"' not in raw


def test_export_filters_lines_but_still_verifies_the_whole_chain():
    env = make_app(role="auditor")
    headers = add_agent_key(env)
    first = chain(b"h" * 32, count=1, action="shell")
    second = chain(b"h" * 32, count=1, action="filesystem.write",
                   base_ts=2_000_000_100.0, start=first[-1].mac)
    assert ingest(env, headers, first + second)[0] == 200

    status, _headers, _body, raw = call(
        env.app, "/v1/audit/export", headers=env.headers,
        query=("host={}&action=filesystem.write".format(env.host.id)).encode())

    assert status == 200
    lines = [line for line in raw.decode().splitlines() if line]
    assert len(lines) == 1
    assert json.loads(lines[0])["action"] == "filesystem.write"


def test_export_windows_on_the_receipt_time_a_search_windows_on():
    # ``_seeded`` writes receipts stamped NOW-60..NOW-58 while the store's
    # ingest clock is NOW, so the two time bases are 60 s apart. A search and
    # its export must select the same receipts: the receipt's own ``ts`` wins
    # and ingest time is only the fallback.
    env, _headers, _receipts = _seeded()
    window = {"from": "1999999940", "to": "1999999941"}

    status, _headers, body, _raw = _search(env, host=env.host.id, **window)
    assert status == 200
    assert len(body["receipts"]) == 2

    query = ("host={}&from={}&to={}".format(
        env.host.id, window["from"], window["to"])).encode()
    status, _headers, _body, raw = call(
        env.app, "/v1/audit/export", headers=env.headers, query=query)

    assert status == 200
    lines = [line for line in raw.decode().splitlines() if line]
    assert len(lines) == len(body["receipts"]) == 2

    # Ingest time is NOW, which is outside this window: an export that fell
    # back to it would have emitted all three receipts.
    assert [json.loads(line)["ts"] for line in lines] == [1999999940.0,
                                                          1999999941.0]


def test_export_requires_a_host():
    env, _headers, _receipts = _seeded()
    status, _headers, body, _raw = call(
        env.app, "/v1/audit/export", headers=env.headers)
    assert status == 422
    assert body["error"]["code"] == "invalid_request"


def test_export_of_an_unknown_host_is_404():
    env, _headers, _receipts = _seeded()
    status, _headers, body, _raw = call(
        env.app, "/v1/audit/export", headers=env.headers,
        query=b"host=host_missing")
    assert status == 404
    assert body["error"]["code"] == "not_found"


def _other_org_host(env):
    other = env.store.create_org(slug="other", name="Other")
    return env.store.create_host(other, "other-box", owner_subject="owner-y")


def test_search_and_export_never_cross_an_org_boundary():
    env, _headers, _receipts = _seeded()
    foreign = _other_org_host(env)

    status, _headers, body, _raw = _search(env, host=foreign.id)
    assert status == 404
    assert body["error"]["code"] == "not_found"

    status, _headers, body, _raw = call(
        env.app, "/v1/audit/export", headers=env.headers,
        query=("host=" + foreign.id).encode())
    assert status == 404
    assert body["error"]["code"] == "not_found"
