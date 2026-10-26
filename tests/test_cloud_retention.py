"""Receipt retention: clamped, head-safe and audited (FR-039).

The job deletes expired receipts and old checkpoints, but never the head of a
chain that is not ``verified``. Every run is audited; a preserved head is
also audited as ``retention_skipped``. A dry run counts without deleting.
"""
from __future__ import annotations

from interlock.cloud.retention import (
    DEFAULT_RETENTION_DAYS,
    MAX_RETENTION_DAYS,
    MIN_RETENTION_DAYS,
    RETENTION_ACTOR,
    clamp_days,
    run,
)
from interlock.cloud.store import MemoryStore

from _c4_helpers import NOW, chain

DAY = 24 * 60 * 60


def _store_with_org(days=365):
    store = MemoryStore()
    org = store.create_org(slug="acme", name="Acme")
    org = store.update_org(org.id, retention_days=days)
    host = store.create_host(org, "box", owner_subject="owner-x")
    return store, org, host


def _append(store, org, host, receipts, *, created, level):
    return store.append_receipts(
        org.id, host.id, receipts, verification=level, now=created)



def test_retention_days_are_clamped_to_the_documented_bounds():
    assert clamp_days(0) == MIN_RETENTION_DAYS
    assert clamp_days(10) == MIN_RETENTION_DAYS
    assert clamp_days(365) == DEFAULT_RETENTION_DAYS
    assert clamp_days(9_999) == MAX_RETENTION_DAYS
    assert clamp_days("365") == DEFAULT_RETENTION_DAYS
    assert clamp_days(True) == DEFAULT_RETENTION_DAYS
    assert clamp_days(None) == DEFAULT_RETENTION_DAYS


def test_expired_receipts_are_deleted_and_newer_ones_remain():
    store, org, host = _store_with_org()
    old = chain(b"h" * 32, count=3, base_ts=NOW - 400 * DAY)
    new = chain(b"h" * 32, count=2, base_ts=NOW - 1 * DAY,
                start=old[-1].mac)
    _append(store, org, host, old, created=NOW - 400 * DAY, level="verified")
    _append(store, org, host, new, created=NOW - 1 * DAY, level="verified")

    result = run(store, NOW, days=365)

    assert result["receipts"] == 3
    assert result["checkpoints"] == 0
    rows = store.receipts_since(org.id, host.id)
    assert [row["mac"] for row in rows] == [receipt.mac for receipt in new]
    events = [entry.event for entry in store.audit_list(org.id)]
    assert "retention.ran" in events
    record = [entry for entry in store.audit_list(org.id)
              if entry.event == "retention.ran"][0]
    assert record.actor == RETENTION_ACTOR
    assert record.detail["receipts"] == 3
    assert record.detail["days"] == 365


def test_the_head_of_a_linkage_only_chain_is_preserved_and_audited():
    store, org, host = _store_with_org()
    receipts = chain(b"h" * 32, count=3, base_ts=NOW - 400 * DAY)
    _append(store, org, host, receipts, created=NOW - 400 * DAY,
            level="linkage_only")

    result = run(store, NOW, days=365)

    assert result["receipts"] == 2
    assert result["runs"][0]["skipped"] == [
        {"host_id": host.id, "mac": receipts[-1].mac}]
    remaining = store.receipts_since(org.id, host.id)
    assert [row["mac"] for row in remaining] == [receipts[-1].mac]
    skipped = [entry for entry in store.audit_list(org.id)
               if entry.event == "retention_skipped"]
    assert len(skipped) == 1
    assert skipped[0].detail["host_id"] == host.id
    assert skipped[0].detail["mac"] == receipts[-1].mac


def test_a_dry_run_counts_but_deletes_nothing():
    store, org, host = _store_with_org()
    old = chain(b"h" * 32, count=2, base_ts=NOW - 400 * DAY)
    _append(store, org, host, old, created=NOW - 400 * DAY, level="verified")

    result = run(store, NOW, days=365, dry_run=True)

    assert result["dry_run"] is True
    assert result["receipts"] == 2
    assert len(store.receipts_since(org.id, host.id)) == 2
    record = [entry for entry in store.audit_list(org.id)
              if entry.event == "retention.ran"][0]
    assert record.detail["dry_run"] is True


def test_the_newest_checkpoint_survives_even_when_old():
    store, org, host = _store_with_org()
    old_issued = NOW - 400 * DAY
    store.checkpoints.extend([
        {"org_id": org.id, "host_id": host.id, "v": 1,
         "head_mac": "a" * 64, "count": 1, "issued_at": old_issued,
         "sig": "00"},
        {"org_id": org.id, "host_id": host.id, "v": 1,
         "head_mac": "b" * 64, "count": 2,
         "issued_at": old_issued + 60, "sig": "00"},
    ])

    result = run(store, NOW, days=365)

    assert result["checkpoints"] == 1
    remaining = store.list_checkpoints(org.id, host.id)
    assert len(remaining) == 1
    assert remaining[0]["head_mac"] == "b" * 64


def test_an_override_is_clamped_like_a_configured_period():
    store, org, host = _store_with_org()
    recent = chain(b"h" * 32, count=1, base_ts=NOW - 40 * DAY)
    _append(store, org, host, recent, created=NOW - 40 * DAY,
            level="verified")

    # 1 day clamps to 30, so a 40-day-old receipt is expired.
    result = run(store, NOW, days=1)

    assert result["receipts"] == 1
    assert result["runs"][0]["days"] == MIN_RETENTION_DAYS
    assert store.receipts_since(org.id, host.id) == []


def test_each_org_uses_its_own_period():
    store = MemoryStore()
    short = store.create_org(slug="short", name="Short")
    short = store.update_org(short.id, retention_days=30)
    long = store.create_org(slug="long", name="Long")
    long = store.update_org(long.id, retention_days=365)
    short_host = store.create_host(short, "a", owner_subject="o")
    long_host = store.create_host(long, "b", owner_subject="o")
    old = chain(b"h" * 32, count=1, base_ts=NOW - 60 * DAY)
    _append(store, short, short_host, old, created=NOW - 60 * DAY,
            level="verified")
    _append(store, long, long_host, old, created=NOW - 60 * DAY,
            level="verified")

    result = run(store, NOW)

    by_org = {entry["org_id"]: entry for entry in result["runs"]}
    assert by_org[short.id]["receipts"] == 1
    assert by_org[long.id]["receipts"] == 0
    assert store.receipts_since(short.id, short_host.id) == []
    assert len(store.receipts_since(long.id, long_host.id)) == 1
