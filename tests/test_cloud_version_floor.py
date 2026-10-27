"""C7 manifest version floor: publish advances it, only a reset lowers it.

The floor is what keeps a restored or rolled-back plane from handing a host a
policy older than the one it is already enforcing. These tests pin the two
directions: a publish can only move it up, and the operator's ``--reset-floor``
is the one deliberate path down.
"""
from __future__ import annotations

import pytest

from interlock.cli import build_parser, main
from interlock.cloud.admin import version_floor
from interlock.cloud.store import MemoryStore
from tests.test_cloud_rollout import _publish, _setup, _verify


def _store():
    store = MemoryStore()
    org = store.create_org(slug="acme", name="Acme")
    return store, org


def _manifest(version, *, target=None):
    return {
        "version": version,
        "epoch": "0123456789abcdef",
        "target": target or {"kind": "ring", "id": "stable"},
        "artifact": {"format": 1, "sha256": "a" * 64, "size": 10},
    }


# -- the policy module --------------------------------------------------

def test_a_publish_version_is_never_below_the_floor():
    store, org = _store()
    assert version_floor.current(store, org.id) == 0
    assert version_floor.next_publish_version(store, org.id) == 1
    version_floor.advance(store, org.id, 5)
    assert version_floor.next_publish_version(store, org.id) == 5
    store.put_manifest(org.id, _manifest(1))
    store.put_manifest(org.id, _manifest(2))
    # The manifest history says 3; the floor still says 5 and wins.
    assert version_floor.next_publish_version(store, org.id) == 5


def test_advance_refuses_to_lower_the_floor_and_keeps_the_old_value():
    store, org = _store()
    version_floor.advance(store, org.id, 5)
    with pytest.raises(version_floor.VersionFloorError) as exc:
        version_floor.advance(store, org.id, 4)
    assert "reset-floor" in str(exc.value) or "--reset-floor" in str(exc.value)
    assert version_floor.current(store, org.id) == 5


def test_bump_to_never_lowers_but_a_reset_deliberately_does():
    store, org = _store()
    assert version_floor.bump_to(store, org.id, 4) == 4
    with pytest.raises(version_floor.VersionFloorError):
        version_floor.bump_to(store, org.id, 3)
    assert version_floor.current(store, org.id) == 4
    assert version_floor.reset(store, org.id, 2) == 2
    assert version_floor.current(store, org.id) == 2


def test_restore_check_flags_a_restored_history_behind_the_floor():
    store, org = _store()
    store.put_manifest(org.id, _manifest(1))
    store.put_manifest(org.id, _manifest(2))
    version_floor.bump_to(store, org.id, 5)
    report = version_floor.restore_check(store, org.id)
    assert report == {"org_id": org.id, "floor": 5, "next_version": 3,
                      "ok": False}
    version_floor.reset(store, org.id, 0)
    assert version_floor.restore_check(store, org.id)["ok"] is True


def test_the_floor_is_per_org():
    store, first = _store()
    second = store.create_org(slug="other", name="Other")
    version_floor.advance(store, first.id, 9)
    assert version_floor.current(store, second.id) == 0


# -- through the publish route -----------------------------------------

def test_publishing_advances_the_floor_to_the_manifest_version():
    ctx = _setup()
    status, _h, _raw, first = _publish(ctx)
    assert status == 201, first
    assert first["manifest"]["version"] == 1
    assert version_floor.current(
        ctx["store"], ctx["org"].id) == first["manifest"]["version"]

    status, _h, _raw, second = _publish(ctx)
    assert status == 201, second
    assert second["manifest"]["version"] == 2
    assert version_floor.current(ctx["store"], ctx["org"].id) == 2


def test_a_bumped_floor_is_the_version_the_next_publish_carries():
    ctx = _setup()
    status, _h, _raw, _first = _publish(ctx)
    assert status == 201
    version_floor.bump_to(ctx["store"], ctx["org"].id, 7)
    status, _h, _raw, published = _publish(ctx)
    assert status == 201, published
    assert published["manifest"]["version"] == 7
    assert _verify(ctx, published["manifest"]) is None
    assert version_floor.current(ctx["store"], ctx["org"].id) == 7


# -- the CLI surface ----------------------------------------------------

def test_the_version_floor_flags_parse():
    args = build_parser().parse_args(
        ["cloud", "admin", "version-floor", "--org", "acme", "--bump-to", "4"])
    assert args.admin_command == "version-floor"
    assert args.bump_to == 4
    assert args.reset_floor is None

    args = build_parser().parse_args(
        ["cloud", "admin", "version-floor", "--reset-floor"])
    assert args.reset_floor == 0
    args = build_parser().parse_args(
        ["cloud", "admin", "version-floor", "--reset-floor", "3"])
    assert args.reset_floor == 3


def test_bump_to_and_reset_floor_are_mutually_exclusive():
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args([
            "cloud", "admin", "version-floor",
            "--bump-to", "4", "--reset-floor", "1",
        ])
    assert exc.value.code == 64


def test_the_cli_needs_a_dsn_and_an_org(monkeypatch, capsys):
    monkeypatch.delenv("IL_CLOUD_DSN", raising=False)
    monkeypatch.delenv("IL_CLOUD_ORG", raising=False)
    assert main(["cloud", "admin", "version-floor"]) == 2
    assert "IL_CLOUD_DSN" in capsys.readouterr().err

    assert main([
        "cloud", "admin", "version-floor", "--dsn", "postgresql://db/x",
    ]) == 2
    assert "IL_CLOUD_ORG" in capsys.readouterr().err


def test_an_unknown_admin_command_is_a_usage_error(monkeypatch, capsys):
    monkeypatch.setenv("IL_CLOUD_DSN", "postgresql://db/x")
    monkeypatch.setenv("IL_CLOUD_ORG", "acme")
    assert main(["cloud", "admin"]) == 64
    assert "version-floor" in capsys.readouterr().err
