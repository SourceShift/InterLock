"""Host-side distribution: verify before fetch, highest version forever.

The connector's ordering is the safety property. A hint only says "look"; a
manifest must verify before a byte is fetched; the accepted version is written
down *before* the bytes arrive; the candidate is loaded before the active
pointer moves. These tests drive a real Ed25519 signer and the scripted
transport, so a refusal is the code production would record.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from interlock import __version__ as AGENT_VERSION
from interlock.cloud.connector.config import CloudHome
from interlock.cloud.connector.policy import (
    EXPIRY_ALARM_SECONDS,
    EXPIRY_GRACE_SECONDS,
    PolicyDistributor,
)
from interlock.cloud.connector.transport import FakeTransport, TransportError
from interlock.cloud.enrollment import generate_agent_key
from interlock.cloud.identity import (
    generate_host_seed,
    key_id,
    public_key_hex,
)
from interlock.cloud.policy.compile import compile_from_source
from interlock.cloud.policy.manifest import (
    policy_key_id,
    sign_kill,
    sign_manifest,
)
from interlock.event import SensorEvent
from interlock.mesh.ed25519 import generate_seed, public_key
from tests.fixtures.cloud.rules_module import scope_document

NOW = 2_000_000_000.0
MODULE = "tests.fixtures.cloud.rules_module:templates"


class _Clock:
    def __init__(self, value=NOW):
        self.value = float(value)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += float(seconds)


def _scope(allow=("ls", "pwd")):
    document = scope_document()
    document["bindings"]["acme"] = [
        {"template": "shell_allowlist", "params": {"allow": list(allow)}},
    ]
    return document


def _compile(allow=("ls", "pwd")):
    return compile_from_source([], _scope(allow), rules_module=MODULE)


def _manifest(seed, result, *, version=2, issued=NOW, expires=NOW + 3600,
              target=None, mode="enforce"):
    public_hex = public_key(seed).hex()
    return sign_manifest(seed, {
        "v": 1,
        "manifest_id": "m-{}".format(version),
        "org_id": "org-1",
        "version": version,
        "epoch": result.epoch,
        "target": target or {"kind": "ring", "id": "stable"},
        "mode": mode,
        "issued_at": issued,
        "expires_at": expires,
        "minimum_agent": None,
        "artifact": {
            "format": 1,
            "sha256": result.sha256,
            "size": len(result.artifact_bytes),
        },
        "rules_digest": result.epoch,
        "key_id": policy_key_id(public_key(seed)),
    })


def _home(tmp_path, seed, *, ring="stable"):
    home = CloudHome(tmp_path / "home")
    raw, _prefix, _digest = generate_agent_key()
    host_seed = generate_host_seed()
    host_public = public_key_hex(host_seed)
    home.save({
        "url": "https://cloud.example",
        "org_id": "org-1",
        "host_id": "host-1",
        "agent_key_id": "key-1",
        "agent_key": raw,
        "host_key_id": key_id(host_public),
        "host_public_key": host_public,
        "plane_public_keys": {
            "approval": "",
            "policy": public_key(seed).hex(),
            "receipt": "",
        },
        "spool_dir": "spool",
        "state_dir": "state",
        "ring": ring,
    })
    home.save_seed(host_seed)
    return home


def _distributor(tmp_path, seed, clock=None, *, ring="stable"):
    return PolicyDistributor(_home(tmp_path, seed, ring=ring),
                             FakeTransport(), clock or _Clock(), ring=ring)


def _json(payload):
    return 200, {}, json.dumps(payload).encode("utf-8")


def _install(dist, result, *, version=2, **overrides):
    manifest = _manifest(dist._seed, result, version=version, **overrides)
    dist.transport.responses.extend([
        _json({"version": version, "kill_epoch": 0}),
        _json(manifest),
        (200, {}, result.artifact_bytes),
    ])
    outcome = dist.poll_once()
    assert outcome["ok"] is True
    return manifest


def _with_seed(tmp_path, clock=None):
    seed = generate_seed()
    dist = _distributor(tmp_path, seed, clock)
    dist._seed = seed  # test-only convenience for the manifest builder
    return seed, dist


# -- the happy path -----------------------------------------------------

def test_a_host_verifies_fetches_loads_and_swaps_atomically(tmp_path):
    _seed, dist = _with_seed(tmp_path)
    result = _compile()
    manifest = _install(dist, result)

    status = dist.status()
    assert status["manifest_version"] == 2
    assert status["artifact_sha256"] == result.sha256
    assert status["epoch"] == result.epoch
    assert status["mode"] == "enforce"
    assert status["kill_active"] is False
    assert status["last_swap"] == NOW

    # The artifact bytes landed under artifacts/<sha>.json and the active
    # pointer names them, canonically and atomically.
    stored = (dist.artifacts_dir / "{}.json".format(result.sha256)).read_bytes()
    assert stored == result.artifact_bytes
    pointer = json.loads(dist.active_path.read_text(encoding="utf-8"))
    assert pointer == {"sha256": result.sha256, "version": 2,
                       "epoch": result.epoch, "mode": "enforce",
                       "rules_module": MODULE}
    assert not str(dist.state_path).startswith(str(dist.artifacts_dir))
    assert json.loads(dist.state_path.read_text(encoding="utf-8"))[
        "highest_version"] == 2
    assert dist.active_policy().sha256 == result.sha256
    assert manifest["version"] == 2


def test_a_second_cycle_without_a_new_hint_touches_no_manifest(tmp_path):
    _seed, dist = _with_seed(tmp_path)
    _install(dist, _compile())
    dist.transport.calls.clear()
    dist.transport.responses.append(_json({"version": 2, "kill_epoch": 0}))

    outcome = dist.poll_once()

    assert outcome["ok"] is True
    assert len(dist.transport.calls) == 1
    assert dist.transport.calls[0][1].startswith("/v1/hints")


# -- ordering and rollback ----------------------------------------------

def test_a_lower_manifest_version_is_refused_and_the_active_artifact_stays(tmp_path):
    seed, dist = _with_seed(tmp_path)
    current = _compile()
    _install(dist, current, version=2)
    old = _compile(allow=("pwd",))

    dist.transport.responses.extend([
        _json({"version": 3, "kill_epoch": 0}),
        _json(_manifest(seed, old, version=1)),
    ])
    outcome = dist.poll_once()

    assert outcome["refusals"]["manifest_version"] == 1
    assert dist.status()["manifest_version"] == 2
    assert dist.status()["artifact_sha256"] == current.sha256
    assert dist.active_policy().sha256 == current.sha256


def test_the_accepted_version_is_persisted_before_the_bytes_arrive(tmp_path):
    seed, dist = _with_seed(tmp_path)
    current = _compile()
    _install(dist, current, version=2)
    newer = _compile(allow=("cat",))

    dist.transport.responses.extend([
        _json({"version": 3, "kill_epoch": 0}),
        _json(_manifest(seed, newer, version=3)),
        TransportError("connection reset mid-download"),
    ])
    dist.poll_once()

    # The plane accepted version 3; a crash before the swap must not let a
    # restored plane re-offer it, and the active artifact is still version 2.
    status = dist.status()
    assert status["highest_version"] == 3
    assert status["manifest_version"] == 3
    assert status["artifact_sha256"] == current.sha256
    assert status["last_error"] == "connection reset mid-download"

    # A new process on the same home refuses the same version as a rollback.
    restarted = PolicyDistributor(dist.home, FakeTransport(), dist.clock, ring="stable")
    restarted.transport.responses.extend([
        _json({"version": 4, "kill_epoch": 0}),
        _json(_manifest(seed, newer, version=3)),
    ])
    outcome = restarted.poll_once()
    assert outcome["refusals"]["manifest_version"] == 1
    assert restarted.active_policy().sha256 == current.sha256


# -- artifact integrity -------------------------------------------------

def test_a_hash_mismatch_is_refused_before_the_pointer_moves(tmp_path):
    seed, dist = _with_seed(tmp_path)
    current = _compile()
    _install(dist, current, version=2)
    newer = _compile(allow=("cat",))
    tampered = bytearray(newer.artifact_bytes)
    tampered[0] ^= 0xFF
    assert len(tampered) == len(newer.artifact_bytes)

    dist.transport.responses.extend([
        _json({"version": 3, "kill_epoch": 0}),
        _json(_manifest(seed, newer, version=3)),
        (200, {}, bytes(tampered)),
    ])
    outcome = dist.poll_once()

    assert outcome["refusals"]["artifact_sha256"] == 1
    assert dist.status()["artifact_sha256"] == current.sha256
    assert dist.active_policy().sha256 == current.sha256


def test_a_truncated_fetch_is_a_size_refusal_not_a_partial_file(tmp_path):
    seed, dist = _with_seed(tmp_path)
    current = _compile()
    _install(dist, current, version=2)
    newer = _compile(allow=("cat",))

    dist.transport.responses.extend([
        _json({"version": 3, "kill_epoch": 0}),
        _json(_manifest(seed, newer, version=3)),
        (200, {}, newer.artifact_bytes[:20]),
    ])
    outcome = dist.poll_once()

    assert outcome["refusals"]["artifact_size"] == 1
    assert not (dist.artifacts_dir / "{}.json".format(newer.sha256)).exists()
    assert dist.status()["artifact_sha256"] == current.sha256


def test_an_artifact_whose_module_will_not_load_never_replaces_a_working_one(tmp_path):
    seed, dist = _with_seed(tmp_path)
    current = _compile()
    _install(dist, current, version=2)
    newer = _compile(allow=("cat",))
    broken = json.loads(newer.artifact_bytes.decode("utf-8"))
    broken["rules_module"] = "tests.fixtures.cloud.gone:templates"
    from interlock.policy.artifact import canonical_bytes, seal_artifact

    raw = canonical_bytes(seal_artifact(broken))
    manifest = _manifest(seed, newer, version=3)
    manifest["artifact"] = {"format": 1,
                            "sha256": hashlib.sha256(raw).hexdigest(),
                            "size": len(raw)}
    manifest = sign_manifest(seed, {key: value for key, value in manifest.items()
                                    if key != "sig"})
    dist.transport.responses.extend([
        _json({"version": 3, "kill_epoch": 0}), _json(manifest),
        (200, {}, raw),
    ])
    outcome = dist.poll_once()

    assert outcome["refusals"]["artifact_invalid"] == 1
    assert dist.status()["artifact_sha256"] == current.sha256
    assert dist.active_policy().sha256 == current.sha256


# -- freshness, expiry and outage ---------------------------------------

def test_a_forged_hint_never_fetches_an_artifact(tmp_path):
    seed, dist = _with_seed(tmp_path)
    current = _compile()
    _install(dist, current, version=2)
    bogus = _manifest(seed, _compile(allow=("cat",)), version=3)
    bogus["sig"] = "00" * 64

    dist.transport.calls.clear()
    dist.transport.responses.extend([
        _json({"version": 99, "kill_epoch": 0}), _json(bogus),
    ])
    outcome = dist.poll_once()

    assert outcome["refusals"]["signature"] == 1
    assert len(dist.transport.calls) == 2  # hints + manifest; no artifact GET
    assert dist.status()["highest_version"] == 2
    assert dist.status()["artifact_sha256"] == current.sha256


def test_expiry_keeps_last_known_good_and_alarms_after_fifteen_minutes(tmp_path):
    clock = _Clock()
    _seed, dist = _with_seed(tmp_path, clock)
    result = _compile()
    _install(dist, result, version=2, expires=NOW + 60)

    clock.advance(120)
    dist.transport.responses.append(_json({"version": 2, "kill_epoch": 0}))
    out = dist.poll_once()
    assert out["expired_since"] == NOW + 120
    status = dist.status()
    assert status["expired"] is True and status["alarm"] is False
    assert status["grace_until"] == NOW + 60 + EXPIRY_GRACE_SECONDS
    assert status["artifact_sha256"] == result.sha256

    clock.advance(EXPIRY_ALARM_SECONDS)
    dist.transport.responses.append(_json({"version": 2, "kill_epoch": 0}))
    dist.poll_once()
    assert dist.status()["alarm"] is True
    assert dist.active_policy().sha256 == result.sha256


def test_an_expired_manifest_offer_is_refused_with_the_expiry_code(tmp_path):
    seed, dist = _with_seed(tmp_path)
    _install(dist, _compile(), version=2)
    clock = dist.clock
    clock.advance(10)
    newer = _compile(allow=("cat",))
    dist.transport.responses.extend([
        _json({"version": 3, "kill_epoch": 0}),
        _json(_manifest(seed, newer, version=3, issued=NOW - 1000,
                        expires=NOW - 120)),
    ])
    outcome = dist.poll_once()
    assert outcome["refusals"]["expired"] == 1
    assert dist.status()["manifest_version"] == 2


def test_a_transport_outage_is_reported_and_never_clears_the_active_policy(tmp_path):
    _seed, dist = _with_seed(tmp_path)
    result = _compile()
    _install(dist, result, version=2)
    dist.transport.responses.append(TransportError("link down"))

    outcome = dist.poll_once()

    assert outcome["ok"] is False
    assert outcome["last_error"] == "link down"
    assert outcome["manifest_version"] == 2
    assert dist.active_policy().sha256 == result.sha256


# -- kills --------------------------------------------------------------

def test_a_verified_kill_is_honoured_despite_a_fresh_artifact(tmp_path):
    seed, dist = _with_seed(tmp_path)
    result = _compile()
    _install(dist, result, version=2)
    kill = sign_kill(seed, {
        "v": 1, "id": "k-1", "org_id": "org-1",
        "reason": "credential leak", "target": {"kind": "ring", "id": "stable"},
        "issued_at": NOW,
    })

    dist.transport.responses.extend([
        _json({"version": 2, "kill_epoch": 1}),
        _json({"kills": [kill], "kill_epoch": 1}),
    ])
    dist.poll_once()
    status = dist.status()
    assert status["kill_active"] is True
    assert status["kill"]["id"] == "k-1"
    assert status["kill_epoch"] == 1
    assert status["manifest_version"] == 2  # the artifact was already fresh

    # Nothing clears a kill: a later cycle with no kill carries it forward.
    dist.transport.responses.append(_json({"version": 2, "kill_epoch": 1}))
    dist.poll_once()
    assert dist.status()["kill_active"] is True
    assert dist.status()["kill"]["id"] == "k-1"


def test_a_forged_kill_is_refused_and_not_activated(tmp_path):
    seed, dist = _with_seed(tmp_path)
    _install(dist, _compile(), version=2)
    kill = sign_kill(seed, {
        "v": 1, "id": "k-1", "org_id": "org-1", "reason": "x",
        "target": {"kind": "ring", "id": "stable"}, "issued_at": NOW,
    })
    kill["sig"] = "00" * 64
    dist.transport.responses.extend([
        _json({"version": 2, "kill_epoch": 1}),
        _json({"kills": [kill], "kill_epoch": 1}),
    ])
    out = dist.poll_once()
    assert out["kill_active"] is False
    assert out["refusals"]["kill_signature"] == 1
    assert dist.status()["kill_epoch"] == 1


# -- in-flight evaluation ----------------------------------------------

def test_a_call_already_evaluating_keeps_its_snapshot_across_a_swap(tmp_path):
    _seed, dist = _with_seed(tmp_path)
    first = _compile(allow=("ls",))
    _install(dist, first, version=2)
    in_flight = dist.active_policy()
    event = SensorEvent("run_shell", {"cmd": "ls"}, principal="acme")
    assert in_flight.evaluate(event).verdict.name == "ALLOW"

    second = _compile(allow=("cat",))
    dist.transport.responses.extend([
        _json({"version": 3, "kill_epoch": 0}),
        _json(_manifest(dist._seed, second, version=3)),
        (200, {}, second.artifact_bytes),
    ])
    dist.poll_once()

    fresh = dist.active_policy()
    assert fresh.evaluate(event).verdict.name == "BLOCK"
    # The call that started under the old artifact still sees the old rules
    # and stamps the old epoch.
    assert in_flight.epoch == first.epoch
    assert in_flight.sha256 == first.sha256
    assert in_flight.evaluate(event).verdict.name == "ALLOW"
    assert fresh.epoch == second.epoch
