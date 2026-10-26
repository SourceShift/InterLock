"""Signed manifests and kill switches: the exact checks a host makes.

``verify_manifest`` is deliberately a pure function returning the first failed
code, never raising: a manifest arrives from the network and an untrusted
envelope is a refusal. The matrix below pins every code in
:data:`MANIFEST_CHECKS` so a connector refusal has a stable name.
"""
from __future__ import annotations

import time

import pytest

from interlock.cloud.policy.manifest import (
    MANIFEST_MAX_TTL,
    MANIFEST_MODES,
    ManifestError,
    canonical_manifest,
    kill_applies,
    policy_key_id,
    sign_kill,
    sign_manifest,
    verify_kill,
    verify_manifest,
)
from interlock.mesh.ed25519 import generate_seed, public_key, sign

NOW = 2_000_000_000.0
SHA = "a" * 64


def _seed_and_key():
    seed = generate_seed()
    return seed, public_key(seed)


def _body(**overrides):
    body = {
        "v": 1,
        "manifest_id": "m-fixed",
        "org_id": "org-1",
        "version": 7,
        "epoch": "0123456789abcdef",
        "target": {"kind": "org", "id": "org-1"},
        "mode": "enforce",
        "issued_at": NOW,
        "expires_at": NOW + 3600,
        "minimum_agent": None,
        "artifact": {"format": 1, "sha256": SHA, "size": 100},
        "rules_digest": "0123456789abcdef",
        "key_id": "policy-fixed",
    }
    body.update(overrides)
    return body


def _signed(seed, **overrides):
    return sign_manifest(seed, _body(**overrides))


def _resign(seed, envelope):
    body = {key: value for key, value in envelope.items() if key != "sig"}
    return {**body, "sig": sign(seed, canonical_manifest(body)).hex()}


def _verify(seed, envelope, **kwargs):
    return verify_manifest(
        envelope, public_key(seed),
        org_id=kwargs.pop("org_id", "org-1"),
        host_id=kwargs.pop("host_id", "host-1"),
        ring=kwargs.pop("ring", "stable"),
        now=kwargs.pop("now", NOW), **kwargs)


# -- signing and the happy path -----------------------------------------

def test_a_signed_manifest_verifies_for_its_target():
    seed, _pub = _seed_and_key()
    manifest = _signed(seed)
    assert manifest["sig"] and len(bytes.fromhex(manifest["sig"])) == 64
    assert _verify(seed, manifest) is None


def test_ring_and_host_targets_are_matched_most_specific_first():
    seed, _pub = _seed_and_key()
    ring_manifest = _signed(seed, target={"kind": "ring", "id": "stable"})
    assert _verify(seed, ring_manifest) is None
    assert _verify(seed, ring_manifest, ring="canary") == "target"

    host_manifest = _signed(seed, target={"kind": "host", "id": "host-1"})
    assert _verify(seed, host_manifest) is None
    assert _verify(seed, host_manifest, host_id="host-2") == "target"


def test_the_key_id_is_derived_from_the_public_key_not_trusted():
    _seed, pub = _seed_and_key()
    assert policy_key_id(pub) == "policy-" + policy_key_id(pub)[7:]
    assert policy_key_id(pub).startswith("policy-")
    assert len(policy_key_id(pub)) == len("policy-") + 16


def test_signing_refuses_a_window_longer_than_seven_days():
    seed, _pub = _seed_and_key()
    with pytest.raises(ManifestError):
        _signed(seed, expires_at=NOW + MANIFEST_MAX_TTL + 1)
    with pytest.raises(ManifestError):
        _signed(seed, expires_at=NOW)
    with pytest.raises(ManifestError):
        _signed(seed, v=2)
    with pytest.raises(ManifestError):
        _signed(seed, mode="aggressive")
    with pytest.raises(ManifestError):
        _signed(seed, target={"kind": "galaxy", "id": "x"})


# -- every refusal code -------------------------------------------------

def test_a_bad_signature_is_refused_before_anything_else():
    seed, _pub = _seed_and_key()
    manifest = _signed(seed)
    manifest["target"] = {"kind": "org", "id": "org-1"}
    manifest["version"] = 99
    assert _verify(seed, manifest) == "signature"

    other, _other_pub = _seed_and_key()
    assert _verify(other, _signed(seed)) == "signature"


def test_a_foreign_org_is_refused():
    seed, _pub = _seed_and_key()
    assert _verify(seed, _signed(seed), org_id="org-2") == "org"


def test_a_version_that_does_not_beat_the_hosts_highest_is_refused():
    seed, _pub = _seed_and_key()
    manifest = _signed(seed, version=11)
    assert _verify(seed, manifest, min_version=10) is None
    assert _verify(seed, manifest, min_version=11) == "manifest_version"
    assert _verify(seed, manifest, min_version=12) == "manifest_version"


def test_expiry_is_an_alarm_after_the_declared_time():
    seed, _pub = _seed_and_key()
    manifest = _signed(seed)
    assert _verify(seed, manifest, now=NOW + 3599) is None
    assert _verify(seed, manifest, now=NOW + 3600 + 61) == "expired"


def test_a_manifest_issued_in_the_future_is_refused():
    seed, _pub = _seed_and_key()
    manifest = _signed(seed, issued_at=NOW + 120,
                       expires_at=NOW + 120 + 3600)
    assert _verify(seed, manifest) == "future"


def test_a_manifest_longer_than_seven_days_is_refused_even_if_signed():
    seed, _pub = _seed_and_key()
    manifest = _resign(seed, _body(expires_at=NOW + MANIFEST_MAX_TTL + 120))
    assert _verify(seed, manifest) == "expiry"


def test_minimum_agent_must_be_understood_and_satisfied():
    seed, _pub = _seed_and_key()
    manifest = _signed(seed, minimum_agent="1.2")
    assert _verify(seed, manifest, agent_version="1.1.9") == "minimum_agent"
    assert _verify(seed, manifest, agent_version="1.2.0") is None
    assert _verify(seed, manifest, agent_version="1.3") is None
    # A caller that does not name its agent version (the live smoke, manifest
    # inspection) leaves the pin unjudged; the connector always names one.
    assert _verify(seed, manifest, agent_version=None) is None

    malformed = _signed(seed, minimum_agent="latest")
    assert _verify(seed, malformed, agent_version="9.9") == "minimum_agent"


def test_an_unknown_mode_is_refused_at_verification_too():
    seed, _pub = _seed_and_key()
    manifest = _resign(seed, _body(mode="shadow"))
    assert _verify(seed, manifest) == "mode"


def test_the_artifact_reference_must_name_a_sha_and_a_size():
    seed, _pub = _seed_and_key()
    assert _verify(seed, _resign(seed, _body(artifact={}))) == "artifact"
    assert _verify(seed, _resign(seed, _body(
        artifact={"format": 1, "sha256": SHA, "size": -1}))) == "artifact"
    assert _verify(seed, _resign(seed, _body(
        artifact={"format": 1, "sha256": SHA, "size": "big"}))) == "artifact"


def test_a_non_object_or_wrong_version_envelope_is_a_version_refusal():
    assert verify_manifest(None, b"") == "version"
    assert verify_manifest([], b"") == "version"
    seed, _pub = _seed_and_key()
    assert verify_manifest({**_signed(seed), "v": 2}, public_key(seed)) == "version"


# -- kill switches ------------------------------------------------------

def _kill(seed, **overrides):
    body = {
        "v": 1, "id": "k-1", "org_id": "org-1", "reason": "leak",
        "target": {"kind": "ring", "id": "stable"}, "issued_at": NOW,
    }
    body.update(overrides)
    return sign_kill(seed, body)


def test_a_signed_kill_verifies_and_applies_to_its_target():
    seed, _pub = _seed_and_key()
    kill = _kill(seed)
    assert verify_kill(kill, public_key(seed), org_id="org-1",
                       host_id="host-1", ring="stable") is None
    assert kill_applies(kill, org_id="org-1", host_id="host-1", ring="stable")
    assert not kill_applies(kill, org_id="org-1", host_id="host-1", ring="canary")


def test_a_kill_is_refused_for_another_org_a_bad_signature_or_another_target():
    seed, _pub = _seed_and_key()
    kill = _kill(seed)
    assert verify_kill(kill, public_key(seed), org_id="org-2",
                       host_id="host-1", ring="stable") == "org"
    broken = {**kill, "sig": "00" * 64}
    assert verify_kill(broken, public_key(seed), org_id="org-1",
                       host_id="host-1", ring="stable") == "signature"
    host_kill = _kill(seed, target={"kind": "host", "id": "other"})
    assert verify_kill(host_kill, public_key(seed), org_id="org-1",
                       host_id="host-1", ring="stable") == "target"


def test_signing_a_kill_needs_a_reason_and_an_id():
    seed, _pub = _seed_and_key()
    with pytest.raises(ManifestError):
        sign_kill(seed, {"v": 1, "id": "k", "org_id": "org-1",
                         "target": {"kind": "org", "id": "org-1"},
                         "issued_at": NOW})
    with pytest.raises(ManifestError):
        sign_kill(seed, {"v": 1, "reason": "why", "org_id": "org-1",
                         "target": {"kind": "org", "id": "org-1"},
                         "issued_at": NOW})


def test_kill_signing_does_not_add_an_expiry():
    seed, _pub = _seed_and_key()
    kill = _kill(seed)
    assert "expires_at" not in kill
    assert set(kill) >= {"v", "id", "org_id", "reason", "target",
                         "issued_at", "sig"}


def test_manifest_modes_are_the_documented_three():
    assert MANIFEST_MODES == ("monitor", "warn", "enforce")
