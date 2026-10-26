"""Artifact format v1: canonical bytes, epoch identity and lazy materialisation.

The artifact is the immutable unit a manifest names. Two properties carry the
whole distribution story: the bytes are canonical (so one source compiles to
one sha256 everywhere) and the epoch is recomputed from the body (so a
tampered epoch is a refusal, not a silent alias). Loading is also where the
rules module is imported - and only there, never at package import time.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

import pytest

from interlock.policy.artifact import (
    ACTIVE_POINTER,
    ARTIFACT_FORMAT,
    ArtifactError,
    FAILURE_POLICY_DEFAULTS,
    canonical_bytes,
    canonical_json,
    compute_epoch,
    load_artifact,
    materialize,
    parse_artifact,
    seal_artifact,
    validate_failure_policy,
)
from tests.fixtures.cloud.rules_module import scope_document

MODULE = "tests.fixtures.cloud.rules_module:templates"


def _body(**overrides):
    body = {
        "format": ARTIFACT_FORMAT,
        "documents": [],
        "scope": {"version": 1, "bindings": {}, "default_scope": [],
                  "allow_unscoped": False},
        "rules_module": None,
        "template_ids": [],
        "catalog": "",
        "failure_policy": dict(FAILURE_POLICY_DEFAULTS),
    }
    body.update(overrides)
    return body


def _scoped(**overrides):
    overrides.setdefault("scope", scope_document())
    overrides.setdefault("rules_module", MODULE)
    overrides.setdefault("template_ids", ["egress_denylist", "file_guard",
                                          "shell_allowlist"])
    return seal_artifact(_body(**overrides))


def _raw(artifact):
    return canonical_bytes(artifact)


# -- canonical form -----------------------------------------------------

def test_canonical_json_sorts_keys_and_keeps_unicode():
    assert canonical_json({"b": 1, "a": {"d": 2, "c": "é"}}) == \
        '{"a":{"c":"é","d":2},"b":1}'
    assert canonical_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}\n'


def test_identical_bodies_have_identical_canonical_bytes():
    first = _scoped()
    second = json.loads(json.dumps(first))
    assert _raw(first) == _raw(second)
    assert hashlib.sha256(_raw(first)).hexdigest() == \
        hashlib.sha256(_raw(second)).hexdigest()


def test_epoch_is_sha256_of_the_body_without_epoch():
    body = _body(format=ARTIFACT_FORMAT)
    sealed = seal_artifact(body)
    without = {key: value for key, value in sealed.items() if key != "epoch"}
    expected = hashlib.sha256(canonical_bytes(without)).hexdigest()[:16]
    assert sealed["epoch"] == expected
    assert compute_epoch(sealed) == expected
    # Recomputing over a body that already names the epoch is idempotent.
    assert compute_epoch({**sealed, "epoch": "0" * 16}) == expected


def test_a_tampered_epoch_is_refused_not_trusted():
    artifact = _scoped()
    artifact["epoch"] = "0" * 16
    with pytest.raises(ArtifactError) as exc:
        parse_artifact(_raw(artifact))
    assert exc.value.code == "epoch_mismatch"


def test_unknown_fields_and_formats_are_refused():
    artifact = _scoped()
    artifact["future_field"] = 1
    with pytest.raises(ArtifactError) as exc:
        parse_artifact(_raw(artifact))
    assert exc.value.code == "unsupported_field"

    artifact = _scoped()
    artifact["format"] = 2
    with pytest.raises(ArtifactError) as exc:
        parse_artifact(_raw(artifact))
    assert exc.value.code == "unsupported_format"


# -- failure policy -----------------------------------------------------

def test_failure_policy_requires_every_class_and_known_values():
    policy = dict(FAILURE_POLICY_DEFAULTS)
    missing = dict(policy)
    missing.pop("payment")
    with pytest.raises(ArtifactError) as exc:
        validate_failure_policy(missing)
    assert exc.value.code == "failure_policy"

    with pytest.raises(ArtifactError):
        validate_failure_policy({**policy, "email": "maybe"})
    with pytest.raises(ArtifactError):
        validate_failure_policy({**policy, "unknown": "closed"})
    assert validate_failure_policy(policy) == policy


def test_an_artifact_without_a_well_formed_failure_policy_is_refused():
    artifact = _scoped()
    artifact["failure_policy"] = {"shell": "closed"}
    with pytest.raises(ArtifactError) as exc:
        parse_artifact(_raw(artifact))
    assert exc.value.code == "failure_policy"


# -- loading and materialisation ----------------------------------------

def test_a_valid_artifact_materialises_and_evaluates():
    policy = load_artifact(_raw(_scoped()))
    assert policy.epoch == _scoped()["epoch"]
    assert policy.sha256 == hashlib.sha256(_raw(_scoped())).hexdigest()
    assert policy.rules_module == MODULE
    assert policy.template_ids == ["egress_denylist", "file_guard",
                                   "shell_allowlist"]
    decision = policy.evaluate(
        __import__("interlock.event", fromlist=["SensorEvent"]).SensorEvent(
            "run_shell", {"cmd": "ls"}, principal="acme/agent1"))
    assert decision.verdict.name == "ALLOW"


def test_module_pin_mismatch_is_refused():
    with pytest.raises(ArtifactError) as exc:
        load_artifact(_raw(_scoped()), module="somewhere.else:templates")
    assert exc.value.code == "module_mismatch"


def test_scope_bindings_without_a_module_are_refused():
    artifact = seal_artifact(_body(scope=scope_document(), rules_module=None))
    with pytest.raises(ArtifactError) as exc:
        parse_artifact(_raw(artifact))
    assert exc.value.code == "missing_rules_module"


def test_a_declared_template_the_module_lost_is_refused():
    artifact = _scoped(template_ids=["shell_allowlist", "ghost"])
    with pytest.raises(ArtifactError) as exc:
        load_artifact(_raw(artifact))
    assert exc.value.code == "missing_template"
    assert "ghost" in str(exc.value)


def test_an_unresolvable_rules_module_is_refused():
    artifact = _scoped(rules_module="tests.fixtures.cloud.nope:templates")
    with pytest.raises(ArtifactError) as exc:
        load_artifact(_raw(artifact))
    assert exc.value.code == "rules_module"


def test_loading_a_directory_follows_active_json(tmp_path):
    artifact = _scoped()
    raw = _raw(artifact)
    sha = hashlib.sha256(raw).hexdigest()
    (tmp_path / "{}.json".format(sha)).write_bytes(raw)
    (tmp_path / ACTIVE_POINTER).write_bytes(canonical_bytes({"sha256": sha}))
    assert load_artifact(tmp_path).sha256 == sha


def test_a_missing_or_corrupt_artifact_is_an_artifact_error(tmp_path):
    with pytest.raises(ArtifactError) as exc:
        load_artifact(tmp_path / "absent.json")
    assert exc.value.code == "missing_artifact"

    corrupt = tmp_path / "corrupt.json"
    corrupt.write_bytes(b"{not json")
    with pytest.raises(ArtifactError) as exc:
        load_artifact(corrupt)
    assert exc.value.code == "invalid_json"


def test_materialize_round_trips_canonical_bytes(tmp_path):
    raw = _raw(_scoped())
    path = tmp_path / "artifacts" / "a.json"
    written = materialize(raw, path)
    assert written == str(path)
    assert path.read_bytes() == raw
    assert load_artifact(path).sha256 == hashlib.sha256(raw).hexdigest()


def test_materialize_seals_a_body_and_replaces_atomically(tmp_path, monkeypatch):
    path = tmp_path / "artifact.json"
    path.write_bytes(b"old")
    materialize(_body(), path)
    assert parse_artifact(path.read_bytes())["epoch"]

    previous = path.read_bytes()
    from interlock.policy import artifact as module

    def fail_replace(source, destination):
        raise OSError("disk full")

    monkeypatch.setattr(module.os, "replace", fail_replace)
    with pytest.raises(OSError):
        materialize(_raw(_scoped()), path)
    # The destination still holds the previous complete artifact and no
    # partially-written temp file is left behind.
    assert path.read_bytes() == previous
    assert not [name for name in os.listdir(tmp_path) if name.endswith(".tmp")]


# -- import hygiene (c:0) -----------------------------------------------

def test_importing_the_artifact_module_imports_no_rules_module():
    code = (
        "import sys\n"
        "import interlock.policy.artifact\n"
        "assert 'tests.fixtures.cloud.rules_module' not in sys.modules\n"
        "assert 'interlock.sidecar.rules' not in sys.modules\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        capture_output=True, text=True, timeout=60,
    )
    assert completed.returncode == 0, completed.stderr


def test_the_same_module_imported_twice_still_produces_the_same_bytes():
    # A module import is a side effect only after load_artifact; the bytes are
    # a pure function of the body.
    first = _raw(_scoped())
    second = _raw(_scoped())
    assert first == second
