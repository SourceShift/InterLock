"""``interlock policy verify`` and ``doctor`` (C6).

``verify`` loads an artifact exactly as a host will - module import included -
and reports its identity and which backend decides which part. ``doctor``
reports whether the optional native accelerator is usable in this process.
Both are diagnostics, so their exit codes are the contract: 0 ok, 1 invalid,
2 unavailable, 64 for an action that does not exist.
"""
from __future__ import annotations

import argparse
import json
import sys

from interlock.cli import main as cli_main
from interlock.cli import policy as policy_cli
from interlock.policy.artifact import (
    ARTIFACT_FORMAT,
    FAILURE_POLICY_DEFAULTS,
    canonical_bytes,
    load_artifact,
    seal_artifact,
)

MODULE = "tests.fixtures.cloud.rules_module:templates"

SCOPE = {
    "version": 1,
    "bindings": {
        "claude-code": [{
            "template": "shell_allowlist",
            "params": {"allow": ["ls"]},
        }],
    },
    "default_scope": [],
    "allow_unscoped": True,
}

RULES = [{
    "id": "no-rm",
    "verdict": "block",
    "reason": "recursive delete",
    "when": {"all": [
        {"action": "Bash"},
        {"arg": "command", "contains": "rm -rf"},
    ]},
}]


def _artifact(tmp_path, *, scope=SCOPE, module=MODULE, load=True):
    raw = canonical_bytes(seal_artifact({
        "format": ARTIFACT_FORMAT,
        "documents": [{"version": 1, "rules": RULES}],
        "scope": scope,
        "rules_module": module if scope.get("bindings") else None,
        "template_ids": ["shell_allowlist"] if scope.get("bindings") else [],
        "catalog": "",
        "failure_policy": dict(FAILURE_POLICY_DEFAULTS),
    }))
    path = tmp_path / "policy.json"
    path.write_bytes(raw)
    return (path, load_artifact(raw)) if load else (path, None)


def _verify(path, *extra):
    return cli_main(["policy", "verify", "--artifact", str(path), *extra])


# --- verify ---------------------------------------------------------------


def test_verify_reports_identity_and_native_status(tmp_path, capsys):
    path, engine = _artifact(tmp_path)

    code = _verify(path)

    out = capsys.readouterr().out
    assert code == 0
    assert engine.epoch in out
    assert engine.sha256 in out
    assert "rules module: {}".format(MODULE) in out
    assert "templates: shell_allowlist" in out
    assert "native base:" in out
    # Scope templates are Python callables, so the bound scope is Python.
    assert "native scopes: 0; python scopes: 1" in out


def test_verify_json_has_the_documented_shape(tmp_path, capsys):
    path, engine = _artifact(tmp_path)

    code = _verify(path, "--json")

    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert set(report) == {
        "path", "format", "sha256", "epoch", "scope_epochs", "rule_count",
        "detector_ids", "catalog", "failure_policy", "rules_module",
        "template_ids", "native", "kill",
    }
    assert report["path"] == str(path)
    assert report["format"] == ARTIFACT_FORMAT
    assert report["sha256"] == engine.sha256
    assert report["epoch"] == engine.epoch
    # One document rule plus the one rule the bound scope's template compiles.
    # The count is what a host will actually evaluate, not the template list.
    assert report["rule_count"] == 2
    assert set(report["scope_epochs"]) == {"claude-code"}
    scope_epoch = report["scope_epochs"]["claude-code"]
    assert scope_epoch is None or (
        isinstance(scope_epoch, str) and len(scope_epoch) == 16)
    assert report["detector_ids"] == []
    assert report["catalog"] == ""
    assert report["failure_policy"] == dict(FAILURE_POLICY_DEFAULTS)
    assert report["rules_module"] == MODULE
    assert report["template_ids"] == ["shell_allowlist"]
    assert report["kill"] is None
    assert set(report["native"]) == {
        "enabled", "rule", "native_base", "native_scopes", "python_scopes",
        "native_fallbacks", "native_unavailable_reason", "epoch", "sha256",
        "scope_epochs",
    }
    assert report["native"]["enabled"] is True
    assert report["native"]["rule"] == "artifact default (native-on)"
    assert report["native"]["python_scopes"] == ["claude-code"]


def test_verify_reports_a_kill_marker(tmp_path, capsys):
    path, _engine = _artifact(tmp_path)
    (tmp_path / "kill.json").write_text(json.dumps({
        "kill": {"id": "k-1", "reason": "credential leak"},
        "kill_epoch": 1,
        "verified_at": 1.0,
    }), encoding="utf-8")

    code = _verify(path)

    out = capsys.readouterr().out
    assert code == 0
    assert "KILLED: k-1 (credential leak)" in out


def test_verify_refuses_a_missing_artifact(tmp_path, capsys):
    code = _verify(tmp_path / "gone.json")
    err = capsys.readouterr().err
    assert code == 2
    assert "missing_artifact" in err


def test_verify_refuses_invalid_json(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_bytes(b'{"format": 1, "epoch": ')
    code = _verify(path)
    err = capsys.readouterr().err
    # A malformed artifact is invalid (1); 2 is reserved for an unavailable
    # environment.
    assert code == 1
    assert "invalid_json" in err


def test_verify_refuses_an_artifact_whose_epoch_does_not_match(tmp_path, capsys):
    path, _engine = _artifact(tmp_path)
    body = json.loads(path.read_text(encoding="utf-8"))
    body["epoch"] = "0" * 16
    path.write_text(canonical_bytes(body).decode("utf-8"), encoding="utf-8")

    code = _verify(path)

    err = capsys.readouterr().err
    assert code == 1
    assert "epoch_mismatch" in err


def test_verify_reports_an_unimportable_rules_module_as_unavailable(
        tmp_path, capsys):
    path, _engine = _artifact(
        tmp_path, module="tests.fixtures.cloud.gone_module:templates",
        load=False)

    code = _verify(path)

    err = capsys.readouterr().err
    assert code == 2
    assert "rules_module" in err


# --- doctor ---------------------------------------------------------------


def test_doctor_json_reports_the_native_path(capsys):
    code = cli_main(["policy", "doctor", "--json"])

    report = json.loads(capsys.readouterr().out)
    assert set(report) == {
        "python", "native", "engine_abi", "module", "module_version",
        "scope_backend", "native_plan", "parity", "active_artifact",
    }
    assert report["python"] == sys.executable
    assert isinstance(report["native"], bool)
    assert report["engine_abi"] is None or isinstance(report["engine_abi"], int)
    assert report["module"] is None or isinstance(report["module"], str)
    assert report["module_version"] is None or isinstance(
        report["module_version"], str)
    assert report["scope_backend"] in ("rust", "python")
    assert isinstance(report["native_plan"], bool)
    assert set(report["parity"]) == {
        "ran", "ok", "cases", "mismatches", "detail"}
    if report["native"]:
        # The parity run builds a NativePlan, so availability implies the
        # plan loaded and the embedded corpus agreed case for case.
        assert report["native_plan"] is True
        assert report["parity"]["ran"] is True
        assert report["parity"]["ok"] is True
        assert report["parity"]["cases"] >= 20
        assert report["parity"]["mismatches"] == 0
    else:  # pragma: no cover - the package installs the accelerator in CI
        assert report["native_plan"] is False
        assert report["parity"]["ran"] is False
    assert report["active_artifact"] is None
    assert code == (0 if report["native"] else 2)


def test_doctor_reports_the_active_artifact_pointer(tmp_path, monkeypatch, capsys):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    pointer = artifacts / "active.json"
    pointer.write_text(json.dumps({
        "sha256": "a" * 64,
        "version": 4,
        "epoch": "0123456789abcdef",
        "mode": "enforce",
        "rules_module": MODULE,
    }), encoding="utf-8")
    monkeypatch.setenv("IL_CLOUD_HOME", str(tmp_path))

    cli_main(["policy", "doctor", "--json"])

    report = json.loads(capsys.readouterr().out)
    assert report["active_artifact"] == {
        "path": str(pointer),
        "sha256": "a" * 64,
        "epoch": "0123456789abcdef",
        "version": 4,
        "mode": "enforce",
    }


def test_doctor_text_matches_its_exit_code(capsys):
    from interlock.policy import native

    code = cli_main(["policy", "doctor"])
    out = capsys.readouterr().out
    if native.available():
        assert code == 0
        assert "native evaluator: available" in out
        assert "scope backend:" in out
    else:  # pragma: no cover - the package installs the accelerator in CI
        assert code == 2
        assert "native evaluator: unavailable" in out


# --- dispatch -------------------------------------------------------------


def test_an_unknown_action_is_a_usage_error(capsys):
    code = policy_cli.run(argparse.Namespace(policy_command="frobnicate"))
    assert code == 64
    assert "choose an action" in capsys.readouterr().err


def test_no_action_is_a_usage_error(capsys):
    code = policy_cli.run(argparse.Namespace(policy_command=None))
    assert code == 64
    assert "check, show, verify, doctor" in capsys.readouterr().err
