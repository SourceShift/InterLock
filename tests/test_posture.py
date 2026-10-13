"""Protection attestation (R15): attest(), require(), and `interlock doctor`."""
import json
import re
from pathlib import Path

import pytest

import interlock
from interlock import PolicyEngine, deny_tool, guard, install, monitor
from interlock import _runtime
from interlock.cli import main
from interlock.posture import (
    FAIL,
    OK,
    WARN,
    WEAKENING_SETTINGS,
    ProtectionError,
    attest,
    require,
)
from interlock.receipt import set_sink
from interlock.sink import FileSink, InMemorySink

ROOT = Path(__file__).resolve().parent.parent


def status(posture, check_id):
    check = posture.check(check_id)
    assert check is not None, check_id
    return check.status


@pytest.fixture
def no_sink():
    set_sink(None)
    yield
    set_sink(None)


def test_every_weakening_setting_in_the_security_model_has_a_check():
    text = (ROOT / "docs" / "security-model.md").read_text(encoding="utf-8")
    section = text.split("## Settings that weaken protection", 1)[1].split("\n## ", 1)[0]
    rows = [line for line in section.splitlines() if line.startswith("| ")][1:]
    settings = [row.split(" | ")[0][2:].strip() for row in rows]
    assert settings, "table not found"
    assert set(settings) == set(WEAKENING_SETTINGS), (
        "security-model.md and posture.WEAKENING_SETTINGS disagree")
    posture = attest()
    ids = {c.id for c in posture.checks}
    assert set(WEAKENING_SETTINGS.values()) <= ids


def test_never_installed_fails(monkeypatch, no_sink):
    monkeypatch.setattr(_runtime, "_engine", None)
    posture = attest()
    assert status(posture, "engine.installed") == FAIL
    assert posture.level == "unprotected"
    with pytest.raises(ProtectionError):
        require()


def test_empty_engine_fails(no_sink):
    install(engine=PolicyEngine())
    assert status(attest(), "engine.installed") == FAIL


def test_well_configured_process_is_enforced(tmp_path, monkeypatch):
    install(rules=[deny_tool("x")], sink=FileSink(str(tmp_path / "r.jsonl"), key=b"k" * 32))
    monkeypatch.setattr("interlock.posture._sandbox_checks", lambda: [])
    try:
        posture = require()
    finally:
        set_sink(None)
    assert posture.level == "enforced"
    assert status(posture, "engine.installed") == OK


def test_monitor_guards_warn(no_sink):
    install(rules=[deny_tool("x")])

    @monitor()
    def trial_tool():
        return 1

    posture = attest()
    assert status(posture, "enforcement.monitor") == WARN
    assert "trial_tool" in posture.check("enforcement.monitor").summary


def test_ephemeral_sink_key_warns():
    install(rules=[deny_tool("x")], sink=InMemorySink())
    try:
        assert status(attest(), "audit.key") == WARN
    finally:
        set_sink(None)


def test_no_sink_warns(no_sink):
    install(rules=[deny_tool("x")])
    assert status(attest(), "audit.sink") == WARN


def test_allow_unscoped_warns(no_sink):
    from interlock.policy.scopes import ScopedEngine, ScopeRegistry, ScopeTree
    install(engine=ScopedEngine(ScopeRegistry(ScopeTree(), {}), allow_unscoped=True))
    assert status(attest(), "scopes.allow_unscoped") == WARN


def test_remote_engine_without_timeout_warns(no_sink):
    from interlock.sidecar.client import RemoteEngine
    install(engine=RemoteEngine("/nonexistent.sock", timeout=None))
    assert status(attest(), "sidecar.timeout") == WARN


def test_require_degraded_accepts_warnings(no_sink):
    install(rules=[deny_tool("x")])
    assert require("degraded").level in ("degraded", "enforced")
    with pytest.raises(ValueError):
        require("bogus")


def test_attest_has_no_side_effects(no_sink):
    install(rules=[deny_tool("x")])
    before = _runtime._engine
    attest()
    assert _runtime._engine is before


# --- the CLI ------------------------------------------------------------------


def test_doctor_without_a_policy_does_not_claim_protection(capsys):
    code = main(["doctor", "--json", "--sidecar", "/nonexistent/guard.sock"])
    out = json.loads(capsys.readouterr().out)
    assert out["level"] in ("degraded", "unprotected")
    assert code in (1, 2)


def test_doctor_with_rules_and_receipts(tmp_path, capsys):
    rules = tmp_path / "doctor_rules_mod.py"
    rules.write_text("from interlock import deny_tool\nRULES = [deny_tool('rm')]\n")
    import sys
    sys.path.insert(0, str(tmp_path))
    log = tmp_path / "audit.jsonl"
    key = b"k" * 32
    sink = FileSink(str(log), key=key)
    set_sink(sink)
    install(rules=[deny_tool("never")])
    interlock.enforce_tool_call("t", {})
    set_sink(None)
    key_file = tmp_path / "key"
    key_file.write_text(key.hex())
    try:
        code = main(["doctor", "--json", "--rules", "doctor_rules_mod:RULES",
                     "--receipts", str(log), "--key-file", str(key_file)])
    finally:
        sys.path.remove(str(tmp_path))
    out = json.loads(capsys.readouterr().out)
    by_id = {c["id"]: c for c in out["checks"]}
    assert by_id["engine.installed"]["status"] == "ok"
    assert by_id["audit.chain"]["status"] == "ok"
    assert code in (0, 1)


def test_doctor_reports_a_broken_chain(tmp_path, capsys):
    log = tmp_path / "audit.jsonl"
    sink = FileSink(str(log), key=b"k" * 32)
    set_sink(sink)
    install(rules=[deny_tool("never")])
    interlock.enforce_tool_call("t", {})
    interlock.enforce_tool_call("t", {})
    set_sink(None)
    lines = log.read_text().splitlines()
    lines[0] = lines[0].replace('"action":"t"', '"action":"u"')
    log.write_text("\n".join(lines) + "\n")
    key_file = tmp_path / "key"
    key_file.write_text(("k" * 32).encode().hex())
    code = main(["doctor", "--json", "--receipts", str(log), "--key-file", str(key_file)])
    out = json.loads(capsys.readouterr().out)
    assert code == 2
    assert {c["id"]: c for c in out["checks"]}["audit.chain"]["status"] == "fail"


def test_doctor_bad_rules_fail(capsys):
    assert main(["doctor", "--json", "--rules", "no_such_module_xyz:RULES"]) == 2


def test_doctor_human_output_has_no_color_when_disabled(capsys):
    main(["--no-color", "doctor"])
    out = capsys.readouterr().out
    assert "interlock protection:" in out
    assert not re.search(r"\x1b\[", out)
