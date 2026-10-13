"""Tiered failure posture for sidecar clients (R19): deny / degraded / allow,
and the signed offline fallback policy the sidecar publishes."""
import json
import logging
import os

import pytest

from interlock import Blocked, Decision, Verdict
from interlock.event import SensorEvent
from interlock.policy.engine import PolicyEngine
from interlock.sidecar.__main__ import main as sidecar_main
from interlock.sidecar.client import UNREACHABLE_POLICY_ID, RemoteEngine
from interlock.sidecar.fallback import (
    FallbackError,
    fallback_path,
    read_fallback,
    validate_offline,
    write_fallback,
)
from interlock.testing.harness import serve

KEY = b"\x07" * 32
POLICY = {"rules": [
    {"id": "no-rm", "verdict": "block", "reason": "no rm", "on": "run_shell",
     "when": {"arg": "cmd", "startswith": "rm "}},
    {"id": "ask-pay", "verdict": "escalate", "reason": "payment",
     "when": {"all": [{"action": {"glob": "pay_*"}}, {"arg": "amount", "gt": 100}]}},
]}


def ev(action="run_shell", **args):
    return SensorEvent(action=action, args=args)


# --- the fallback file ----------------------------------------------------------


def test_round_trip(tmp_path):
    path = str(tmp_path / "g.sock.fallback.json")
    write_fallback(path, POLICY, KEY)
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    assert read_fallback(path, KEY) == POLICY


def test_tampered_wrong_key_stale_and_missing_are_refused(tmp_path):
    path = str(tmp_path / "f.json")
    write_fallback(path, POLICY, KEY)
    with pytest.raises(FallbackError, match="does not verify"):
        read_fallback(path, b"other")
    with pytest.raises(FallbackError, match="stale"):
        read_fallback(path, KEY, max_age=60, now=10 ** 11)
    body = json.loads(open(path).read())
    body["policy"] = body["policy"].replace("rm ", "zz ")
    open(path, "w").write(json.dumps(body))
    with pytest.raises(FallbackError, match="does not verify"):
        read_fallback(path, KEY)
    with pytest.raises(FallbackError, match="no fallback policy"):
        read_fallback(str(tmp_path / "missing.json"), KEY)
    body["mac"] = None
    open(path, "w").write(json.dumps(body))
    with pytest.raises(FallbackError, match="unsigned"):
        read_fallback(path, KEY)


@pytest.mark.parametrize("doc", [
    {"rules": []},
    {"extends": "builtin:coding-agent", "rules": [{"id": "a", "verdict": "block", "when": {"action": "x"}}]},
    {"rules": [{"id": "a", "verdict": "modify", "set": {"a": 1}, "when": {"action": "x"}}]},
    {"rules": [{"id": "a", "detector": "destructive_command_guard"}]},
    {"rules": [{"id": "a", "verdict": "block", "when": {"intent": "pkg.publish"}}]},
    {"rules": [{"id": "a", "verdict": "block", "when": {"arg": "x", "matches": "."}}]},
])
def test_only_the_offline_subset_is_accepted(doc, tmp_path):
    with pytest.raises(FallbackError):
        validate_offline(doc)
    with pytest.raises(FallbackError):
        write_fallback(str(tmp_path / "f.json"), doc, KEY)


# --- the client tiers -------------------------------------------------------------


@pytest.fixture
def dead_socket(tmp_path):
    return str(tmp_path / "guard.sock")  # nothing listens here


def test_deny_is_the_default(dead_socket):
    with pytest.raises(Blocked, match="unreachable"):
        RemoteEngine(dead_socket).evaluate(ev(cmd="ls"))


def test_allow_lets_every_call_through_and_warns_every_time(dead_socket, caplog):
    engine = RemoteEngine(dead_socket, unreachable="allow")
    with caplog.at_level(logging.WARNING, logger="interlock"):
        first = engine.evaluate(ev(cmd="rm -rf x"))
        engine.evaluate(ev(cmd="ls"))
    assert first.verdict is Verdict.ALLOW and first.policy_id == UNREACHABLE_POLICY_ID
    assert caplog.text.count("ALLOWING") == 2
    assert engine.fallbacks == 2


def test_degraded_uses_the_signed_fallback(dead_socket, caplog):
    write_fallback(fallback_path(dead_socket), POLICY, KEY)
    engine = RemoteEngine(dead_socket, unreachable="degraded", fallback_key=KEY)
    with caplog.at_level(logging.WARNING, logger="interlock"):
        blocked = engine.evaluate(ev(cmd="rm -rf x"))
        allowed = engine.evaluate(ev(cmd="ls"))
        asked = engine.evaluate(ev("pay_card", amount=500))
    assert blocked.verdict is Verdict.BLOCK and blocked.policy_id == "fallback/no-rm"
    assert blocked.reason.startswith("[guard daemon unreachable: fallback policy]")
    assert allowed.verdict is Verdict.ALLOW
    assert asked.verdict is Verdict.ESCALATE
    assert caplog.text.count("offline fallback policy") == 3


def test_degraded_without_a_valid_file_denies(dead_socket):
    engine = RemoteEngine(dead_socket, unreachable="degraded", fallback_key=KEY)
    with pytest.raises(Blocked, match="fallback policy is unusable"):
        engine.evaluate(ev(cmd="ls"))
    write_fallback(fallback_path(dead_socket), POLICY, b"someone else's key")
    with pytest.raises(Blocked, match="does not verify"):
        engine.evaluate(ev(cmd="ls"))


def test_configuration_errors():
    with pytest.raises(ValueError):
        RemoteEngine("/x.sock", unreachable="maybe")
    with pytest.raises(ValueError):
        RemoteEngine("/x.sock", unreachable="degraded")


def test_a_reachable_daemon_that_refuses_is_never_bypassed(sock_path):
    """An error frame comes from a live daemon: not 'unreachable', so even
    unreachable='allow' blocks it."""
    def unrepresentable(event):
        return Decision.modify({"x": object()}, "cannot travel")
    path = sock_path()
    with serve(PolicyEngine([unrepresentable]), path):
        engine = RemoteEngine(path, unreachable="allow")
        with pytest.raises(Blocked, match="refused"):
            engine.evaluate(ev(cmd="ls"))
        assert engine.fallbacks == 0


# --- the sidecar publishes it ------------------------------------------------------


def test_sidecar_requires_a_key_for_the_fallback(tmp_path, socket_dir, capsys):
    policy = tmp_path / "fallback.json"
    policy.write_text(json.dumps(POLICY))
    code = sidecar_main(["--rules", "interlock.testing.fixtures:CONFORMANCE_ENGINE",
                         "--socket", os.path.join(socket_dir, "g.sock"),
                         "--fallback-policy", str(policy)])
    assert code != 0
    assert "needs --key-file" in capsys.readouterr().err


def test_sidecar_publish_helper(tmp_path, socket_dir):
    from interlock.sidecar.__main__ import _publish_fallback
    policy = tmp_path / "fallback.json"
    policy.write_text(json.dumps(POLICY))
    key = tmp_path / "key"
    key.write_text(KEY.hex())
    sock = os.path.join(socket_dir, "g.sock")
    _publish_fallback(str(policy), str(key), sock)
    assert read_fallback(fallback_path(sock), KEY) == POLICY
