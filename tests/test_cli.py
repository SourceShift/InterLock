"""The shared ``interlock`` command surface: registration, dispatch and exit codes.

``interlock/cli/__init__.py`` is the single table of commands; every module it
names must expose ``add_arguments`` and ``run``, and ``main`` must map usage
mistakes to 64 while letting a command choose its own non-zero code. C2 makes
the connector actions real: only ``policy`` still prints a notice and returns
3, while an unconfigured connector returns 2 and a missing flag returns 64.
"""
from __future__ import annotations

import importlib

import pytest

from interlock.cli import COMMANDS, build_parser, main
from interlock.cli import cloud as cloud_cli

CLOUD_ACTIONS = ["enroll", "run", "status", "leave", "policy", "keys"]


def _enrolled_home(tmp_path):
    """A valid connector home, so ``run --once`` gets past its config check."""
    from interlock.cloud.connector.config import CloudHome
    from interlock.cloud.enrollment import generate_agent_key
    from interlock.cloud.identity import (
        generate_host_seed,
        key_id,
        public_key_hex,
    )

    home = CloudHome(tmp_path / "home")
    raw, _prefix, _digest = generate_agent_key()
    seed = generate_host_seed()
    public = public_key_hex(seed)
    home.save({
        "url": "https://cloud.example",
        "org_id": "org-1",
        "host_id": "host-1",
        "agent_key_id": "key-1",
        "agent_key": raw,
        "host_key_id": key_id(public),
        "host_public_key": public,
        "plane_public_keys": {},
        "spool_dir": "spool",
        "state_dir": "state",
    })
    home.save_seed(seed)
    return home


class _StubConnector:
    def __init__(self, result):
        self.result = result

    def run_once(self):
        return self.result


def test_every_registered_command_module_exposes_the_contract():
    for name, _help, module_name in COMMANDS:
        module = importlib.import_module("interlock.cli." + module_name)
        assert callable(module.add_arguments), name
        assert callable(module.run), name


def test_no_command_is_a_usage_error_and_prints_help(capsys):
    assert main([]) == 64
    assert "usage: interlock" in capsys.readouterr().out


def test_cloud_without_an_action_is_a_usage_error():
    assert main(["cloud"]) == 64


def test_cloud_with_an_unknown_action_is_a_usage_error():
    assert main(["cloud", "bogus"]) == 64


@pytest.mark.parametrize("action", CLOUD_ACTIONS)
def test_cloud_actions_parse(action):
    args = build_parser().parse_args(["cloud", action])
    assert args.cloud_command == action


def test_cloud_policy_is_the_one_remaining_stub(capsys):
    assert main(["cloud", "policy"]) == 3
    assert "interlock cloud policy: not implemented yet" in (
        capsys.readouterr().err
    )


def test_unconfigured_connector_actions_exit_not_configured(tmp_path,
                                                             monkeypatch,
                                                             capsys):
    monkeypatch.setenv("IL_CLOUD_HOME", str(tmp_path / "home"))
    for action in ("status", "run", "leave"):
        assert main(["cloud", action]) == 2, action
        assert "no connector config" in capsys.readouterr().err
    assert not (tmp_path / "home").exists()


def test_enroll_without_url_or_token_is_a_usage_error(tmp_path, monkeypatch,
                                                      capsys):
    monkeypatch.setenv("IL_CLOUD_HOME", str(tmp_path / "home"))
    assert main(["cloud", "enroll"]) == 64
    assert "--url and --token are required" in capsys.readouterr().err
    assert main(["cloud", "enroll", "--url", "https://cloud.example"]) == 64


def test_keys_without_a_subcommand_is_a_usage_error(tmp_path, monkeypatch,
                                                    capsys):
    monkeypatch.setenv("IL_CLOUD_HOME", str(tmp_path / "home"))
    assert main(["cloud", "keys"]) == 64
    assert "choose rotate or revoke" in capsys.readouterr().err


def test_keys_without_an_admin_cookie_explains_the_web_ui_path(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("IL_CLOUD_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("IL_CLOUD_ADMIN_COOKIE", raising=False)
    monkeypatch.delenv("IL_CLOUD_ADMIN_CSRF", raising=False)
    assert main(["cloud", "keys", "rotate", "--host", "host_1"]) == 1
    err = capsys.readouterr().err
    assert "need the web UI session" in err
    assert "No password is accepted" in err
    assert "command line" in err


def test_keys_reads_the_admin_session_from_the_environment(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("IL_CLOUD_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("IL_CLOUD_ADMIN_COOKIE", "__Host-il_session=abc")
    monkeypatch.setenv("IL_CLOUD_ADMIN_CSRF", "csrf-value")
    seen = {}

    def _fake(url, path, *, cookie, csrf, body=None):
        seen.update(url=url, path=path, cookie=cookie, csrf=csrf, body=body)
        return 200, {"id": "key_2"}

    monkeypatch.setattr(cloud_cli, "_admin_request", _fake)
    assert main(["cloud", "keys", "rotate", "--host", "host_1",
                 "--url", "https://cloud.example"]) == 0
    assert seen == {"url": "https://cloud.example", "path": "/v1/keys",
                    "cookie": "__Host-il_session=abc",
                    "csrf": "csrf-value", "body": {"host_id": "host_1"}}
    assert "key_2" in capsys.readouterr().out


def test_keys_refuses_a_plaintext_admin_url(monkeypatch, capsys):
    monkeypatch.setenv("IL_CLOUD_ADMIN_COOKIE", "__Host-il_session=abc")
    monkeypatch.setenv("IL_CLOUD_ADMIN_CSRF", "csrf-value")
    assert main(["cloud", "keys", "rotate", "--host", "host_1",
                 "--url", "http://cloud.example"]) == 1
    assert "https" in capsys.readouterr().err


def test_run_once_exits_zero_on_a_successful_cycle(tmp_path, monkeypatch,
                                                   capsys):
    home = _enrolled_home(tmp_path)
    monkeypatch.setenv("IL_CLOUD_HOME", str(home.root))
    monkeypatch.setattr(
        cloud_cli, "_connector",
        lambda *a, **k: _StubConnector(
            {"ok": True, "reviews": 2, "uploaded": 1}))
    assert main(["cloud", "run", "--once"]) == 0
    assert "sync ok: 2 review(s), 1 batch(es) uploaded" in (
        capsys.readouterr().out)


def test_run_once_exits_one_on_a_failed_cycle(tmp_path, monkeypatch, capsys):
    home = _enrolled_home(tmp_path)
    monkeypatch.setenv("IL_CLOUD_HOME", str(home.root))
    monkeypatch.setattr(
        cloud_cli, "_connector",
        lambda *a, **k: _StubConnector({"ok": False, "error": "revoked"}))
    assert main(["cloud", "run", "--once"]) == 1
    err = capsys.readouterr().err
    assert "interlock cloud run: revoked" in err


def test_cloud_enroll_help_exits_zero():
    assert main(["cloud", "enroll", "--help"]) == 0


def test_cloud_run_help_lists_once_and_verbose():
    args = build_parser().parse_args(["cloud", "run", "--once", "--verbose"])
    assert args.once is True and args.verbose is True
