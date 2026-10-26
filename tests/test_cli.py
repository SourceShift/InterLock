"""The shared ``interlock`` command surface: registration, dispatch and exit codes.

``interlock/cli/__init__.py`` is the single table of commands; every module it
names must expose ``add_arguments`` and ``run``, and ``main`` must map usage
mistakes to 64 while letting a command choose its own non-zero code. The cloud
connector is the newest entry, so its stub contract (0 for ``--help``, 3 for a
stub, 64 for a missing or unknown action) is exercised here as well.
"""
from __future__ import annotations

import importlib

import pytest

from interlock.cli import COMMANDS, build_parser, main

CLOUD_ACTIONS = ["enroll", "run", "status", "leave", "policy", "keys"]


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
def test_cloud_actions_parse_and_are_stubs(action, capsys):
    args = build_parser().parse_args(["cloud", action])
    assert args.cloud_command == action

    assert main(["cloud", action]) == 3
    assert "interlock cloud {}: not implemented yet".format(action) in (
        capsys.readouterr().err
    )


def test_cloud_enroll_help_exits_zero():
    assert main(["cloud", "enroll", "--help"]) == 0
