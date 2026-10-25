"""The `interlock mesh dap …` actions and the DAP roles of `mesh serve`.

Driven through ``interlock.cli.main`` so the parser, the dispatch and the exit
codes are exercised together. The protocol itself is covered by
``tests/test_mesh_dap.py``; these tests never open a socket except where a fake
server stands in.
"""

import json
import os

from interlock.cli import main
from interlock.mesh.dap import task as taskmod

BUCKETS = ["rule-a|block|shell|pre|*", "rule-b|allow|read|post|*"]


def _create(tmp_path, name="dap"):
    task, leader, helper, collector = taskmod.create_task(
        leader="https://leader.example", helper="https://helper.example",
        buckets=BUCKETS, batch_hours=24, min_batch_size=3,
        out_dir=str(tmp_path / name))
    return task, leader, helper, collector, tmp_path / name


def _task_argv(out, *extra):
    return ["mesh", "dap", "task", "--out", str(out),
            "--leader-url", "https://leader.example",
            "--helper-url", "https://helper.example",
            "--bucket", BUCKETS[0], "--bucket", BUCKETS[1]] + list(extra)


# --- dap task --------------------------------------------------------------

def test_dap_task_writes_the_public_file_and_three_secret_ones(tmp_path, capsys):
    out = tmp_path / "dap"
    assert main(_task_argv(out)) == 0
    assert sorted(os.listdir(out)) == [
        "collector.json", "helper.json", "leader.json", "task.json"]
    for name in ("leader.json", "helper.json", "collector.json"):
        assert (os.stat(out / name).st_mode & 0o777) == 0o600
    assert (os.stat(out / "task.json").st_mode & 0o777) == 0o644
    printed = capsys.readouterr().out
    assert "task.json, leader.json, helper.json, collector.json" in printed
    assert "0600" in printed  # the warning names the secret files


def test_dap_task_refuses_to_overwrite_an_existing_task(tmp_path, capsys):
    out = tmp_path / "dap"
    assert main(_task_argv(out)) == 0
    before = (out / "task.json").read_bytes()
    assert main(_task_argv(out)) == 3
    assert "already exists" in capsys.readouterr().err
    assert (out / "task.json").read_bytes() == before


def test_dap_task_json_is_the_public_task_only(tmp_path, capsys):
    out = tmp_path / "dap"
    assert main(_task_argv(out, "--json")) == 0
    document = json.loads(capsys.readouterr().out)
    text = json.dumps(document)
    assert document["task_id_b64"] == taskmod.b64url(
        taskmod.from_b64url(document["task_id_b64"]))
    assert len(document["buckets"]) == 2
    # task.json is shareable: no secret ever appears in it.
    for secret in ("secret", "token", "verify_key"):
        assert secret not in text
    assert "hpke_secret" not in text


def test_dap_task_refuses_an_overlapping_bucket_list(tmp_path, capsys):
    out = tmp_path / "dap"
    argv = _task_argv(out, "--bucket", "rule-a|block|shell|pre|0")
    assert main(argv) == 3
    assert "overlap" in capsys.readouterr().err
    assert not (out / "task.json").exists()


def test_dap_without_an_action_lists_them(tmp_path, capsys):
    assert main(["mesh", "dap"]) == 64
    assert "task, submit, collect" in capsys.readouterr().err


# --- dap submit ------------------------------------------------------------

def test_dap_submit_is_refused_by_the_kill_switch_before_reading_files(
        tmp_path, monkeypatch, capsys):
    # Neither path exists; the kill switch is checked first, so this is exit 2
    # with the consent message rather than a file error.
    monkeypatch.setenv("INTERLOCK_MESH_NO_REPORT", "1")
    status = main(["mesh", "dap", "submit", "--report", str(tmp_path / "nope.json"),
                   "--task", str(tmp_path / "nope-task.json")])
    assert status == 2
    error = capsys.readouterr().err
    assert "INTERLOCK_MESH_NO_REPORT" in error and "not sent" in error


def test_dap_submit_reports_an_unusable_envelope(tmp_path, capsys):
    task, _, _, _, out = _create(tmp_path)
    status = main(["mesh", "dap", "submit", "--report", str(tmp_path / "missing.json"),
                   "--task", str(out / "task.json")])
    assert status == 3
    assert "not usable" in capsys.readouterr().err


# --- dap collect -----------------------------------------------------------

def test_dap_collect_needs_a_readable_task(tmp_path, capsys):
    status = main(["mesh", "dap", "collect", "--task", str(tmp_path / "missing.json"),
                   "--keys", str(tmp_path / "missing.json"), "--start", "1"])
    assert status == 2
    assert "collect" in capsys.readouterr().err


def test_dap_collect_refuses_the_wrong_role_keys(tmp_path, capsys):
    task, leader, helper, collector, out = _create(tmp_path)
    status = main(["mesh", "dap", "collect", "--task", str(out / "task.json"),
                   "--keys", str(out / "leader.json"), "--start", "1"])
    assert status == 2
    assert "collector" in capsys.readouterr().err


# --- mesh serve --role dap-* ----------------------------------------------

def test_serve_dap_needs_task_and_keys(capsys):
    assert main(["mesh", "serve", "--role", "dap-leader"]) == 64
    assert "--task and --keys" in capsys.readouterr().err


def test_serve_dap_refuses_a_key_file_for_the_other_role(tmp_path, capsys):
    task, leader, helper, collector, out = _create(tmp_path)
    status = main(["mesh", "serve", "--role", "dap-leader",
                   "--task", str(out / "task.json"),
                   "--keys", str(out / "helper.json")])
    assert status == 2
    assert "helper" in capsys.readouterr().err


def test_serve_dap_dispatches_the_leader_with_the_key_file_tokens(
        tmp_path, monkeypatch, capsys):
    task, leader, helper, collector, out = _create(tmp_path)
    seen = {}

    class FakeServer:
        url = "http://127.0.0.1:1"

        def serve_forever(self):
            seen["served"] = True

        def server_close(self):
            seen["closed"] = True

    def fake_make(bind, *, role, task, keys, state_path, peer_token=None,
                  collector_token=None):
        seen.update(bind=bind, role=role, keys=keys, state_path=state_path,
                    peer_token=peer_token, collector_token=collector_token)
        return FakeServer()

    monkeypatch.setattr("interlock.mesh.dap.server.make_dap_server", fake_make)
    status = main(["mesh", "serve", "--role", "dap-leader",
                   "--task", str(out / "task.json"),
                   "--keys", str(out / "leader.json"),
                   "--bind", "127.0.0.1:1"])
    assert status == 0
    assert seen["role"] == "leader"
    assert seen["bind"] == "127.0.0.1:1"
    assert seen["state_path"] == str(out / "leader.json") + ".state"
    assert seen["peer_token"] is None and seen["collector_token"] is None
    assert seen["served"] and seen["closed"]
    assert "dap-leader" in capsys.readouterr().out


def test_serve_dap_maps_the_helper_role_and_state_override(
        tmp_path, monkeypatch):
    task, leader, helper, collector, out = _create(tmp_path)
    seen = {}

    class FakeServer:
        url = "http://127.0.0.1:2"

        def serve_forever(self):
            pass

        def server_close(self):
            pass

    def fake_make(bind, *, role, **kwargs):
        seen.update(role=role, **kwargs)
        return FakeServer()

    monkeypatch.setattr("interlock.mesh.dap.server.make_dap_server", fake_make)
    status = main(["mesh", "serve", "--role", "dap-helper",
                   "--task", str(out / "task.json"),
                   "--keys", str(out / "helper.json"),
                   "--state", str(tmp_path / "st.state"),
                   "--peer-token", "peer-secret",
                   "--bind", "127.0.0.1:2"])
    assert status == 0
    assert seen["role"] == "helper"
    assert seen["state_path"] == str(tmp_path / "st.state")
    assert seen["peer_token"] == "peer-secret"


def test_serve_dap_refuses_a_bad_bind_before_serving(tmp_path, capsys):
    task, leader, helper, collector, out = _create(tmp_path)
    status = main(["mesh", "serve", "--role", "dap-helper",
                   "--task", str(out / "task.json"),
                   "--keys", str(out / "helper.json"),
                   "--bind", "not-a-bind"])
    assert status == 2
    assert "HOST:PORT" in capsys.readouterr().err
