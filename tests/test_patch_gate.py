"""The patch gate: a test that cannot fail is not evidence.

Every test here builds a real git repository in a temp directory, because the
check under test *is* a replay against a real pre-patch revision. A mocked
replay would pass whether or not the gate can tell a decorative test from a
real one, which is the only thing this feature exists to tell.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from interlock import patch_gate
from interlock.enforce import Decision, Verdict
from interlock.event import SensorEvent


def _run(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True, text=True)


def _write(repo: Path, path: str, text: str) -> None:
    full = repo / path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(text, encoding="utf-8")


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    """A repo whose HEAD is buggy, ready for a patch on top of it."""
    root = tmp_path / "repo"
    root.mkdir()
    _run(root, "init", "-q", "-b", "main")
    _run(root, "config", "user.email", "gate@example.com")
    _run(root, "config", "user.name", "gate")
    _write(root, "calc.py", "def add(a, b):\n    return a - b\n")  # the bug
    _write(root, "conftest.py", "")  # keep pytest from walking upward
    _run(root, "add", "-A")
    _run(root, "commit", "-qm", "buggy base")
    return root


REAL_FIX = "def add(a, b):\n    return a + b\n"
REAL_TEST = "from calc import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"
DECORATIVE_TEST = (
    "from calc import add\n\n\ndef test_add():\n    result = add(1, 2)\n"
    "    assert result is not None\n"
)


def _apply_real_fix(repo: Path) -> None:
    _write(repo, "calc.py", REAL_FIX)
    _write(repo, "tests/test_calc.py", REAL_TEST)


# --------------------------------------------------------------------------
# The gate end to end, against real git state
# --------------------------------------------------------------------------

def test_real_fix_passes(repo: Path) -> None:
    _apply_real_fix(repo)
    report = patch_gate.gate(repo=str(repo))
    assert report.verdict == patch_gate.PASS, report.reason()
    assert report.check("replay_base").status == patch_gate.PASS
    assert report.check("replay_head").status == patch_gate.PASS
    assert report.tests == ["tests/test_calc.py"]


def test_decorative_test_fails(repo: Path) -> None:
    """The measured failure: the test passes before the change too."""
    _write(repo, "calc.py", REAL_FIX)
    _write(repo, "tests/test_calc.py", DECORATIVE_TEST)
    report = patch_gate.gate(repo=str(repo))
    assert report.verdict == patch_gate.FAIL
    replay = report.check("replay")
    assert replay is not None and replay.status == patch_gate.FAIL
    assert "pre-patch revision" in replay.detail


def test_test_file_without_assertion_fails(repo: Path) -> None:
    _write(repo, "calc.py", REAL_FIX)
    _write(repo, "tests/test_calc.py",
           "from calc import add\n\n\ndef test_add():\n    add(1, 2)\n")
    report = patch_gate.gate(repo=str(repo))
    assert report.verdict == patch_gate.FAIL
    assert report.check("assertions").status == patch_gate.FAIL


def test_added_skip_marker_fails(repo: Path) -> None:
    _write(repo, "calc.py", REAL_FIX)
    _write(repo, "tests/test_calc.py",
           "import pytest\nfrom calc import add\n\n\n"
           "@pytest.mark.skip(reason='flaky')\ndef test_add():\n"
           "    assert add(1, 2) == 3\n")
    report = patch_gate.gate(repo=str(repo))
    assert report.verdict == patch_gate.FAIL
    assert "skip" in (report.check("no_weakening").detail or "")


def test_code_patch_without_a_test_fails(repo: Path) -> None:
    _write(repo, "calc.py", REAL_FIX)
    report = patch_gate.gate(repo=str(repo))
    assert report.verdict == patch_gate.FAIL
    assert "no test" in (report.check("replay").detail or "")


def test_allow_untested_is_recorded_as_a_skip(repo: Path) -> None:
    _write(repo, "calc.py", REAL_FIX)
    report = patch_gate.gate(repo=str(repo), allow_untested=True)
    assert report.verdict == patch_gate.PASS
    assert report.check("replay").status == patch_gate.SKIP


def test_docs_only_diff_needs_no_test(repo: Path) -> None:
    _write(repo, "docs/guide.md", "hello\n")
    report = patch_gate.gate(repo=str(repo))
    assert report.verdict == patch_gate.PASS
    assert report.check("scope").status == patch_gate.SKIP


def test_deleted_test_file_fails(repo: Path) -> None:
    _write(repo, "calc.py", REAL_FIX)
    _write(repo, "tests/test_calc.py", REAL_TEST)
    _run(repo, "add", "-A")
    _run(repo, "commit", "-qm", "fix plus real test")
    (repo / "tests/test_calc.py").unlink()
    report = patch_gate.gate(repo=str(repo), base="HEAD")
    assert report.verdict == patch_gate.FAIL
    assert "deletes" in (report.check("assertions").detail or "")


# --------------------------------------------------------------------------
# The signed record
# --------------------------------------------------------------------------

def test_record_roundtrip_then_tamper(repo: Path, tmp_path: Path) -> None:
    _apply_real_fix(repo)
    gates = tmp_path / "gates"
    key = tmp_path / "gates.key"
    report = patch_gate.gate(repo=str(repo))
    path = patch_gate.write_record(report, str(gates), str(key))
    assert os.path.exists(path)
    assert oct(os.stat(key).st_mode & 0o777) == "0o600"

    record = patch_gate.read_record(str(patch_gate.repo_root(str(repo))),
                                    str(gates), str(key))
    assert record is not None and record["verdict"] == patch_gate.PASS

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    payload["verdict"] = "fail"
    Path(path).write_text(json.dumps(payload), encoding="utf-8")
    assert patch_gate.read_record(str(patch_gate.repo_root(str(repo))),
                                  str(gates), str(key)) is None


def test_stale_record_is_ignored(repo: Path, tmp_path: Path) -> None:
    _apply_real_fix(repo)
    gates, key = tmp_path / "gates", tmp_path / "gates.key"
    report = patch_gate.gate(repo=str(repo))
    path = patch_gate.write_record(report, str(gates), str(key))
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    payload.pop("mac")
    payload["created_at"] = 0
    payload["mac"] = patch_gate._mac(patch_gate._read_or_create_key(str(key)), payload)
    Path(path).write_text(json.dumps(payload), encoding="utf-8")
    assert patch_gate.read_record(str(patch_gate.repo_root(str(repo))),
                                  str(gates), str(key)) is None


# --------------------------------------------------------------------------
# The policy layer
# --------------------------------------------------------------------------

class _AllowAll:
    def evaluate(self, event):
        return Decision.allow("inner")


class _BlockAll:
    def evaluate(self, event):
        return Decision.block("inner", policy_id="inner_policy")


def _event(cwd: Path, command: str) -> SensorEvent:
    return SensorEvent(action="Bash", args={"command": command}, cwd=str(cwd))


def test_evaluator_blocks_an_uncovered_commit(repo: Path, tmp_path: Path) -> None:
    _apply_real_fix(repo)
    evaluator = patch_gate.PatchGateEvaluator(
        _AllowAll(), gates_dir=str(tmp_path / "gates"),
        key_path=str(tmp_path / "gates.key"))
    decision = evaluator.evaluate(_event(repo, "git commit -m 'fix calc'"))
    assert decision.verdict == Verdict.BLOCK
    assert decision.policy_id == patch_gate.PatchGateEvaluator.policy_id
    assert "interlock patch gate" in decision.reason


def test_evaluator_allows_a_covered_commit(repo: Path, tmp_path: Path) -> None:
    _apply_real_fix(repo)
    gates, key = tmp_path / "gates", tmp_path / "gates.key"
    report = patch_gate.gate(repo=str(repo))
    patch_gate.write_record(report, str(gates), str(key))
    _run(repo, "add", "-A")
    evaluator = patch_gate.PatchGateEvaluator(
        _AllowAll(), gates_dir=str(gates), key_path=str(key))
    decision = evaluator.evaluate(_event(repo, "git commit -m 'fix calc'"))
    assert decision.verdict == Verdict.ALLOW


def test_the_record_still_covers_the_commit_it_verified(repo: Path, tmp_path: Path) -> None:
    """A record bound to the *name* HEAD stops covering anything once HEAD moves.

    The gate is run against a moving ref on purpose here: a record has to store
    the resolved commit, or the very next ``git push`` compares an empty
    ``HEAD..HEAD`` and refuses the patch it just verified.
    """
    _apply_real_fix(repo)
    gates, key = tmp_path / "gates", tmp_path / "gates.key"
    report = patch_gate.gate(repo=str(repo), base="HEAD")
    assert report.verdict == patch_gate.PASS
    assert report.base != "HEAD" and report.base_ref == "HEAD"
    patch_gate.write_record(report, str(gates), str(key))
    _run(repo, "add", "-A")
    _run(repo, "commit", "-qm", "the verified fix")
    evaluator = patch_gate.PatchGateEvaluator(
        _AllowAll(), gates_dir=str(gates), key_path=str(key))
    assert evaluator.evaluate(
        _event(repo, "git push origin main")).verdict == Verdict.ALLOW
    _write(repo, "calc.py", REAL_FIX + "\n\n\ndef mul(a, b):\n    return a * b\n")
    _run(repo, "commit", "-qam", "and something else")
    assert evaluator.evaluate(
        _event(repo, "git push origin main")).verdict == Verdict.BLOCK


def test_evaluator_blocks_a_push_after_the_diff_changes(repo: Path, tmp_path: Path) -> None:
    _apply_real_fix(repo)
    gates, key = tmp_path / "gates", tmp_path / "gates.key"
    report = patch_gate.gate(repo=str(repo))
    patch_gate.write_record(report, str(gates), str(key))
    _write(repo, "calc.py", REAL_FIX + "\n\ndef sub(a, b):\n    return a + b\n")
    evaluator = patch_gate.PatchGateEvaluator(
        _AllowAll(), gates_dir=str(gates), key_path=str(key))
    assert evaluator.evaluate(
        _event(repo, "git push origin main")).verdict == Verdict.BLOCK


def test_evaluator_ignores_a_non_vcs_command(repo: Path, tmp_path: Path) -> None:
    evaluator = patch_gate.PatchGateEvaluator(
        _AllowAll(), gates_dir=str(tmp_path / "gates"),
        key_path=str(tmp_path / "gates.key"))
    assert evaluator.evaluate(
        _event(repo, "pytest -q")).verdict == Verdict.ALLOW


def test_evaluator_never_launders_a_block(repo: Path, tmp_path: Path) -> None:
    evaluator = patch_gate.PatchGateEvaluator(
        _BlockAll(), gates_dir=str(tmp_path / "gates"),
        key_path=str(tmp_path / "gates.key"))
    decision = evaluator.evaluate(_event(repo, "git commit -m x"))
    assert decision.verdict == Verdict.BLOCK
    assert decision.policy_id == "inner_policy"


def test_monitor_mode_records_without_refusing(repo: Path, tmp_path: Path) -> None:
    evaluator = patch_gate.PatchGateEvaluator(
        _AllowAll(), gates_dir=str(tmp_path / "gates"),
        key_path=str(tmp_path / "gates.key"), mode="monitor")
    decision = evaluator.evaluate(_event(repo, "git commit -m x"))
    assert decision.verdict == Verdict.ALLOW
    assert decision.policy_id == patch_gate.PatchGateEvaluator.policy_id
    assert "monitor" in decision.reason


# --------------------------------------------------------------------------
# The CLI
# --------------------------------------------------------------------------

def test_cli_gate_then_status(repo: Path, tmp_path: Path, capsys) -> None:
    from interlock.cli import main

    _apply_real_fix(repo)
    gates, key = str(tmp_path / "gates"), str(tmp_path / "gates.key")
    cwd = os.getcwd()
    os.chdir(repo)
    try:
        assert main(["patch", "gate", "--gates-dir", gates, "--key", key]) == 0
        out = capsys.readouterr().out
        assert "PASS" in out and "replay_head" in out
        assert main(["patch", "status", "--gates-dir", gates, "--key", key]) == 0
    finally:
        os.chdir(cwd)
    _write(repo, "calc.py", REAL_FIX + "\nX = 1\n")
    os.chdir(repo)
    try:
        assert main(["patch", "status", "--gates-dir", gates, "--key", key]) == 1
    finally:
        os.chdir(cwd)
