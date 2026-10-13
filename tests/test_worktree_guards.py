"""The worktree guards in .githooks/ and scripts/codex-worktree.sh, end to end.

Each test builds a throwaway repo with a bare `origin`, installs this checkout's
hooks and scripts into it, and drives real git commands. Nothing touches the
repo the tests run from, and nothing reaches the network.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Tuple

import pytest

ROOT = Path(__file__).resolve().parent.parent
GUARD_FILES = [
    ".githooks/_primary.sh",
    ".githooks/reference-transaction",
    ".githooks/pre-commit",
    ".githooks/pre-merge-commit",
    ".githooks/pre-push",
    "scripts/codex-worktree.sh",
    "scripts/install-worktree-guards.sh",
]


def _git_version() -> Tuple[int, int]:
    out = subprocess.run(["git", "--version"], capture_output=True, text=True).stdout
    m = re.search(r"(\d+)\.(\d+)", out)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


pytestmark = pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("bash") is None or _git_version() < (2, 31),
    reason="needs git >= 2.31 (rev-parse --path-format) and bash",
)


def _env(**extra):
    # Drop every inherited GIT_* variable, not just the config files: a caller
    # can inject config through GIT_CONFIG_COUNT/KEY_n/VALUE_n (mini-ork's lanes
    # set every pushurl to no-push:// that way) or point at another repo with
    # GIT_DIR, and either would leak into the throwaway repos below.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@example.invalid",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@example.invalid",
    )
    for name in ("ALLOW_WORKTREE_BRANCH_CREATE", "ALLOW_MAIN_COMMIT", "ALLOW_MAIN_MERGE",
                 "WORKTREE_PRIMARY_COMMIT_GUARD", "PUSH_MAIN_GUARD", "SHIP_ALLOW_DELETIONS"):
        env.pop(name, None)
    env.update(extra)
    return env


def _run(args, cwd, check=True, **extra_env):
    res = subprocess.run(args, cwd=str(cwd), env=_env(**extra_env), capture_output=True, text=True)
    if check and res.returncode != 0:
        raise AssertionError("{} failed ({}):\n{}{}".format(" ".join(args), res.returncode, res.stdout, res.stderr))
    return res


def _commit(repo, name, text="x\n", **extra_env):
    (Path(repo) / name).write_text(text)
    _run(["git", "add", name], repo)
    return _run(["git", "commit", "-q", "-m", "add " + name], repo, check=False, **extra_env)


@pytest.fixture
def repo(tmp_path):
    """A primary checkout on main with the guards installed, plus a bare origin."""
    origin = tmp_path / "origin.git"
    primary = tmp_path / "primary"
    _run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], tmp_path)
    _run(["git", "init", "-q", "-b", "main", str(primary)], tmp_path)
    (primary / "README").write_text("base\n")
    _run(["git", "add", "README"], primary)
    _run(["git", "commit", "-q", "-m", "base, before the guards existed"], primary)
    for rel in GUARD_FILES:
        dest = primary / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, dest)
    _run(["git", "add", "."], primary)
    _run(["git", "commit", "-q", "-m", "guards"], primary)
    _run(["git", "remote", "add", "origin", str(origin)], primary)
    _run(["git", "push", "-q", "origin", "main"], primary)
    _run(["git", "fetch", "-q", "origin"], primary)
    _run(["bash", "scripts/install-worktree-guards.sh"], primary)
    return {"primary": primary, "origin": origin, "worktrees": tmp_path / "wts"}


def _script(repo, *args, **extra_env):
    return _run(["bash", "scripts/codex-worktree.sh", *args], repo["primary"], check=False,
                INTERLOCK_WORKTREES_DIR=str(repo["worktrees"]), **extra_env)


def test_branch_creation_in_the_primary_is_refused(repo):
    res = _run(["git", "checkout", "-q", "-b", "feature"], repo["primary"], check=False)
    assert res.returncode != 0
    assert "worktree-guard" in res.stderr
    assert _run(["git", "symbolic-ref", "--short", "HEAD"], repo["primary"]).stdout.strip() == "main"


def test_the_allow_flag_and_mini_ork_branches_are_exempt(repo):
    _run(["git", "branch", "mini-ork/run-1"], repo["primary"])
    _run(["git", "branch", "allowed"], repo["primary"], ALLOW_WORKTREE_BRANCH_CREATE="1")


def test_a_commit_on_primary_main_is_refused_unless_escaped(repo):
    res = _commit(repo["primary"], "direct.txt")
    assert res.returncode != 0 and "G1" in res.stderr
    assert _commit(repo["primary"], "direct.txt", ALLOW_MAIN_COMMIT="1").returncode == 0


def test_a_feature_branch_commit_in_the_primary_is_refused(repo):
    _run(["git", "checkout", "-q", "-b", "side"], repo["primary"], ALLOW_WORKTREE_BRANCH_CREATE="1")
    res = _commit(repo["primary"], "side.txt")
    assert res.returncode != 0 and "G1" in res.stderr


def test_a_merge_commit_in_the_primary_is_refused(repo):
    primary = repo["primary"]
    _run(["git", "checkout", "-q", "-b", "side"], primary, ALLOW_WORKTREE_BRANCH_CREATE="1")
    assert _commit(primary, "side.txt", WORKTREE_PRIMARY_COMMIT_GUARD="skip").returncode == 0
    _run(["git", "checkout", "-q", "main"], primary)
    assert _commit(primary, "main.txt", ALLOW_MAIN_COMMIT="1").returncode == 0
    res = _run(["git", "merge", "--no-edit", "side"], primary, check=False)
    assert res.returncode != 0 and "G10" in res.stderr
    _run(["git", "merge", "--abort"], primary, check=False)


def test_create_commit_ship_lands_a_fast_forward_and_refreshes_the_primary(repo):
    assert _script(repo, "create", "task one").returncode == 0
    wt = repo["worktrees"] / "task-one"
    assert _run(["git", "symbolic-ref", "--short", "HEAD"], wt).stdout.strip() == "codex/task-one"
    assert _commit(wt, "feature.txt").returncode == 0  # commits are free in a worktree
    res = _script(repo, "ship", "task-one")
    assert res.returncode == 0, res.stderr
    head = _run(["git", "rev-parse", "HEAD"], wt).stdout.strip()
    assert _run(["git", "rev-parse", "main"], repo["origin"]).stdout.strip() == head
    assert _run(["git", "rev-parse", "HEAD"], repo["primary"]).stdout.strip() == head
    assert _script(repo, "remove", "task-one").returncode == 0
    assert not wt.exists()


def test_ship_refuses_uncommitted_work(repo):
    _script(repo, "create", "dirty")
    wt = repo["worktrees"] / "dirty"
    (wt / "loose.txt").write_text("not committed\n")
    res = _script(repo, "ship", "dirty")
    assert res.returncode != 0 and "uncommitted" in res.stderr


def test_ship_rebases_over_a_concurrent_landing(repo):
    _script(repo, "create", "first")
    _script(repo, "create", "second")
    _commit(repo["worktrees"] / "first", "a.txt")
    _commit(repo["worktrees"] / "second", "b.txt")
    assert _script(repo, "ship", "first").returncode == 0
    res = _script(repo, "ship", "second")  # its base is now stale: ship must rebase, not fail
    assert res.returncode == 0, res.stderr
    files = _run(["git", "ls-tree", "--name-only", "main"], repo["origin"]).stdout.split()
    assert {"a.txt", "b.txt"} <= set(files)


def test_a_forced_push_over_main_is_refused(repo):
    _script(repo, "create", "stale")
    _script(repo, "create", "fresh")
    _commit(repo["worktrees"] / "fresh", "fresh.txt")
    assert _script(repo, "ship", "fresh").returncode == 0
    stale = repo["worktrees"] / "stale"
    _commit(stale, "stale.txt")
    _run(["git", "fetch", "-q", "origin"], stale)
    # git itself refuses a plain non-fast-forward before pre-push runs; the guard
    # exists for the forced push, which git would otherwise let through.
    assert _run(["git", "push", "origin", "HEAD:main"], stale, check=False).returncode != 0
    res = _run(["git", "push", "--force", "origin", "HEAD:main"], stale, check=False)
    assert res.returncode != 0 and "G4" in res.stderr
    _run(["git", "fetch", "-q", "origin"], stale)
    assert "fresh.txt" in _run(["git", "ls-tree", "--name-only", "origin/main"], stale).stdout


def test_ship_leaves_a_primary_on_another_branch_untouched(repo):
    primary = repo["primary"]
    _run(["git", "checkout", "-q", "-b", "elsewhere"], primary, ALLOW_WORKTREE_BRANCH_CREATE="1")
    _script(repo, "create", "land")
    _commit(repo["worktrees"] / "land", "land.txt")
    assert _script(repo, "ship", "land").returncode == 0
    assert _run(["git", "symbolic-ref", "--short", "HEAD"], primary).stdout.strip() == "elsewhere"
    assert not (primary / "land.txt").exists()
    origin_main = _run(["git", "rev-parse", "main"], repo["origin"]).stdout.strip()
    assert _run(["git", "rev-parse", "main"], primary).stdout.strip() == origin_main


def test_the_guards_hold_even_on_a_branch_that_predates_them(repo):
    """The primary checkout on an old branch has no .githooks/ on disk; the
    installed copies in the shared hooks dir must still refuse the commit."""
    primary = repo["primary"]
    _run(["git", "checkout", "-q", "-b", "old", "HEAD~1"], primary, ALLOW_WORKTREE_BRANCH_CREATE="1")
    assert not (primary / ".githooks").exists()
    res = _commit(primary, "old.txt")
    assert res.returncode != 0 and "G1" in res.stderr


def test_uninstall_removes_only_the_guards(repo):
    hooks = Path(_run(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"], repo["primary"]).stdout.strip()) / "hooks"
    (hooks / "post-checkout").write_text("#!/bin/sh\nexit 0\n")
    _run(["bash", "scripts/install-worktree-guards.sh", "--uninstall"], repo["primary"])
    assert not (hooks / "pre-commit").exists()
    assert (hooks / "post-checkout").exists()
    assert _commit(repo["primary"], "after.txt").returncode == 0
