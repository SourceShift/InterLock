"""Gate an agent-authored patch before it becomes an effect.

An agent that writes, repairs or reviews code does not fail at generation in the
way the operator expects: it fails at *verification*. Measured in 2026, over 40%
of patches an agent validated with its own tests fail developer-written
regression tests (arxiv:2603.06858); only 24.8% of 319 agent patches were fully
correct, and agent code introduces vulnerabilities at roughly nine times the
human rate (arxiv:2603.10072); and an independent exploit agent found a new
confirmed exploit in 41% of runs *after* the patch already blocked the original
proof of concept (arxiv:2610.20245).

Those numbers share one root cause: a gate that accepts the patch's own evidence.
A test file that exists is not coverage. A test that passes at every working-tree
state proves nothing about the change. A self-reported "fixed" is not a fact.

So this module asks three questions about a diff and refuses to guess:

1. **Does every test file the patch adds or edits contain an assertion at all?**
   A test file with no assertion is a file, not a test.
2. **Does the suite fail with the patch's own test files at the pre-patch
   revision?** A test that passes before the change does not test the change.
   This is the check that separates a real fix from a decorative one, and it is
   the one hand-rolled gates skip.
3. **Does the same suite pass with the patch applied?**

Three states, two commands, one verdict. Everything else here - the diff
parser, the weakening scan, the signed record - exists to make that verdict
answerable and honest:

* The gate never runs the agent's claimed validation command unless you pass it,
  and it never reads the agent's summary of the result.
* A pass is written to a **signed record bound to the diff digest**, so the hook
  can refuse a ``git commit``/``git push``/``git merge`` whose content is not
  the content that was verified. A record that does not match the current diff
  is the same as no record.
* Every check that cannot be performed is a *failure*, not a skip, unless the
  patch provably changes no code (docs, config metadata).

What this is not: a sandbox. The replay runs the repository's own test command,
in a temporary extraction of the base revision, with the patch's test files
overlaid. A hostile patch can write a hostile test command; run the gate where
that is acceptable, or pass ``--test-cmd`` with a command you chose.

Cost: two test runs per gate (base and head), plus one archive extraction.
Nothing is spent per call; the hook only compares a digest.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

#: Bumped when the record's shape changes; a reader refuses a record it does not
#: understand rather than guessing what an old field meant.
RECORD_VERSION = 1

PASS, FAIL, SKIP = "pass", "fail", "skip"

#: Default per-state test timeout. A gate that hangs is a gate that fails.
DEFAULT_TIMEOUT = 600

#: Longest detail string a record keeps per check, in bytes. Reasons reach a
#: receipt and a terminal; an unbounded one reaches both.
MAX_DETAIL = 600

#: The VCS effects this gate governs, and how to recognise one in a shell
#: command. A commit, a push and a merge each make a patch real.
_EFFECTS: Tuple[Tuple["re.Pattern[str]", str], ...] = (
    (re.compile(r"\bgit\b[^\n;&|]*\bcommit\b"), "commit"),
    (re.compile(r"\bgit\b[^\n;&|]*\bpush\b"), "push"),
    (re.compile(r"\bgit\b[^\n;&|]*\bmerge\b"), "merge"),
    (re.compile(r"\bgh\b[^\n;&|]*\bpr\b[^\n;&|]*\bmerge\b"), "merge"),
)

#: Paths that hold tests, across the languages an agent writes today. The test
#: is a name/shape test on purpose: a patch can put its tests anywhere, and a
#: classifier that guesses "is this a test" wrongly is worse than a directory
#: convention.
_TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs)/"
    r"|(^|/)(test_[^/]+\.py|[^/]+_test\.py|[^/]+_test\.go|conftest\.py"
    r"|[^/]+\.(test|spec)\.[cm]?[jt]sx?|Test[^/]+\.(java|kt)|[^/]+_spec\.rb)$"
)

#: Assertion tokens per language family. Presence, not style: the gate asks
#: whether the test can fail, not whether it is well written.
_ASSERTIONS: Tuple[str, ...] = (
    # Python: unittest, pytest, plain assert, third-party
    "assert ", "assert(", "assertRaises", "assertEqual", "assertIn",
    "assertTrue", "assertFalse", "assertIsNone", "assertRaisesRegex",
    "pytest.raises", "pytest.warns", "self.fail(",
    # JavaScript / TypeScript
    "expect(", "assert.", "assert(", "should.", ".toBe(", ".toEqual(",
    "t.error(", "t.fail(",
    # Go
    "t.errorf(", "t.fatalf(", "t.fail(", "require.", "if got !=",
    # Rust
    "assert!", "assert_eq!", "assert_ne!", "debug_assert!",
    # Java / Kotlin
    "assertThat(", "assertThrows(",
    # Ruby
    "expect(", "should ", "refute ",
)

#: Lines that make a failing test stop failing, or a failing gate stop gating.
#: Each entry is (pattern, why). Matched against *added* lines only: removing a
#: skip is an improvement, adding one is the failure being measured.
_WEAKENING: Tuple[Tuple["re.Pattern[str]", str], ...] = (
    (re.compile(r"pytest\.mark\.(skip|xfail)"), "adds a pytest skip/xfail marker"),
    (re.compile(r"@unittest\.skip"), "adds a unittest skip decorator"),
    (re.compile(r"unittest\.skip(If|Unless)?"), "adds a unittest skip"),
    (re.compile(r"\bt\.Skipf?\("), "adds a Go test skip"),
    (re.compile(r"\b(it|test|describe)\.skip\("), "adds a JS test skip"),
    (re.compile(r"\bxit\(|\bxdescribe\("), "adds an excluded JS test"),
    (re.compile(r"^\s*#\[ignore\]"), "adds a Rust ignore attribute"),
    (re.compile(r"\.only\("), "adds a JS .only, silently dropping sibling tests"),
    (re.compile(r"--no-verify"), "bypasses a pre-commit hook"),
    (re.compile(r"continue-on-error\s*:\s*true"), "marks a CI step non-blocking"),
    (re.compile(r"allow_failure\s*:\s*true"), "marks a CI job non-blocking"),
    (re.compile(r"\|\|\s*true\b"), "swallows the command's exit status"),
    (re.compile(r"^\s*set \+e\b"), "disables errexit in a shell step"),
)

#: A record older than this is stale evidence: the tree it certified has almost
#: certainly moved. 24 hours is generous for one agent turn and short enough
#: that yesterday's green cannot be replayed onto today's diff.
RECORD_TTL_SEC = 86400


# --------------------------------------------------------------------------
# Diff model
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class FileDiff:
    """One file's part of a unified diff."""

    path: str
    added: Tuple[str, ...] = ()
    removed: Tuple[str, ...] = ()
    is_new: bool = False
    is_deleted: bool = False
    #: ``git diff``'s ``index <old>..<new>`` header. Blob ids are
    #: content-addressed, so the same content carries the same ids in a
    #: worktree diff and a ``--cached`` diff - which is what lets one digest
    #: describe both. Excluded from the digest for a new file, where the old
    #: side is always the null blob and an untracked file has no header at all.
    index: Optional[str] = None

    @property
    def is_test(self) -> bool:
        return is_test_path(self.path)

    @property
    def added_text(self) -> str:
        return "\n".join(self.added)

    @property
    def removed_text(self) -> str:
        return "\n".join(self.removed)

    @property
    def contents_changed(self) -> bool:
        return bool(self.added or self.removed)


@dataclass
class Diff:
    """A parsed unified diff."""

    files: List[FileDiff] = field(default_factory=list)

    @property
    def paths(self) -> List[str]:
        return [f.path for f in self.files]

    @property
    def tests(self) -> List[FileDiff]:
        return [f for f in self.files if f.is_test and f.contents_changed]

    @property
    def code(self) -> List[FileDiff]:
        return [f for f in self.files
                if not f.is_test and not _is_non_code(f.path) and f.contents_changed]


@dataclass
class Check:
    """One question asked of the patch, and its answer."""

    id: str
    status: str
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "status": self.status,
                "detail": self.detail[:MAX_DETAIL]}


@dataclass
class Report:
    """The gate's verdict and the evidence behind it."""

    verdict: str
    checks: List[Check]
    repo: str
    base: str
    head: str
    diff_sha256: str
    tests: List[str]
    test_cmd: Optional[str]
    #: The name the operator asked for (``origin/main``, ``HEAD~1``); ``base``
    #: holds the resolved commit, because a record bound to a *name* stops
    #: covering anything the moment that name moves.
    base_ref: Optional[str] = None
    created_at: float = field(default_factory=time.time)

    @property
    def failed(self) -> bool:
        return self.verdict != PASS

    def check(self, check_id: str) -> Optional[Check]:
        return next((c for c in self.checks if c.id == check_id), None)

    def reason(self) -> str:
        """One line a human reads in a block message: the first failure."""
        for check in self.checks:
            if check.status == FAIL:
                return "{}: {}".format(check.id, check.detail)
        return "verdict {}".format(self.verdict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": RECORD_VERSION,
            "verdict": self.verdict,
            "checks": [c.as_dict() for c in self.checks],
            "repo": self.repo,
            "base": self.base,
            "base_ref": self.base_ref,
            "head": self.head,
            "diff_sha256": self.diff_sha256,
            "tests": self.tests,
            "test_cmd": self.test_cmd,
            "created_at": self.created_at,
        }


#: Build and test caches: files an agent, or the gate's own replay, *produces*.
#: They are not the patch, and they must not decide whether a record covers it -
#: the first version of this gate broke on exactly that, because running pytest
#: to verify the patch wrote ``__pycache__/`` and ``.pytest_cache/`` into the
#: tree, so the diff the hook recomputed a second later no longer matched the
#: diff that had just passed. Derived files are excluded from the digest on
#: both sides; a repo whose ``.gitignore`` already covers them sees no change.
_ARTIFACT = re.compile(
    r"(^|/)(__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.tox|\.venv"
    r"|node_modules|\.git|htmlcov)(/|$)"
    r"|\.pyc$|(^|/)\.coverage(\.[^/]*)?$"
)


def is_artifact_path(path: str) -> bool:
    return bool(_ARTIFACT.search(path.replace("\\", "/")))


def digest(diff: Diff) -> str:
    """The digest of what a diff *changes*, not of how git printed it.

    Hashing the raw text would make the record unforgeable but unusable: the
    same patch arrives as ``git diff`` (worktree), ``git diff --cached``
    (staged) and ``git diff base..HEAD`` (committed), and those agree on what
    changed while disagreeing on hunk offsets and headers. Hashing the parsed
    content lets one record cover all three - which is exactly what the hook
    needs, because it recomputes the diff at the moment of the commit.

    The ``index`` blob ids stay in for non-new files: they are content
    hashes, identical in every one of those three diffs, and they keep two
    different binary patches from sharing a digest.
    """
    rows = []
    for file in sorted(diff.files, key=lambda f: f.path):
        if is_artifact_path(file.path):
            continue
        rows.append({
            "path": file.path,
            "new": file.is_new,
            "deleted": file.is_deleted,
            "index": None if file.is_new else file.index,
            "added": [line.rstrip() for line in file.added],
            "removed": [line.rstrip() for line in file.removed],
        })
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def diff_sha256(text: str) -> str:
    """The digest of a unified diff given as text."""
    return digest(parse_diff(text))


def is_test_path(path: str) -> bool:
    return bool(_TEST_PATH.search(path.replace("\\", "/")))


def assertions_in(text: str) -> int:
    """How many assertion-shaped tokens a block of text contains.

    Counting tokens rather than statements is deliberate: the gate needs
    "can this test fail at all", and every false positive here is a patch the
    three-state replay will still judge. Under-counting is what would let a
    decorative test through, so the token list errs wide.
    """
    lowered = text.lower()
    return sum(lowered.count(token) for token in _ASSERTIONS)


def weakening_in(added_lines: Iterable[str]) -> List[str]:
    """Reasons a patch's added lines weaken its own gate, most severe first."""
    found: List[str] = []
    text = "\n".join(added_lines)
    for pattern, why in _WEAKENING:
        if pattern.search(text) or any(pattern.search(line) for line in added_lines):
            found.append(why)
    return found


def parse_diff(text: str) -> Diff:
    """Parse a unified diff into per-file added and removed lines.

    Tolerant by design: an unrecognised line is ignored rather than fatal,
    because a gate that crashes on a diff shape is a gate an agent learns to
    produce.
    """
    diff = Diff()
    current: Optional[FileDiff] = None
    added: List[str] = []
    removed: List[str] = []
    is_new = False
    is_deleted = False
    in_header = False
    index: Optional[str] = None

    def flush() -> None:
        nonlocal current, added, removed, is_new, is_deleted, index
        if current is not None:
            diff.files.append(FileDiff(path=current.path, added=tuple(added),
                                       removed=tuple(removed), is_new=is_new,
                                       is_deleted=is_deleted, index=index))
        current, added, removed, is_new, is_deleted, index = (
            None, [], [], False, False, None)

    for raw in text.splitlines():
        if raw.startswith("diff --git "):
            flush()
            path = _path_from_git_header(raw)
            current = FileDiff(path=path)
            in_header = True
            continue
        if current is None:
            continue
        if raw.startswith("new file mode"):
            is_new = True
            continue
        if raw.startswith("deleted file mode"):
            is_deleted = True
            continue
        if raw.startswith("index ") and in_header:
            index = raw[len("index "):].strip()
            continue
        if raw.startswith("rename from "):
            continue
        if raw.startswith("rename to "):
            current = FileDiff(path=raw[len("rename to "):].strip(), index=index)
            continue
        if raw.startswith("--- "):
            if raw[4:].strip() in ("/dev/null", '"/dev/null"'):
                is_new = True
            continue
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            if target in ("/dev/null", '"/dev/null"'):
                is_deleted = True
            else:
                current = FileDiff(path=_strip_prefix(target), index=index)
            in_header = False
            continue
        if raw.startswith("@@"):
            in_header = False
            continue
        if in_header:
            continue
        if raw.startswith("+"):
            added.append(raw[1:])
        elif raw.startswith("-"):
            removed.append(raw[1:])
    flush()
    return diff


def _path_from_git_header(line: str) -> str:
    """``diff --git a/x b/x`` -> ``x`` (best effort; later headers win)."""
    parts = line.split()
    if len(parts) >= 4:
        return _strip_prefix(parts[3])
    return line[len("diff --git "):].strip()


def _strip_prefix(path: str) -> str:
    path = path.strip().strip('"')
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def _is_non_code(path: str) -> bool:
    """Docs and prose assets: the only diff that cannot change behaviour.

    Config, CI and data files are *not* on this list on purpose. A patch that
    edits a workflow, a policy or a config can change what ships as surely as
    one that edits Python, and the gate's whole point is that "it's just
    config" is not evidence. It takes ``--allow-untested`` to say so out loud.
    """
    lowered = path.lower()
    if lowered.startswith(("docs/", "doc/", "website/", "landing/")):
        return True
    return lowered.endswith((
        ".md", ".mdx", ".rst", ".txt", ".adoc", ".png", ".jpg", ".jpeg",
        ".gif", ".svg", ".webp", ".ico", ".pdf", ".po", ".pot",
    ))


# --------------------------------------------------------------------------
# Git plumbing
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class _Git:
    rc: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


def _git(repo: str, *args: str, timeout: int = 120) -> _Git:
    """Run one git command. Never raises: an unusable repo is a failed check."""
    try:
        proc = subprocess.run(
            ["git", "-C", repo, *args],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return _Git(1, "", "{}: {}".format(type(exc).__name__, exc))
    return _Git(proc.returncode, proc.stdout or "", proc.stderr or "")


def repo_root(path: Optional[str] = None) -> Optional[str]:
    """The working-tree root containing ``path``, or None."""
    result = _git(path or os.getcwd(), "rev-parse", "--show-toplevel")
    if not result.ok:
        return None
    root = result.out.strip()
    return os.path.realpath(root) if root else None


def default_base(repo: str) -> str:
    """``origin/main`` when it resolves, else ``HEAD``.

    The gate must name a base it can prove: guessing one silently would let a
    patch be judged against itself.
    """
    if _git(repo, "rev-parse", "--verify", "--quiet", "origin/main").ok:
        return "origin/main"
    return "HEAD"


def _diff_text(repo: str, base: str, head: Optional[str]) -> _Git:
    if head is None:
        return _git(repo, "diff", base)
    return _git(repo, "diff", base, head)


#: Largest untracked file the gate will read, in bytes. A generated blob is
#: not a test; it still appears in the diff, so the gate still has to judge it.
MAX_UNTRACKED_BYTES = 2 * 1024 * 1024


def _untracked_diff(repo: str) -> str:
    """Synthesise diff hunks for files git does not track yet.

    This is the difference between a gate that works on an agent's patch and
    one that works only after a human stages it. An agent's new test file is
    *untracked*: plain ``git diff`` does not show it, so a gate reading only
    ``git diff`` would see a code change with no test and file it as
    untested - or, worse, not see the new helper the test imports. Staging
    the agent's work to read it would mutate the index the agent is about to
    commit, so the hunk is built here instead.

    ``--exclude-standard`` keeps ignored files out on purpose: a file that
    will not land in the commit is not part of the patch under judgement.
    """
    listing = _git(repo, "ls-files", "--others", "--exclude-standard")
    if not listing.ok:
        return ""
    chunks: List[str] = []
    for rel in sorted(p for p in listing.out.splitlines() if p.strip()):
        if is_artifact_path(rel):
            continue
        full = os.path.join(repo, rel)
        try:
            size = os.path.getsize(full)
            if size > MAX_UNTRACKED_BYTES:
                chunks.append(
                    "diff --git a/{0} b/{0}\nnew file mode 100644\n"
                    "Binary files /dev/null and b/{0} differ\n".format(rel))
                continue
            with open(full, "rb") as fh:
                content = fh.read()
        except OSError:
            continue
        if b"\0" in content[:8000]:
            chunks.append(
                "diff --git a/{0} b/{0}\nnew file mode 100644\n"
                "Binary files /dev/null and b/{0} differ\n".format(rel))
            continue
        lines = content.decode("utf-8", "replace").splitlines()
        body = "".join("+{0}\n".format(line) for line in lines)
        chunks.append(
            "diff --git a/{0} b/{0}\nnew file mode 100644\n--- /dev/null\n"
            "+++ b/{0}\n@@ -0,0 +1,{1} @@\n{2}".format(rel, len(lines), body))
    return "".join(chunks)


def resolve_ref(repo: str, ref: str) -> str:
    """A ref's commit id, or the ref itself when it does not resolve.

    A record has to name a commit, not a name: ``HEAD`` moves the instant the
    patch is committed, so a record bound to ``HEAD`` would stop covering the
    very commit it verified - and a ``git push`` check would compare the empty
    ``HEAD..HEAD`` against a record that covered a full patch.
    """
    result = _git(repo, "rev-parse", "--verify", "--quiet", ref + "^{commit}")
    resolved = result.out.strip()
    return resolved if result.ok and resolved else ref


def _full_diff_text(repo: str, base: str, head: Optional[str]) -> _Git:
    """The diff the gate judges: git's own, plus untracked files in worktree mode."""
    result = _diff_text(repo, base, head)
    if not result.ok or head is not None:
        return result
    extra = _untracked_diff(repo)
    return _Git(result.rc, result.out + extra, result.err) if extra else result


def diff_digest(repo: str, base: str, head: Optional[str] = None) -> Optional[str]:
    """The digest of the diff a record would be bound to, or None."""
    result = _full_diff_text(repo, base, head)
    return diff_sha256(result.out) if result.ok else None


def _content(repo: str, path: str, head: Optional[str]) -> Optional[bytes]:
    """A file's content at the head side, or None when it does not exist there."""
    if head is None:
        full = os.path.join(repo, path)
        try:
            with open(full, "rb") as fh:
                return fh.read()
        except OSError:
            return None
    result = _git(repo, "show", "{}:{}".format(head, path))
    if not result.ok:
        return None
    return result.out.encode("utf-8")


def _extract(repo: str, ref: str, destination: str) -> Optional[str]:
    """Extract ``ref``'s tree into ``destination`` without touching the repo.

    ``git archive`` piped through ``tarfile`` rather than two chained
    processes: the base-revision state has to exist on disk before the replay
    starts, and a half-extracted tree that still runs would make the base run
    fail for the wrong reason.
    """
    with tempfile.TemporaryFile() as archive:
        proc = subprocess.run(
            ["git", "-C", repo, "archive", "--format=tar", ref],
            stdout=archive, stderr=subprocess.PIPE, check=False,
        )
        if proc.returncode != 0:
            return "git archive {} failed: {}".format(
                ref, (proc.stderr or b"").decode("utf-8", "replace").strip()[:300])
        archive.seek(0)
        import tarfile
        with tarfile.open(fileobj=archive, mode="r:") as tar:
            try:
                tar.extractall(destination, filter="data")
            except TypeError:  # Python < 3.12 has no extraction filter
                tar.extractall(destination)
    return None


# --------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------

def default_test_command(paths: Sequence[str]) -> Optional[List[str]]:
    """A test command derived from the touched test files, or None.

    Only pytest is inferred. Everything else needs ``--test-cmd``: guessing a
    runner is how a gate ends up green because nothing ran (exit code 5 from
    pytest means "no tests collected", which is a failure here, not a pass).
    """
    python_tests = [p for p in paths if p.endswith(".py")]
    if python_tests and len(python_tests) == len(paths):
        return [sys.executable, "-m", "pytest", "-q", *python_tests]
    return None


def gate(repo: Optional[str] = None,
         base: Optional[str] = None,
         head: Optional[str] = None,
         test_cmd: Optional[str] = None,
         timeout: int = DEFAULT_TIMEOUT,
         allow_untested: bool = False,
         rescan: Optional[str] = None,
         keep: Optional[str] = None,
         run: Optional[Callable[[Sequence[str], str, Dict[str, str], int],
                                Tuple[int, str]]] = None) -> Report:
    """Judge a patch. Never raises for an answerable question.

    ``head`` selects what is judged:

    * ``None`` (default) - the working tree, diffed against ``base``. This is
      what an agent has just produced, staged or not.
    * a ref - that commit, diffed against ``base``. This is what a CI job or a
      release check has.

    ``run`` is injectable for tests: ``(argv, cwd, env, timeout) -> (rc, out)``.
    """
    root = repo_root(repo) if repo else repo_root()
    if root is None:
        return Report(FAIL, [Check("repo", FAIL, "not inside a git working tree")],
                      repo or "", base or "", head or "WORKTREE", "", [], test_cmd)
    base_ref = base or default_base(root)
    base = resolve_ref(root, base_ref)
    diff_result = _full_diff_text(root, base, head)
    if not diff_result.ok:
        return Report(
            FAIL,
            [Check("diff", FAIL, "cannot diff {}..{}: {}".format(
                base, head or "WORKTREE", diff_result.err.strip()[:300]))],
            root, base, head or "WORKTREE", "", [], test_cmd)
    text = diff_result.out
    diff = parse_diff(text)
    checks: List[Check] = []

    if not text.strip() or not diff.files:
        checks.append(Check("diff", FAIL,
                            "the patch is empty: nothing to verify against {}".format(base)))
        return _finish(root, base, head, text, diff, checks, test_cmd, base_ref)

    checks.append(Check("diff", PASS, "{} file(s) changed against {}".format(
        len(diff.files), base)))

    tests = [f.path for f in diff.tests]
    code = [f.path for f in diff.code]
    if not code and not tests:
        checks.append(Check("scope", SKIP, "docs and metadata only: no code changed"))
        return _finish(root, base, head, text, diff, checks, test_cmd, base_ref)

    # 1. Every touched test file must be able to fail.
    checks.append(_assertion_check(root, diff, head))

    # 2. No added line may weaken the gate that is judging it.
    added = [line for f in diff.files for line in f.added]
    weakened = weakening_in(added)
    if weakened:
        checks.append(Check("no_weakening", FAIL, "; ".join(weakened[:4])))
    else:
        checks.append(Check("no_weakening", PASS, ""))

    # 3. Three-state replay: the patch's own tests must fail before it and pass
    #    after it. Without a test file this cannot be answered, and an
    #    unanswerable gate fails closed unless the operator says otherwise.
    if not tests:
        if allow_untested:
            checks.append(Check("replay", SKIP,
                                "no test file touched; allowed by --allow-untested"))
        else:
            checks.append(Check(
                "replay", FAIL,
                "patch changes {} code file(s) and adds or updates no test; "
                "a self-reported fix is not evidence".format(len(code))))
        return _finish(root, base, head, text, diff, checks, test_cmd, base_ref)

    cmd = _shell(test_cmd) if test_cmd else _derive_command(tests)
    if cmd is None:
        checks.append(Check(
            "replay", FAIL,
            "cannot derive a test command for {}; pass --test-cmd".format(
                ", ".join(tests[:3]))))
        return _finish(root, base, head, text, diff, checks, test_cmd, base_ref)
    runner = run or _run_command
    checks.extend(_replay(root, base, head, diff, cmd, timeout, runner, keep))

    if rescan:
        rc, out = runner(_shell(rescan), root, dict(os.environ), timeout)
        checks.append(Check("rescan", PASS if rc == 0 else FAIL,
                            "" if rc == 0 else "rescan failed (rc={}): {}".format(
                                rc, out.strip()[-300:])))
    return _finish(root, base, head, text, diff, checks, _render(cmd), base_ref)


def _finish(repo: str, base: str, head: Optional[str], text: str, diff: Diff,
            checks: List[Check], test_cmd: Optional[str],
            base_ref: Optional[str] = None) -> Report:
    verdict = FAIL if any(c.status == FAIL for c in checks) else PASS
    return Report(verdict=verdict, checks=checks, repo=repo, base=base,
                  head=head or "WORKTREE", diff_sha256=diff_sha256(text),
                  tests=[f.path for f in diff.tests], test_cmd=test_cmd,
                  base_ref=base_ref)


def _render(cmd: Sequence[str]) -> str:
    """A command as one line, for a record a human may read later."""
    return " ".join(cmd)


def _derive_command(tests: Sequence[str]) -> Optional[List[str]]:
    return default_test_command(list(tests))


def _assertion_check(repo: str, diff: Diff, head: Optional[str]) -> Check:
    empty: List[str] = []
    missing: List[str] = []
    deleted: List[str] = []
    for file in diff.tests:
        if file.is_deleted:
            deleted.append(file.path)
            continue
        content = _content(repo, file.path, head)
        if content is None:
            missing.append(file.path)
            continue
        text = content.decode("utf-8", "replace")
        if assertions_in(text) == 0:
            empty.append(file.path)
    if deleted:
        return Check("assertions", FAIL,
                     "the patch deletes test file(s): {}".format(", ".join(deleted[:5])))
    if missing:
        return Check("assertions", FAIL,
                     "cannot read touched test file(s): {}".format(", ".join(missing[:3])))
    if empty:
        return Check("assertions", FAIL,
                     "test file(s) with no assertion: {}".format(", ".join(empty[:5])))
    return Check("assertions", PASS, "{} test file(s) carry an assertion".format(len(diff.tests)))


def _replay(repo: str, base: str, head: Optional[str], diff: Diff, cmd: Any,
            timeout: int, runner: Callable[..., Tuple[int, str]],
            keep: Optional[str]) -> List[Check]:
    """Run the patch's tests at the base revision, then at the head."""
    workdir = keep or tempfile.mkdtemp(prefix="interlock-patch-gate-")
    base_tree = os.path.join(workdir, "base")
    os.makedirs(base_tree, exist_ok=True)
    try:
        problem = _extract(repo, base, base_tree)
        if problem:
            return [Check("replay", FAIL, problem)]
        # The patch's own test files, in place, on the pre-patch code: this is
        # the state the test was written to fail in. Newly *added* files ride
        # along for the same reason - a helper or fixture cannot change
        # pre-patch behaviour by existing, and leaving it out would make the
        # base run fail on an import instead of on the bug, which is the one
        # failure this check must not mistake for a real one.
        for file in list(diff.tests) + [f for f in diff.files if f.is_new and not f.is_test]:
            destination = os.path.join(base_tree, file.path)
            content = _content(repo, file.path, head)
            if content is None:
                if os.path.exists(destination):
                    os.remove(destination)
                continue
            os.makedirs(os.path.dirname(destination) or base_tree, exist_ok=True)
            with open(destination, "wb") as fh:
                fh.write(content)

        env = dict(os.environ)
        env["INTERLOCK_PATCH_GATE_STATE"] = "base"
        base_rc, _base_out = runner(cmd, base_tree, env, timeout)
        if base_rc == 0:
            return [Check(
                "replay", FAIL,
                "the patch's test passes at the pre-patch revision ({}): it does "
                "not test the change".format(base))]

        env = dict(os.environ)
        env["INTERLOCK_PATCH_GATE_STATE"] = "head"
        head_rc, head_out = runner(cmd, repo, env, timeout)
        checks = [
            Check("replay_base", PASS, "fails before the patch (rc={})".format(base_rc)),
            Check("replay_head", PASS if head_rc == 0 else FAIL,
                  "" if head_rc == 0 else
                  "the suite does not pass with the patch (rc={}): {}".format(
                      head_rc, head_out.strip()[-300:])),
        ]
        return checks
    finally:
        if keep is None:
            shutil.rmtree(workdir, ignore_errors=True)


def _shell(command: str) -> List[str]:
    return ["/bin/sh", "-c", command] if os.name != "nt" else ["cmd", "/c", command]


def _run_command(argv: Sequence[str], cwd: str, env: Dict[str, str],
                 timeout: int) -> Tuple[int, str]:
    try:
        proc = subprocess.run(argv, cwd=cwd, env=env, capture_output=True,
                              text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return 124, "timed out after {}s".format(timeout)
    except OSError as exc:
        return 127, "{}: {}".format(type(exc).__name__, exc)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


# --------------------------------------------------------------------------
# Signed gate records
# --------------------------------------------------------------------------

def default_gates_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".interlock", "patch-gates")


def default_key_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".interlock", "patch-gates.key")


def record_path(repo: str, gates_dir: Optional[str] = None) -> str:
    """Where a repo's latest gate record lives: one file per working tree."""
    directory = gates_dir or default_gates_dir()
    key = hashlib.sha256(os.path.realpath(repo).encode("utf-8")).hexdigest()[:16]
    return os.path.join(directory, key + ".json")


def _mac(key: bytes, payload: Dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, encoded, hashlib.sha256).hexdigest()


def _read_or_create_key(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            key = fh.read()
        if len(key) < 32:
            raise ValueError(
                "patch-gate key {} is truncated; restore it, or delete it to "
                "start a new one (which invalidates every gate record signed "
                "with the old key)".format(path))
        return key
    except FileNotFoundError:
        key = os.urandom(32)
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        return key


def write_record(report: Report, gates_dir: Optional[str] = None,
                 key_path: Optional[str] = None) -> str:
    """Sign and store a gate report. Returns the record's path."""
    directory = gates_dir or default_gates_dir()
    os.makedirs(directory, exist_ok=True)
    key = _read_or_create_key(key_path or default_key_path())
    payload = report.as_dict()
    payload["mac"] = _mac(key, payload)
    path = record_path(report.repo, directory)
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(temporary, path)
    return path


def read_record(repo: str, gates_dir: Optional[str] = None,
                key_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """The repo's signed gate record, or None when absent, tampered or stale."""
    path = record_path(repo, gates_dir)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("version") != RECORD_VERSION:
        return None
    claimed = payload.pop("mac", None)
    if not isinstance(claimed, str):
        return None
    try:
        key = _read_or_create_key(key_path or default_key_path())
    except (OSError, ValueError):
        return None
    if not hmac.compare_digest(claimed, _mac(key, payload)):
        return None
    if time.time() - float(payload.get("created_at") or 0) > RECORD_TTL_SEC:
        return None
    return payload


# --------------------------------------------------------------------------
# The gate as a policy layer
# --------------------------------------------------------------------------

def vcs_effect(event: Any, args: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """``"commit"``/``"push"``/``"merge"`` when the event makes a patch real.

    Reads only top-level string arguments, and only for an action that can run a
    shell command: a policy that fires on a note mentioning ``git commit`` is a
    false positive every agent writes. ``args`` overrides the event's own, so a
    MODIFY from an earlier layer is judged as the command that would actually
    run.
    """
    action = str(getattr(event, "action", "") or "")
    if action and not any(word in action.lower() for word in
                          ("bash", "shell", "command", "exec", "run", "terminal")):
        return None
    if args is None:
        args = getattr(event, "args", None)
    if not isinstance(args, dict):
        return None
    for value in args.values():
        if not isinstance(value, str):
            continue
        for pattern, effect in _EFFECTS:
            if pattern.search(value):
                return effect
    return None


class PatchGateEvaluator:
    """Wrap an evaluator and refuse unverified VCS effects.

    Composes exactly like the other wrapper evaluators: the inner policy decides
    first, and this layer only ever adds a restriction. A BLOCK from the inner
    engine is returned untouched - the gate cannot launder a block into an
    allow - and an ESCALATE too, because an approval is a human's judgement of
    a call, not evidence about whether the tests can fail.

    ``mode``:

    * ``"block"`` (default) - an uncovered commit/push/merge becomes a BLOCK.
    * ``"monitor"`` - the same finding, recorded as an ALLOW whose receipt
      carries the would-block reason and the ``patch_gate`` policy id. A
      rollout needs the measurements, not a silent no-op.

    ``gates_dir``/``key_path`` default to ``~/.interlock/``; pass
    :func:`default_gates_dir` / :func:`default_key_path` explicitly when a
    deployment stores them elsewhere (the simple tier and the shared tier are
    the same code path, only the paths differ).
    """

    policy_id = "patch_gate"

    def __init__(self, inner: Any, gates_dir: Optional[str] = None,
                 key_path: Optional[str] = None, mode: str = "block") -> None:
        if mode not in ("block", "monitor"):
            raise ValueError("mode must be 'block' or 'monitor'")
        self.inner = inner
        self.gates_dir = gates_dir
        self.key_path = key_path
        self.mode = mode

    def evaluate(self, event: Any) -> Any:
        from .enforce import Decision, Verdict

        decision = self.inner.evaluate(event)
        verdict = getattr(decision, "verdict", None)
        if verdict in (Verdict.BLOCK, Verdict.ESCALATE):
            return decision
        args = getattr(event, "args", None)
        if verdict == Verdict.MODIFY and isinstance(
                getattr(decision, "modified_args", None), dict):
            args = {**(args or {}), **decision.modified_args}
        effect = vcs_effect(event, args)
        if effect is None:
            return decision
        cwd = getattr(event, "cwd", None) or os.getcwd()
        root = repo_root(cwd)
        if root is None:
            return decision
        record = read_record(root, self.gates_dir, self.key_path)
        covered, why = self._covers(root, effect, record)
        if covered:
            return decision
        reason = (
            "this {} would land a patch that has not passed `interlock patch "
            "gate` ({}). Stage the patch and run `interlock patch gate` "
            "outside the agent, then retry.".format(effect, why))
        if self.mode == "monitor":
            return Decision.allow(reason="patch gate (monitor): " + reason,
                                  policy_id=self.policy_id)
        return Decision.block(reason, policy_id=self.policy_id,
                              attributed_to="command")

    def _covers(self, root: str, effect: str,
                record: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
        if record is None:
            return False, "no signed gate record for this working tree"
        if record.get("verdict") != PASS:
            return False, "the latest gate failed: {}".format(
                _record_reason(record))
        base = str(record.get("base") or "")
        if not base:
            return False, "the gate record names no base revision"
        candidates: List[List[str]] = []
        if effect == "commit":
            candidates.append(["diff", "--cached", base])
            candidates.append(["diff", base])
        else:
            candidates.append(["diff", "{}..HEAD".format(base)])
        head = record.get("head")
        if isinstance(head, str) and head not in ("WORKTREE", ""):
            candidates.append(["diff", "{}..{}".format(base, head)])
        for args in candidates:
            result = _git(root, *args)
            if result.ok and diff_sha256(result.out) == record.get("diff_sha256"):
                return True, ""
        return False, "the recorded pass does not cover this diff (it was granted for a different patch)"


def _record_reason(record: Dict[str, Any]) -> str:
    for check in record.get("checks") or []:
        if isinstance(check, dict) and check.get("status") == FAIL:
            return "{}: {}".format(check.get("id"), check.get("detail"))
    return "verdict {}".format(record.get("verdict"))
