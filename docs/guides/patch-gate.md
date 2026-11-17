# Patch gate

A coding agent's patch is judged by evidence the agent did not produce.

`interlock patch gate` asks three questions about a diff and writes a signed
record when all three hold. The hook adapters can then refuse a
`git commit`, `git push` or `git merge` that would land a diff no passing
record covers.

## Why

The failure this closes is measured, not hypothetical:

| Observation | Source |
|---|---|
| over 40% of patches an agent validated with its own tests fail developer-written regression tests | arxiv:2603.06858 |
| 24.8% of 319 agent patches were fully correct; agent code introduces vulnerabilities at ~9x the human rate | arxiv:2603.10072 |
| an independent exploit agent found a *new* confirmed exploit in 41% of runs after the patch blocked the original proof of concept | arxiv:2610.20245 |

They share a cause: the gate accepted the patch's own evidence. A test file
that exists is not coverage, and a test that passes before and after the change
proves nothing about the change.

## The three questions

1. **Does every test file the patch adds or edits contain an assertion?**
   A test file with no assertion is a file.
2. **Does the suite fail at the pre-patch revision, with the patch's own test
   files in place?** This is the check hand-rolled gates skip, and it is the one
   that separates a repair from a decorative test.
3. **Does the same suite pass with the patch applied?**

Plus one static rule: an added line may not weaken the gate that is judging it
(`pytest.mark.skip`, `@unittest.skip`, `it.skip(`, `.only(`, `#[ignore]`,
`--no-verify`, `continue-on-error: true`, `allow_failure: true`, `|| true` on a
test invocation, `set +e`).

## Quick start

```bash
interlock patch gate                     # judge the working tree vs origin/main
interlock patch gate --base HEAD~1       # against an explicit base
interlock patch gate --test-cmd 'npm test --silent'   # non-Python suites
interlock patch status                   # does a record cover the current diff?
```

Exit codes: `0` passed, `1` failed, `64` bad arguments. Nothing is committed,
staged or pushed by either command. A failed gate still writes its record - the
verdict is part of the evidence - and the hook refuses on it.

Output:

```
patch gate: PASS  base origin/main (bd49804a)  diff 0c8240f42e35
  ok    diff: 3 file(s) changed against origin/main
  ok    assertions: 1 test file(s) carry an assertion
  ok    no_weakening
  ok    replay_base: fails before the patch (rc=1)
  ok    replay_head
  test command: /usr/bin/python3 -m pytest -q tests/test_calc.py
  tests touched: tests/test_calc.py
  record: /Users/you/.interlock/patch-gates/e31bbe95dc1bf148.json
```

### Put it in front of the agent

```bash
# One session, no install:
INTERLOCK_PATCH_GATE=block interlock hook --agent claude-code
```

Or in the hook command line `interlock install-hook` already wrote, add
`--patch-gate block`. Values: `off` (default), `block`, `monitor`.

`monitor` records the same finding as an ALLOW whose receipt carries the
would-block reason and the `patch_gate` policy id, so a rollout has
measurements instead of a silent no-op. `--monitor` on the hook records every
verdict without refusing; the two are independent and compose.

## What counts as what

- **Test paths**: `tests/`, `test/`, `__tests__/`, `spec/`, `specs/`,
  `test_*.py`, `*_test.py`, `*_test.go`, `conftest.py`, `*.test.ts(x)`,
  `*.spec.js(x)`, `Test*.java|kt`, `*_spec.rb`. A convention, not a classifier:
  a guess about "is this a test" that is wrong in the strict direction is worse
  than a convention.
- **Assertion tokens**: `assert`, `pytest.raises`, `assertEqual`, `expect(`,
  `t.Errorf`, `assert_eq!`, `assertThrows(`, … across Python, JS/TS, Go, Rust,
  Java/Kotlin, Ruby. Presence, not style.
- **Code that is not code**: `docs/`, prose and image extensions. A diff of
  those alone needs no test. Config, CI and data files are *not* on that list:
  editing a workflow can change what ships.
- **No test file, no pass**: a code patch that adds or edits no test fails the
  replay check unless you pass `--allow-untested`, which records the skip
  instead of hiding it.

## How the replay works

The base revision is extracted with `git archive` into a temporary directory;
the patch's own test files (plus files the patch adds) are written over it; the
test command runs there, and then runs again in the real working tree. The base
run **must not exit 0** - a test that passes before the change does not test the
change.

Two states, two runs, one verdict. `--timeout` (default 600s) bounds each run; a
timeout is a failure, not a skip.

`git diff` does not show untracked files, and an agent's new test is untracked
until someone stages it. The gate synthesises hunks for files
`git ls-files --others --exclude-standard` reports, so it judges the patch the
agent actually wrote without touching the index.

## The signed record

A pass is written to `~/.interlock/patch-gates/<hash of the working tree>.json`
with an HMAC (`~/.interlock/patch-gates.key`, mode 0600, created on first use),
and bound to a digest of the diff's *content* - paths, added and removed lines,
blob ids - not of git's text. That is what lets one record cover the worktree
diff, the staged diff and the committed diff of the same patch, which is what
the hook needs when it recomputes the diff at the moment of the commit.

The record stores the **resolved commit** of the base, not the ref you typed:
`HEAD` moves the moment the patch is committed, so a record bound to the name
would stop covering the commit it verified - and the following `git push` would
compare an empty `HEAD..HEAD` against a full patch. The name is kept beside it
for display (`base origin/main (bd49804a)`).

The record is ignored when it is absent, unsigned, tampered with, older than 24
hours, or bound to a different diff. All four are "no record", and no record
means block.

The hook checks coverage, not correctness: it recomputes `git diff --cached
<base>` (for `commit`) or `git diff <base>..HEAD` (for `push`/`merge`) and
compares digests. Two cache-directory families are excluded from that digest on
both sides (`__pycache__`, `.pytest_cache`, `.mypy_cache`, `node_modules`, …),
because the replay itself produces them and they are not the patch.

## Two tiers

**Simple** - the defaults above. No server, no account, no network: a key file
and a directory under `$HOME`. Enough for one developer and one agent.

**Cooperative / shared** - point `--gates-dir` and `--key` at storage the agent
cannot write, and keep the key in your secret store:

```bash
interlock patch gate --gates-dir /srv/interlock/gates --key /run/secrets/patch-gate.key
# and the hook reads them from the same two locations:
#   --patch-gates-dir /srv/interlock/gates --patch-key /run/secrets/patch-gate.key
# or $INTERLOCK_PATCH_GATES_DIR and $INTERLOCK_PATCH_KEY
```

If the two disagree, no record is found and the gate blocks - the defaults
never quietly apply to a tree that was verified under different paths.

The gate fails closed on all of this: a missing key is an error, never an empty
string, and an unreadable record is a missing record.

## Limits, stated plainly

- **Not a sandbox.** The replay runs the repository's own test command. A
  hostile patch can ship a hostile test command, so run the gate somewhere that
  is acceptable - or pass `--test-cmd` with a command you chose.
- **A signature is this host's statement.** An agent that can read the key can
  sign its own pass. The boundary is the one the rest of the hook has: it holds
  only if the agent cannot write where the key lives.
- **The base run can fail for the wrong reason.** A test that imports a module
  the patch *creates* fails at the base revision because the module is absent.
  The gate counts that as "fails before the patch" and the head run decides, so
  it is weaker than a behavioural failure but not silently weaker.
- **Inference covers pytest only.** Everything else needs `--test-cmd`;
  a runner the gate guesses wrong is a gate that is green because nothing ran.
- **`--allow-untested` is a decision, not a default.** It is recorded as a skip
  in the record, so the exemption is visible afterwards.

## In CI

```bash
interlock patch gate --head HEAD --test-cmd 'pytest -q'
```

`--head` judges a commit instead of the working tree and needs no staging, so
the same three-state check runs on every pull request. That is the useful
division of labour: the hook refuses a local landing, CI proves the landed
patch.
