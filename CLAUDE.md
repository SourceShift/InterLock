# interlock: agent working agreement

## Dev loop — worktree first, merge fast, smoke live

**Every change (code AND docs) lands in a worktree, then merges to main.** Branch creation in the main checkout is blocked by the `worktree-guard` hook — use the script:

```bash
bash scripts/codex-worktree.sh create <task-slug>     # the ONLY sanctioned way to branch
```

It creates `codex/<task-slug>` from `origin/main` in `../interlock-worktrees/<task-slug>`.
`bash scripts/codex-worktree.sh list` shows every worktree with its ahead/behind/dirty state.

**When a task is done: commit, merge, push — without being asked.** Then smoke it.

```bash
# 1. Rebase — a multi-minute gap is enough for a concurrent merge to land
git -C <worktree> fetch origin main --quiet && git -C <worktree> rebase origin/main

# 2. Stage EXPLICIT paths only. Never `git add -A`: it sweeps other sessions' work
#    and local scratch (rsi/, build output) into your commit.
git -C <worktree> add <file1> <file2>

# 3. SCOPE ASSERTION — the diff must contain ONLY files your task touched.
#    Deletions of files you never authored = STALE BASE. Rebase; do not merge.
git -C <worktree> diff --name-only origin/main

# 4. Ship
git -C <worktree> push origin <branch>:main            # direct ff-push to main
git -C <repo> fetch origin main --quiet
git -C <repo> merge --ff-only origin/main              # MANDATORY: refresh the local
#                                                        checkout, or anything run from
#                                                        it keeps running OLD code

# 5. gh run watch  →  then smoke against live (table below)
```

`bash scripts/codex-worktree.sh ship <task-slug>` runs steps 1, 3 and 4 for you once
step 2's commit is made: it refuses a dirty worktree, rebases, prints the scope and
stops on deletions (`SHIP_ALLOW_DELETIONS=1` to confirm intended ones), ff-pushes,
and refreshes the primary checkout. If the primary is on another branch it leaves
that checkout alone and fast-forwards the local `main` ref instead. Afterwards:
`bash scripts/codex-worktree.sh remove <task-slug>`.

**If step 4's `--ff-only` REFUSES** ("Not possible to fast-forward"), local main
has commits origin/main doesn't. **STOP. Do NOT `git merge origin/main` (plain),
do NOT `git reset --hard`, do NOT `--no-verify` past it.** Reconcile preserving
every SHA on both sides: move the local-only commits onto a worktree branch,
rebase it onto origin/main, ship it, then the local ff-refresh succeeds. A refusal
means investigate, never bulldoze.

**Smoke LOCAL, on `main` only** — a divergent checkout serves stale code. The
console binds loopback only; start it on a free port and stop it when done.

| Change kind | Smoke with |
|---|---|
| SDK (`interlock/`) | `python3 -m pytest -q` (full suite) + the targeted test file |
| Detector | `python3 scripts/gen_detector_catalog.py --check` + its tests |
| Console API (`interlock/console/`) | `python3 -m interlock.console --port <free>` + `curl` the route |
| Console web (`web/`) | `npm --prefix web test`, `npm --prefix web run build`, then `agent-browser` (open → screenshot → snapshot) against the console |
| Node client (`js/`) | `npm --prefix js test` |
| Rust scopes (`rust/`) | `maturin develop --release`, then the suite; check `interlock_scopes.__file__` is the fresh build, not a stale root `.so` |

**Tight fix-loops:** batch iterative fixes on the branch; ship once at the end.

## Docs are public

Everything under `docs/` is built and published at https://interlock.sourceshift.ai/docs/
by the Docs workflow, Markdown or not; Zensical has no exclude list. Scratch -- todos,
audits, notes -- goes in `todos/`, never `docs/todos/`, and `tests/test_site_config.py`
fails if that directory comes back. The landing page at the host root is `landing/`,
a second one-page build; `make docs` builds both halves into `site/` and checks them,
`make docs-serve` serves the result.

`internal-docs/` is ignored: private notes, and reviews nothing public links to. `research/`
is tracked and holds only what ROADMAP, GOVERNANCE, the manual or the code link to; a file
moves there when something public starts linking to it, not before.

## Guards

Install once per clone, and again whenever `.githooks/` changes:
`bash scripts/install-worktree-guards.sh` copies them into the shared `.git/hooks/`, so they
guard every checkout whatever branch it has. They keep the primary checkout a pure
fast-forward of origin/main.

| Guard | Hook | Refuses | Escape (deliberate, reviewed only) |
|---|---|---|---|
| worktree-guard | `reference-transaction` | creating a branch anywhere except via the script (`main`, `mini-ork/*` exempt) | `ALLOW_WORKTREE_BRANCH_CREATE=1` |
| G1 | `pre-commit` | any commit in the primary checkout | `ALLOW_MAIN_COMMIT=1` (main) / `WORKTREE_PRIMARY_COMMIT_GUARD=skip` |
| G10 | `pre-merge-commit` | a merge commit in the primary checkout (`--ff-only` refreshes pass) | `ALLOW_MAIN_MERGE=1` |
| G3/G4 | `pre-push` | deleting main, or a forced / stale push over it | `PUSH_MAIN_GUARD=skip` |

Never reach for an escape hatch to get unstuck; a guard firing means the work is
in the wrong place.
