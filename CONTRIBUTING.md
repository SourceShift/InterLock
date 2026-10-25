# Contributing to interlock

Thanks for helping. This page covers setting up, running the tests, adding a
detector, and keeping the docs accurate. For anything bigger than a bug fix or a
detector, open an issue first so we can agree on the approach.

## Where to start

- **A detector request** is the easiest first PR: one module in
  `interlock/detectors/`, one test file, one catalog line. See
  [Adding a detector](#adding-a-detector).
- [`good first issue`](https://github.com/SourceShift/InterLock/labels/good%20first%20issue)
  and [`help wanted`](https://github.com/SourceShift/InterLock/labels/help%20wanted)
  are triaged to be self-contained.
- **A docs correction** can go straight to a PR; if you would rather report it,
  use the documentation issue form.
- **Anything larger** — a new adapter, a policy-language change, a console
  screen — open an issue first, or check [ROADMAP.md](ROADMAP.md) to see whether
  it is already planned.

## What runs where

| Surface | Path | Needs | Local gate |
|---|---|---|---|
| Python SDK | `interlock/`, `tests/` | Python 3.9–3.13 | `make check` |
| Node client | `js/` | Node 20, 22 or 24 | `make check-js` |
| Console UI | `web/` | Node ≥ 20.19 | `make check-web` |
| Docs site | `docs/` | Python ≥ 3.11 (Zensical) | the Docs workflow |
| Native scope store | `rust/` | Rust + maturin (optional) | `make check-rust` |

You only need the toolchain for the surface you change. The gates are the same
ones CI runs, and `make check-all` runs the first three.

## Set up

```bash
git clone https://github.com/SourceShift/InterLock.git
cd InterLock
pip install -e ".[dev]"
```

The package is pure Python with no build step and no runtime dependencies. The
`dev` extra adds `pytest`, `langchain-core` (for the LangChain adapter tests),
and the `ruff` version CI pins. Install the Node dependencies only for the
surface you touched:

```bash
npm --prefix js ci
npm --prefix web ci
```

## Run the tests

```bash
python -m pytest tests -q                    # the full Python suite
python -m pytest tests/test_guard.py -q      # one module
python -m pytest tests -q -rs                # also show why tests were skipped
```

`conftest.py` puts the repo root on `sys.path` and resets the global engine
between tests, so tests don't leak rules into each other. Some sandbox tests skip
on hosts without the backend they need (bubblewrap on macOS, for example), and
`-rs` names the reason.

Before you push, run the same gate CI runs:

```bash
make check        # ruff (E9,F), detector catalog --check, full pytest suite
```

`make check` needs only the Python toolchain. If your change touches `js/` or
`web/`, run `make check-js` or `make check-web` too — both install from the
lockfile, test, and build the artifact that ships:

```bash
make check-js     # npm ci, test, build for the Node client
make check-web    # npm ci, typecheck, test, build for the console UI
make check-all    # all three
```

## The console (`web/`)

The console UI is a React/Vite app whose built bundle ships inside the Python
package, so a type error is as user-visible as a Python bug. The dev server,
the generated design screens, and how each screen binds to the API are covered
in [the console guide](docs/guides/console.md#development).

```bash
npm --prefix web run dev        # dev server against a running console
npm --prefix web run typecheck  # every binding checked against the view model
npm --prefix web test           # vitest
npm --prefix web run build      # web/dist/, the bundle the server serves
```

The Node.js client has its own suite: see [js/README.md](js/README.md#development).

## Commit messages

Use the [Conventional Commits](https://www.conventionalcommits.org/) style the
history already follows, with a scope where it helps:

```
feat(mcp): capability leases that expire, enforced at call time
fix(guard): apply MODIFY rewrites to positional arguments
docs: explain rule order in concepts
```

The **pull request title** is the squash commit on `main`, so give the PR the
title you want in the history. A maintainer edits the title if it is not in this
form rather than asking you to rename the branch.

## How a pull request lands

- **Squash and merge** is the default: one PR becomes one Conventional-Commits
  commit on `main`, which keeps `git log --oneline main` readable and a revert
  one command. If you split a series into commits that are each worth keeping
  on their own, say so and we will rebase-merge instead. Merge commits are not
  used on `main`.
- **The required check is `ci-ok`**, the single job that aggregates Python,
  Rust, Node, console and lint. A red `ci-ok` is not mergeable; the individual
  job names tell you which half broke.
- **One approving review** and resolved conversations, for anything that touches
  `interlock/`, `js/`, `web/` or a workflow. Documentation-only PRs can land
  with checks green.
- **DCO; there is no CLA.** Sign off your commits with `git commit -s`
  (`Signed-off-by:` line) to certify you wrote or have the right to contribute
  the change. There is no separate paperwork.
- **Data comes with a warranty.** A change that adds data to the mesh
  commons (indicators, fingerprints, redacted samples, or the sample strings in
  a pack's `*.tests.json`) is covered by the same `Signed-off-by:`, which then
  also warrants that the data:
  1. was lawfully obtained;
  2. contains no personal data;
  3. contains no third party's confidential data.

  You warrant that you have the data, not that you wrote it: attackers wrote
  the payloads. That data is CC0-1.0 under [LICENSE-DATA](LICENSE-DATA); code
  and packs stay Apache-2.0 under [LICENSE](LICENSE). A sample later found to
  hold personal data is erased as [GOVERNANCE.md](GOVERNANCE.md#erasure) says.
- **Auto-merge is welcome** once `ci-ok` is green and the PR has its review.

## Adding a detector

A detector is one module in `interlock/detectors/` with a `POLICY_ID` and a
factory that returns a rule:

```python
"""What attack this catches, why it's visible at this point, and what is matched.

The first sentence becomes the detector's description in the docs catalog, so
make it a plain summary.
"""
from typing import Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "my_guard"


def my_guard(*, extra_patterns=None) -> Rule:
    def rule(event: SensorEvent) -> Optional[Decision]:
        # return None for "no opinion", Decision.block(...) or Decision.modify(...) to act
        return None

    return rule
```

The conventions every detector follows:

- **Never raise on odd input.** If `args` isn't a dict, a value is `None`, or a
  type is unexpected, return `None`. In production a raising rule stops the call.
- **Prefer precision over recall.** Match shapes that ordinary values won't
  contain, and explain the reasoning in the module docstring. A detector that
  fires on normal traffic gets switched off.
- **One concern per detector, standard library only.** Detectors stay
  dependency-free, like the core.
- **Name arguments, never values.** Set `attributed_to` to the argument's name.
- **Scope it on purpose.** If the detector only makes sense for certain tools,
  keep their names in a module-level constant whose name contains `ACTIONS`
  (for example `EGRESS_ACTIONS`). The catalog generator reads it to fill in
  "Scoped to". Accepting an `actions=` parameter lets users match their own tool
  names.
- **Test both sides.** Add `tests/test_<name>.py` covering a match *and* a
  non-match. The non-match test is what keeps a detector from becoming noise.
- **Don't auto-register.** Users import and install the detectors they want.

Then put it in the docs catalog:

1. Add the module name to the right category in `CATEGORIES` in
   [`scripts/gen_detector_catalog.py`](scripts/gen_detector_catalog.py). The
   script refuses to run while any detector is uncategorised.
2. Regenerate the page:

   ```bash
   python scripts/gen_detector_catalog.py
   ```

If the detector depends on an argument convention the generator can't see (a
special key like `__origin__`), add a line to `SCOPE_NOTES` in the same script.

## The native scope store

The optional Rust crate in `rust/` reimplements `ScopeTree`. Build and test it
with:

```bash
pip install maturin
cd rust && maturin develop --release && cd ..
python -c "from interlock.policy import SCOPE_BACKEND; print(SCOPE_BACKEND)"   # -> rust
python -m pytest tests/test_scopes.py tests/test_scope_backend.py -q
```

`tests/test_scope_backend.py` checks that the Python and Rust trees resolve
identically. If tests behave as though your change isn't there, look for a stale
`interlock_scopes*.so` in the repo root from an older build. It's git-ignored, so
`git status` won't show it, and it can shadow the module you just built. See
[rust/README.md](rust/README.md).

## Keeping the docs accurate

These docs have drifted from the code before, so treat a docs claim like code:

- **Run what you write.** Every code snippet in `README.md` and `docs/` was run,
  and the output shown is what it printed. If you change a snippet, run it again
  and paste the new output.
- **Regenerate the catalog** after touching a detector, and check it's current:

  ```bash
  python scripts/gen_detector_catalog.py --check
  ```

- **Check numbers before you change them:**

  ```bash
  ls interlock/detectors/*.py | grep -v __init__ | wc -l    # detector count
  python -m pytest tests -q | tail -1                       # test count
  ```

- **Follow the docs layout.** Tutorials go in `docs/getting-started.md`,
  explanations in `docs/concepts.md` and `docs/security-model.md`, task-focused
  how-tos in `docs/guides/`, and lookup material in `docs/reference/`.
  `docs/index.md` indexes them all.
- **Match the voice.** Second person, short sentences, plain words. Explain why
  before how. Lead a guide with the problem it solves, show output after code,
  and end with an honest "Limits" section. Say what doesn't work as clearly as
  what does.

## Changelog and releases

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
**A PR that changes user-visible behaviour adds a line under `## [Unreleased]`**
in the matching heading (`Added`, `Changed`, `Fixed`, `Deprecated`, `Removed`,
`Security`) as part of the same PR. Internal refactors, tests and CI do not need
an entry.

While the version is `0.x`, breaking changes land in the minor number; from 1.0
the project follows Semantic Versioning. Maintainers cut a release from `main`
by moving the `Unreleased` entries under a new version heading, bumping
`version` in `pyproject.toml`, `js/package.json` and `web/package.json`, and
publishing the Python package and Node client from that commit. Contributors do
not bump versions.

## Maintainer tooling (not needed to contribute)

Two bits of this repo exist for the maintainer's agent-assisted workflow and are
**not** part of a contributor's setup:

- `.githooks/` plus `scripts/install-worktree-guards.sh` keep the primary
  checkout a fast-forward of `main` for the maintainer's worktree loop. Do not
  run the installer: the `pre-commit` guard refuses every commit made in the
  primary checkout, which is not what you want on your own clone.
- `.mini-ork/`, the vendored mini-ork engine, is git-ignored and local only.

Your normal fork → branch → pull request flow is the supported path.

## Reporting a security issue

Please don't open a public issue. See the
[security model](docs/security-model.md#reporting-a-vulnerability).
