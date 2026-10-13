# Contributing to interlock

Thanks for helping. This page covers setting up, running the tests, adding a
detector, and keeping the docs accurate. For anything bigger than a bug fix or a
detector, open an issue first so we can agree on the approach.

## Set up

```bash
git clone https://github.com/SourceShift/InterLock.git
cd InterLock
pip install -e ".[dev]"
```

The package is pure Python with no build step and no runtime dependencies. The
`dev` extra adds `pytest` and `langchain-core` (for the LangChain adapter tests).

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

CI also runs a narrow lint over the package. Run it before you push:

```bash
pip install "ruff==0.16.9"
ruff check --select E9,F interlock/
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
  `docs/overview.md` indexes them all.
- **Match the voice.** Second person, short sentences, plain words. Explain why
  before how. Lead a guide with the problem it solves, show output after code,
  and end with an honest "Limits" section. Say what doesn't work as clearly as
  what does.

## Reporting a security issue

Please don't open a public issue. See the
[security model](docs/security-model.md#reporting-a-vulnerability).
